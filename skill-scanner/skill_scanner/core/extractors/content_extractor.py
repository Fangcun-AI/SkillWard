"""
Unpacks archives and compound document formats with built-in safety guards.

Handles ZIP, TAR (with gzip/bz2/xz), Office Open XML (DOCX/XLSX/PPTX),
and ZIP-derived containers (JAR, WAR, APK). Enforces configurable limits
on recursion depth, total bytes, entry count, and compression ratio to
prevent resource exhaustion (zip-bomb) and directory traversal attacks.
"""

import hashlib
import logging
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...utils.file_utils import get_file_type
from ..models import Finding, Severity, SkillFile, ThreatCategory

_log = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Configuration & result containers
# ------------------------------------------------------------------

@dataclass
class ExtractionLimits:
    """Governs how aggressively archives may be unpacked."""

    max_depth: int = 3
    max_total_size_bytes: int = 50 * 1024 * 1024  # 50 MiB ceiling
    max_file_count: int = 500
    max_compression_ratio: float = 100.0  # ratio above this flags a zip bomb


@dataclass
class ExtractionResult:
    """Aggregates everything produced while unpacking archives."""

    extracted_files: list[SkillFile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_extracted_size: int = 0
    total_extracted_count: int = 0


# ------------------------------------------------------------------
# Main extractor
# ------------------------------------------------------------------

_ZIP_LIKE_SUFFIXES = frozenset(
    {".zip", ".jar", ".war", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
)
_TAR_SUFFIXES = frozenset({".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"})
_OOXML_SUFFIXES = frozenset({".docx", ".xlsx", ".pptx"})


class ContentExtractor:
    """Unpacks archives and compound documents, collecting files and security findings."""

    ZIP_EXTENSIONS = _ZIP_LIKE_SUFFIXES
    TAR_EXTENSIONS = _TAR_SUFFIXES
    OFFICE_EXTENSIONS = _OOXML_SUFFIXES

    def __init__(self, limits: ExtractionLimits | None = None):
        self.limits = limits or ExtractionLimits()
        self._work_dirs: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_skill_archives(self, skill_files: list[SkillFile]) -> ExtractionResult:
        """Walk *skill_files*, unpack every recognised archive, return results.

        Archives are identified by file extension. Each recognised archive is
        unpacked into a temporary directory; nested archives are handled
        recursively up to the configured depth limit.
        """
        outcome = ExtractionResult()

        for sf in skill_files:
            if not self._looks_like_archive(sf):
                continue
            if not sf.path.exists():
                continue

            try:
                self._unpack(sf.path, sf.relative_path, outcome, nesting=0)
            except Exception as exc:
                _log.warning("Unpacking failed for %s: %s", sf.relative_path, exc)
                outcome.findings.append(
                    Finding(
                        id=f"EXTRACTION_FAILED_{hash(sf.relative_path) & 0xFFFFFFFF:08x}",
                        rule_id="ARCHIVE_EXTRACTION_FAILED",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.MEDIUM,
                        title="Archive extraction failed",
                        description=f"Could not extract {sf.relative_path}: {exc}",
                        file_path=sf.relative_path,
                        remediation="Ensure archive is not corrupted. Consider providing files directly.",
                        analyzer="static",
                    )
                )

        return outcome

    def cleanup(self) -> None:
        """Delete every temporary directory created during extraction."""
        for d in self._work_dirs:
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
        self._work_dirs.clear()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _unpack(
        self,
        path: Path,
        rel_path: str,
        outcome: ExtractionResult,
        nesting: int,
    ) -> None:
        """Route an archive to the right handler, enforcing depth limits."""
        if nesting > self.limits.max_depth:
            outcome.findings.append(
                Finding(
                    id=f"NESTED_ARCHIVE_{hash(rel_path) & 0xFFFFFFFF:08x}",
                    rule_id="ARCHIVE_NESTED_TOO_DEEP",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Deeply nested archive detected",
                    description=(
                        f"Archive {rel_path} has nesting depth > {self.limits.max_depth}. "
                        f"Deep nesting is a common obfuscation technique."
                    ),
                    file_path=rel_path,
                    remediation="Flatten archive structure.",
                    analyzer="static",
                )
            )
            return

        if outcome.total_extracted_count >= self.limits.max_file_count:
            return

        if self._has_tar_extension(path):
            self._handle_tar(path, rel_path, outcome, nesting)
        elif path.suffix.lower() in _ZIP_LIKE_SUFFIXES:
            self._handle_zip(path, rel_path, outcome, nesting)

    # ------------------------------------------------------------------
    # ZIP handling
    # ------------------------------------------------------------------

    def _handle_zip(
        self, arc_path: Path, rel_path: str, outcome: ExtractionResult, nesting: int
    ) -> None:
        """Safely unpack a ZIP-based container."""
        try:
            with zipfile.ZipFile(arc_path, "r") as zf:
                if not self._zip_ratio_ok(zf, arc_path, rel_path, outcome):
                    return
                if not self._zip_entries_safe(zf, rel_path, outcome):
                    return

                work = tempfile.mkdtemp(prefix="skillscan_z_")
                self._work_dirs.append(work)

                self._unzip_members(zf, work, rel_path, outcome, nesting)

                # Office-specific inspections
                if arc_path.suffix.lower() in _OOXML_SUFFIXES:
                    self._scan_office_content(arc_path, rel_path, zf, outcome)

                # Recurse into any nested archives we just unpacked
                self._recurse_nested(rel_path, outcome, nesting)

        except zipfile.BadZipFile as exc:
            outcome.findings.append(
                Finding(
                    id=f"BAD_ZIP_{hash(rel_path) & 0xFFFFFFFF:08x}",
                    rule_id="ARCHIVE_EXTRACTION_FAILED",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.MEDIUM,
                    title="Corrupt or malformed ZIP archive",
                    description=f"Archive {rel_path} is corrupt: {exc}",
                    file_path=rel_path,
                    remediation="Remove corrupt archive.",
                    analyzer="static",
                )
            )

    def _zip_ratio_ok(
        self,
        zf: zipfile.ZipFile,
        arc_path: Path,
        rel_path: str,
        outcome: ExtractionResult,
    ) -> bool:
        """Return False and record a finding if the compression ratio is suspicious."""
        raw_total = sum(i.file_size for i in zf.infolist() if not i.is_dir())
        on_disk = arc_path.stat().st_size
        if on_disk <= 0:
            return True
        ratio = raw_total / on_disk
        if ratio <= self.limits.max_compression_ratio:
            return True

        outcome.findings.append(
            Finding(
                id=f"ZIP_BOMB_{hash(rel_path) & 0xFFFFFFFF:08x}",
                rule_id="ARCHIVE_ZIP_BOMB",
                category=ThreatCategory.RESOURCE_ABUSE,
                severity=Severity.CRITICAL,
                title="Potential zip bomb detected",
                description=(
                    f"Archive {rel_path} has compression ratio {ratio:.0f}:1 "
                    f"(threshold: {self.limits.max_compression_ratio:.0f}:1). "
                    f"This may be a zip bomb designed to cause denial of service."
                ),
                file_path=rel_path,
                remediation="Remove suspicious archive or verify its contents.",
                analyzer="static",
            )
        )
        return False

    def _zip_entries_safe(
        self, zf: zipfile.ZipFile, rel_path: str, outcome: ExtractionResult
    ) -> bool:
        """Validate all ZIP entries for traversal attacks and symlinks."""
        for entry in zf.infolist():
            if ".." in entry.filename or entry.filename.startswith("/"):
                outcome.findings.append(
                    Finding(
                        id=f"PATH_TRAVERSAL_{hash(rel_path + entry.filename) & 0xFFFFFFFF:08x}",
                        rule_id="ARCHIVE_PATH_TRAVERSAL",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Path traversal in archive",
                        description=(
                            f"Archive {rel_path} contains entry with path traversal: "
                            f"'{entry.filename}'. This could overwrite files outside the extraction directory."
                        ),
                        file_path=rel_path,
                        remediation="Remove malicious archive entries.",
                        analyzer="static",
                    )
                )
                return False

            if self._entry_is_symlink(entry):
                outcome.findings.append(
                    Finding(
                        id=f"SYMLINK_{hash(rel_path + entry.filename) & 0xFFFFFFFF:08x}",
                        rule_id="ARCHIVE_SYMLINK",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Symlink entry in archive",
                        description=(
                            f"Archive {rel_path} contains a symbolic link entry: "
                            f"'{entry.filename}'. Symlinks inside archives can be used to read or "
                            f"overwrite files outside the extraction directory."
                        ),
                        file_path=rel_path,
                        remediation="Remove symbolic links from the archive and include files directly.",
                        analyzer="static",
                    )
                )
                return False
        return True

    def _unzip_members(
        self,
        zf: zipfile.ZipFile,
        dest: str,
        rel_path: str,
        outcome: ExtractionResult,
        nesting: int,
    ) -> None:
        """Extract individual ZIP members, enforcing size/count caps."""
        for entry in zf.infolist():
            if entry.is_dir():
                continue
            if outcome.total_extracted_count >= self.limits.max_file_count:
                break
            if outcome.total_extracted_size + entry.file_size > self.limits.max_total_size_bytes:
                break

            out_path = Path(dest) / entry.filename
            out_path.parent.mkdir(parents=True, exist_ok=True)
            zf.extract(entry, dest)

            # Belt-and-suspenders: remove symlinks that slipped through
            if out_path.is_symlink():
                out_path.unlink()
                outcome.findings.append(
                    Finding(
                        id=f"SYMLINK_ON_DISK_{hash(rel_path + entry.filename) & 0xFFFFFFFF:08x}",
                        rule_id="ARCHIVE_SYMLINK",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Symlink created during archive extraction",
                        description=(
                            f"Extracting '{entry.filename}' from {rel_path} created "
                            f"a symbolic link on disk. The link has been removed."
                        ),
                        file_path=rel_path,
                        remediation="Remove symbolic links from the archive and include files directly.",
                        analyzer="static",
                    )
                )
                continue

            outcome.total_extracted_count += 1
            outcome.total_extracted_size += entry.file_size

            virt_rel = f"{rel_path}!/{entry.filename}"
            ftype = get_file_type(out_path)
            text = None
            if ftype != "binary":
                try:
                    text = out_path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    ftype = "binary"

            outcome.extracted_files.append(
                SkillFile(
                    path=out_path,
                    relative_path=virt_rel,
                    file_type=ftype,
                    content=text,
                    size_bytes=entry.file_size,
                    extracted_from=rel_path,
                    archive_depth=nesting + 1,
                )
            )

    # ------------------------------------------------------------------
    # TAR handling
    # ------------------------------------------------------------------

    def _handle_tar(
        self, arc_path: Path, rel_path: str, outcome: ExtractionResult, nesting: int
    ) -> None:
        """Safely unpack a TAR-based archive."""
        try:
            with tarfile.open(arc_path, "r:*") as tf:
                if not self._tar_entries_safe(tf, rel_path, outcome):
                    return

                work = tempfile.mkdtemp(prefix="skillscan_t_")
                self._work_dirs.append(work)

                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    if outcome.total_extracted_count >= self.limits.max_file_count:
                        break
                    if outcome.total_extracted_size + member.size > self.limits.max_total_size_bytes:
                        break

                    tf.extract(member, work, filter="data")
                    out_path = Path(work) / member.name

                    outcome.total_extracted_count += 1
                    outcome.total_extracted_size += member.size

                    virt_rel = f"{rel_path}!/{member.name}"
                    ftype = get_file_type(out_path)
                    text = None
                    if ftype != "binary":
                        try:
                            text = out_path.read_text(encoding="utf-8")
                        except (UnicodeDecodeError, OSError):
                            ftype = "binary"

                    outcome.extracted_files.append(
                        SkillFile(
                            path=out_path,
                            relative_path=virt_rel,
                            file_type=ftype,
                            content=text,
                            size_bytes=member.size,
                            extracted_from=rel_path,
                            archive_depth=nesting + 1,
                        )
                    )

                self._recurse_nested(rel_path, outcome, nesting)

        except (tarfile.TarError, OSError) as exc:
            outcome.findings.append(
                Finding(
                    id=f"BAD_TAR_{hash(rel_path) & 0xFFFFFFFF:08x}",
                    rule_id="ARCHIVE_EXTRACTION_FAILED",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.MEDIUM,
                    title="Corrupt or malformed TAR archive",
                    description=f"Archive {rel_path} is corrupt: {exc}",
                    file_path=rel_path,
                    remediation="Remove corrupt archive.",
                    analyzer="static",
                )
            )

    def _tar_entries_safe(
        self, tf: tarfile.TarFile, rel_path: str, outcome: ExtractionResult
    ) -> bool:
        """Screen TAR members for traversal and link attacks."""
        for member in tf.getmembers():
            if ".." in member.name or member.name.startswith("/"):
                outcome.findings.append(
                    Finding(
                        id=f"PATH_TRAVERSAL_{hash(rel_path + member.name) & 0xFFFFFFFF:08x}",
                        rule_id="ARCHIVE_PATH_TRAVERSAL",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Path traversal in archive",
                        description=(
                            f"Archive {rel_path} contains entry with path traversal: "
                            f"'{member.name}'."
                        ),
                        file_path=rel_path,
                        remediation="Remove malicious archive entries.",
                        analyzer="static",
                    )
                )
                return False

            if member.issym() or member.islnk():
                link_kind = "symbolic" if member.issym() else "hard"
                outcome.findings.append(
                    Finding(
                        id=f"SYMLINK_{hash(rel_path + member.name) & 0xFFFFFFFF:08x}",
                        rule_id="ARCHIVE_SYMLINK",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Symlink or hardlink entry in archive",
                        description=(
                            f"Archive {rel_path} contains a "
                            f"{link_kind} link entry: "
                            f"'{member.name}' -> '{member.linkname}'. Links inside archives "
                            f"can be used to read or overwrite files outside the extraction directory."
                        ),
                        file_path=rel_path,
                        remediation="Remove symbolic/hard links from the archive and include files directly.",
                        analyzer="static",
                    )
                )
                return False
        return True

    # ------------------------------------------------------------------
    # Office document inspection
    # ------------------------------------------------------------------

    def _scan_office_content(
        self,
        arc_path: Path,
        rel_path: str,
        zf: zipfile.ZipFile,
        outcome: ExtractionResult,
    ) -> None:
        """Flag VBA macros and embedded OLE objects inside Office Open XML files."""
        entries = zf.namelist()

        vba_hits = [n for n in entries if "vbaProject" in n]
        if vba_hits:
            outcome.findings.append(
                Finding(
                    id=f"VBA_MACRO_{hashlib.sha256(rel_path.encode()).hexdigest()[:8]}",
                    rule_id="OFFICE_VBA_MACRO",
                    category=ThreatCategory.COMMAND_INJECTION,
                    severity=Severity.CRITICAL,
                    title="VBA macro detected in Office document",
                    description=(
                        f"Office document {rel_path} contains VBA macros: "
                        f"{', '.join(vba_hits[:3])}. VBA macros can execute arbitrary code."
                    ),
                    file_path=rel_path,
                    remediation="Remove VBA macros or replace with a text-based format (Markdown, plain text).",
                    analyzer="static",
                )
            )

        ole_hits = [n for n in entries if "oleObject" in n or "embeddings" in n.lower()]
        if ole_hits:
            outcome.findings.append(
                Finding(
                    id=f"OLE_OBJECT_{hash(rel_path) & 0xFFFFFFFF:08x}",
                    rule_id="OFFICE_EMBEDDED_OLE",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Embedded OLE object in Office document",
                    description=(
                        f"Office document {rel_path} contains embedded OLE objects. "
                        f"These can contain executables or other malicious content."
                    ),
                    file_path=rel_path,
                    remediation="Remove embedded objects from the document.",
                    analyzer="static",
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _recurse_nested(
        self, parent_rel: str, outcome: ExtractionResult, nesting: int
    ) -> None:
        """Find archives that were just extracted from *parent_rel* and unpack them."""
        for sf in list(outcome.extracted_files):
            if sf.extracted_from != parent_rel:
                continue
            if not sf.path.exists():
                continue
            if self._looks_like_archive_path(sf.path):
                self._unpack(sf.path, sf.relative_path, outcome, nesting + 1)

    def _looks_like_archive(self, sf: SkillFile) -> bool:
        """Decide whether a SkillFile is an archive worth unpacking."""
        return self._looks_like_archive_path(sf.path)

    @staticmethod
    def _looks_like_archive_path(p: Path) -> bool:
        """Return True if the path has a recognised archive extension."""
        suffix = p.suffix.lower()
        name = p.name.lower()
        if suffix in _ZIP_LIKE_SUFFIXES:
            return True
        if suffix == ".tar":
            return True
        for ending in (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"):
            if name.endswith(ending):
                return True
        return False

    @staticmethod
    def _has_tar_extension(p: Path) -> bool:
        """Check whether *p* should be treated as a TAR variant."""
        suffix = p.suffix.lower()
        name = p.name.lower()
        return (
            suffix == ".tar"
            or name.endswith(".tar.gz")
            or name.endswith(".tgz")
            or name.endswith(".tar.bz2")
            or name.endswith(".tar.xz")
        )

    @staticmethod
    def _entry_is_symlink(info: zipfile.ZipInfo) -> bool:
        """Detect whether a ZIP entry represents a symbolic link on Unix."""
        mode_bits = (info.external_attr >> 16) & 0xFFFF
        return mode_bits != 0 and stat.S_ISLNK(mode_bits)
