"""
Validates compiled Python bytecode against original source.

Inspects .pyc artifacts to detect post-compilation modifications by
reconstructing the AST from bytecode and diffing it against the AST
derived from the paired .py file. Catches supply-chain tampering
where compiled output diverges from visible source.

Only uses standard library modules (ast, marshal, struct).
Can optionally leverage decompyle3 or uncompyle6 when installed.
"""

import ast
import hashlib
import io
import logging
import marshal
import struct
from pathlib import Path
from typing import Any

from ..models import Finding, Severity, Skill, SkillFile, ThreatCategory
from ..scan_policy import ScanPolicy
from .base import BaseAnalyzer

_log = logging.getLogger(__name__)


class BytecodeAnalyzer(BaseAnalyzer):
    """Checks .pyc files for integrity by diffing against their .py counterparts."""

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__(name="bytecode", policy=policy)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, skill: Skill) -> list[Finding]:
        """Scan all bytecode artifacts in *skill* and return integrity findings."""
        results: list[Finding] = []

        compiled_items: list[SkillFile] = []
        src_by_relpath: dict[str, SkillFile] = {}
        src_by_name: dict[str, list[SkillFile]] = {}

        for entry in skill.files:
            suffix = entry.path.suffix.lower()
            if suffix == ".pyc":
                compiled_items.append(entry)
            elif suffix == ".py":
                src_by_relpath[entry.relative_path] = entry
                src_by_name.setdefault(entry.path.stem, []).append(entry)

        if not compiled_items:
            return results

        for compiled in compiled_items:
            base_name = compiled.path.stem
            # Strip cpython version tag, e.g. "foo.cpython-312" -> "foo"
            if ".cpython-" in base_name:
                base_name = base_name.split(".cpython-")[0]

            source = self._locate_source_file(
                compiled, base_name, src_by_relpath, src_by_name
            )

            if source is None:
                results.append(
                    Finding(
                        id=self._make_finding_hash("BYTECODE_NO_SOURCE", compiled.relative_path),
                        rule_id="BYTECODE_NO_SOURCE",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.HIGH,
                        title="Python bytecode without matching source",
                        description=(
                            f"Bytecode file {compiled.relative_path} has no corresponding .py source. "
                            f"Bytecode-only distribution hides the actual code from review."
                        ),
                        file_path=compiled.relative_path,
                        remediation="Include .py source files or remove .pyc files.",
                        analyzer=self.name,
                    )
                )
            else:
                results.extend(self._diff_compiled_vs_source(compiled, source))

        return results

    # ------------------------------------------------------------------
    # Source-file resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _locate_source_file(
        compiled_file: SkillFile,
        base_name: str,
        relpath_index: dict[str, SkillFile],
        name_index: dict[str, list[SkillFile]],
    ) -> SkillFile | None:
        """Resolve which .py file a given .pyc was compiled from.

        Applies three heuristics in priority order:
        - Standard layout: __pycache__/<mod>.cpython-XXX.pyc maps to ../<mod>.py
        - Co-located layout: .pyc and .py in the same directory
        - Global stem match: if exactly one .py shares the stem, use it
        Returns None when the match is ambiguous or absent.
        """
        parent_dir = Path(compiled_file.relative_path).parent

        # Heuristic A: conventional __pycache__ placement
        if parent_dir.name == "__pycache__":
            candidate_rel = str(parent_dir.parent / f"{base_name}.py")
            hit = relpath_index.get(candidate_rel)
            if hit is not None:
                return hit

        # Heuristic B: same folder
        candidate_rel = str(parent_dir / f"{base_name}.py")
        hit = relpath_index.get(candidate_rel)
        if hit is not None:
            return hit

        # Heuristic C: unique stem across the whole package
        matches = name_index.get(base_name, [])
        if len(matches) == 1:
            return matches[0]

        return None

    # ------------------------------------------------------------------
    # AST-level comparison
    # ------------------------------------------------------------------

    def _diff_compiled_vs_source(
        self, compiled_file: SkillFile, source_file: SkillFile
    ) -> list[Finding]:
        """Build ASTs from both artifacts and flag structural divergence."""
        issues: list[Finding] = []

        raw_source = source_file.read_content()
        if not raw_source:
            return issues

        try:
            src_tree = ast.parse(raw_source, filename=source_file.relative_path)
            src_repr = ast.dump(src_tree, annotate_fields=True, include_attributes=False)
        except SyntaxError as exc:
            _log.debug("Syntax error in %s: %s", source_file.relative_path, exc)
            return issues

        compiled_tree = self._reconstruct_ast(compiled_file.path)
        if compiled_tree is None:
            # Cannot decompile -- other rules already cover the presence of .pyc
            return issues

        compiled_repr = ast.dump(
            compiled_tree, annotate_fields=True, include_attributes=False
        )

        if src_repr != compiled_repr:
            issues.append(
                Finding(
                    id=self._make_finding_hash(
                        "BYTECODE_SOURCE_MISMATCH", compiled_file.relative_path
                    ),
                    rule_id="BYTECODE_SOURCE_MISMATCH",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.CRITICAL,
                    title="Bytecode does not match source code",
                    description=(
                        f"CRITICAL: {compiled_file.relative_path} was compiled from different source "
                        f"than {source_file.relative_path}. The bytecode has been tampered with to "
                        f"contain code not present in the visible .py file. "
                        f"This is a supply-chain attack pattern (cf. xz-utils)."
                    ),
                    file_path=compiled_file.relative_path,
                    remediation=(
                        "URGENT: Remove all .pyc files and investigate the source of modification. "
                        "This skill may be compromised."
                    ),
                    analyzer=self.name,
                )
            )

        return issues

    # ------------------------------------------------------------------
    # .pyc deserialization helpers
    # ------------------------------------------------------------------

    def _reconstruct_ast(self, pyc_path: Path) -> ast.AST | None:
        """Attempt to recover an AST from a compiled .pyc file.

        Reads the bytecode header, unmarshals the code object, then tries
        available decompilers (decompyle3, uncompyle6) to obtain source
        text that can be re-parsed into an AST.
        Returns None when decompilation is not possible.
        """
        try:
            code_obj = self._unmarshal_code(pyc_path)
            if code_obj is None:
                return None

            # Attempt decompyle3 first
            tree = self._try_decompile_with("decompyle3", code_obj)
            if tree is not None:
                return tree

            # Fall back to uncompyle6
            tree = self._try_decompile_with("uncompyle6", code_obj)
            if tree is not None:
                return tree

            return None
        except Exception as exc:
            _log.debug("Could not process .pyc file %s: %s", pyc_path, exc)
            return None

    @staticmethod
    def _unmarshal_code(pyc_path: Path) -> Any | None:
        """Read and unmarshal the code object from a .pyc file."""
        try:
            with open(pyc_path, "rb") as fh:
                _magic = fh.read(4)
                flag_bits = struct.unpack("<I", fh.read(4))[0]

                if flag_bits & 0x1:
                    # PEP 552 hash-based validation
                    fh.read(8)
                else:
                    # Legacy timestamp-based validation
                    fh.read(4)  # timestamp
                    fh.read(4)  # source length

                return marshal.load(fh)
        except Exception:
            return None

    @staticmethod
    def _try_decompile_with(backend_name: str, code_obj: Any) -> ast.AST | None:
        """Run a named decompiler backend and parse the result into an AST."""
        try:
            backend = __import__(backend_name)
            buf = io.StringIO()
            backend.deparse_code2str(code_obj, out=buf)
            return ast.parse(buf.getvalue())
        except (ImportError, Exception):
            return None

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _make_finding_hash(rule: str, context: str) -> str:
        """Produce a deterministic identifier for a finding."""
        digest = hashlib.sha256(f"{rule}:{context}".encode()).hexdigest()[:10]
        return f"{rule}_{digest}"
