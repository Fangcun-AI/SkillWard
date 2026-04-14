"""
Inspection-coverage scoring for skill packages.

Measures what fraction of a skill's content the scanner is able to
meaningfully examine.  Files that defy inspection -- encrypted blobs,
stripped binaries, bytecode lacking corresponding sources -- reduce the
overall coverage score.

    coverage = (inspectable_weight / cumulative_weight) * 100

A low coverage value is not proof of malice; it simply means the scanner
cannot provide a confident safety assessment.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import Skill, SkillFile

if TYPE_CHECKING:
    from .scan_policy import ScanPolicy


# ------------------------------------------------------------------
# Data containers
# ------------------------------------------------------------------

@dataclass
class FileAnalyzability:
    """Per-file inspection verdict."""

    relative_path: str
    file_type: str
    size_bytes: int
    is_analyzable: bool
    analysis_methods: list[str] = field(default_factory=list)
    skip_reason: str | None = None
    weight: float = 1.0  # Larger/more important files have higher weight


@dataclass
class AnalyzabilityReport:
    """Aggregated inspection-coverage result for an entire skill."""

    score: float = 100.0  # 0-100
    total_files: int = 0
    analyzed_files: int = 0
    unanalyzable_files: int = 0
    total_weight: float = 0.0
    analyzed_weight: float = 0.0
    file_details: list[FileAnalyzability] = field(default_factory=list)
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH based on score

    def to_dict(self) -> dict[str, Any]:
        """Serialise the report to a plain dictionary."""
        blocked = [
            {"path": entry.relative_path, "reason": entry.skip_reason}
            for entry in self.file_details
            if not entry.is_analyzable
        ]
        return {
            "score": round(self.score, 1),
            "total_files": self.total_files,
            "analyzed_files": self.analyzed_files,
            "unanalyzable_files": self.unanalyzable_files,
            "risk_level": self.risk_level,
            "unanalyzable_file_list": blocked,
        }


# ------------------------------------------------------------------
# Recognised extension / type sets
# ------------------------------------------------------------------

SUPPORTED_FILE_KINDS = frozenset({"python", "bash", "markdown", "other"})

READABLE_EXTENSIONS = frozenset({
    ".py", ".sh", ".bash", ".rb", ".pl",
    ".js", ".ts", ".php",
    ".md", ".markdown", ".txt", ".rst",
    ".json", ".yaml", ".yml", ".xml",
    ".html", ".css",
    ".toml", ".cfg", ".ini", ".conf",
    ".csv", ".env",
    ".gitignore", ".dockerignore",
})

PASSIVE_MEDIA_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".webp", ".ico", ".tiff", ".tif", ".svg",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
})


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _derive_inspection_techniques(sf: SkillFile) -> list[str]:
    """Return the list of inspection techniques applicable to *sf*."""
    suffix = sf.path.suffix.lower()
    techniques: list[str] = []

    if sf.file_type == "python":
        techniques += ["static_regex", "yara_scan", "behavioral_ast"]
    elif sf.file_type == "bash":
        techniques += ["static_regex", "yara_scan", "command_safety"]
    elif sf.file_type == "markdown":
        techniques += ["static_regex", "yara_scan", "prompt_analysis"]
    else:
        techniques.append("yara_scan")

    if suffix in (".json", ".yaml", ".yml", ".toml"):
        techniques.append("config_analysis")

    return techniques


def _assess_single_file(sf: SkillFile, all_files: list[SkillFile]) -> FileAnalyzability:
    """Produce an analyzability verdict for one file."""
    log_weight = max(1.0, math.log2(max(sf.size_bytes, 1)))
    suffix = sf.path.suffix.lower()

    verdict = FileAnalyzability(
        relative_path=sf.relative_path,
        file_type=sf.file_type,
        size_bytes=sf.size_bytes,
        is_analyzable=False,
        weight=log_weight,
    )

    # --- Category 1: known inspectable file kinds ---
    if sf.file_type in SUPPORTED_FILE_KINDS:
        content = sf.read_content()
        if content:
            verdict.is_analyzable = True
            verdict.analysis_methods = _derive_inspection_techniques(sf)
        else:
            verdict.skip_reason = "File exists but content is empty or unreadable"
        return verdict

    # --- Category 2: passive media / font assets ---
    if suffix in PASSIVE_MEDIA_EXTENSIONS:
        verdict.is_analyzable = True
        verdict.analysis_methods = ["magic_byte_check", "extension_validation"]
        return verdict

    # --- Category 3: compiled Python bytecode ---
    if suffix in (".pyc", ".pyo"):
        stem_base = sf.path.stem.split(".cpython-")[0]
        source_present = any(
            f.path.suffix == ".py"
            and f.path.stem.split(".cpython-")[0] == stem_base
            for f in all_files
        )
        if source_present:
            verdict.is_analyzable = True
            verdict.analysis_methods = ["bytecode_integrity_check"]
        else:
            verdict.skip_reason = "Bytecode without matching source - cannot verify"
        return verdict

    # --- Category 4: generic binary blob ---
    if sf.file_type == "binary":
        verdict.skip_reason = f"Binary file ({suffix}) - cannot inspect content"
        return verdict

    # --- Fallback: unrecognised format ---
    verdict.skip_reason = f"Unknown file type ({suffix})"
    return verdict


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------

def compute_analyzability(
    skill: Skill,
    *,
    policy: ScanPolicy | None = None,
) -> AnalyzabilityReport:
    """Calculate the inspection-coverage report for *skill*.

    Every file is assigned a log-scaled weight proportional to its byte
    size so that large opaque artefacts pull the score down more than
    tiny ones.

    Parameters
    ----------
    skill:
        Skill package whose files will be evaluated.
    policy:
        When supplied, risk-level thresholds are drawn from
        ``policy.analysis_thresholds`` instead of the built-in defaults.

    Returns
    -------
    AnalyzabilityReport
        Populated report with per-file details and an aggregate score.
    """
    report = AnalyzabilityReport()

    if not skill.files:
        return report  # defaults: score=100, risk_level="LOW"

    # Evaluate every file and accumulate totals in one pass.
    for sf in skill.files:
        entry = _assess_single_file(sf, skill.files)
        report.file_details.append(entry)
        report.total_files += 1
        report.total_weight += entry.weight

        if entry.is_analyzable:
            report.analyzed_files += 1
            report.analyzed_weight += entry.weight
        else:
            report.unanalyzable_files += 1

    # Derive the percentage score.
    report.score = (
        (report.analyzed_weight / report.total_weight) * 100.0
        if report.total_weight > 0
        else 100.0
    )

    # Map score to a risk band using policy overrides when available.
    safe_ceiling = 90
    caution_floor = 70
    if policy is not None:
        safe_ceiling = policy.analysis_thresholds.analyzability_low_risk
        caution_floor = policy.analysis_thresholds.analyzability_medium_risk

    if report.score >= safe_ceiling:
        report.risk_level = "LOW"
    elif report.score >= caution_floor:
        report.risk_level = "MEDIUM"
    else:
        report.risk_level = "HIGH"

    return report
