"""
Definitions for skill packages, scan outcomes, and aggregated reports.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Risk level assigned to each detected issue."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"


class ThreatCategory(str, Enum):
    """Classification labels for identified security concerns."""

    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    OBFUSCATION = "obfuscation"
    HARDCODED_SECRETS = "hardcoded_secrets"
    SOCIAL_ENGINEERING = "social_engineering"
    RESOURCE_ABUSE = "resource_abuse"
    POLICY_VIOLATION = "policy_violation"
    MALWARE = "malware"
    HARMFUL_CONTENT = "harmful_content"
    SKILL_DISCOVERY_ABUSE = "skill_discovery_abuse"
    TRANSITIVE_TRUST_ABUSE = "transitive_trust_abuse"
    AUTONOMY_ABUSE = "autonomy_abuse"
    TOOL_CHAINING_ABUSE = "tool_chaining_abuse"
    UNICODE_STEGANOGRAPHY = "unicode_steganography"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"


@dataclass
class SkillManifest:
    """Structured representation of SKILL.md YAML frontmatter.

    Handles both Codex and Cursor agent skill formats. Required
    fields are ``name`` and ``description``; everything else is optional.
    """

    name: str
    description: str
    license: str | None = None
    compatibility: str | None = None
    allowed_tools: list[str] | str | None = None
    metadata: dict[str, Any] | None = None
    disable_model_invocation: bool = False

    def __post_init__(self):
        """Ensure allowed_tools is always stored as a list."""
        if self.allowed_tools is None:
            self.allowed_tools = []
        elif isinstance(self.allowed_tools, str):
            self.allowed_tools = [
                tok for tok in (t.strip() for t in self.allowed_tools.split(",")) if tok
            ]

    @property
    def short_description(self) -> str | None:
        """Extract optional short-description value from the metadata dict."""
        if isinstance(self.metadata, dict):
            return self.metadata.get("short-description")
        return None


@dataclass
class SkillFile:
    """Represents a single file belonging to a skill package."""

    path: Path
    relative_path: str
    file_type: str  # 'markdown', 'python', 'bash', 'binary', 'other'
    content: str | None = None
    size_bytes: int = 0
    extracted_from: str | None = None
    archive_depth: int = 0

    def read_content(self) -> str:
        """Load and cache the file contents, returning an empty string on failure."""
        if self.content is None and self.path.exists():
            try:
                self.content = self.path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                self.content = ""
        return self.content or ""

    @property
    def is_hidden(self) -> bool:
        """True when the file resides under a dotfile or dot-directory."""
        return any(
            segment.startswith(".") and segment != "."
            for segment in Path(self.relative_path).parts
        )

    @property
    def is_pycache(self) -> bool:
        """True when the file sits inside a __pycache__ folder."""
        return "__pycache__" in Path(self.relative_path).parts


@dataclass
class Skill:
    """A fully loaded agent skill, including manifest and all associated files.

    Standard package layout:
      - SKILL.md -- manifest with instructions
      - scripts/  -- runnable code
      - references/ -- supporting docs
      - assets/ -- templates and static resources
    """

    directory: Path
    manifest: SkillManifest
    skill_md_path: Path
    instruction_body: str
    files: list[SkillFile] = field(default_factory=list)
    referenced_files: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def description(self) -> str:
        return self.manifest.description

    def get_scripts(self) -> list[SkillFile]:
        """Return every file classified as executable code."""
        script_types = {"python", "bash", "javascript", "typescript"}
        return [sf for sf in self.files if sf.file_type in script_types]

    def get_markdown_files(self) -> list[SkillFile]:
        """Return every markdown file in the skill package."""
        return [sf for sf in self.files if sf.file_type == "markdown"]


@dataclass
class Finding:
    """One discrete security issue detected during analysis."""

    id: str  # Unique finding identifier (e.g., rule ID + line number)
    rule_id: str  # Rule that triggered this finding
    category: ThreatCategory
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    snippet: str | None = None
    remediation: str | None = None
    analyzer: str | None = None  # Which analyzer produced this finding (e.g., "static", "llm", "behavioral")
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this finding into a plain dictionary."""
        output: dict[str, Any] = {}
        for attr in (
            "id", "rule_id", "title", "description",
            "file_path", "line_number", "snippet",
            "remediation", "analyzer", "metadata",
        ):
            output[attr] = getattr(self, attr)
        output["category"] = self.category.value
        output["severity"] = self.severity.value
        return output


# Ordered from most to least severe, used for comparisons.
_SEVERITY_RANKING = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


@dataclass
class ScanResult:
    """Outcome of scanning a single skill package."""

    skill_name: str
    skill_directory: str
    findings: list[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    analyzers_used: list[str] = field(default_factory=list)
    analyzers_failed: list[dict[str, str]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    analyzability_score: float | None = None
    analyzability_details: dict[str, Any] | None = None
    scan_metadata: dict[str, Any] | None = None

    @property
    def is_safe(self) -> bool:
        """True when no CRITICAL or HIGH severity issues were found."""
        return all(
            f.severity not in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )

    @property
    def max_severity(self) -> Severity:
        """Determine the most severe finding level present."""
        if not self.findings:
            return Severity.SAFE
        for level in _SEVERITY_RANKING:
            for f in self.findings:
                if f.severity == level:
                    return level
        return Severity.SAFE

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Filter findings to only those matching the given severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: ThreatCategory) -> list[Finding]:
        """Filter findings to only those matching the given threat category."""
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> dict[str, Any]:
        """Produce a dictionary suitable for JSON serialization."""
        payload: dict[str, Any] = {
            "skill_name": self.skill_name,
            "skill_path": self.skill_directory,
            "is_safe": self.is_safe,
            "max_severity": self.max_severity.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_seconds": self.scan_duration_seconds,
            "duration_ms": int(self.scan_duration_seconds * 1000),
            "analyzers_used": self.analyzers_used,
            "timestamp": self.timestamp.isoformat(),
            "scan_metadata": self.scan_metadata or {},
        }
        if self.analyzers_failed:
            payload["analyzers_failed"] = self.analyzers_failed
        return payload


@dataclass
class Report:
    """Combined report spanning one or more scanned skills."""

    scan_results: list[ScanResult] = field(default_factory=list)
    total_skills_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    safe_count: int = 0
    skills_skipped: list[dict[str, str]] = field(default_factory=list)
    cross_skill_findings: list[Finding] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def _tally_severities(self, items: list[Finding]) -> None:
        """Walk a list of findings and bump the matching severity counter."""
        counter_map = {
            Severity.CRITICAL: "critical_count",
            Severity.HIGH: "high_count",
            Severity.MEDIUM: "medium_count",
            Severity.LOW: "low_count",
            Severity.INFO: "info_count",
        }
        for item in items:
            attr = counter_map.get(item.severity)
            if attr is not None:
                setattr(self, attr, getattr(self, attr) + 1)

    def add_scan_result(self, result: ScanResult):
        """Incorporate a single skill's scan outcome into the report."""
        self.scan_results.append(result)
        self.total_skills_scanned += 1
        self.total_findings += len(result.findings)
        self._tally_severities(result.findings)
        if result.is_safe:
            self.safe_count += 1

    def add_cross_skill_findings(self, findings: list[Finding]) -> None:
        """Record findings that span multiple skills without double-counting skills."""
        self.cross_skill_findings.extend(findings)
        self.total_findings += len(findings)
        self._tally_severities(findings)

    def to_dict(self) -> dict[str, Any]:
        """Build a nested dictionary representing the full report."""
        severity_breakdown = {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
        }
        overview: dict[str, Any] = {
            "total_skills_scanned": self.total_skills_scanned,
            "total_findings": self.total_findings,
            "safe_skills": self.safe_count,
            "findings_by_severity": severity_breakdown,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.skills_skipped:
            overview["skills_skipped"] = self.skills_skipped

        output: dict[str, Any] = {
            "summary": overview,
            "results": [r.to_dict() for r in self.scan_results],
        }
        if self.cross_skill_findings:
            output["cross_skill_findings"] = [
                f.to_dict() for f in self.cross_skill_findings
            ]
        return output
