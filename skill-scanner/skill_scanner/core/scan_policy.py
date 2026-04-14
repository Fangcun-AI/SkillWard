"""
Policy configuration for skill security scanning.

A ``ScanPolicy`` object encapsulates every tuneable knob an organisation
might adjust: allowlists, severity overrides, rule targeting, and numeric
thresholds.  Policies are loaded from YAML and merged on top of built-in
defaults so that only the overridden sections need to be specified.

Quick start::

    from skill_scanner.core.scan_policy import ScanPolicy

    policy = ScanPolicy.default()                  # built-in defaults
    policy = ScanPolicy.from_yaml("custom.yaml")   # org overrides
    policy.to_yaml("full_policy.yaml")              # export for review
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_log = logging.getLogger(__name__)

_PATTERN_CHAR_LIMIT = 1000


def _try_compile(raw: str, flags: int = 0, *, limit: int = _PATTERN_CHAR_LIMIT) -> re.Pattern | None:
    """Attempt to compile *raw* as a regex, returning ``None`` on failure."""
    if len(raw) > limit:
        _log.warning("Pattern exceeds %d chars (%d), ignored: %.60s...", limit, len(raw), raw)
        return None
    try:
        return re.compile(raw, flags)
    except re.error as exc:
        _log.warning("Cannot compile regex %r: %s", raw, exc)
        return None


# ---------------------------------------------------------------------------
# Built-in policy file locations
# ---------------------------------------------------------------------------
_ASSETS_DIR = Path(__file__).resolve().parent.parent / "data"
_BUILTIN_POLICY = _ASSETS_DIR / "default_policy.yaml"

_AVAILABLE_PRESETS: dict[str, Path] = {
    "strict": _ASSETS_DIR / "strict_policy.yaml",
    "balanced": _BUILTIN_POLICY,
    "permissive": _ASSETS_DIR / "permissive_policy.yaml",
}


# ---------------------------------------------------------------------------
# Section dataclasses
# ---------------------------------------------------------------------------


@dataclass
class HiddenFilePolicy:
    """Allowlists for dotfiles and dot-directories considered harmless."""

    benign_dotfiles: set[str] = field(default_factory=set)
    benign_dotdirs: set[str] = field(default_factory=set)


@dataclass
class PipelinePolicy:
    """Settings governing pipeline taint tracking and fetch-execute detection."""

    known_installer_domains: set[str] = field(default_factory=set)
    benign_pipe_targets: list[str] = field(default_factory=list)
    doc_path_indicators: set[str] = field(default_factory=set)
    demote_in_docs: bool = True
    demote_instructional: bool = True
    check_known_installers: bool = True
    dedupe_equivalent_pipelines: bool = True
    compound_fetch_require_download_intent: bool = True
    compound_fetch_filter_api_requests: bool = True
    compound_fetch_filter_shell_wrapped_fetch: bool = True
    compound_fetch_exec_prefixes: list[str] = field(
        default_factory=lambda: ["sudo", "env", "command", "time", "nohup", "nice"]
    )
    compound_fetch_exec_commands: list[str] = field(
        default_factory=lambda: ["bash", "sh", "zsh", "source", "python", "python3", "."]
    )
    exfil_hints: list[str] = field(
        default_factory=lambda: ["send", "upload", "transmit", "webhook", "slack", "exfil", "forward"]
    )
    api_doc_tokens: list[str] = field(
        default_factory=lambda: ["@app.", "app.", "router.", "route", "endpoint"]
    )


@dataclass
class RuleScopingPolicy:
    """Determines which rule sets apply to which file categories."""

    skillmd_and_scripts_only: set[str] = field(default_factory=set)
    skip_in_docs: set[str] = field(default_factory=set)
    code_only: set[str] = field(default_factory=set)
    doc_path_indicators: set[str] = field(default_factory=set)
    doc_filename_patterns: list[str] = field(default_factory=list)
    dedupe_reference_aliases: bool = True
    dedupe_duplicate_findings: bool = True
    asset_prompt_injection_skip_in_docs: bool = True


@dataclass
class CredentialPolicy:
    """Well-known test credentials that can be auto-suppressed."""

    known_test_values: set[str] = field(default_factory=set)
    placeholder_markers: set[str] = field(default_factory=set)


@dataclass
class SystemCleanupPolicy:
    """Paths considered safe targets for destructive ``rm`` commands."""

    safe_rm_targets: set[str] = field(default_factory=set)


@dataclass
class FileClassificationPolicy:
    """Maps file extensions to analysis categories (inert, structured, etc.)."""

    inert_extensions: set[str] = field(default_factory=set)
    structured_extensions: set[str] = field(default_factory=set)
    archive_extensions: set[str] = field(default_factory=set)
    code_extensions: set[str] = field(default_factory=set)
    skip_inert_extensions: bool = True
    allow_script_shebang_text_extensions: bool = True
    script_shebang_extensions: set[str] = field(default_factory=set)


@dataclass
class FileLimitsPolicy:
    """Numeric caps on file counts, sizes, and metadata lengths."""

    max_file_count: int = 100
    max_file_size_bytes: int = 5_242_880  # 5 MB
    max_reference_depth: int = 5
    max_name_length: int = 64
    max_description_length: int = 1024
    min_description_length: int = 20
    max_yara_scan_file_size_bytes: int = 52_428_800  # 50 MB
    max_loader_file_size_bytes: int = 10_485_760  # 10 MB


@dataclass
class AnalysisThresholdsPolicy:
    """Tuneable numeric thresholds for YARA rules and analyzability scoring."""

    zerowidth_threshold_with_decode: int = 50
    zerowidth_threshold_alone: int = 200
    analyzability_low_risk: int = 90
    analyzability_medium_risk: int = 70
    min_dangerous_lines: int = 5
    min_confidence_pct: int = 80
    exception_handler_context_lines: int = 20
    short_match_max_chars: int = 2
    cyrillic_cjk_min_chars: int = 10
    homoglyph_filter_math_context: bool = True
    homoglyph_math_aliases: list[str] = field(default_factory=lambda: ["COMMON", "GREEK"])
    max_regex_pattern_length: int = 1000


@dataclass
class SensitiveFilesPolicy:
    """Regex patterns identifying sensitive file paths in command arguments."""

    patterns: list[str] = field(default_factory=list)


@dataclass
class CommandSafetyPolicy:
    """Tiered classification of shell commands by risk level.

    Tiers (matching ``command_safety.CommandRisk``):
      safe -- read-only, no side effects
      caution -- generally safe but context-sensitive
      risky -- may alter system state or leak data
      dangerous -- direct code execution or network exfiltration

    ``dangerous_arg_patterns`` holds regex strings that force a command
    line to the DANGEROUS tier regardless of the base command.
    """

    safe_commands: set[str] = field(default_factory=set)
    caution_commands: set[str] = field(default_factory=set)
    risky_commands: set[str] = field(default_factory=set)
    dangerous_commands: set[str] = field(default_factory=set)
    dangerous_arg_patterns: list[str] = field(default_factory=list)


@dataclass
class AnalyzersPolicy:
    """Toggles for each available analyzer pass."""

    static: bool = True
    bytecode: bool = True
    pipeline: bool = True
    use_parallel_static_engines: bool = False


@dataclass
class LLMAnalysisPolicy:
    """Token-budget limits shared by the LLM and meta analyzers.

    The meta analyzer applies ``meta_budget_multiplier`` on top of the
    base limits so it has additional headroom for cross-file reasoning.
    Content exceeding any budget is skipped (not truncated) and an
    informational finding is emitted.
    """

    max_instruction_body_chars: int = 20_000
    max_code_file_chars: int = 15_000
    max_referenced_file_chars: int = 10_000
    max_total_prompt_chars: int = 100_000
    max_output_tokens: int = 8192
    meta_budget_multiplier: float = 3.0

    @property
    def meta_max_instruction_body_chars(self) -> int:
        return int(self.max_instruction_body_chars * self.meta_budget_multiplier)

    @property
    def meta_max_code_file_chars(self) -> int:
        return int(self.max_code_file_chars * self.meta_budget_multiplier)

    @property
    def meta_max_referenced_file_chars(self) -> int:
        return int(self.max_referenced_file_chars * self.meta_budget_multiplier)

    @property
    def meta_max_total_prompt_chars(self) -> int:
        return int(self.max_total_prompt_chars * self.meta_budget_multiplier)


@dataclass
class FindingOutputPolicy:
    """Controls deduplication and traceability annotations on emitted findings."""

    dedupe_exact_findings: bool = True
    dedupe_same_issue_per_location: bool = True
    same_issue_preferred_analyzers: list[str] = field(
        default_factory=lambda: [
            "meta_analyzer",
            "llm_analyzer",
            "meta",
            "llm",
            "behavioral",
            "pipeline",
            "pattern_analyzer",
            "structure_validator",
            "capability_risk",
            "static",
            "yara",
            "analyzability",
        ]
    )
    same_issue_collapse_within_analyzer: bool = True
    annotate_same_path_rule_cooccurrence: bool = True
    attach_policy_fingerprint: bool = True


@dataclass
class SeverityOverride:
    """Overrides the default severity for a specific rule."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    reason: str = ""


# ---------------------------------------------------------------------------
# Top-level policy
# ---------------------------------------------------------------------------


@dataclass
class ScanPolicy:
    """Root configuration object aggregating every tuneable policy section."""

    # Identity
    policy_name: str = "default"
    policy_version: str = "1.0"
    preset_base: str = "balanced"

    # Sections
    hidden_files: HiddenFilePolicy = field(default_factory=HiddenFilePolicy)
    pipeline: PipelinePolicy = field(default_factory=PipelinePolicy)
    rule_scoping: RuleScopingPolicy = field(default_factory=RuleScopingPolicy)
    credentials: CredentialPolicy = field(default_factory=CredentialPolicy)
    system_cleanup: SystemCleanupPolicy = field(default_factory=SystemCleanupPolicy)
    file_classification: FileClassificationPolicy = field(default_factory=FileClassificationPolicy)
    file_limits: FileLimitsPolicy = field(default_factory=FileLimitsPolicy)
    analysis_thresholds: AnalysisThresholdsPolicy = field(default_factory=AnalysisThresholdsPolicy)
    sensitive_files: SensitiveFilesPolicy = field(default_factory=SensitiveFilesPolicy)
    command_safety: CommandSafetyPolicy = field(default_factory=CommandSafetyPolicy)
    analyzers: AnalyzersPolicy = field(default_factory=AnalyzersPolicy)
    llm_analysis: LLMAnalysisPolicy = field(default_factory=LLMAnalysisPolicy)
    finding_output: FindingOutputPolicy = field(default_factory=FindingOutputPolicy)
    severity_overrides: list[SeverityOverride] = field(default_factory=list)
    disabled_rules: set[str] = field(default_factory=set)

    # -- Convenience helpers -------------------------------------------------

    def get_severity_override(self, rule_id: str) -> str | None:
        """Look up a severity override for *rule_id*, returning ``None`` if absent."""
        matches = [o.severity for o in self.severity_overrides if o.rule_id == rule_id]
        return matches[0] if matches else None

    @property
    def _compiled_doc_filename_re(self) -> re.Pattern | None:
        """Lazily compile and cache a combined regex for documentation filenames."""
        cache_attr = "_cached_doc_fn_re"
        if not hasattr(self, cache_attr):
            pat_limit = self.analysis_thresholds.max_regex_pattern_length
            sources = self.rule_scoping.doc_filename_patterns
            compiled = [_try_compile(p, re.IGNORECASE, limit=pat_limit) for p in sources]
            valid = [c for c in compiled if c is not None]
            if valid:
                joined = "|".join(f"(?:{c.pattern})" for c in valid)
                upper_bound = pat_limit * max(len(valid), 1) + 4 * len(valid)
                setattr(self, cache_attr, _try_compile(joined, re.IGNORECASE, limit=upper_bound))
            else:
                setattr(self, cache_attr, None)
        return getattr(self, cache_attr)

    @property
    def _compiled_benign_pipes(self) -> list[re.Pattern]:
        """Lazily compile and cache regex patterns for benign pipe targets."""
        cache_attr = "_cached_benign_pipes"
        if not hasattr(self, cache_attr):
            result = [c for p in self.pipeline.benign_pipe_targets if (c := _try_compile(p)) is not None]
            setattr(self, cache_attr, result)
        return getattr(self, cache_attr)

    # -- Construction --------------------------------------------------------

    @classmethod
    def default(cls) -> ScanPolicy:
        """Return a policy populated from the bundled default YAML."""
        return cls.from_yaml(_BUILTIN_POLICY)

    @classmethod
    def from_preset(cls, name: str) -> ScanPolicy:
        """Instantiate from a named preset (``strict``, ``balanced``, or ``permissive``)."""
        key = name.lower()
        if key not in _AVAILABLE_PRESETS:
            valid = ", ".join(sorted(_AVAILABLE_PRESETS))
            raise ValueError(f"No preset named '{name}'. Choose from: {valid}")
        return cls.from_yaml(_AVAILABLE_PRESETS[key])

    @classmethod
    def preset_names(cls) -> list[str]:
        """List the identifiers of all bundled presets."""
        return sorted(_AVAILABLE_PRESETS.keys())

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanPolicy:
        """Read a YAML policy file, merging it over the built-in defaults.

        When *path* points to the built-in default itself the merge step
        is skipped for efficiency.
        """
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(f"Policy file does not exist: {target}")

        with target.open(encoding="utf-8") as fp:
            user_data: dict[str, Any] = yaml.safe_load(fp) or {}

        if target.resolve() == _BUILTIN_POLICY.resolve():
            return cls._parse_sections(user_data)

        base_data = cls._read_builtin_defaults()
        combined = cls._overlay(base_data, user_data)
        return cls._parse_sections(combined)

    def to_yaml(self, path: str | Path) -> None:
        """Write the complete policy to *path* in YAML format."""
        serialized = self._serialize()
        with open(path, "w", encoding="utf-8") as fp:
            header_lines = [
                "# SkillWard Scan Policy",
                "# Adjust sections below to match your organisation's requirements.",
                "# Omitted sections fall back to built-in defaults.",
                "",
            ]
            fp.write("\n".join(header_lines) + "\n")
            yaml.dump(serialized, fp, default_flow_style=False, sort_keys=False, width=120)

    # -- Internal helpers ----------------------------------------------------

    @classmethod
    def _read_builtin_defaults(cls) -> dict[str, Any]:
        """Load the raw YAML dict from the bundled default policy file."""
        if not _BUILTIN_POLICY.exists():
            return {}
        with _BUILTIN_POLICY.open(encoding="utf-8") as fp:
            return yaml.safe_load(fp) or {}

    @staticmethod
    def _overlay(base: dict, top: dict) -> dict:
        """Recursively layer *top* over *base*.

        Dicts are merged key-by-key; all other types (including lists)
        in *top* replace the corresponding value in *base*.
        """
        merged = {**base}
        for k, v in top.items():
            if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
                merged[k] = ScanPolicy._overlay(merged[k], v)
            else:
                merged[k] = v
        return merged

    @classmethod
    def _parse_sections(cls, d: dict[str, Any]) -> ScanPolicy:  # noqa: C901
        """Construct a ``ScanPolicy`` from a flat dict of section dicts."""
        sec_hf = d.get("hidden_files", {})
        sec_pl = d.get("pipeline", {})
        sec_rs = d.get("rule_scoping", {})
        sec_cr = d.get("credentials", {})
        sec_sc = d.get("system_cleanup", {})
        sec_fc = d.get("file_classification", {})
        sec_fl = d.get("file_limits", {})
        sec_at = d.get("analysis_thresholds", {})
        sec_sf = d.get("sensitive_files", {})
        sec_cs = d.get("command_safety", {})
        sec_az = d.get("analyzers", {})
        sec_la = d.get("llm_analysis", {})
        sec_fo = d.get("finding_output", {})

        overrides = [SeverityOverride(**entry) for entry in d.get("severity_overrides", [])]

        return cls(
            policy_name=d.get("policy_name", "default"),
            policy_version=d.get("policy_version", "1.0"),
            preset_base=d.get("preset_base", "balanced"),
            hidden_files=HiddenFilePolicy(
                benign_dotfiles=set(sec_hf.get("benign_dotfiles", [])),
                benign_dotdirs=set(sec_hf.get("benign_dotdirs", [])),
            ),
            pipeline=PipelinePolicy(
                known_installer_domains=set(sec_pl.get("known_installer_domains", [])),
                benign_pipe_targets=sec_pl.get("benign_pipe_targets", []),
                doc_path_indicators=set(sec_pl.get("doc_path_indicators", [])),
                demote_in_docs=sec_pl.get("demote_in_docs", True),
                demote_instructional=sec_pl.get("demote_instructional", True),
                check_known_installers=sec_pl.get("check_known_installers", True),
                dedupe_equivalent_pipelines=sec_pl.get("dedupe_equivalent_pipelines", True),
                compound_fetch_require_download_intent=sec_pl.get("compound_fetch_require_download_intent", True),
                compound_fetch_filter_api_requests=sec_pl.get("compound_fetch_filter_api_requests", True),
                compound_fetch_filter_shell_wrapped_fetch=sec_pl.get("compound_fetch_filter_shell_wrapped_fetch", True),
                compound_fetch_exec_prefixes=sec_pl.get(
                    "compound_fetch_exec_prefixes", ["sudo", "env", "command", "time", "nohup", "nice"]
                ),
                compound_fetch_exec_commands=sec_pl.get(
                    "compound_fetch_exec_commands", ["bash", "sh", "zsh", "source", "python", "python3", "."]
                ),
                exfil_hints=sec_pl.get(
                    "exfil_hints", ["send", "upload", "transmit", "webhook", "slack", "exfil", "forward"]
                ),
                api_doc_tokens=sec_pl.get("api_doc_tokens", ["@app.", "app.", "router.", "route", "endpoint"]),
            ),
            rule_scoping=RuleScopingPolicy(
                skillmd_and_scripts_only=set(sec_rs.get("skillmd_and_scripts_only", [])),
                skip_in_docs=set(sec_rs.get("skip_in_docs", [])),
                code_only=set(sec_rs.get("code_only", [])),
                doc_path_indicators=set(sec_rs.get("doc_path_indicators", [])),
                doc_filename_patterns=sec_rs.get("doc_filename_patterns", []),
                dedupe_reference_aliases=sec_rs.get("dedupe_reference_aliases", True),
                dedupe_duplicate_findings=sec_rs.get("dedupe_duplicate_findings", True),
                asset_prompt_injection_skip_in_docs=sec_rs.get("asset_prompt_injection_skip_in_docs", True),
            ),
            credentials=CredentialPolicy(
                known_test_values=set(sec_cr.get("known_test_values", [])),
                placeholder_markers=set(sec_cr.get("placeholder_markers", [])),
            ),
            system_cleanup=SystemCleanupPolicy(
                safe_rm_targets=set(sec_sc.get("safe_rm_targets", [])),
            ),
            file_classification=FileClassificationPolicy(
                inert_extensions=set(sec_fc.get("inert_extensions", [])),
                structured_extensions=set(sec_fc.get("structured_extensions", [])),
                archive_extensions=set(sec_fc.get("archive_extensions", [])),
                code_extensions=set(sec_fc.get("code_extensions", [])),
                skip_inert_extensions=sec_fc.get("skip_inert_extensions", True),
                allow_script_shebang_text_extensions=sec_fc.get("allow_script_shebang_text_extensions", True),
                script_shebang_extensions=set(sec_fc.get("script_shebang_extensions", [])),
            ),
            file_limits=FileLimitsPolicy(
                max_file_count=sec_fl.get("max_file_count", 100),
                max_file_size_bytes=sec_fl.get("max_file_size_bytes", 5_242_880),
                max_reference_depth=sec_fl.get("max_reference_depth", 5),
                max_name_length=sec_fl.get("max_name_length", 64),
                max_description_length=sec_fl.get("max_description_length", 1024),
                min_description_length=sec_fl.get("min_description_length", 20),
                max_yara_scan_file_size_bytes=sec_fl.get("max_yara_scan_file_size_bytes", 52_428_800),
                max_loader_file_size_bytes=sec_fl.get("max_loader_file_size_bytes", 10_485_760),
            ),
            analysis_thresholds=AnalysisThresholdsPolicy(
                zerowidth_threshold_with_decode=sec_at.get("zerowidth_threshold_with_decode", 50),
                zerowidth_threshold_alone=sec_at.get("zerowidth_threshold_alone", 200),
                analyzability_low_risk=sec_at.get("analyzability_low_risk", 90),
                analyzability_medium_risk=sec_at.get("analyzability_medium_risk", 70),
                min_dangerous_lines=sec_at.get("min_dangerous_lines", 5),
                min_confidence_pct=sec_at.get("min_confidence_pct", 80),
                exception_handler_context_lines=sec_at.get("exception_handler_context_lines", 20),
                short_match_max_chars=sec_at.get("short_match_max_chars", 2),
                cyrillic_cjk_min_chars=sec_at.get("cyrillic_cjk_min_chars", 10),
                homoglyph_filter_math_context=sec_at.get("homoglyph_filter_math_context", True),
                homoglyph_math_aliases=sec_at.get("homoglyph_math_aliases", ["COMMON", "GREEK"]),
                max_regex_pattern_length=sec_at.get("max_regex_pattern_length", 1000),
            ),
            sensitive_files=SensitiveFilesPolicy(
                patterns=sec_sf.get("patterns", []),
            ),
            command_safety=CommandSafetyPolicy(
                safe_commands=set(sec_cs.get("safe_commands", [])),
                caution_commands=set(sec_cs.get("caution_commands", [])),
                risky_commands=set(sec_cs.get("risky_commands", [])),
                dangerous_commands=set(sec_cs.get("dangerous_commands", [])),
                dangerous_arg_patterns=list(sec_cs.get("dangerous_arg_patterns", [])),
            ),
            analyzers=AnalyzersPolicy(
                static=sec_az.get("static", True),
                bytecode=sec_az.get("bytecode", True),
                pipeline=sec_az.get("pipeline", True),
                use_parallel_static_engines=sec_az.get("use_parallel_static_engines", False),
            ),
            llm_analysis=LLMAnalysisPolicy(
                max_instruction_body_chars=sec_la.get("max_instruction_body_chars", 20_000),
                max_code_file_chars=sec_la.get("max_code_file_chars", 15_000),
                max_referenced_file_chars=sec_la.get("max_referenced_file_chars", 10_000),
                max_total_prompt_chars=sec_la.get("max_total_prompt_chars", 100_000),
                max_output_tokens=sec_la.get("max_output_tokens", 8192),
                meta_budget_multiplier=sec_la.get("meta_budget_multiplier", 3.0),
            ),
            finding_output=FindingOutputPolicy(
                dedupe_exact_findings=sec_fo.get("dedupe_exact_findings", True),
                dedupe_same_issue_per_location=sec_fo.get("dedupe_same_issue_per_location", True),
                same_issue_preferred_analyzers=sec_fo.get(
                    "same_issue_preferred_analyzers",
                    [
                        "meta_analyzer",
                        "llm_analyzer",
                        "meta",
                        "llm",
                        "behavioral",
                        "pipeline",
                        "pattern_analyzer",
                        "structure_validator",
                        "capability_risk",
                        "static",
                        "yara",
                        "analyzability",
                    ],
                ),
                same_issue_collapse_within_analyzer=sec_fo.get("same_issue_collapse_within_analyzer", True),
                annotate_same_path_rule_cooccurrence=sec_fo.get("annotate_same_path_rule_cooccurrence", True),
                attach_policy_fingerprint=sec_fo.get("attach_policy_fingerprint", True),
            ),
            severity_overrides=overrides,
            disabled_rules=set(d.get("disabled_rules", [])),
        )

    def _serialize(self) -> dict[str, Any]:
        """Convert the entire policy into a plain dict for YAML output."""

        def _sorted_set(s: set[str]) -> list[str]:
            return sorted(s)

        return {
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "preset_base": self.preset_base,
            "hidden_files": {
                "benign_dotfiles": _sorted_set(self.hidden_files.benign_dotfiles),
                "benign_dotdirs": _sorted_set(self.hidden_files.benign_dotdirs),
            },
            "pipeline": {
                "known_installer_domains": _sorted_set(self.pipeline.known_installer_domains),
                "benign_pipe_targets": self.pipeline.benign_pipe_targets,
                "doc_path_indicators": _sorted_set(self.pipeline.doc_path_indicators),
                "demote_in_docs": self.pipeline.demote_in_docs,
                "demote_instructional": self.pipeline.demote_instructional,
                "check_known_installers": self.pipeline.check_known_installers,
                "dedupe_equivalent_pipelines": self.pipeline.dedupe_equivalent_pipelines,
                "compound_fetch_require_download_intent": self.pipeline.compound_fetch_require_download_intent,
                "compound_fetch_filter_api_requests": self.pipeline.compound_fetch_filter_api_requests,
                "compound_fetch_filter_shell_wrapped_fetch": self.pipeline.compound_fetch_filter_shell_wrapped_fetch,
                "compound_fetch_exec_prefixes": self.pipeline.compound_fetch_exec_prefixes,
                "compound_fetch_exec_commands": self.pipeline.compound_fetch_exec_commands,
                "exfil_hints": self.pipeline.exfil_hints,
                "api_doc_tokens": self.pipeline.api_doc_tokens,
            },
            "rule_scoping": {
                "skillmd_and_scripts_only": _sorted_set(self.rule_scoping.skillmd_and_scripts_only),
                "skip_in_docs": _sorted_set(self.rule_scoping.skip_in_docs),
                "code_only": _sorted_set(self.rule_scoping.code_only),
                "doc_path_indicators": _sorted_set(self.rule_scoping.doc_path_indicators),
                "doc_filename_patterns": self.rule_scoping.doc_filename_patterns,
                "dedupe_reference_aliases": self.rule_scoping.dedupe_reference_aliases,
                "dedupe_duplicate_findings": self.rule_scoping.dedupe_duplicate_findings,
                "asset_prompt_injection_skip_in_docs": self.rule_scoping.asset_prompt_injection_skip_in_docs,
            },
            "credentials": {
                "known_test_values": _sorted_set(self.credentials.known_test_values),
                "placeholder_markers": _sorted_set(self.credentials.placeholder_markers),
            },
            "system_cleanup": {
                "safe_rm_targets": _sorted_set(self.system_cleanup.safe_rm_targets),
            },
            "file_classification": {
                "inert_extensions": _sorted_set(self.file_classification.inert_extensions),
                "structured_extensions": _sorted_set(self.file_classification.structured_extensions),
                "archive_extensions": _sorted_set(self.file_classification.archive_extensions),
                "code_extensions": _sorted_set(self.file_classification.code_extensions),
                "skip_inert_extensions": self.file_classification.skip_inert_extensions,
                "allow_script_shebang_text_extensions": self.file_classification.allow_script_shebang_text_extensions,
                "script_shebang_extensions": _sorted_set(self.file_classification.script_shebang_extensions),
            },
            "file_limits": {
                "max_file_count": self.file_limits.max_file_count,
                "max_file_size_bytes": self.file_limits.max_file_size_bytes,
                "max_reference_depth": self.file_limits.max_reference_depth,
                "max_name_length": self.file_limits.max_name_length,
                "max_description_length": self.file_limits.max_description_length,
                "min_description_length": self.file_limits.min_description_length,
                "max_yara_scan_file_size_bytes": self.file_limits.max_yara_scan_file_size_bytes,
                "max_loader_file_size_bytes": self.file_limits.max_loader_file_size_bytes,
            },
            "analysis_thresholds": {
                "zerowidth_threshold_with_decode": self.analysis_thresholds.zerowidth_threshold_with_decode,
                "zerowidth_threshold_alone": self.analysis_thresholds.zerowidth_threshold_alone,
                "analyzability_low_risk": self.analysis_thresholds.analyzability_low_risk,
                "analyzability_medium_risk": self.analysis_thresholds.analyzability_medium_risk,
                "min_dangerous_lines": self.analysis_thresholds.min_dangerous_lines,
                "min_confidence_pct": self.analysis_thresholds.min_confidence_pct,
                "exception_handler_context_lines": self.analysis_thresholds.exception_handler_context_lines,
                "short_match_max_chars": self.analysis_thresholds.short_match_max_chars,
                "cyrillic_cjk_min_chars": self.analysis_thresholds.cyrillic_cjk_min_chars,
                "homoglyph_filter_math_context": self.analysis_thresholds.homoglyph_filter_math_context,
                "homoglyph_math_aliases": self.analysis_thresholds.homoglyph_math_aliases,
                "max_regex_pattern_length": self.analysis_thresholds.max_regex_pattern_length,
            },
            "sensitive_files": {
                "patterns": self.sensitive_files.patterns,
            },
            "command_safety": {
                "safe_commands": _sorted_set(self.command_safety.safe_commands),
                "caution_commands": _sorted_set(self.command_safety.caution_commands),
                "risky_commands": _sorted_set(self.command_safety.risky_commands),
                "dangerous_commands": _sorted_set(self.command_safety.dangerous_commands),
                "dangerous_arg_patterns": self.command_safety.dangerous_arg_patterns,
            },
            "analyzers": {
                "static": self.analyzers.static,
                "bytecode": self.analyzers.bytecode,
                "pipeline": self.analyzers.pipeline,
                "use_parallel_static_engines": self.analyzers.use_parallel_static_engines,
            },
            "llm_analysis": {
                "max_instruction_body_chars": self.llm_analysis.max_instruction_body_chars,
                "max_code_file_chars": self.llm_analysis.max_code_file_chars,
                "max_referenced_file_chars": self.llm_analysis.max_referenced_file_chars,
                "max_total_prompt_chars": self.llm_analysis.max_total_prompt_chars,
                "max_output_tokens": self.llm_analysis.max_output_tokens,
                "meta_budget_multiplier": self.llm_analysis.meta_budget_multiplier,
            },
            "finding_output": {
                "dedupe_exact_findings": self.finding_output.dedupe_exact_findings,
                "dedupe_same_issue_per_location": self.finding_output.dedupe_same_issue_per_location,
                "same_issue_preferred_analyzers": self.finding_output.same_issue_preferred_analyzers,
                "same_issue_collapse_within_analyzer": self.finding_output.same_issue_collapse_within_analyzer,
                "annotate_same_path_rule_cooccurrence": self.finding_output.annotate_same_path_rule_cooccurrence,
                "attach_policy_fingerprint": self.finding_output.attach_policy_fingerprint,
            },
            "severity_overrides": [
                {"rule_id": o.rule_id, "severity": o.severity, "reason": o.reason}
                for o in self.severity_overrides
            ],
            "disabled_rules": sorted(self.disabled_rules),
        }
