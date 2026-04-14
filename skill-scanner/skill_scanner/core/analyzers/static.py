"""
Static pattern analyzer for detecting security vulnerabilities in skill packages.

Applies rule-based and signature-driven checks to skill manifests, instruction
files, bundled scripts, binary assets, and referenced documents.  Results are
returned as a flat list of ``Finding`` objects consumed by downstream reporters.
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from ...config.yara_modes import YaraModeConfig
from ...core.models import Finding, Severity, Skill, ThreatCategory
from ...core.rules.patterns import RuleLoader, SecurityRule
from ...core.rules.yara_scanner import YaraScanner
from ...core.scan_policy import ScanPolicy
from ...threats.threats import ThreatMapping
from .base import BaseAnalyzer

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns used by capability-detection helpers
# ---------------------------------------------------------------------------

_FILE_READ_INDICATORS = [
    re.compile(r"open\([^)]+['\"]r['\"]"),
    re.compile(r"\.read\("),
    re.compile(r"\.readline\("),
    re.compile(r"\.readlines\("),
    re.compile(r"Path\([^)]+\)\.read_text"),
    re.compile(r"Path\([^)]+\)\.read_bytes"),
    re.compile(r"with\s+open\([^)]+['\"]r"),
]

_FILE_WRITE_INDICATORS = [
    re.compile(r"open\([^)]+['\"]w['\"]"),
    re.compile(r"\.write\("),
    re.compile(r"\.writelines\("),
    re.compile(r"pathlib\.Path\([^)]+\)\.write"),
    re.compile(r"with\s+open\([^)]+['\"]w"),
]

_SEARCH_INDICATORS = [
    re.compile(r"re\.search\("),
    re.compile(r"re\.findall\("),
    re.compile(r"re\.match\("),
    re.compile(r"re\.finditer\("),
    re.compile(r"re\.sub\("),
    re.compile(r"grep"),
]

_GLOB_INDICATORS = [
    re.compile(r"glob\.glob\("),
    re.compile(r"glob\.iglob\("),
    re.compile(r"Path\([^)]*\)\.glob\("),
    re.compile(r"\.glob\("),
    re.compile(r"\.rglob\("),
    re.compile(r"fnmatch\."),
]

_ERROR_HANDLER_PATTERNS = [
    re.compile(r"except\s+(EOFError|StopIteration|KeyboardInterrupt|Exception|BaseException)"),
    re.compile(r"except\s*:"),
    re.compile(r"break\s*$", re.MULTILINE),
    re.compile(r"return\s*$", re.MULTILINE),
    re.compile(r"sys\.exit\s*\("),
    re.compile(r"raise\s+StopIteration"),
]

_NAME_EXTRACTOR = re.compile(r"[a-z0-9-]+")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^\)]+)\)")
_PY_IMPORT_RE = re.compile(r"^from\s+\.([A-Za-z0-9_.]*)\s+import", re.MULTILINE)
_BASH_SOURCE_RE = re.compile(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))")
_RM_TARGET_RE = re.compile(r"rm\s+-r[^;]*?\s+([^\s;]+)")
_HARMLESS_CLEANUP_DIRS = {
    "dist",
    "build",
    "tmp",
    "temp",
    ".tmp",
    ".temp",
    "bundle.html",
    "bundle.js",
    "bundle.css",
    "node_modules",
    ".next",
    ".nuxt",
    ".cache",
}
_KNOWN_DUMMY_MARKERS = {
    "your-",
    "your_",
    "your ",
    "example",
    "sample",
    "dummy",
    "placeholder",
    "replace",
    "changeme",
    "change_me",
    "<your",
    "<insert",
}


class StaticAnalyzer(BaseAnalyzer):
    """Rule-driven security analyzer that inspects skill packages via pattern matching."""

    def __init__(
        self,
        rules_file: Path | None = None,
        use_yara: bool = True,
        yara_mode: YaraModeConfig | str | None = None,
        custom_yara_rules_path: str | Path | None = None,
        disabled_rules: set[str] | None = None,
        _skip_text_pattern_checks: bool = False,
        policy: ScanPolicy | None = None,
    ):
        """Set up the static analyzer with rules, YARA configuration, and policy.

        Parameters
        ----------
        rules_file:
            Path to a custom YAML rules definition.  Falls back to the
            built-in rule set when *None*.
        use_yara:
            Toggle YARA-based signature scanning.
        yara_mode:
            Controls YARA sensitivity.  Accepts a ``YaraModeConfig``, a
            preset name (``"strict"``, ``"balanced"``, ``"permissive"``),
            or *None* for auto-detection from the active policy preset.
        custom_yara_rules_path:
            Directory of ``.yara`` rule files that replace the built-in set.
        disabled_rules:
            Explicit set of rule identifiers to suppress.  Merged with
            mode-level and policy-level disable lists.
        _skip_text_pattern_checks:
            Internal flag -- when *True* the text-pattern phases are
            delegated to parallel analysis engines.
        policy:
            Organisation-specific scan policy.  Built-in defaults are used
            when *None*.
        """
        super().__init__("static_analyzer", policy=policy)
        self._skip_text_pattern_checks = _skip_text_pattern_checks

        # Populated during _audit_file_inventory(); exposed for LLM context.
        self._unreferenced_scripts: list[str] = []

        self.rule_loader = RuleLoader(rules_file)
        self.rule_loader.load_rules()

        # Derive YARA mode from the policy preset when not given explicitly.
        if yara_mode is None:
            preset = getattr(self.policy, "preset_base", "balanced")
            _PRESET_TO_YARA = {"strict": "strict", "permissive": "permissive"}
            mode_name = _PRESET_TO_YARA.get(preset, "balanced")
            self.yara_mode = YaraModeConfig.from_mode_name(mode_name)
        elif isinstance(yara_mode, str):
            self.yara_mode = YaraModeConfig.from_mode_name(yara_mode)
        else:
            self.yara_mode = yara_mode

        # Merge disabled-rule sources: CLI flags, mode config, policy.
        self.disabled_rules = set(disabled_rules or set())
        self.disabled_rules.update(self.yara_mode.disabled_rules)
        self.disabled_rules.update(self.policy.disabled_rules)

        self.custom_yara_rules_path = Path(custom_yara_rules_path) if custom_yara_rules_path else None

        self.use_yara = use_yara
        self.yara_scanner = None
        if use_yara:
            try:
                max_scan_bytes = self.policy.file_limits.max_yara_scan_file_size_bytes
                if self.custom_yara_rules_path:
                    self.yara_scanner = YaraScanner(
                        rules_dir=self.custom_yara_rules_path,
                        max_scan_file_size=max_scan_bytes,
                    )
                    _log.info("Loaded custom YARA rules from: %s", self.custom_yara_rules_path)
                else:
                    self.yara_scanner = YaraScanner(max_scan_file_size=max_scan_bytes)
            except Exception as exc:
                _log.warning("YARA scanner unavailable: %s", exc)
                self.yara_scanner = None

    # ------------------------------------------------------------------
    # Rule gating
    # ------------------------------------------------------------------

    def _rule_is_active(self, rule_name: str) -> bool:
        """Return *True* when *rule_name* is not suppressed by mode or policy."""
        if not self.yara_mode.is_rule_enabled(rule_name):
            return False
        if rule_name in self.disabled_rules:
            return False
        base_name = rule_name.replace("YARA_", "") if rule_name.startswith("YARA_") else rule_name
        if base_name in self.disabled_rules:
            return False
        return True

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, skill: Skill) -> list[Finding]:
        """Run the full static analysis pipeline on *skill*.

        The pipeline proceeds through several phases: manifest validation,
        instruction-body scanning, script inspection, consistency checks,
        reference traversal, binary/hidden-file detection, document analysis,
        homoglyph detection, YARA signature matching, and asset scanning.

        Returns a de-duplicated, policy-filtered list of findings.
        """
        findings: list[Finding] = []
        self._unreferenced_scripts = []

        if not self._skip_text_pattern_checks:
            findings.extend(self._inspect_manifest(skill))
            findings.extend(self._review_instructions(skill))
            findings.extend(self._inspect_script_files(skill))

        findings.extend(self._verify_coherence(skill))

        if not self._skip_text_pattern_checks:
            findings.extend(self._traverse_references(skill))

        findings.extend(self._inspect_binaries(skill))
        findings.extend(self._detect_concealed_files(skill))
        findings.extend(self._audit_file_inventory(skill))
        findings.extend(self._inspect_pdf_files(skill))
        findings.extend(self._inspect_office_files(skill))

        if not self._skip_text_pattern_checks:
            findings.extend(self._detect_homoglyphs(skill))

        if self.yara_scanner:
            findings.extend(self._run_yara_rules(skill))

        if not self._skip_text_pattern_checks:
            findings.extend(self._inspect_assets(skill))

        # Drop disabled / placeholder-credential findings.
        findings = [f for f in findings if self._rule_is_active(f.rule_id)]
        findings = [f for f in findings if not self._is_placeholder_credential(f)]

        if self.policy.rule_scoping.dedupe_duplicate_findings:
            findings = self._remove_duplicates(findings)

        return findings

    def get_unreferenced_scripts(self) -> list[str]:
        """Return script paths not mentioned in SKILL.md (from the last scan).

        Provided as enrichment context for downstream LLM analysis rather
        than standalone findings.
        """
        return list(self._unreferenced_scripts)

    # ------------------------------------------------------------------
    # Credential / documentation helpers
    # ------------------------------------------------------------------

    def _is_placeholder_credential(self, finding: Finding) -> bool:
        """Suppress findings that match well-known test/placeholder secrets."""
        if finding.category != ThreatCategory.HARDCODED_SECRETS:
            return False
        snippet = finding.snippet or ""
        return any(cred in snippet for cred in self.policy.credentials.known_test_values)

    def _path_is_documentation(self, rel_path: str) -> bool:
        """Decide whether *rel_path* resides in a docs/examples area."""
        path_obj = Path(rel_path)
        parts = path_obj.parts
        doc_indicators = self.policy.rule_scoping.doc_path_indicators
        if any(p.lower() in doc_indicators for p in parts):
            return True
        doc_re = self.policy._compiled_doc_filename_re
        if doc_re and doc_re.search(path_obj.stem):
            return True
        return False

    # ------------------------------------------------------------------
    # Phase 1 -- Manifest validation
    # ------------------------------------------------------------------

    def _inspect_manifest(self, skill: Skill) -> list[Finding]:
        """Validate the YAML front-matter for policy compliance and social-engineering signals."""
        findings: list[Finding] = []
        manifest = skill.manifest

        max_name_length = self.policy.file_limits.max_name_length
        if len(manifest.name) > max_name_length or not _NAME_EXTRACTOR.fullmatch(manifest.name or ""):
            findings.append(
                Finding(
                    id=self._compute_finding_hash("MANIFEST_INVALID_NAME", "manifest"),
                    rule_id="MANIFEST_INVALID_NAME",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Skill name does not follow agent skills naming rules",
                    description=(
                        f"Skill name '{manifest.name}' is invalid. Agent skills require lowercase letters, numbers, "
                        f"and hyphens only, with a maximum length of {max_name_length} characters."
                    ),
                    file_path="SKILL.md",
                    remediation="Rename the skill to match `[a-z0-9-]{1,64}` (e.g., 'pdf-processing')",
                    analyzer="static",
                )
            )

        max_desc_length = self.policy.file_limits.max_description_length
        if len(manifest.description or "") > max_desc_length:
            findings.append(
                Finding(
                    id=self._compute_finding_hash("MANIFEST_DESCRIPTION_TOO_LONG", "manifest"),
                    rule_id="MANIFEST_DESCRIPTION_TOO_LONG",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Skill description exceeds agent skills length limit",
                    description=(
                        f"Skill description is {len(manifest.description)} characters; Agent skills limit the "
                        f"`description` field to {max_desc_length} characters."
                    ),
                    file_path="SKILL.md",
                    remediation=f"Shorten the description to {max_desc_length} characters or fewer while keeping it specific",
                    analyzer="static",
                )
            )

        min_desc_length = self.policy.file_limits.min_description_length
        if len(manifest.description or "") < min_desc_length:
            findings.append(
                Finding(
                    id=self._compute_finding_hash("SOCIAL_ENG_VAGUE_DESCRIPTION", "manifest"),
                    rule_id="SOCIAL_ENG_VAGUE_DESCRIPTION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.LOW,
                    title="Vague skill description",
                    description=f"Skill description is too short ({len(manifest.description)} chars). Provide detailed explanation.",
                    file_path="SKILL.md",
                    remediation="Provide a clear, detailed description of what the skill does and when to use it",
                    analyzer="static",
                )
            )

        description_lower = manifest.description.lower()
        name_lower = manifest.name.lower()
        is_anthropic_mentioned = "anthropic" in name_lower or "anthropic" in description_lower

        if is_anthropic_mentioned:
            legitimate_patterns = ["apply", "brand", "guidelines", "colors", "typography", "style"]
            is_legitimate = any(pattern in description_lower for pattern in legitimate_patterns)

            if not is_legitimate:
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("SOCIAL_ENG_ANTHROPIC_IMPERSONATION", "manifest"),
                        rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=Severity.MEDIUM,
                        title="Potential Anthropic brand impersonation",
                        description="Skill name or description contains 'Anthropic', suggesting official affiliation",
                        file_path="SKILL.md",
                        remediation="Do not impersonate official skills or use unauthorized branding",
                        analyzer="static",
                    )
                )

        if "claude official" in manifest.name.lower() or "claude official" in manifest.description.lower():
            findings.append(
                Finding(
                    id=self._compute_finding_hash("SOCIAL_ENG_CLAUDE_OFFICIAL", "manifest"),
                    rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.HIGH,
                    title="Claims to be official skill",
                    description="Skill claims to be an 'official' skill",
                    file_path="SKILL.md",
                    remediation="Remove 'official' claims unless properly authorized",
                    analyzer="static",
                )
            )

        if not manifest.license:
            findings.append(
                Finding(
                    id=self._compute_finding_hash("MANIFEST_MISSING_LICENSE", "manifest"),
                    rule_id="MANIFEST_MISSING_LICENSE",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Skill does not specify a license",
                    description="Skill manifest does not include a 'license' field. Specifying a license helps users understand usage terms.",
                    file_path="SKILL.md",
                    remediation="Add 'license' field to SKILL.md frontmatter (e.g., MIT, Apache-2.0)",
                    analyzer="static",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Phase 2 -- Instruction body scanning
    # ------------------------------------------------------------------

    def _review_instructions(self, skill: Skill) -> list[Finding]:
        """Scan the SKILL.md body for prompt-injection and social-engineering patterns."""
        findings: list[Finding] = []
        markdown_rules = self.rule_loader.get_rules_for_file_type("markdown")
        for rule in markdown_rules:
            matches = rule.scan_content(skill.instruction_body, "SKILL.md")
            for match in matches:
                findings.append(self._build_finding(rule, match))
        return findings

    # ------------------------------------------------------------------
    # Phase 3 -- Script file scanning
    # ------------------------------------------------------------------

    def _inspect_script_files(self, skill: Skill) -> list[Finding]:
        """Apply pattern rules to every Python, Bash, JS, and TS file."""
        findings: list[Finding] = []
        skip_in_docs = set(self.policy.rule_scoping.skip_in_docs)

        for skill_file in skill.files:
            if skill_file.file_type not in ("python", "bash", "javascript", "typescript"):
                continue

            rules = self.rule_loader.get_rules_for_file_type(skill_file.file_type)
            content = skill_file.read_content()
            if not content:
                continue

            is_doc = self._path_is_documentation(skill_file.relative_path)

            for rule in rules:
                if is_doc and rule.id in skip_in_docs:
                    continue
                matches = rule.scan_content(content, skill_file.relative_path)
                for match in matches:
                    if rule.id == "RESOURCE_ABUSE_INFINITE_LOOP" and skill_file.file_type == "python":
                        if self._loop_has_error_handler(content, match["line_number"]):
                            continue
                    findings.append(self._build_finding(rule, match))

        return findings

    def _loop_has_error_handler(self, content: str, loop_line_num: int) -> bool:
        """Return *True* if a ``while True`` loop near *loop_line_num* has a termination guard."""
        context_size = self.policy.analysis_thresholds.exception_handler_context_lines
        lines = content.split("\n")
        context_lines = lines[loop_line_num - 1 : min(loop_line_num + context_size, len(lines))]
        context_text = "\n".join(context_lines)
        return any(pat.search(context_text) for pat in _ERROR_HANDLER_PATTERNS)

    # ------------------------------------------------------------------
    # Phase 4 -- Consistency checks
    # ------------------------------------------------------------------

    def _verify_coherence(self, skill: Skill) -> list[Finding]:
        """Flag inconsistencies between declared capabilities and actual behaviour."""
        findings: list[Finding] = []

        uses_network = self._has_network_activity(skill)
        declared_network = self._network_declared_in_manifest(skill)
        skillmd = str(skill.skill_md_path)

        if uses_network and not declared_network:
            findings.append(
                Finding(
                    id=self._compute_finding_hash("TOOL_MISMATCH_NETWORK", skill.name),
                    rule_id="TOOL_ABUSE_UNDECLARED_NETWORK",
                    category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                    severity=Severity.MEDIUM,
                    title="Undeclared network usage",
                    description="Skill code uses network libraries but doesn't declare network requirement",
                    file_path=skillmd,
                    remediation="Declare network usage in compatibility field or remove network calls",
                    analyzer="static",
                )
            )

        if not self._skip_text_pattern_checks:
            findings.extend(self._audit_tool_permissions(skill))

        if self._description_contradicts_code(skill):
            findings.append(
                Finding(
                    id=self._compute_finding_hash("DESC_BEHAVIOR_MISMATCH", skill.name),
                    rule_id="SOCIAL_ENG_MISLEADING_DESC",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.MEDIUM,
                    title="Potential description-behavior mismatch",
                    description="Skill performs actions not reflected in its description",
                    file_path="SKILL.md",
                    remediation="Ensure description accurately reflects all skill capabilities",
                    analyzer="static",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Phase 5 -- Reference traversal
    # ------------------------------------------------------------------

    def _traverse_references(self, skill: Skill) -> list[Finding]:
        """Walk files referenced from SKILL.md and scan their contents."""
        max_depth = self.policy.file_limits.max_reference_depth
        return self._follow_references(skill, skill.referenced_files, max_depth=max_depth)

    def _follow_references(
        self,
        skill: Skill,
        references: list[str],
        max_depth: int = 5,
        current_depth: int = 0,
        visited: set[str] | None = None,
    ) -> list[Finding]:
        """Recursively scan referenced files, guarding against cycles and deep nesting."""
        findings: list[Finding] = []

        if visited is None:
            visited = set()

        if current_depth > max_depth:
            if references:
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("LAZY_LOAD_DEEP", str(current_depth)),
                        rule_id="LAZY_LOAD_DEEP_NESTING",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.MEDIUM,
                        title="Deeply nested file references detected",
                        description=(
                            f"Skill has file references nested more than {max_depth} levels deep. "
                            f"This could be an attempt to hide malicious content in files that are "
                            f"only loaded under specific conditions."
                        ),
                        file_path="SKILL.md",
                        remediation="Flatten the reference structure or ensure all nested files are safe",
                        analyzer="static",
                    )
                )
            return findings

        for ref_file_path in references:
            full_path = skill.directory / ref_file_path
            if not full_path.exists():
                alt_paths = [
                    skill.directory / "references" / ref_file_path,
                    skill.directory / "assets" / ref_file_path,
                    skill.directory / "templates" / ref_file_path,
                    skill.directory / "scripts" / ref_file_path,
                ]
                for alt in alt_paths:
                    if alt.exists():
                        full_path = alt
                        break

            if not full_path.exists():
                continue

            dedupe_reference_aliases = self.policy.rule_scoping.dedupe_reference_aliases
            if dedupe_reference_aliases:
                try:
                    visited_key = str(full_path.resolve())
                except OSError:
                    visited_key = str(full_path)
            else:
                visited_key = ref_file_path
            if visited_key in visited:
                continue
            visited.add(visited_key)

            # Prefer the canonical skill-relative path for reporting.
            display_path = ref_file_path
            if dedupe_reference_aliases:
                try:
                    resolved_full = full_path.resolve()
                    for sf in skill.files:
                        try:
                            if sf.path.resolve() == resolved_full:
                                display_path = sf.relative_path
                                break
                        except OSError:
                            continue
                except OSError:
                    pass

            try:
                with open(full_path, encoding="utf-8") as fh:
                    content = fh.read()

                suffix = full_path.suffix.lower()
                if suffix in (".md", ".markdown"):
                    rules = self.rule_loader.get_rules_for_file_type("markdown")
                elif suffix == ".py":
                    rules = self.rule_loader.get_rules_for_file_type("python")
                elif suffix in (".sh", ".bash"):
                    rules = self.rule_loader.get_rules_for_file_type("bash")
                elif suffix in (".js", ".mjs", ".cjs"):
                    rules = self.rule_loader.get_rules_for_file_type("javascript")
                elif suffix in (".ts", ".tsx"):
                    rules = self.rule_loader.get_rules_for_file_type("typescript")
                else:
                    rules = []

                skip_in_docs = set(self.policy.rule_scoping.skip_in_docs)
                is_doc = self._path_is_documentation(display_path)

                for rule in rules:
                    if is_doc and rule.id in skip_in_docs:
                        continue
                    matches = rule.scan_content(content, display_path)
                    for match in matches:
                        finding = self._build_finding(rule, match)
                        finding.metadata["reference_depth"] = current_depth
                        findings.append(finding)

                nested_refs = self._find_references_in_text(full_path, content)
                if nested_refs:
                    findings.extend(
                        self._follow_references(skill, nested_refs, max_depth, current_depth + 1, visited)
                    )

            except Exception as exc:
                _log.debug("Could not scan reference %s: %s", full_path, exc)

        return findings

    def _find_references_in_text(self, file_path: Path, content: str) -> list[str]:
        """Extract file references from *content* based on the file type of *file_path*."""
        references: list[str] = []
        suffix = file_path.suffix.lower()

        if suffix in (".md", ".markdown"):
            for _, link in _MD_LINK_RE.findall(content):
                if not link.startswith(("http://", "https://", "ftp://", "#")):
                    references.append(link)

        elif suffix == ".py":
            for imp in _PY_IMPORT_RE.findall(content):
                if imp:
                    references.append(f"{imp}.py")

        elif suffix in (".sh", ".bash"):
            references.extend(_BASH_SOURCE_RE.findall(content))

        return references

    # ------------------------------------------------------------------
    # Phase 6 -- Binary file inspection
    # ------------------------------------------------------------------

    def _inspect_binaries(self, skill: Skill) -> list[Finding]:
        """Classify binary assets and flag extension mismatches via magic-byte validation."""
        from ..file_magic import check_extension_mismatch

        findings: list[Finding] = []

        INERT_EXTENSIONS = self.policy.file_classification.inert_extensions
        STRUCTURED_EXTENSIONS = self.policy.file_classification.structured_extensions
        ARCHIVE_EXTENSIONS = self.policy.file_classification.archive_extensions
        allow_script_shebang_text_extensions = self.policy.file_classification.allow_script_shebang_text_extensions
        shebang_compatible_extensions = self.policy.file_classification.script_shebang_extensions or None

        min_confidence = self.policy.analysis_thresholds.min_confidence_pct / 100.0

        for skill_file in skill.files:
            file_path_obj = Path(skill_file.relative_path)
            ext = file_path_obj.suffix.lower()
            if file_path_obj.name.endswith(".tar.gz"):
                ext = ".tar.gz"

            # Magic-byte mismatch detection on all files with known extensions.
            if skill_file.path.exists():
                mismatch = check_extension_mismatch(
                    skill_file.path,
                    min_confidence=min_confidence,
                    allow_script_shebang_text_extensions=allow_script_shebang_text_extensions,
                    shebang_compatible_extensions=shebang_compatible_extensions,
                )
                if mismatch:
                    mismatch_severity, mismatch_desc, magic_match = mismatch
                    severity_map = {
                        "CRITICAL": Severity.CRITICAL,
                        "HIGH": Severity.HIGH,
                        "MEDIUM": Severity.MEDIUM,
                    }
                    findings.append(
                        Finding(
                            id=self._compute_finding_hash("FILE_MAGIC_MISMATCH", skill_file.relative_path),
                            rule_id="FILE_MAGIC_MISMATCH",
                            category=ThreatCategory.OBFUSCATION,
                            severity=severity_map.get(mismatch_severity, Severity.MEDIUM),
                            title="File extension does not match actual content type",
                            description=mismatch_desc,
                            file_path=skill_file.relative_path,
                            remediation="Rename the file to match its actual content type, or remove it if it appears malicious.",
                            analyzer="static",
                            metadata={
                                "actual_type": magic_match.content_type,
                                "actual_family": magic_match.content_family,
                                "claimed_extension": ext,
                                "confidence_score": magic_match.score,
                            },
                        )
                    )

            if skill_file.file_type != "binary":
                continue

            if ext in INERT_EXTENSIONS:
                continue

            if ext in STRUCTURED_EXTENSIONS:
                continue

            if ext in ARCHIVE_EXTENSIONS:
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("ARCHIVE_FILE_DETECTED", skill_file.relative_path),
                        rule_id="ARCHIVE_FILE_DETECTED",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Archive file detected in skill package",
                        description=(
                            f"Archive file found: {skill_file.relative_path}. "
                            f"Archives can contain hidden executables, scripts, or other malicious content "
                            f"that is not visible without extraction."
                        ),
                        file_path=skill_file.relative_path,
                        remediation="Extract archive contents and include files directly, or document the archive's purpose.",
                        analyzer="static",
                    )
                )
                continue

            # Unrecognised binary -- informational.
            findings.append(
                Finding(
                    id=self._compute_finding_hash("BINARY_FILE_DETECTED", skill_file.relative_path),
                    rule_id="BINARY_FILE_DETECTED",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Binary file detected in skill package",
                    description=f"Binary file found: {skill_file.relative_path}. "
                    f"Binary files cannot be inspected by static analysis. "
                    f"Consider using Python or Bash scripts for transparency.",
                    file_path=skill_file.relative_path,
                    remediation="Review binary file necessity. Replace with auditable scripts if possible.",
                    analyzer="static",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Phase 7 -- Hidden / dot-file detection
    # ------------------------------------------------------------------

    def _detect_concealed_files(self, skill: Skill) -> list[Finding]:
        """Flag dot-files and ``__pycache__`` directories in the skill package."""
        findings: list[Finding] = []

        CODE_EXTENSIONS = self.policy.file_classification.code_extensions
        benign_dotfiles = self.policy.hidden_files.benign_dotfiles
        benign_dotdirs = self.policy.hidden_files.benign_dotdirs
        flagged_pycache_dirs: set[str] = set()

        for skill_file in skill.files:
            rel_path = skill_file.relative_path
            path_obj = Path(rel_path)

            if skill_file.is_pycache:
                pycache_dir = str(path_obj.parent)
                if pycache_dir in flagged_pycache_dirs:
                    continue
                flagged_pycache_dirs.add(pycache_dir)

                pyc_count = sum(
                    1 for sf in skill.files if sf.is_pycache and str(Path(sf.relative_path).parent) == pycache_dir
                )

                findings.append(
                    Finding(
                        id=self._compute_finding_hash("PYCACHE_FILES_DETECTED", pycache_dir),
                        rule_id="PYCACHE_FILES_DETECTED",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.LOW,
                        title="Python bytecode cache directory detected",
                        description=(
                            f"__pycache__ directory found at {pycache_dir}/ "
                            f"containing {pyc_count} bytecode file(s). "
                            f"Pre-compiled bytecode should not be distributed in skill packages."
                        ),
                        file_path=pycache_dir,
                        remediation="Remove __pycache__ directories from skill packages. Ship source code only.",
                        analyzer="static",
                    )
                )
            elif skill_file.is_hidden:
                ext = path_obj.suffix.lower()
                parts = path_obj.parts
                filename = path_obj.name

                if filename.lower() in benign_dotfiles:
                    continue

                hidden_parts = [p for p in parts if p.startswith(".") and p != "."]
                if any(p.lower() in benign_dotdirs for p in hidden_parts):
                    continue

                if ext in CODE_EXTENSIONS:
                    findings.append(
                        Finding(
                            id=self._compute_finding_hash("HIDDEN_EXECUTABLE_SCRIPT", rel_path),
                            rule_id="HIDDEN_EXECUTABLE_SCRIPT",
                            category=ThreatCategory.OBFUSCATION,
                            severity=Severity.HIGH,
                            title="Hidden executable script detected",
                            description=(
                                f"Hidden script file found: {rel_path}. "
                                f"Hidden files (dotfiles) are often used to conceal malicious code "
                                f"from casual inspection."
                            ),
                            file_path=rel_path,
                            remediation="Move script to a visible location or remove if not needed.",
                            analyzer="static",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id=self._compute_finding_hash("HIDDEN_DATA_FILE", rel_path),
                            rule_id="HIDDEN_DATA_FILE",
                            category=ThreatCategory.OBFUSCATION,
                            severity=Severity.LOW,
                            title="Hidden data file detected",
                            description=(
                                f"Hidden file found: {rel_path}. "
                                f"Hidden files may contain concealed configuration or data "
                                f"that should be reviewed."
                            ),
                            file_path=rel_path,
                            remediation="Move file to a visible location or document its purpose.",
                            analyzer="static",
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Capability-detection helpers
    # ------------------------------------------------------------------

    def _has_network_activity(self, skill: Skill) -> bool:
        """Return *True* if bundled scripts import external-networking libraries."""
        external_network_indicators = [
            "import requests",
            "from requests import",
            "import urllib.request",
            "from urllib.request import",
            "import http.client",
            "import httpx",
            "import aiohttp",
        ]

        socket_external_indicators = ["socket.connect", "socket.create_connection"]
        socket_localhost_indicators = ["localhost", "127.0.0.1", "::1"]

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()

            if any(indicator in content for indicator in external_network_indicators):
                return True

            if "import socket" in content:
                has_socket_connect = any(ind in content for ind in socket_external_indicators)
                is_localhost_only = any(ind in content for ind in socket_localhost_indicators)

                if has_socket_connect and not is_localhost_only:
                    return True

        return False

    def _network_declared_in_manifest(self, skill: Skill) -> bool:
        """Return *True* if the manifest's compatibility field mentions networking."""
        if skill.manifest.compatibility:
            compatibility_lower = str(skill.manifest.compatibility).lower()
            return "network" in compatibility_lower or "internet" in compatibility_lower
        return False

    def _description_contradicts_code(self, skill: Skill) -> bool:
        """Heuristic: flag "simple" skills that make unexpected network calls."""
        description = skill.description.lower()
        simple_keywords = ["calculator", "format", "template", "style", "lint"]
        if any(kw in description for kw in simple_keywords):
            if self._has_network_activity(skill):
                return True
        return False

    # ------------------------------------------------------------------
    # Allowed-tools violation checks
    # ------------------------------------------------------------------

    def _audit_tool_permissions(self, skill: Skill) -> list[Finding]:
        """Compare declared allowed-tools against actual code capabilities."""
        findings: list[Finding] = []

        if not skill.manifest.allowed_tools:
            return findings

        allowed_tools_lower = [tool.lower() for tool in skill.manifest.allowed_tools]
        skillmd = str(skill.skill_md_path)

        if "read" not in allowed_tools_lower:
            if self._detects_file_reads(skill):
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("ALLOWED_TOOLS_READ_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_READ_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.MEDIUM,
                        title="Code reads files but Read tool not in allowed-tools",
                        description=(
                            f"Skill restricts tools to {skill.manifest.allowed_tools} but bundled scripts appear to "
                            f"read files from the filesystem."
                        ),
                        file_path=skillmd,
                        remediation="Add 'Read' to allowed-tools or remove file reading operations from scripts",
                        analyzer="static",
                    )
                )

        if "write" not in allowed_tools_lower:
            if self._detects_file_writes(skill):
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("ALLOWED_TOOLS_WRITE_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_WRITE_VIOLATION",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Skill declares no Write tool but bundled scripts write files",
                        description=(
                            f"Skill restricts tools to {skill.manifest.allowed_tools} but bundled scripts appear to "
                            f"write to the filesystem, which conflicts with a read-only tool declaration."
                        ),
                        file_path=skillmd,
                        remediation="Either add 'Write' to allowed-tools (if intentional) or remove filesystem writes from scripts",
                        analyzer="static",
                    )
                )

        if "bash" not in allowed_tools_lower:
            if self._detects_bash_execution(skill):
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("ALLOWED_TOOLS_BASH_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_BASH_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.HIGH,
                        title="Code executes bash but Bash tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code executes bash commands",
                        file_path=skillmd,
                        remediation="Add 'Bash' to allowed-tools or remove bash execution from code",
                        analyzer="static",
                    )
                )

        if "grep" not in allowed_tools_lower:
            if self._detects_grep_usage(skill):
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("ALLOWED_TOOLS_GREP_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_GREP_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.LOW,
                        title="Code uses search/grep patterns but Grep tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses regex search patterns",
                        file_path=skillmd,
                        remediation="Add 'Grep' to allowed-tools or remove regex search operations",
                        analyzer="static",
                    )
                )

        if "glob" not in allowed_tools_lower:
            if self._detects_glob_usage(skill):
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("ALLOWED_TOOLS_GLOB_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_GLOB_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.LOW,
                        title="Code uses glob/file patterns but Glob tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses glob patterns",
                        file_path=skillmd,
                        remediation="Add 'Glob' to allowed-tools or remove glob operations",
                        analyzer="static",
                    )
                )

        if self._detects_network_calls(skill):
            findings.append(
                Finding(
                    id=self._compute_finding_hash("ALLOWED_TOOLS_NETWORK_USAGE", skill.name),
                    rule_id="ALLOWED_TOOLS_NETWORK_USAGE",
                    category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                    severity=Severity.MEDIUM,
                    title="Code makes network requests",
                    description=(
                        "Skill code makes network requests. While not controlled by allowed-tools, "
                        "network access should be documented and justified in the skill description."
                    ),
                    file_path=skillmd,
                    remediation="Document network usage in skill description or remove network operations if not needed",
                    analyzer="static",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Low-level capability detectors
    # ------------------------------------------------------------------

    def _detects_file_reads(self, skill: Skill) -> bool:
        """Return *True* if any script contains file-read operations."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pat in _FILE_READ_INDICATORS:
                if pat.search(content):
                    return True
        return False

    def _detects_file_writes(self, skill: Skill) -> bool:
        """Return *True* if any script contains file-write operations."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pat in _FILE_WRITE_INDICATORS:
                if pat.search(content):
                    return True
        return False

    def _detects_bash_execution(self, skill: Skill) -> bool:
        """Return *True* if code invokes shell/subprocess calls."""
        bash_indicators = [
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_output",
            "os.system",
            "os.popen",
            "commands.getoutput",
            "shell=True",
        ]

        if any(f.file_type == "bash" for f in skill.files):
            return True

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if any(indicator in content for indicator in bash_indicators):
                return True
        return False

    def _detects_grep_usage(self, skill: Skill) -> bool:
        """Return *True* if any script uses regex search / grep patterns."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pat in _SEARCH_INDICATORS:
                if pat.search(content):
                    return True
        return False

    def _detects_glob_usage(self, skill: Skill) -> bool:
        """Return *True* if any script uses glob / file-pattern matching."""
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pat in _GLOB_INDICATORS:
                if pat.search(content):
                    return True
        return False

    def _detects_network_calls(self, skill: Skill) -> bool:
        """Return *True* if any script invokes HTTP or socket networking APIs."""
        network_indicators = [
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "urllib.request",
            "urllib.urlopen",
            "http.client",
            "httpx.",
            "aiohttp.",
            "socket.connect",
            "socket.create_connection",
        ]

        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if any(indicator in content for indicator in network_indicators):
                return True
        return False

    # ------------------------------------------------------------------
    # Asset file scanning
    # ------------------------------------------------------------------

    def _inspect_assets(self, skill: Skill) -> list[Finding]:
        """Scan files under assets/, templates/, references/, and data/ for injection patterns."""
        findings: list[Finding] = []

        ASSET_DIRS = ["assets", "templates", "references", "data"]

        ASSET_PATTERNS = [
            (
                re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.HIGH,
                "Prompt injection pattern in asset file",
            ),
            (
                re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.HIGH,
                "Prompt override pattern in asset file",
            ),
            (
                re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Role reassignment pattern in asset file",
            ),
            (
                re.compile(r"à\s+partir\s+de\s+maintenant", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "French role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"a\s+partir\s+de\s+ahora", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Spanish role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"a\s+partir\s+de\s+agora", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Portuguese role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"ab\s+jetzt", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "German role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"da\s+ora\s+in\s+poi", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Italian role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"bundan\s+sonra", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "Turkish role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"from\s+now\s+on", re.IGNORECASE),
                "ASSET_PROMPT_INJECTION",
                Severity.MEDIUM,
                "English role-switch prompt pattern in asset file",
            ),
            (
                re.compile(r"https?://[^\s]+\.(tk|ml|ga|cf|gq)/", re.IGNORECASE),
                "ASSET_SUSPICIOUS_URL",
                Severity.MEDIUM,
                "Suspicious free domain URL in asset",
            ),
        ]

        for skill_file in skill.files:
            path_parts = skill_file.relative_path.split("/")

            is_asset_file = (
                (len(path_parts) > 1 and path_parts[0] in ASSET_DIRS)
                or skill_file.relative_path.endswith((".template", ".tmpl", ".tpl"))
                or (
                    skill_file.file_type == "other"
                    and skill_file.relative_path.endswith(
                        (
                            ".txt",
                            ".json",
                            ".yaml",
                            ".yml",
                            ".html",
                            ".css",
                            ".svg",
                            ".xml",
                            ".xsd",
                        )
                    )
                )
            )

            if not is_asset_file:
                continue

            content = skill_file.read_content()
            if not content:
                continue

            is_doc = self._path_is_documentation(skill_file.relative_path)

            for pattern, rule_id, severity, description in ASSET_PATTERNS:
                matches = list(pattern.finditer(content))

                for match in matches:
                    line_number = content[: match.start()].count("\n") + 1
                    line_content = content.split("\n")[line_number - 1] if content else ""

                    if (
                        rule_id == "ASSET_PROMPT_INJECTION"
                        and is_doc
                        and self.policy.rule_scoping.asset_prompt_injection_skip_in_docs
                    ):
                        continue

                    findings.append(
                        Finding(
                            id=self._compute_finding_hash(rule_id, f"{skill_file.relative_path}:{line_number}"),
                            rule_id=rule_id,
                            category=ThreatCategory.PROMPT_INJECTION
                            if "PROMPT" in rule_id
                            else ThreatCategory.COMMAND_INJECTION
                            if "CODE" in rule_id or "SCRIPT" in rule_id
                            else ThreatCategory.OBFUSCATION
                            if "BASE64" in rule_id
                            else ThreatCategory.POLICY_VIOLATION,
                            severity=severity,
                            title=description,
                            description=f"Pattern '{match.group()[:50]}...' detected in asset file",
                            file_path=skill_file.relative_path,
                            line_number=line_number,
                            snippet=line_content[:100],
                            remediation="Review the asset file and remove any malicious or unnecessary dynamic patterns",
                            analyzer="static",
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # De-duplication
    # ------------------------------------------------------------------

    @staticmethod
    def _remove_duplicates(findings: list[Finding]) -> list[Finding]:
        """Collapse identical findings while preserving discovery order."""
        deduped: list[Finding] = []
        seen: set[tuple[Any, ...]] = set()
        for f in findings:
            key = (
                f.rule_id,
                f.file_path or "",
                int(f.line_number or 0),
                f.snippet or "",
                f.metadata.get("matched_pattern"),
                f.metadata.get("matched_text"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    # ------------------------------------------------------------------
    # Finding construction helpers
    # ------------------------------------------------------------------

    def _build_finding(self, rule: SecurityRule, match: dict[str, Any]) -> Finding:
        """Translate a rule match dict into a ``Finding``, enriched with threat taxonomy data."""
        threat_mapping = None
        try:
            threat_name = rule.category.value.upper().replace("_", " ")
            threat_mapping = ThreatMapping.get_threat_mapping("static", threat_name)
        except (ValueError, AttributeError):
            pass

        return Finding(
            id=self._compute_finding_hash(rule.id, f"{match.get('file_path', 'unknown')}:{match.get('line_number', 0)}"),
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            title=rule.description,
            description=f"Pattern detected: {match.get('matched_text', 'N/A')}",
            file_path=match.get("file_path"),
            line_number=match.get("line_number"),
            snippet=match.get("line_content"),
            remediation=rule.remediation,
            analyzer="static",
            metadata={
                "matched_pattern": match.get("matched_pattern"),
                "matched_text": match.get("matched_text"),
                "aitech": threat_mapping.get("aitech") if threat_mapping else None,
                "aitech_name": threat_mapping.get("aitech_name") if threat_mapping else None,
                "scanner_category": threat_mapping.get("scanner_category") if threat_mapping else None,
            },
        )

    def _compute_finding_hash(self, rule_id: str, context: str) -> str:
        """Produce a deterministic finding identifier from *rule_id* and *context*."""
        combined = f"{rule_id}:{context}"
        digest = hashlib.sha256(combined.encode())
        return f"{rule_id}_{digest.hexdigest()[:10]}"

    # ------------------------------------------------------------------
    # YARA signature scanning
    # ------------------------------------------------------------------

    def _run_yara_rules(self, skill: Skill) -> list[Finding]:
        """Execute YARA rules against every file in the skill tree.

        Covers the SKILL.md instruction body, all text-readable files, and
        binary assets (scanned on disk when the YARA engine supports it).
        """
        if self.yara_scanner is None:
            return []

        findings: list[Finding] = []

        # Instruction body first.
        yara_matches = self.yara_scanner.scan_content(skill.instruction_body, "SKILL.md")
        for match in yara_matches:
            rule_name = match.get("rule_name", "")
            if not self._rule_is_active(rule_name):
                continue
            if rule_name == "embedded_shebang_in_binary":
                continue
            findings.extend(self._yara_match_to_findings(match, skill))

        # Policy-driven rule scoping sets.
        _SKILLMD_AND_SCRIPTS_ONLY = self.policy.rule_scoping.skillmd_and_scripts_only
        _SCRIPT_ONLY_YARA_RULES = self.policy.rule_scoping.skip_in_docs
        _CODE_ONLY_YARA_RULES = self.policy.rule_scoping.code_only

        def _is_skillmd_or_script(skill_file) -> bool:
            return (
                skill_file.relative_path == "SKILL.md"
                or skill_file.file_type in ("python", "bash")
                or Path(skill_file.relative_path).suffix.lower() in {".py", ".sh", ".bash", ".rb", ".pl", ".js", ".ts"}
            )

        scanned_files = {"SKILL.md"}

        for skill_file in skill.files:
            if skill_file.relative_path in scanned_files:
                continue
            scanned_files.add(skill_file.relative_path)

            if skill_file.file_type == "binary":
                if skill_file.path.exists():
                    _ext = skill_file.path.suffix.lower()
                    _inert_exts = set(self.policy.file_classification.inert_extensions)
                    _is_inert = _ext in _inert_exts
                    _skip_shebang_inert = self.policy.file_classification.skip_inert_extensions
                    try:
                        yara_matches = self.yara_scanner.scan_file(
                            skill_file.path,
                            display_path=skill_file.relative_path,
                        )
                        for match in yara_matches:
                            rule_name = match.get("rule_name", "")
                            if not self._rule_is_active(rule_name):
                                continue
                            if rule_name == "embedded_shebang_in_binary" and _is_inert and _skip_shebang_inert:
                                continue
                            findings.extend(self._yara_match_to_findings(match, skill))
                    except Exception as exc:
                        _log.debug("YARA binary scan failed for %s: %s", skill_file.relative_path, exc)
                continue

            content = skill_file.read_content()
            if content:
                is_doc = self._path_is_documentation(skill_file.relative_path)

                yara_matches = self.yara_scanner.scan_content(content, skill_file.relative_path)
                for match in yara_matches:
                    rule_name = match.get("rule_name", "")
                    if not self._rule_is_active(rule_name):
                        continue

                    if rule_name in _SKILLMD_AND_SCRIPTS_ONLY:
                        if not _is_skillmd_or_script(skill_file):
                            continue

                    if is_doc and rule_name in _SCRIPT_ONLY_YARA_RULES:
                        continue

                    is_non_script = skill_file.file_type not in ("python", "bash")
                    if is_non_script and rule_name in _CODE_ONLY_YARA_RULES:
                        continue

                    if rule_name == "embedded_shebang_in_binary":
                        continue

                    findings.extend(self._yara_match_to_findings(match, skill, content))

        # Post-filter: honour policy zero-width steganography thresholds.
        zw_threshold_decode = self.policy.analysis_thresholds.zerowidth_threshold_with_decode
        zw_threshold_alone = self.policy.analysis_thresholds.zerowidth_threshold_alone

        if zw_threshold_decode != 50 or zw_threshold_alone != 200:
            steg_files: set[str] = set()
            for f in findings:
                if f.rule_id == "YARA_prompt_injection_unicode_steganography" and f.file_path:
                    steg_files.add(f.file_path)

            if steg_files:
                _ZW_CHARS = frozenset("\u200b\u200c\u200d")
                _DECODE_PATTERNS = ("atob", "unescape", "fromCharCode", "base64", "decode")
                suppressed_files: set[str] = set()

                for rel_path in steg_files:
                    sf = next((s for s in skill.files if s.relative_path == rel_path), None)
                    if sf is None:
                        continue
                    content = sf.read_content()
                    if not content:
                        continue
                    zw_count = sum(1 for ch in content if ch in _ZW_CHARS)
                    has_decode = any(pat in content for pat in _DECODE_PATTERNS)
                    threshold = zw_threshold_decode if has_decode else zw_threshold_alone
                    if zw_count <= threshold:
                        suppressed_files.add(rel_path)

                if suppressed_files:
                    findings = [
                        f
                        for f in findings
                        if not (
                            f.rule_id == "YARA_prompt_injection_unicode_steganography"
                            and f.file_path in suppressed_files
                        )
                    ]

        return findings

    # ------------------------------------------------------------------
    # Document scanners (PDF, Office)
    # ------------------------------------------------------------------

    def _inspect_pdf_files(self, skill: Skill) -> list[Finding]:
        """Use pdfid to detect suspicious structural elements (JS, auto-actions) in PDFs."""
        if "PDF_STRUCTURAL_THREAT" in self.policy.disabled_rules:
            return []

        try:
            from pdfid import pdfid as pdfid_mod  # type: ignore[import-untyped]
        except ImportError:
            _log.debug("pdfid not installed -- skipping structural PDF scan")
            return []

        findings: list[Finding] = []

        suspicious_keywords: dict[str, tuple[Severity, str]] = {
            "/JS": (Severity.CRITICAL, "Embedded JavaScript code"),
            "/JavaScript": (Severity.CRITICAL, "JavaScript action dictionary"),
            "/OpenAction": (Severity.HIGH, "Auto-execute action on open"),
            "/AA": (Severity.HIGH, "Additional actions (auto-trigger)"),
            "/Launch": (Severity.CRITICAL, "Launch external application"),
            "/EmbeddedFile": (Severity.MEDIUM, "Embedded file attachment"),
            "/RichMedia": (Severity.MEDIUM, "Rich media (Flash/video) content"),
            "/XFA": (Severity.MEDIUM, "XFA form (can contain scripts)"),
            "/AcroForm": (Severity.LOW, "Interactive form fields"),
        }

        for sf in skill.files:
            is_pdf = sf.path.suffix.lower() == ".pdf" or (
                sf.file_type in ("binary", "other")
                and sf.path.exists()
                and sf.path.stat().st_size > 4
                and sf.path.read_bytes()[:5] == b"%PDF-"
            )
            if not is_pdf or not sf.path.exists():
                continue

            try:
                xml_doc = pdfid_mod.PDFiD(str(sf.path), disarm=False)
                if xml_doc is None:
                    continue

                pdfid_elem = xml_doc.getElementsByTagName("PDFiD")
                if pdfid_elem and pdfid_elem[0].getAttribute("IsPDF") != "True":
                    continue

                detected: list[tuple[str, int, Severity, str]] = []
                for keyword_elem in xml_doc.getElementsByTagName("Keyword"):
                    name = keyword_elem.getAttribute("Name")
                    count = int(keyword_elem.getAttribute("Count") or "0")
                    if count > 0 and name in suspicious_keywords:
                        severity, desc = suspicious_keywords[name]
                        detected.append((name, count, severity, desc))

                if not detected:
                    continue

                _SEV_ORDER = {
                    Severity.CRITICAL: 5,
                    Severity.HIGH: 4,
                    Severity.MEDIUM: 3,
                    Severity.LOW: 2,
                    Severity.INFO: 1,
                }
                max_severity = max(detected, key=lambda d: _SEV_ORDER.get(d[2], 0))[2]
                keyword_summary = ", ".join(f"{name} ({count}x)" for name, count, _, _ in detected)
                detail_lines = "\n".join(
                    f"  - {name}: {desc} (found {count} occurrence(s))" for name, count, _, desc in detected
                )

                findings.append(
                    Finding(
                        id=self._compute_finding_hash("PDF_STRUCTURAL_THREAT", sf.relative_path),
                        rule_id="PDF_STRUCTURAL_THREAT",
                        category=ThreatCategory.COMMAND_INJECTION,
                        severity=max_severity,
                        title="PDF contains suspicious structural elements",
                        description=(
                            f"Structural analysis of '{sf.relative_path}' detected "
                            f"suspicious PDF keywords: {keyword_summary}.\n{detail_lines}\n"
                            f"These elements can execute code when the PDF is opened."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove JavaScript actions and auto-execute triggers from PDF files. "
                            "PDF files in skill packages should contain only static content."
                        ),
                        analyzer="static",
                        metadata={
                            "detected_keywords": {name: count for name, count, _, _ in detected},
                            "analysis_method": "pdfid_structural",
                        },
                    )
                )

            except Exception as exc:
                _log.debug("pdfid analysis failed for %s: %s", sf.relative_path, exc)

        return findings

    def _inspect_office_files(self, skill: Skill) -> list[Finding]:
        """Use oletools to detect VBA macros and suspicious OLE indicators in Office files."""
        if "OFFICE_DOCUMENT_THREAT" in self.policy.disabled_rules:
            return []

        try:
            from oletools.oleid import OleID  # type: ignore[import-untyped]
        except ImportError:
            _log.debug("oletools not installed -- skipping Office document scan")
            return []

        findings: list[Finding] = []

        office_extensions = {
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".odt",
            ".ods",
            ".odp",
        }

        for sf in skill.files:
            ext = sf.path.suffix.lower()
            if ext not in office_extensions or not sf.path.exists():
                continue

            try:
                oid = OleID(str(sf.path))
                indicators = oid.check()

                has_macros = False
                is_encrypted = False
                suspicious_indicators: list[str] = []

                for indicator in indicators:
                    ind_id = getattr(indicator, "id", "")
                    ind_value = getattr(indicator, "value", None)
                    ind_name = getattr(indicator, "name", str(indicator))

                    if ind_id == "vba_macros" and ind_value:
                        has_macros = True
                        suspicious_indicators.append(f"VBA macros detected: {ind_value}")
                    elif ind_id == "xlm_macros" and ind_value:
                        has_macros = True
                        suspicious_indicators.append(f"XLM/Excel4 macros detected: {ind_value}")
                    elif ind_id == "encrypted" and ind_value:
                        is_encrypted = True
                        suspicious_indicators.append(f"Document is encrypted: {ind_value}")
                    elif ind_id == "flash" and ind_value:
                        suspicious_indicators.append(f"Embedded Flash content: {ind_value}")
                    elif ind_id == "ObjectPool" and ind_value:
                        suspicious_indicators.append(f"Embedded OLE objects: {ind_value}")
                    elif ind_id == "ext_rels" and ind_value:
                        suspicious_indicators.append(f"External relationships: {ind_value}")

                if not suspicious_indicators:
                    continue

                if has_macros:
                    severity = Severity.CRITICAL
                    title = "Office document contains VBA macros"
                elif is_encrypted:
                    severity = Severity.HIGH
                    title = "Office document is encrypted (resists analysis)"
                else:
                    severity = Severity.MEDIUM
                    title = "Office document contains suspicious indicators"

                findings.append(
                    Finding(
                        id=self._compute_finding_hash("OFFICE_DOCUMENT_THREAT", sf.relative_path),
                        rule_id="OFFICE_DOCUMENT_THREAT",
                        category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                        severity=severity,
                        title=title,
                        description=(
                            f"Analysis of '{sf.relative_path}' detected:\n"
                            + "\n".join(f"  - {s}" for s in suspicious_indicators)
                            + "\nMalicious macros in Office documents can execute code "
                            "when the agent processes the file."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove VBA macros from Office documents. Use plain text, "
                            "Markdown, or macro-free formats (.docx, .xlsx) instead."
                        ),
                        analyzer="static",
                        metadata={
                            "has_macros": has_macros,
                            "is_encrypted": is_encrypted,
                            "indicators": suspicious_indicators,
                            "analysis_method": "oletools_oleid",
                        },
                    )
                )

            except Exception as exc:
                _log.debug("oleid analysis failed for %s: %s", sf.relative_path, exc)

        return findings

    # ------------------------------------------------------------------
    # Homoglyph detection
    # ------------------------------------------------------------------

    def _detect_homoglyphs(self, skill: Skill) -> list[Finding]:
        """Flag Unicode look-alike characters in code that could bypass pattern rules."""
        try:
            from confusable_homoglyphs import confusables  # type: ignore[import-untyped]
        except ImportError:
            _log.debug("confusable-homoglyphs not installed -- skipping homoglyph check")
            return []

        findings: list[Finding] = []

        code_file_types = {"python", "bash"}

        _CODE_TOKEN_RE = re.compile(r"[=\(\)\[\]\{\};]|import |def |class |if |for |while |return |print\(")
        _MATH_OPERATOR_RE = re.compile(r"[=+\-*/\u00d7\u00f7\u2264\u2265\u2248\u2260\u2211\u220f\u221a]")
        _STRING_LITERAL_RE = re.compile(r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')")
        _GREEK_CHAR_RE = re.compile(r"[\u0370-\u03FF\u1F00-\u1FFF]")
        filter_math_context = self.policy.analysis_thresholds.homoglyph_filter_math_context
        low_risk_confusable_aliases = {
            alias.upper() for alias in self.policy.analysis_thresholds.homoglyph_math_aliases
        }

        for sf in skill.files:
            if sf.file_type not in code_file_types:
                continue

            content = sf.read_content()
            if not content:
                continue

            dangerous_lines: list[tuple[int, str, list[dict]]] = []
            in_triple_quote_block = False
            triple_quote_delim = ""

            for line_num, line in enumerate(content.split("\n"), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue

                if filter_math_context and sf.file_type == "python":
                    if in_triple_quote_block:
                        if triple_quote_delim and triple_quote_delim in line:
                            in_triple_quote_block = False
                            triple_quote_delim = ""
                        continue
                    if '"""' in line or "'''" in line:
                        delim = '"""' if '"""' in line else "'''"
                        if line.count(delim) % 2 == 1:
                            in_triple_quote_block = True
                            triple_quote_delim = delim
                        continue

                if stripped.isascii():
                    continue

                if filter_math_context:
                    outside_literals = _STRING_LITERAL_RE.sub("", stripped)
                    if all(ord(ch) < 128 for ch in outside_literals):
                        continue

                if not _CODE_TOKEN_RE.search(stripped):
                    continue

                result = confusables.is_dangerous(stripped, preferred_aliases=["LATIN"])
                if result:
                    if filter_math_context:
                        confusable_info = confusables.is_confusable(stripped, preferred_aliases=["LATIN"]) or []
                        aliases = {
                            str(entry.get("alias", "")).upper()
                            for entry in confusable_info
                            if isinstance(entry, dict) and entry.get("alias")
                        }
                        if (
                            aliases
                            and aliases.issubset(low_risk_confusable_aliases)
                            and (_MATH_OPERATOR_RE.search(stripped) or _GREEK_CHAR_RE.search(stripped))
                        ):
                            continue
                    dangerous_lines.append((line_num, stripped, result))

            min_dangerous_lines = self.policy.analysis_thresholds.min_dangerous_lines
            if len(dangerous_lines) < min_dangerous_lines:
                continue

            reported = dangerous_lines[:5]
            line_details = "\n".join(f"  - Line {ln}: {text[:80]}" for ln, text, _ in reported)
            extra = ""
            if len(dangerous_lines) > 5:
                extra = f"\n  ... and {len(dangerous_lines) - 5} more lines"

            findings.append(
                Finding(
                    id=self._compute_finding_hash("HOMOGLYPH_ATTACK", sf.relative_path),
                    rule_id="HOMOGLYPH_ATTACK",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Unicode homoglyph characters detected in code",
                    description=(
                        f"File '{sf.relative_path}' contains characters from mixed Unicode "
                        f"scripts that are visually identical to ASCII letters. "
                        f"This technique can bypass pattern-matching security rules.\n"
                        f"{line_details}{extra}"
                    ),
                    file_path=sf.relative_path,
                    line_number=reported[0][0],
                    remediation=(
                        "Replace all non-ASCII lookalike characters with their ASCII "
                        "equivalents. All code should use standard Latin characters."
                    ),
                    analyzer="static",
                    metadata={
                        "affected_lines": len(dangerous_lines),
                        "analysis_method": "confusable_homoglyphs",
                    },
                )
            )

        return findings

    # ------------------------------------------------------------------
    # File inventory audit
    # ------------------------------------------------------------------

    def _audit_file_inventory(self, skill: Skill) -> list[Finding]:
        """Inspect the overall file inventory for anomalies (size, count, unreferenced scripts)."""
        findings: list[Finding] = []

        if not skill.files:
            return findings

        type_counts: dict[str, int] = {}
        ext_counts: dict[str, int] = {}
        total_size = 0
        largest_file = None
        largest_size = 0

        for sf in skill.files:
            file_type = sf.file_type
            type_counts[file_type] = type_counts.get(file_type, 0) + 1

            ext = sf.path.suffix.lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

            total_size += sf.size_bytes
            if sf.size_bytes > largest_size:
                largest_size = sf.size_bytes
                largest_file = sf

        max_file_count = self.policy.file_limits.max_file_count
        if len(skill.files) > max_file_count:
            findings.append(
                Finding(
                    id=self._compute_finding_hash("EXCESSIVE_FILE_COUNT", str(len(skill.files))),
                    rule_id="EXCESSIVE_FILE_COUNT",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Skill package contains many files",
                    description=(
                        f"Skill package contains {len(skill.files)} files. "
                        f"Large file counts increase attack surface and may indicate "
                        f"bundled dependencies or unnecessary content."
                    ),
                    file_path=".",
                    remediation="Review file inventory and remove unnecessary files.",
                    analyzer="static",
                    metadata={
                        "file_count": len(skill.files),
                        "type_breakdown": type_counts,
                    },
                )
            )

        max_file_size = self.policy.file_limits.max_file_size_bytes
        if largest_file and largest_size > max_file_size:
            findings.append(
                Finding(
                    id=self._compute_finding_hash("OVERSIZED_FILE", largest_file.relative_path),
                    rule_id="OVERSIZED_FILE",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Oversized file in skill package",
                    description=(
                        f"File {largest_file.relative_path} is {largest_size / 1024 / 1024:.1f}MB. "
                        f"Large files in skill packages may contain hidden content or serve as "
                        f"a vector for resource abuse."
                    ),
                    file_path=largest_file.relative_path,
                    remediation="Review large files and consider hosting externally.",
                    analyzer="static",
                )
            )

        # Detect unreferenced scripts (potential hidden functionality).
        code_extensions = self.policy.file_classification.code_extensions
        referenced_lower = {r.lower() for r in skill.referenced_files}

        # Transitively expand: scripts imported by referenced scripts count too.
        _import_re = re.compile(r"^(?:from\s+\.?(\w[\w.]*)\s+import|import\s+\.?(\w[\w.]*))", re.MULTILINE)
        _source_re = re.compile(r"(?:source|\.)\s+[\"']?([A-Za-z0-9_\-./]+\.(?:sh|bash))[\"']?")
        expanded_refs: set[str] = set(referenced_lower)
        for sf in skill.files:
            if sf.relative_path.lower() not in referenced_lower:
                fn = Path(sf.relative_path).name.lower()
                if fn not in referenced_lower and fn not in skill.instruction_body.lower():
                    continue
            content = sf.read_content()
            if not content:
                continue
            if sf.file_type == "python":
                for m in _import_re.finditer(content):
                    mod = (m.group(1) or m.group(2) or "").replace(".", "/")
                    if mod:
                        expanded_refs.add(f"{mod}.py")
                        expanded_refs.add(mod.split("/")[-1] + ".py")
            elif sf.file_type == "bash":
                for m in _source_re.finditer(content):
                    expanded_refs.add(m.group(1).lower())
                    expanded_refs.add(Path(m.group(1)).name.lower())

        _BENIGN_FILENAMES = {
            "__init__.py",
            "__main__.py",
            "conftest.py",
            "setup.py",
            "setup.cfg",
            "manage.py",
            "wsgi.py",
            "asgi.py",
            "fabfile.py",
            "noxfile.py",
            "tasks.py",
            "makefile",
            "rakefile",
            "gulpfile.js",
            "gruntfile.js",
            "webpack.config.js",
            "tsconfig.json",
            "jest.config.js",
            "babel.config.js",
            ".eslintrc.js",
            "vite.config.js",
        }
        _TEST_FILE_RE = re.compile(r"^(?:test_|tests_).*\.py$|^.*_test\.py$|^conftest\.py$", re.IGNORECASE)

        for sf in skill.files:
            if sf.file_type in ("python", "bash") or sf.path.suffix.lower() in code_extensions:
                rel = sf.relative_path
                if rel.lower() == "skill.md":
                    continue
                filename = Path(rel).name
                filename_lower = filename.lower()

                if filename_lower in _BENIGN_FILENAMES:
                    continue

                if _TEST_FILE_RE.match(filename):
                    continue

                is_referenced = (
                    rel.lower() in expanded_refs
                    or filename_lower in expanded_refs
                    or any(ref in rel.lower() for ref in expanded_refs if ref)
                    or filename_lower in skill.instruction_body.lower()
                )
                if not is_referenced:
                    self._unreferenced_scripts.append(rel)

        # Archives containing executable scripts.
        for sf in skill.files:
            if sf.extracted_from and sf.file_type in ("python", "bash"):
                findings.append(
                    Finding(
                        id=self._compute_finding_hash("ARCHIVE_CONTAINS_EXECUTABLE", sf.relative_path),
                        rule_id="ARCHIVE_CONTAINS_EXECUTABLE",
                        category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                        severity=Severity.HIGH,
                        title="Archive contains executable script",
                        description=(
                            f"Executable script '{sf.relative_path}' was extracted from "
                            f"archive '{sf.extracted_from}'. Archives can be used to conceal "
                            f"malicious scripts from casual inspection."
                        ),
                        file_path=sf.relative_path,
                        remediation=(
                            "Remove executable scripts from archives. "
                            "Include scripts directly in the skill package for transparency."
                        ),
                        analyzer="static",
                        metadata={
                            "extracted_from": sf.extracted_from,
                            "file_type": sf.file_type,
                        },
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # YARA match conversion
    # ------------------------------------------------------------------

    def _yara_match_to_findings(
        self, match: dict[str, Any], skill: Skill, file_content: str | None = None
    ) -> list[Finding]:
        """Convert a raw YARA match dict into zero or more ``Finding`` objects."""
        findings: list[Finding] = []

        rule_name = match["rule_name"]
        namespace = match["namespace"]
        file_path = match["file_path"]
        meta = match["meta"].get("meta", {})

        category, severity = self._resolve_yara_threat(rule_name, meta)

        from ..command_safety import evaluate_command

        safe_cleanup_dirs = self.policy.system_cleanup.safe_rm_targets or _HARMLESS_CLEANUP_DIRS
        placeholder_markers = self.policy.credentials.placeholder_markers or _KNOWN_DUMMY_MARKERS

        for string_match in match["strings"]:
            string_identifier = string_match.get("identifier", "")
            if string_identifier.startswith("$documentation") or string_identifier.startswith("$safe"):
                continue

            if rule_name == "code_execution_generic":
                line_content = string_match.get("line_content", "").lower()
                matched_data = string_match.get("matched_data", "").lower()

                cmd_to_eval = matched_data.strip() or line_content.strip()
                verdict = evaluate_command(cmd_to_eval, policy=self.policy)
                if verdict.should_suppress_yara:
                    continue

            if rule_name == "system_manipulation_generic":
                line_content = string_match.get("line_content", "").lower()
                matched_data = string_match.get("matched_data", "").lower()

                cmd_to_eval = matched_data.strip() or line_content.strip()
                verdict = evaluate_command(cmd_to_eval, policy=self.policy)
                if verdict.should_suppress_yara:
                    continue

                rm_source = line_content if ("rm -rf" in line_content or "rm -r" in line_content) else matched_data
                if "rm -rf" in rm_source or "rm -r" in rm_source:
                    rm_targets = _RM_TARGET_RE.findall(rm_source)
                    if rm_targets:
                        all_safe = all(
                            any(safe_dir in target for safe_dir in safe_cleanup_dirs) for target in rm_targets
                        )
                        if all_safe:
                            continue

            if rule_name == "credential_harvesting_generic":
                if self.yara_mode.credential_harvesting.filter_placeholder_patterns:
                    line_content = string_match.get("line_content", "")
                    matched_data = string_match.get("matched_data", "")
                    combined = f"{line_content} {matched_data}".lower()

                    if any(marker in combined for marker in placeholder_markers):
                        continue

                    if "export " in combined and "=" in combined:
                        _, value = combined.split("=", 1)
                        if any(marker in value for marker in placeholder_markers):
                            continue

            if rule_name == "tool_chaining_abuse_generic":
                line_content = string_match.get("line_content", "")
                lower_line = line_content.lower()
                exfil_raw = ",".join(self.policy.pipeline.exfil_hints)
                exfil_hints = tuple(h.strip() for h in exfil_raw.split(","))

                if self.yara_mode.tool_chaining.filter_generic_http_verbs:
                    if (
                        "get" in lower_line
                        and "post" in lower_line
                        and not any(hint in lower_line for hint in exfil_hints)
                    ):
                        continue

                if self.yara_mode.tool_chaining.filter_api_documentation:
                    api_raw = ",".join(self.policy.pipeline.api_doc_tokens)
                    api_doc_tokens = tuple(t.strip() for t in api_raw.split(","))
                    if any(token in line_content for token in api_doc_tokens) and not any(
                        hint in lower_line for hint in exfil_hints
                    ):
                        continue

                if self.yara_mode.tool_chaining.filter_email_field_mentions:
                    if "by email" in lower_line or "email address" in lower_line or "email field" in lower_line:
                        continue

            if rule_name == "prompt_injection_unicode_steganography":
                _steg_rule_id = "YARA_prompt_injection_unicode_steganography"
                line_content = string_match.get("line_content", "")
                matched_data = string_match.get("matched_data", "")
                has_ascii_letters = any("A" <= char <= "Z" or "a" <= char <= "z" for char in line_content)

                short_match_max = self.policy.analysis_thresholds.short_match_max_chars
                if len(matched_data) <= short_match_max and not has_ascii_letters:
                    continue

                i18n_markers = ("i18n", "locale", "translation", "lang=", "charset", "utf-8", "encoding")
                if any(marker in line_content.lower() for marker in i18n_markers):
                    continue

                cyrillic_cjk_pattern = any(
                    ("\u0400" <= char <= "\u04ff")
                    or ("\u4e00" <= char <= "\u9fff")
                    or ("\u0600" <= char <= "\u06ff")
                    or ("\u0590" <= char <= "\u05ff")
                    for char in line_content
                )
                cyrillic_cjk_min = self.policy.analysis_thresholds.cyrillic_cjk_min_chars
                if cyrillic_cjk_pattern and len(matched_data) < cyrillic_cjk_min:
                    continue

            finding_id = self._compute_finding_hash(f"YARA_{rule_name}", f"{file_path}:{string_match['line_number']}")

            description = meta.get("description", f"YARA rule {rule_name} matched")
            threat_type = meta.get("threat_type", "SECURITY THREAT")

            findings.append(
                Finding(
                    id=finding_id,
                    rule_id=f"YARA_{rule_name}",
                    category=category,
                    severity=severity,
                    title=f"{threat_type} detected by YARA",
                    description=f"{description}: {string_match['matched_data'][:100]}",
                    file_path=file_path,
                    line_number=string_match["line_number"],
                    snippet=string_match["line_content"],
                    remediation=f"Review and remove {threat_type.lower()} pattern",
                    analyzer="static",
                    metadata={
                        "yara_rule": rule_name,
                        "yara_namespace": namespace,
                        "matched_string": string_match["identifier"],
                        "threat_type": threat_type,
                    },
                )
            )

        return findings

    def _resolve_yara_threat(self, rule_name: str, meta: dict[str, Any]) -> tuple:
        """Map a YARA rule name and its metadata to a ``(ThreatCategory, Severity)`` pair."""
        threat_type = meta.get("threat_type", "").upper()
        classification = meta.get("classification", "harmful")

        category_map = {
            "PROMPT INJECTION": ThreatCategory.PROMPT_INJECTION,
            "INJECTION ATTACK": ThreatCategory.COMMAND_INJECTION,
            "COMMAND INJECTION": ThreatCategory.COMMAND_INJECTION,
            "CREDENTIAL HARVESTING": ThreatCategory.HARDCODED_SECRETS,
            "DATA EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
            "SYSTEM MANIPULATION": ThreatCategory.UNAUTHORIZED_TOOL_USE,
            "CODE EXECUTION": ThreatCategory.COMMAND_INJECTION,
            "SQL INJECTION": ThreatCategory.COMMAND_INJECTION,
            "SKILL DISCOVERY ABUSE": ThreatCategory.SKILL_DISCOVERY_ABUSE,
            "TRANSITIVE TRUST ABUSE": ThreatCategory.TRANSITIVE_TRUST_ABUSE,
            "AUTONOMY ABUSE": ThreatCategory.AUTONOMY_ABUSE,
            "TOOL CHAINING ABUSE": ThreatCategory.TOOL_CHAINING_ABUSE,
            "UNICODE STEGANOGRAPHY": ThreatCategory.UNICODE_STEGANOGRAPHY,
        }

        category = category_map.get(threat_type, ThreatCategory.POLICY_VIOLATION)

        if classification == "harmful":
            if "INJECTION" in threat_type or "CREDENTIAL" in threat_type:
                severity = Severity.CRITICAL
            elif "EXFILTRATION" in threat_type or "MANIPULATION" in threat_type:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return category, severity
