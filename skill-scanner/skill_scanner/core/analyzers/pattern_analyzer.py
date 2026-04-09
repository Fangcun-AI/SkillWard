# Copyright 2026 FangcunGuard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Engine 1: Pattern Analyzer.

Performs text-based security pattern matching across all skill content:
SKILL.md (name, description, instruction body), scripts, referenced files,
and asset files. Also detects Unicode homoglyph attacks in code files.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from ..models import Finding, Severity, Skill, ThreatCategory
from ..rules.patterns import RuleLoader, SecurityRule
from ..scan_policy import ScanPolicy
from ...threats.threats import ThreatMapping
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

_MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^\)]+)\)")
_PYTHON_IMPORT_PATTERN = re.compile(r"^from\s+\.([A-Za-z0-9_.]*)\s+import", re.MULTILINE)
_BASH_SOURCE_PATTERN = re.compile(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))")

_EXCEPTION_PATTERNS = [
    re.compile(r"except\s+(EOFError|StopIteration|KeyboardInterrupt|Exception|BaseException)"),
    re.compile(r"except\s*:"),
    re.compile(r"break\s*$", re.MULTILINE),
    re.compile(r"return\s*$", re.MULTILINE),
    re.compile(r"sys\.exit\s*\("),
    re.compile(r"raise\s+StopIteration"),
]

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


class PatternAnalyzer(BaseAnalyzer):
    """Text pattern security scanner for all skill content."""

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__("pattern_analyzer", policy=policy)
        self.rule_loader = RuleLoader()
        self.rule_loader.load_rules()

    def analyze(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_manifest_text(skill))
        findings.extend(self._scan_instruction_body(skill))
        findings.extend(self._scan_scripts(skill))
        findings.extend(self._scan_referenced_files(skill))
        findings.extend(self._scan_asset_files(skill))
        findings.extend(self._check_homoglyph_attacks(skill))
        return findings

    # ------------------------------------------------------------------
    # Scan manifest name + description as virtual text
    # ------------------------------------------------------------------

    def _scan_manifest_text(self, skill: Skill) -> list[Finding]:
        """Scan name+description concatenated as virtual text with markdown rules."""
        findings: list[Finding] = []
        manifest = skill.manifest
        virtual_text = f"{manifest.name or ''} {manifest.description or ''}"
        if not virtual_text.strip():
            return findings

        markdown_rules = self.rule_loader.get_rules_for_file_type("markdown")
        for rule in markdown_rules:
            matches = rule.scan_content(virtual_text, "SKILL.md")
            for match in matches:
                findings.append(self._create_finding_from_match(rule, match))
        return findings

    # ------------------------------------------------------------------
    # Instruction body scan (from static.py._scan_instruction_body)
    # ------------------------------------------------------------------

    def _scan_instruction_body(self, skill: Skill) -> list[Finding]:
        """Scan SKILL.md instruction body for prompt injection patterns."""
        findings: list[Finding] = []
        markdown_rules = self.rule_loader.get_rules_for_file_type("markdown")
        for rule in markdown_rules:
            matches = rule.scan_content(skill.instruction_body, "SKILL.md")
            for match in matches:
                findings.append(self._create_finding_from_match(rule, match))
        return findings

    # ------------------------------------------------------------------
    # Script scan (from static.py._scan_scripts)
    # ------------------------------------------------------------------

    def _scan_scripts(self, skill: Skill) -> list[Finding]:
        """Scan all script files (Python, Bash, JS, TS) for vulnerabilities."""
        findings: list[Finding] = []
        skip_in_docs = set(self.policy.rule_scoping.skip_in_docs)

        for skill_file in skill.files:
            if skill_file.file_type not in ("python", "bash", "javascript", "typescript"):
                continue

            rules = self.rule_loader.get_rules_for_file_type(skill_file.file_type)
            content = skill_file.read_content()
            if not content:
                continue

            is_doc = self._is_doc_file(skill_file.relative_path)

            for rule in rules:
                if is_doc and rule.id in skip_in_docs:
                    continue
                matches = rule.scan_content(content, skill_file.relative_path)
                for match in matches:
                    if rule.id == "RESOURCE_ABUSE_INFINITE_LOOP" and skill_file.file_type == "python":
                        if self._is_loop_with_exception_handler(content, match["line_number"]):
                            continue
                    findings.append(self._create_finding_from_match(rule, match))

        return findings

    def _is_loop_with_exception_handler(self, content: str, loop_line_num: int) -> bool:
        context_size = self.policy.analysis_thresholds.exception_handler_context_lines
        lines = content.split("\n")
        context_lines = lines[loop_line_num - 1 : min(loop_line_num + context_size, len(lines))]
        context_text = "\n".join(context_lines)
        for pattern in _EXCEPTION_PATTERNS:
            if pattern.search(context_text):
                return True
        return False

    # ------------------------------------------------------------------
    # Referenced files scan (from static.py._scan_referenced_files)
    # ------------------------------------------------------------------

    def _scan_referenced_files(self, skill: Skill) -> list[Finding]:
        max_depth = self.policy.file_limits.max_reference_depth
        findings: list[Finding] = []
        findings.extend(self._scan_references_recursive(skill, skill.referenced_files, max_depth=max_depth))
        return findings

    def _scan_references_recursive(
        self,
        skill: Skill,
        references: list[str],
        max_depth: int = 5,
        current_depth: int = 0,
        visited: set[str] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if visited is None:
            visited = set()

        if current_depth > max_depth:
            if references:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("LAZY_LOAD_DEEP", str(current_depth)),
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
                        analyzer="pattern_analyzer",
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
                with open(full_path, encoding="utf-8") as f:
                    content = f.read()

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
                is_doc = self._is_doc_file(display_path)

                for rule in rules:
                    if is_doc and rule.id in skip_in_docs:
                        continue
                    matches = rule.scan_content(content, display_path)
                    for match in matches:
                        finding = self._create_finding_from_match(rule, match)
                        finding.metadata["reference_depth"] = current_depth
                        findings.append(finding)

                nested_refs = self._extract_references_from_content(full_path, content)
                if nested_refs:
                    findings.extend(
                        self._scan_references_recursive(skill, nested_refs, max_depth, current_depth + 1, visited)
                    )

            except Exception as e:
                logger.debug("Failed to scan reference %s: %s", full_path, e)

        return findings

    def _extract_references_from_content(self, file_path: Path, content: str) -> list[str]:
        references = []
        suffix = file_path.suffix.lower()

        if suffix in (".md", ".markdown"):
            markdown_links = _MARKDOWN_LINK_PATTERN.findall(content)
            for _, link in markdown_links:
                if not link.startswith(("http://", "https://", "ftp://", "#")):
                    references.append(link)

        elif suffix == ".py":
            import_patterns = _PYTHON_IMPORT_PATTERN.findall(content)
            for imp in import_patterns:
                if imp:
                    references.append(f"{imp}.py")

        elif suffix in (".sh", ".bash"):
            source_patterns = _BASH_SOURCE_PATTERN.findall(content)
            references.extend(source_patterns)

        return references

    # ------------------------------------------------------------------
    # Asset file scan (from static.py._scan_asset_files)
    # ------------------------------------------------------------------

    def _scan_asset_files(self, skill: Skill) -> list[Finding]:
        """Scan files in assets/, templates/, references/, data/ for injection patterns."""
        findings: list[Finding] = []

        for skill_file in skill.files:
            path_parts = skill_file.relative_path.split("/")

            is_asset_file = (
                (len(path_parts) > 1 and path_parts[0] in ASSET_DIRS)
                or skill_file.relative_path.endswith((".template", ".tmpl", ".tpl"))
                or (
                    skill_file.file_type == "other"
                    and skill_file.relative_path.endswith(
                        (".txt", ".json", ".yaml", ".yml", ".html", ".css", ".svg", ".xml", ".xsd")
                    )
                )
            )

            if not is_asset_file:
                continue

            content = skill_file.read_content()
            if not content:
                continue

            is_doc = self._is_doc_file(skill_file.relative_path)

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
                            id=self._generate_finding_id(rule_id, f"{skill_file.relative_path}:{line_number}"),
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
                            analyzer="pattern_analyzer",
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Homoglyph detection (from static.py._check_homoglyph_attacks)
    # ------------------------------------------------------------------

    def _check_homoglyph_attacks(self, skill: Skill) -> list[Finding]:
        """Detect Unicode homoglyph attacks in code files."""
        try:
            from confusable_homoglyphs import confusables  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("confusable-homoglyphs not installed – skipping homoglyph check")
            return []

        findings: list[Finding] = []
        code_file_types = {"python", "bash"}

        _CODE_TOKEN_RE = re.compile(r"[=\(\)\[\]\{\};]|import |def |class |if |for |while |return |print\(")
        _MATH_OPERATOR_RE = re.compile(r"[=+\-*/×÷≤≥≈≠∑∏√]")
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
                    id=self._generate_finding_id("HOMOGLYPH_ATTACK", sf.relative_path),
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
                    analyzer="pattern_analyzer",
                    metadata={
                        "affected_lines": len(dangerous_lines),
                        "analysis_method": "confusable_homoglyphs",
                    },
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_doc_file(self, rel_path: str) -> bool:
        path_obj = Path(rel_path)
        parts = path_obj.parts
        doc_indicators = self.policy.rule_scoping.doc_path_indicators
        if any(p.lower() in doc_indicators for p in parts):
            return True
        doc_re = self.policy._compiled_doc_filename_re
        if doc_re and doc_re.search(path_obj.stem):
            return True
        return False

    def _create_finding_from_match(self, rule: SecurityRule, match: dict[str, Any]) -> Finding:
        threat_mapping = None
        try:
            threat_name = rule.category.value.upper().replace("_", " ")
            threat_mapping = ThreatMapping.get_threat_mapping("static", threat_name)
        except (ValueError, AttributeError):
            pass

        return Finding(
            id=self._generate_finding_id(rule.id, f"{match.get('file_path', 'unknown')}:{match.get('line_number', 0)}"),
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            title=rule.description,
            description=f"Pattern detected: {match.get('matched_text', 'N/A')}",
            file_path=match.get("file_path"),
            line_number=match.get("line_number"),
            snippet=match.get("line_content"),
            remediation=rule.remediation,
            analyzer="pattern_analyzer",
            metadata={
                "matched_pattern": match.get("matched_pattern"),
                "matched_text": match.get("matched_text"),
                "aitech": threat_mapping.get("aitech") if threat_mapping else None,
                "aitech_name": threat_mapping.get("aitech_name") if threat_mapping else None,
                "scanner_category": threat_mapping.get("scanner_category") if threat_mapping else None,
            },
        )

    @staticmethod
    def _generate_finding_id(rule_id: str, context: str) -> str:
        combined = f"{rule_id}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{rule_id}_{hash_obj.hexdigest()[:10]}"
