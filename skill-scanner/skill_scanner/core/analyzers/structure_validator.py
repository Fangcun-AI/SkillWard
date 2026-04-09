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
Engine 2: Structure Validator Analyzer.

Validates SKILL.md structural security: name conventions, description quality,
allowed-tools safety, and instruction body integrity.
"""

from __future__ import annotations

import hashlib
import logging
import re

from ..models import Finding, Severity, Skill, ThreatCategory
from ..scan_policy import ScanPolicy
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

_SKILL_NAME_PATTERN = re.compile(r"[a-z0-9-]+")

_UNSAFE_NAME_PATTERNS = [
    re.compile(r"execute[_-]?shell", re.IGNORECASE),
    re.compile(r"run[_-]?command", re.IGNORECASE),
    re.compile(r"^admin[_-]", re.IGNORECASE),
    re.compile(r"^root[_-]", re.IGNORECASE),
    re.compile(r"^system[_-]", re.IGNORECASE),
]

# Dangerous values in allowed-tools declaration
_OVER_AUTHORIZATION_VALUES = {"*", "all", "any"}
_DANGEROUS_TOOL_NAMES = {"bash", "exec", "shell", "terminal"}

# Patterns for detecting code behaviors (mirrored from static.py)
_READ_PATTERNS = [
    re.compile(r"open\([^)]+['\"]r['\"]"),
    re.compile(r"\.read\("),
    re.compile(r"\.readline\("),
    re.compile(r"\.readlines\("),
    re.compile(r"Path\([^)]+\)\.read_text"),
    re.compile(r"Path\([^)]+\)\.read_bytes"),
    re.compile(r"with\s+open\([^)]+['\"]r"),
]

_WRITE_PATTERNS = [
    re.compile(r"open\([^)]+['\"]w['\"]"),
    re.compile(r"\.write\("),
    re.compile(r"\.writelines\("),
    re.compile(r"pathlib\.Path\([^)]+\)\.write"),
    re.compile(r"with\s+open\([^)]+['\"]w"),
]

_GREP_PATTERNS = [
    re.compile(r"re\.search\("),
    re.compile(r"re\.findall\("),
    re.compile(r"re\.match\("),
    re.compile(r"re\.finditer\("),
    re.compile(r"re\.sub\("),
    re.compile(r"grep"),
]

_GLOB_PATTERNS = [
    re.compile(r"glob\.glob\("),
    re.compile(r"glob\.iglob\("),
    re.compile(r"Path\([^)]*\)\.glob\("),
    re.compile(r"\.glob\("),
    re.compile(r"\.rglob\("),
    re.compile(r"fnmatch\."),
]


class StructureValidatorAnalyzer(BaseAnalyzer):
    """Validates SKILL.md structure and allowed-tools security."""

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__("structure_validator", policy=policy)

    def analyze(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_manifest(skill))
        findings.extend(self._check_instruction_body(skill))
        findings.extend(self._check_allowed_tools_security(skill))
        findings.extend(self._check_allowed_tools_violations(skill))
        return findings

    # ------------------------------------------------------------------
    # Manifest checks (from static.py._check_manifest, analyzer changed)
    # ------------------------------------------------------------------

    def _check_manifest(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        manifest = skill.manifest

        max_name_length = self.policy.file_limits.max_name_length
        if len(manifest.name) > max_name_length or not _SKILL_NAME_PATTERN.fullmatch(manifest.name or ""):
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_INVALID_NAME", "manifest"),
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
                    analyzer="structure_validator",
                )
            )

        # NEW: Unsafe name patterns
        for pattern in _UNSAFE_NAME_PATTERNS:
            if pattern.search(manifest.name or ""):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("MANIFEST_UNSAFE_NAME_PATTERN", "manifest"),
                        rule_id="MANIFEST_UNSAFE_NAME_PATTERN",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Skill name contains unsafe pattern",
                        description=(
                            f"Skill name '{manifest.name}' matches an unsafe pattern "
                            f"(e.g., execute_shell, run_command, admin_*, root_*, system_*). "
                            f"Such names suggest elevated or dangerous capabilities."
                        ),
                        file_path="SKILL.md",
                        remediation="Rename the skill to a descriptive, capability-neutral name",
                        analyzer="structure_validator",
                    )
                )
                break

        max_desc_length = self.policy.file_limits.max_description_length
        if len(manifest.description or "") > max_desc_length:
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_DESCRIPTION_TOO_LONG", "manifest"),
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
                    analyzer="structure_validator",
                )
            )

        min_desc_length = self.policy.file_limits.min_description_length
        if len(manifest.description or "") < min_desc_length:
            findings.append(
                Finding(
                    id=self._generate_finding_id("SOCIAL_ENG_VAGUE_DESCRIPTION", "manifest"),
                    rule_id="SOCIAL_ENG_VAGUE_DESCRIPTION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.LOW,
                    title="Vague skill description",
                    description=f"Skill description is too short ({len(manifest.description or '')} chars). Provide detailed explanation.",
                    file_path="SKILL.md",
                    remediation="Provide a clear, detailed description of what the skill does and when to use it",
                    analyzer="structure_validator",
                )
            )

        description_lower = (manifest.description or "").lower()
        name_lower = (manifest.name or "").lower()
        is_anthropic_mentioned = "anthropic" in name_lower or "anthropic" in description_lower

        if is_anthropic_mentioned:
            legitimate_patterns = ["apply", "brand", "guidelines", "colors", "typography", "style"]
            is_legitimate = any(pattern in description_lower for pattern in legitimate_patterns)

            if not is_legitimate:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("SOCIAL_ENG_ANTHROPIC_IMPERSONATION", "manifest"),
                        rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=Severity.MEDIUM,
                        title="Potential Anthropic brand impersonation",
                        description="Skill name or description contains 'Anthropic', suggesting official affiliation",
                        file_path="SKILL.md",
                        remediation="Do not impersonate official skills or use unauthorized branding",
                        analyzer="structure_validator",
                    )
                )

        if "claude official" in (manifest.name or "").lower() or "claude official" in description_lower:
            findings.append(
                Finding(
                    id=self._generate_finding_id("SOCIAL_ENG_CLAUDE_OFFICIAL", "manifest"),
                    rule_id="SOCIAL_ENG_ANTHROPIC_IMPERSONATION",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.HIGH,
                    title="Claims to be official skill",
                    description="Skill claims to be an 'official' skill",
                    file_path="SKILL.md",
                    remediation="Remove 'official' claims unless properly authorized",
                    analyzer="structure_validator",
                )
            )

        if not manifest.license:
            findings.append(
                Finding(
                    id=self._generate_finding_id("MANIFEST_MISSING_LICENSE", "manifest"),
                    rule_id="MANIFEST_MISSING_LICENSE",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.INFO,
                    title="Skill does not specify a license",
                    description="Skill manifest does not include a 'license' field. Specifying a license helps users understand usage terms.",
                    file_path="SKILL.md",
                    remediation="Add 'license' field to SKILL.md frontmatter (e.g., MIT, Apache-2.0)",
                    analyzer="structure_validator",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Instruction body integrity check (new)
    # ------------------------------------------------------------------

    def _check_instruction_body(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        body = skill.instruction_body or ""
        body_len = len(body)

        if body_len < 50:
            findings.append(
                Finding(
                    id=self._generate_finding_id("INSTRUCTION_BODY_TOO_SHORT", "manifest"),
                    rule_id="INSTRUCTION_BODY_TOO_SHORT",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Instruction body is too short",
                    description=(
                        f"Skill instruction body is only {body_len} characters. "
                        f"A meaningful instruction body should be at least 50 characters "
                        f"to adequately describe what the skill should do."
                    ),
                    file_path="SKILL.md",
                    remediation="Expand the instruction body with clear, detailed instructions for the skill",
                    analyzer="structure_validator",
                )
            )

        if body_len > 100_000:
            findings.append(
                Finding(
                    id=self._generate_finding_id("INSTRUCTION_BODY_TOO_LONG", "manifest"),
                    rule_id="INSTRUCTION_BODY_TOO_LONG",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.MEDIUM,
                    title="Instruction body is excessively long",
                    description=(
                        f"Skill instruction body is {body_len} characters, exceeding the 100,000 character limit. "
                        f"Excessively long instruction bodies may be attempting to hide malicious instructions "
                        f"or overwhelm context-based security controls."
                    ),
                    file_path="SKILL.md",
                    remediation="Reduce instruction body size; move reference material to separate files",
                    analyzer="structure_validator",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Allowed-tools structural security (new checks)
    # ------------------------------------------------------------------

    def _check_allowed_tools_security(self, skill: Skill) -> list[Finding]:
        """Check allowed-tools for over-authorization and dangerous tool declarations."""
        findings: list[Finding] = []
        allowed_tools = skill.manifest.allowed_tools
        if not allowed_tools:
            return findings

        skillmd = str(skill.skill_md_path)
        allowed_lower = [t.strip().lower() for t in allowed_tools]

        # Over-authorization: wildcard or "all"/"any"
        for tool_val in allowed_lower:
            if tool_val in _OVER_AUTHORIZATION_VALUES:
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_OVER_AUTHORIZATION", skill.name),
                        rule_id="ALLOWED_TOOLS_OVER_AUTHORIZATION",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.HIGH,
                        title="Overly broad allowed-tools declaration",
                        description=(
                            f"Skill declares '{tool_val}' in allowed-tools, granting unrestricted access "
                            f"to all available tools. This violates the principle of least privilege."
                        ),
                        file_path=skillmd,
                        remediation="Replace wildcard/all/any with an explicit list of only the tools the skill needs",
                        analyzer="structure_validator",
                    )
                )
                break

        # Dangerous tools explicitly declared
        declared_dangerous = [t for t in allowed_lower if t in _DANGEROUS_TOOL_NAMES]
        if declared_dangerous:
            findings.append(
                Finding(
                    id=self._generate_finding_id("ALLOWED_TOOLS_DANGEROUS_DECLARATION", skill.name),
                    rule_id="ALLOWED_TOOLS_DANGEROUS_DECLARATION",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.HIGH,
                    title="Skill declares dangerous execution tools",
                    description=(
                        f"Skill explicitly declares dangerous tools in allowed-tools: {declared_dangerous}. "
                        f"Tools like Bash, exec, and shell grant arbitrary code execution capability."
                    ),
                    file_path=skillmd,
                    remediation=(
                        "Verify that code execution tools are strictly necessary. "
                        "If Bash is required, document the exact commands used and ensure input validation."
                    ),
                    analyzer="structure_validator",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Allowed-tools behavior violations (from static.py._check_allowed_tools_violations)
    # ------------------------------------------------------------------

    def _check_allowed_tools_violations(self, skill: Skill) -> list[Finding]:
        """Check if code behavior violates allowed-tools restrictions."""
        findings: list[Finding] = []

        if not skill.manifest.allowed_tools:
            return findings

        allowed_tools_lower = [tool.lower() for tool in skill.manifest.allowed_tools]
        skillmd = str(skill.skill_md_path)

        if "read" not in allowed_tools_lower:
            if self._code_reads_files(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_READ_VIOLATION", skill.name),
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
                        analyzer="structure_validator",
                    )
                )

        if "write" not in allowed_tools_lower:
            if self._code_writes_files(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_WRITE_VIOLATION", skill.name),
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
                        analyzer="structure_validator",
                    )
                )

        if "bash" not in allowed_tools_lower:
            if self._code_executes_bash(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_BASH_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_BASH_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.HIGH,
                        title="Code executes bash but Bash tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code executes bash commands",
                        file_path=skillmd,
                        remediation="Add 'Bash' to allowed-tools or remove bash execution from code",
                        analyzer="structure_validator",
                    )
                )

        if "grep" not in allowed_tools_lower:
            if self._code_uses_grep(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_GREP_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_GREP_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.LOW,
                        title="Code uses search/grep patterns but Grep tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses regex search patterns",
                        file_path=skillmd,
                        remediation="Add 'Grep' to allowed-tools or remove regex search operations",
                        analyzer="structure_validator",
                    )
                )

        if "glob" not in allowed_tools_lower:
            if self._code_uses_glob(skill):
                findings.append(
                    Finding(
                        id=self._generate_finding_id("ALLOWED_TOOLS_GLOB_VIOLATION", skill.name),
                        rule_id="ALLOWED_TOOLS_GLOB_VIOLATION",
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=Severity.LOW,
                        title="Code uses glob/file patterns but Glob tool not in allowed-tools",
                        description=f"Skill restricts tools to {skill.manifest.allowed_tools} but code uses glob patterns",
                        file_path=skillmd,
                        remediation="Add 'Glob' to allowed-tools or remove glob operations",
                        analyzer="structure_validator",
                    )
                )

        if self._code_uses_network(skill):
            findings.append(
                Finding(
                    id=self._generate_finding_id("ALLOWED_TOOLS_NETWORK_USAGE", skill.name),
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
                    analyzer="structure_validator",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Code behavior helpers (mirrored from static.py)
    # ------------------------------------------------------------------

    def _code_reads_files(self, skill: Skill) -> bool:
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _READ_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_writes_files(self, skill: Skill) -> bool:
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _WRITE_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_executes_bash(self, skill: Skill) -> bool:
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
        has_bash_scripts = any(f.file_type == "bash" for f in skill.files)
        if has_bash_scripts:
            return True
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            if any(indicator in content for indicator in bash_indicators):
                return True
        return False

    def _code_uses_grep(self, skill: Skill) -> bool:
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _GREP_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_uses_glob(self, skill: Skill) -> bool:
        for skill_file in skill.get_scripts():
            content = skill_file.read_content()
            for pattern in _GLOB_PATTERNS:
                if pattern.search(content):
                    return True
        return False

    def _code_uses_network(self, skill: Skill) -> bool:
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

    @staticmethod
    def _generate_finding_id(rule_id: str, context: str) -> str:
        combined = f"{rule_id}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{rule_id}_{hash_obj.hexdigest()[:10]}"
