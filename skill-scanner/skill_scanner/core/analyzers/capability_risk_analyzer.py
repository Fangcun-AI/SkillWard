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
Engine 3: Capability Risk Analyzer.

Maps allowed-tools to capability domains and detects dangerous attack chains
formed by combining multiple high-risk domains.
"""

from __future__ import annotations

import hashlib
import logging

from ..models import Finding, Severity, Skill, ThreatCategory
from ..scan_policy import ScanPolicy
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domain definitions
# ---------------------------------------------------------------------------

CAPABILITY_DOMAINS: dict[str, set[str]] = {
    "filesystem": {"read", "write", "glob", "edit"},
    "network": {"webfetch", "websearch"},
    "code_execution": {"bash", "exec", "shell", "terminal"},
    "search": {"grep", "glob"},
    "authentication": {"token", "oauth", "credential", "auth"},
    "database": {"sql", "query", "db", "mysql", "postgres", "sqlite"},
    "system": {"computer", "screenshot", "clipboard"},
}

DOMAIN_RISK_SCORES: dict[str, int] = {
    "code_execution": 9,
    "system": 8,
    "authentication": 7,
    "database": 6,
    "network": 5,
    "filesystem": 4,
    "search": 2,
}

# Each entry: (chain_name, required_domains, severity_str)
ATTACK_CHAINS: list[tuple[str, frozenset[str], str]] = [
    ("DATA_EXFILTRATION_CHAIN", frozenset({"filesystem", "network"}), "HIGH"),
    ("REMOTE_CODE_EXECUTION_CHAIN", frozenset({"code_execution", "network"}), "CRITICAL"),
    ("PRIVILEGE_ESCALATION_CHAIN", frozenset({"authentication", "code_execution"}), "CRITICAL"),
    ("PRIVILEGE_ESCALATION_CHAIN", frozenset({"authentication", "system"}), "CRITICAL"),
    ("PERSISTENCE_CHAIN", frozenset({"filesystem", "code_execution"}), "HIGH"),
    ("SQL_TO_CODE_CHAIN", frozenset({"database", "code_execution"}), "HIGH"),
    ("FULL_COMPROMISE_CHAIN", frozenset({"filesystem", "network", "code_execution"}), "CRITICAL"),
]

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_CHAIN_DESCRIPTIONS: dict[str, str] = {
    "DATA_EXFILTRATION_CHAIN": (
        "Skill has both filesystem (Read/Write/Glob/Edit) and network (WebFetch/WebSearch) capabilities. "
        "This combination enables reading sensitive files and transmitting them to external servers."
    ),
    "REMOTE_CODE_EXECUTION_CHAIN": (
        "Skill has both code execution (Bash/exec/shell) and network capabilities. "
        "This combination enables downloading and executing arbitrary code from remote sources."
    ),
    "PRIVILEGE_ESCALATION_CHAIN": (
        "Skill has authentication/credential capabilities combined with code execution or system control. "
        "This combination enables credential theft paired with arbitrary command execution."
    ),
    "PERSISTENCE_CHAIN": (
        "Skill has both filesystem (Read/Write) and code execution (Bash) capabilities. "
        "This combination enables writing malicious scripts and executing them for persistence."
    ),
    "SQL_TO_CODE_CHAIN": (
        "Skill has both database and code execution capabilities. "
        "This combination can enable SQL injection leading to OS command execution."
    ),
    "FULL_COMPROMISE_CHAIN": (
        "Skill has filesystem, network, AND code execution capabilities simultaneously. "
        "This combination represents full system compromise potential: read, exfiltrate, and execute."
    ),
}

_CHAIN_REMEDIATIONS: dict[str, str] = {
    "DATA_EXFILTRATION_CHAIN": (
        "Review whether the skill genuinely requires both file access and network connectivity. "
        "If network access is only for fetching external data (not sending), document this clearly. "
        "Consider splitting into separate skills if filesystem and network uses are independent."
    ),
    "REMOTE_CODE_EXECUTION_CHAIN": (
        "Audit all network-fetched content before any code execution. "
        "Ensure the skill never executes data received from external URLs. "
        "Consider removing Bash/exec if only WebFetch for read-only data retrieval is needed."
    ),
    "PRIVILEGE_ESCALATION_CHAIN": (
        "Verify that authentication tools are scoped to read-only credential lookups. "
        "Ensure code execution paths cannot be influenced by credential values. "
        "Separate credential handling from execution logic."
    ),
    "PERSISTENCE_CHAIN": (
        "Restrict write permissions to known safe directories. "
        "Ensure scripts written to disk are not later executed by the skill. "
        "Consider whether both Write and Bash are truly necessary for the skill's purpose."
    ),
    "SQL_TO_CODE_CHAIN": (
        "Ensure all database queries use parameterized statements. "
        "Isolate database operations from command execution paths. "
        "Verify no SQL query results are passed to shell commands."
    ),
    "FULL_COMPROMISE_CHAIN": (
        "This skill has the highest risk profile. Perform a thorough security review. "
        "Restrict each capability to the minimum needed. "
        "Consider architectural changes to separate concerns across multiple skills."
    ),
}


def _get_active_domains(allowed_tools: list[str]) -> set[str]:
    """Map allowed_tools entries to active capability domains."""
    active: set[str] = set()
    for tool in allowed_tools:
        tool_lower = tool.strip().lower().rstrip("*").strip()
        for domain, keywords in CAPABILITY_DOMAINS.items():
            for kw in keywords:
                if kw in tool_lower or tool_lower in kw:
                    active.add(domain)
    return active


class CapabilityRiskAnalyzer(BaseAnalyzer):
    """Analyzes allowed-tools capability domains and detects dangerous attack chains."""

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__("capability_risk", policy=policy)

    def analyze(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []

        allowed_tools = skill.manifest.allowed_tools
        if not allowed_tools:
            return findings

        active_domains = _get_active_domains(allowed_tools)
        if not active_domains:
            return findings

        # Compute total risk score for context
        total_risk = sum(DOMAIN_RISK_SCORES.get(d, 0) for d in active_domains)

        # Check each attack chain
        reported_chains: set[str] = set()
        for chain_name, required_domains, severity_str in ATTACK_CHAINS:
            if chain_name in reported_chains:
                continue
            if required_domains.issubset(active_domains):
                reported_chains.add(chain_name)
                severity = _SEVERITY_MAP.get(severity_str, Severity.HIGH)
                description = _CHAIN_DESCRIPTIONS.get(chain_name, f"Attack chain detected: {chain_name}")
                remediation = _CHAIN_REMEDIATIONS.get(chain_name, "Review capability combination.")

                domain_list = ", ".join(sorted(required_domains))
                tool_list = ", ".join(allowed_tools)

                findings.append(
                    Finding(
                        id=self._generate_finding_id(chain_name, skill.name),
                        rule_id=chain_name,
                        category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                        severity=severity,
                        title=f"Attack chain detected: {chain_name.replace('_', ' ').title()}",
                        description=(
                            f"{description}\n"
                            f"Active domains: {domain_list}\n"
                            f"Declared tools: {tool_list}"
                        ),
                        file_path="SKILL.md",
                        remediation=remediation,
                        analyzer="capability_risk",
                        metadata={
                            "chain_name": chain_name,
                            "active_domains": sorted(active_domains),
                            "required_domains": sorted(required_domains),
                            "total_risk_score": total_risk,
                        },
                    )
                )

        return findings

    @staticmethod
    def _generate_finding_id(rule_id: str, context: str) -> str:
        combined = f"{rule_id}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{rule_id}_{hash_obj.hexdigest()[:10]}"
