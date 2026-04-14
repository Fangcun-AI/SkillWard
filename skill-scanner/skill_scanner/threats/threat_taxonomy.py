"""
AI security threat taxonomy definitions and validation utilities.

Provides the canonical set of AITech and AISubtech classification codes
used to categorize threats discovered during skill scanning. Supports
loading custom taxonomy profiles from external JSON or YAML files at
runtime via environment variable or programmatic configuration.
"""

import json
import os
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Technique-level codes and their human-readable labels
# ---------------------------------------------------------------------------
AITECH_TAXONOMY: dict[str, str] = {}
_INITIAL_AITECH_ENTRIES: list[tuple[str, str]] = [
    # -- Goal Hijacking (OB-001) --
    ("AITech-1.1", "Direct Prompt Injection"),
    ("AITech-1.2", "Indirect Prompt Injection"),
    ("AITech-1.3", "Goal Manipulation"),
    ("AITech-1.4", "Multi-Modal Injection and Manipulation"),
    # -- Jailbreak (OB-002) --
    ("AITech-2.1", "Jailbreak"),
    # -- Masquerading / Obfuscation / Impersonation (OB-003) --
    ("AITech-3.1", "Masquerading / Obfuscation / Impersonation"),
    # -- Communication Compromise (OB-004) --
    ("AITech-4.1", "Agent Injection"),
    ("AITech-4.2", "Context Boundary Attacks"),
    ("AITech-4.3", "Protocol Manipulation"),
    # -- Persistence (OB-005) --
    ("AITech-5.1", "Memory System Persistence"),
    ("AITech-5.2", "Configuration Persistence"),
    # -- Feedback Loop Manipulation (OB-006) --
    ("AITech-6.1", "Training Data Poisoning"),
    # -- Sabotage / Integrity Degradation (OB-007) --
    ("AITech-7.1", "Reasoning Corruption"),
    ("AITech-7.2", "Memory System Corruption"),
    ("AITech-7.3", "Data Source Abuse and Manipulation"),
    ("AITech-7.4", "Token Manipulation"),
    # -- Data Privacy Violations (OB-008) --
    ("AITech-8.1", "Membership Inference"),
    ("AITech-8.2", "Data Exfiltration / Exposure"),
    ("AITech-8.3", "Information Disclosure"),
    ("AITech-8.4", "Prompt/Meta Extraction"),
    # -- Supply Chain Compromise (OB-009) --
    ("AITech-9.1", "Model or Agentic System Manipulation"),
    ("AITech-9.2", "Detection Evasion"),
    ("AITech-9.3", "Dependency / Plugin Compromise"),
    # -- Model Theft / Extraction (OB-010) --
    ("AITech-10.1", "Model Extraction"),
    ("AITech-10.2", "Model Inversion"),
    # -- Adversarial Evasion (OB-011) --
    ("AITech-11.1", "Environment-Aware Evasion"),
    ("AITech-11.2", "Model-Selective Evasion"),
    # -- Action-Space and Integration Abuse (OB-012) --
    ("AITech-12.1", "Tool Exploitation"),
    ("AITech-12.2", "Insecure Output Handling"),
    # -- Availability Abuse (OB-013) --
    ("AITech-13.1", "Disruption of Availability"),
    ("AITech-13.2", "Cost Harvesting / Repurposing"),
    # -- Privilege Compromise (OB-014) --
    ("AITech-14.1", "Unauthorized Access"),
    ("AITech-14.2", "Abuse of Delegated Authority"),
    # -- Harmful / Misleading / Inaccurate Content (OB-015) --
    ("AITech-15.1", "Harmful Content"),
    # -- Surveillance (OB-016) --
    ("AITech-16.1", "Eavesdropping"),
    # -- Cyber-Physical / Sensor Attacks (OB-017) --
    ("AITech-17.1", "Sensor Spoofing"),
    # -- System Misuse / Malicious Application (OB-018) --
    ("AITech-18.1", "Fraudulent Use"),
    ("AITech-18.2", "Malicious Workflows"),
    # -- Multi-Modal / Cross-Modal Risks (OB-019) --
    ("AITech-19.1", "Cross-Modal Inconsistency Exploits"),
    ("AITech-19.2", "Fusion Payload Split"),
]
for _code, _label in _INITIAL_AITECH_ENTRIES:
    AITECH_TAXONOMY[_code] = _label

# ---------------------------------------------------------------------------
# Sub-technique codes and their human-readable labels
# ---------------------------------------------------------------------------
AISUBTECH_TAXONOMY: dict[str, str] = {}
_INITIAL_AISUBTECH_ENTRIES: list[tuple[str, str]] = [
    # Direct Prompt Injection (AITech-1.1)
    ("AISubtech-1.1.1", "Instruction Manipulation (Direct Prompt Injection)"),
    ("AISubtech-1.1.2", "Obfuscation (Direct Prompt Injection)"),
    ("AISubtech-1.1.3", "Multi-Agent Prompt Injection"),
    # Indirect Prompt Injection (AITech-1.2)
    ("AISubtech-1.2.1", "Instruction Manipulation (Indirect Prompt Injection)"),
    ("AISubtech-1.2.2", "Obfuscation (Indirect Prompt Injection)"),
    ("AISubtech-1.2.3", "Multi-Agent (Indirect Prompt Injection)"),
    # Goal Manipulation (AITech-1.3)
    ("AISubtech-1.3.1", "Goal Manipulation (Models, Agents)"),
    ("AISubtech-1.3.2", "Goal Manipulation (Tools, Prompts, Resources)"),
    # Multi-Modal Injection (AITech-1.4)
    ("AISubtech-1.4.1", "Image-Text Injection"),
    ("AISubtech-1.4.2", "Image Manipulation"),
    ("AISubtech-1.4.3", "Audio Command Injection"),
    ("AISubtech-1.4.4", "Video Overlay Manipulation"),
    # Jailbreak (AITech-2.1)
    ("AISubtech-2.1.1", "Context Manipulation (Jailbreak)"),
    ("AISubtech-2.1.2", "Obfuscation (Jailbreak)"),
    ("AISubtech-2.1.3", "Semantic Manipulation (Jailbreak)"),
    ("AISubtech-2.1.4", "Token Exploitation (Jailbreak)"),
    ("AISubtech-2.1.5", "Multi-Agent Jailbreak Collaboration"),
    # Masquerading (AITech-3.1)
    ("AISubtech-3.1.1", "Identity Obfuscation"),
    ("AISubtech-3.1.2", "Trusted Agent Spoofing"),
    # Agent Injection (AITech-4.1)
    ("AISubtech-4.1.1", "Rogue Agent Introduction"),
    # Context Boundary Attacks (AITech-4.2)
    ("AISubtech-4.2.1", "Context Window Exploitation"),
    ("AISubtech-4.2.2", "Session Boundary Violation"),
    # Protocol Manipulation (AITech-4.3)
    ("AISubtech-4.3.1", "Schema Inconsistencies"),
    ("AISubtech-4.3.2", "Namespace Collision"),
    ("AISubtech-4.3.3", "Server Rebinding Attack"),
    ("AISubtech-4.3.4", "Replay Exploitation"),
    ("AISubtech-4.3.5", "Capability Inflation"),
    ("AISubtech-4.3.6", "Cross-Origin Exploitation"),
    # Memory System Persistence (AITech-5.1)
    ("AISubtech-5.1.1", "Long-term / Short-term Memory Injection"),
    # Configuration Persistence (AITech-5.2)
    ("AISubtech-5.2.1", "Agent Profile Tampering"),
    # Training Data Poisoning (AITech-6.1)
    ("AISubtech-6.1.1", "Knowledge Base Poisoning"),
    ("AISubtech-6.1.2", "Reinforcement Biasing"),
    ("AISubtech-6.1.3", "Reinforcement Signal Corruption"),
    # Memory System Corruption (AITech-7.2)
    ("AISubtech-7.2.1", "Memory Anchor Attacks"),
    ("AISubtech-7.2.2", "Memory Index Manipulation"),
    # Data Source Abuse (AITech-7.3)
    ("AISubtech-7.3.1", "Corrupted Third-Party Data"),
    # Token Manipulation (AITech-7.4)
    ("AISubtech-7.4.1", "Token Theft"),
    # Membership Inference (AITech-8.1)
    ("AISubtech-8.1.1", "Presence Detection"),
    # Data Exfiltration / Exposure (AITech-8.2)
    ("AISubtech-8.2.1", "Training Data Exposure"),
    ("AISubtech-8.2.2", "LLM Data Leakage"),
    ("AISubtech-8.2.3", "Data Exfiltration via Agent Tooling"),
    # Information Disclosure (AITech-8.3)
    ("AISubtech-8.3.1", "Tool Metadata Exposure"),
    ("AISubtech-8.3.2", "System Information Leakage"),
    # Prompt/Meta Extraction (AITech-8.4)
    ("AISubtech-8.4.1", "System LLM Prompt Leakage"),
    # Model or Agentic System Manipulation (AITech-9.1)
    ("AISubtech-9.1.1", "Code Execution"),
    ("AISubtech-9.1.2", "Unauthorized or Unsolicited System Access"),
    ("AISubtech-9.1.3", "Unauthorized or Unsolicited Network Access"),
    ("AISubtech-9.1.4", "Injection Attacks (SQL, Command Execution, XSS)"),
    ("AISubtech-9.1.5", "Template Injection (SSTI)"),
    # Detection Evasion (AITech-9.2)
    ("AISubtech-9.2.1", "Obfuscation Vulnerabilities"),
    ("AISubtech-9.2.2", "Backdoors and Trojans"),
    # Dependency / Plugin Compromise (AITech-9.3)
    ("AISubtech-9.3.1", "Malicious Package / Tool Injection"),
    ("AISubtech-9.3.2", "Dependency Name Squatting (Tools / Servers)"),
    ("AISubtech-9.3.3", "Dependency Replacement / Rug Pull"),
    # Model Extraction (AITech-10.1)
    ("AISubtech-10.1.1", "API Query Stealing"),
    ("AISubtech-10.1.2", "Weight Reconstruction"),
    ("AISubtech-10.1.3", "Sensitive Data Reconstruction"),
    # Model Inversion (AITech-10.2)
    ("AISubtech-10.2.1", "Model Inversion"),
    # Environment-Aware Evasion (AITech-11.1)
    ("AISubtech-11.1.1", "Agent-Specific Evasion"),
    ("AISubtech-11.1.2", "Tool-Scoped Evasion"),
    ("AISubtech-11.1.3", "Environment-Scoped Payloads"),
    ("AISubtech-11.1.4", "Defense-Aware Payloads"),
    # Model-Selective Evasion (AITech-11.2)
    ("AISubtech-11.2.1", "Targeted Model Fingerprinting"),
    ("AISubtech-11.2.2", "Conditional Attack Execution"),
    # Tool Exploitation (AITech-12.1)
    ("AISubtech-12.1.1", "Parameter Manipulation"),
    ("AISubtech-12.1.2", "Tool Poisoning"),
    ("AISubtech-12.1.3", "Unsafe System / Browser / File Execution"),
    ("AISubtech-12.1.4", "Tool Shadowing"),
    # Insecure Output Handling (AITech-12.2)
    ("AISubtech-12.2.1", "Code Detection / Malicious Code Output"),
    # Disruption of Availability (AITech-13.1)
    ("AISubtech-13.1.1", "Compute Exhaustion"),
    ("AISubtech-13.1.2", "Memory Flooding"),
    ("AISubtech-13.1.3", "Model Denial of Service"),
    ("AISubtech-13.1.4", "Application Denial of Service"),
    ("AISubtech-13.1.5", "Decision Paralysis Attacks"),
    # Cost Harvesting (AITech-13.2)
    ("AISubtech-13.2.1", "Service Misuse for Cost Inflation"),
    # Unauthorized Access (AITech-14.1)
    ("AISubtech-14.1.1", "Credential Theft"),
    ("AISubtech-14.1.2", "Insufficient Access Controls"),
    # Abuse of Delegated Authority (AITech-14.2)
    ("AISubtech-14.2.1", "Permission Escalation via Delegation"),
    # Harmful Content (AITech-15.1)
    ("AISubtech-15.1.1", "Cybersecurity and Hacking: Malware / Exploits"),
    ("AISubtech-15.1.2", "Cybersecurity and Hacking: Cyber Abuse"),
    ("AISubtech-15.1.3", "Safety Harms and Toxicity: Animal Abuse"),
    ("AISubtech-15.1.4", "Safety Harms and Toxicity: Child Abuse / Exploitation"),
    ("AISubtech-15.1.5", "Safety Harms and Toxicity: Disinformation"),
    ("AISubtech-15.1.6", "Safety Harms and Toxicity: Environmental Harm"),
    ("AISubtech-15.1.7", "Safety Harms and Toxicity: Financial Harm"),
    ("AISubtech-15.1.8", "Safety Harms and Toxicity: Harassment"),
    ("AISubtech-15.1.9", "Safety Harms and Toxicity: Hate Speech"),
    ("AISubtech-15.1.10", "Safety Harms and Toxicity: Non-Violent Crime"),
    ("AISubtech-15.1.11", "Safety Harms and Toxicity: Profanity"),
    ("AISubtech-15.1.12", "Safety Harms and Toxicity: Scams and Deception"),
    ("AISubtech-15.1.13", "Safety Harms and Toxicity: Self Harm"),
    ("AISubtech-15.1.14", "Safety Harms and Toxicity: Sexual Content and Exploitation"),
    ("AISubtech-15.1.15", "Safety Harms and Toxicity: Social Division and Polarization"),
    ("AISubtech-15.1.16", "Safety Harms and Toxicity: Terrorism / Extremism"),
    ("AISubtech-15.1.17", "Safety Harms and Toxicity: Violence and Public Safety Threat"),
    ("AISubtech-15.1.18", "Safety Harms and Toxicity: Weapons / CBRN Risks"),
    ("AISubtech-15.1.19", "Integrity: Hallucinations / Misinformation"),
    ("AISubtech-15.1.20", "Integrity: Unauthorized Financial Advice"),
    ("AISubtech-15.1.21", "Integrity: Unauthorized Legal Advice"),
    ("AISubtech-15.1.22", "Integrity: Unauthorized Medical Advice"),
    ("AISubtech-15.1.23", "Intellectual Property Compromise: Intellectual Property Infringement"),
    ("AISubtech-15.1.24", "Intellectual Property Compromise: Confidential Data"),
    ("AISubtech-15.1.25", "Privacy Attacks: PII / PHI / PCI"),
    # Eavesdropping (AITech-16.1)
    ("AISubtech-16.1.1", "Logging Sensitive Conversations"),
    # Sensor Spoofing (AITech-17.1)
    ("AISubtech-17.1.1", "Sensor Spoofing: Action Signals (audio, visual)"),
    # Fraudulent Use (AITech-18.1)
    ("AISubtech-18.1.1", "Spam / Scam / Social Engineering Generation"),
    # Malicious Workflows (AITech-18.2)
    ("AISubtech-18.2.1", "Abuse of APIs for Mass Automation"),
    ("AISubtech-18.2.2", "Dedicated Malicious Server or Infrastructure"),
    # Cross-Modal Inconsistency (AITech-19.1)
    ("AISubtech-19.1.1", "Contradictory Inputs Attack"),
    ("AISubtech-19.1.2", "Modality Skewing"),
    # Fusion Payload Split (AITech-19.2)
    ("AISubtech-19.2.1", "Convergence Payload Injection"),
    ("AISubtech-19.2.2", "Chained Payload Execution"),
]
for _code, _label in _INITIAL_AISUBTECH_ENTRIES:
    AISUBTECH_TAXONOMY[_code] = _label

# ---------------------------------------------------------------------------
# Immutable snapshots of the default data, used to restore after overrides.
# ---------------------------------------------------------------------------
_DEFAULT_AITECH: dict[str, str] = {k: v for k, v in AITECH_TAXONOMY.items()}
_DEFAULT_AISUBTECH: dict[str, str] = {k: v for k, v in AISUBTECH_TAXONOMY.items()}

# Cross-framework mapping tables (initially empty lists per code).
AITECH_FRAMEWORK_MAPPINGS: dict[str, list[str]] = {c: [] for c in AITECH_TAXONOMY}
AISUBTECH_FRAMEWORK_MAPPINGS: dict[str, list[str]] = {c: [] for c in AISUBTECH_TAXONOMY}

_DEFAULT_AITECH_FW: dict[str, list[str]] = {
    c: list(m) for c, m in AITECH_FRAMEWORK_MAPPINGS.items()
}
_DEFAULT_AISUBTECH_FW: dict[str, list[str]] = {
    c: list(m) for c, m in AISUBTECH_FRAMEWORK_MAPPINGS.items()
}

# Fast-lookup sets for membership checks.
VALID_AITECH_CODES: set[str] = set(AITECH_TAXONOMY)
VALID_AISUBTECH_CODES: set[str] = set(AISUBTECH_TAXONOMY)

# Environment variable that may point to a custom taxonomy file.
TAXONOMY_ENV_VAR = "SKILL_SCANNER_TAXONOMY_PATH"

# Tracks whether the active taxonomy is the built-in default or an override.
_taxonomy_origin = "builtin"


# ---------------------------------------------------------------------------
# Internal file-loading helpers
# ---------------------------------------------------------------------------

def _load_taxonomy_from_disk(filepath: Path) -> dict[str, Any]:
    """Open a JSON or YAML taxonomy file and return the parsed mapping."""
    if not filepath.exists():
        raise FileNotFoundError(f"Taxonomy file not found: {filepath}")

    ext = filepath.suffix.lower()
    raw_text = filepath.read_text(encoding="utf-8")

    if ext in (".yaml", ".yml"):
        import yaml
        result = yaml.safe_load(raw_text)
    else:
        result = json.loads(raw_text)

    if not isinstance(result, dict):
        raise ValueError("Taxonomy file must parse to a JSON/YAML object")
    return result


def _to_string_list(raw: Any) -> list[str]:
    """Convert a raw value into a deduplicated list of non-empty strings."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("Framework mappings must be a list of strings")
    seen: list[str] = []
    for item in raw:
        cleaned = str(item).strip()
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
    return seen


def _parse_mapping_dict(raw: Any, field_label: str) -> dict[str, list[str]]:
    """Turn a code-to-list-of-strings mapping into canonical form."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field_label} must be an object mapping codes to lists")
    return {str(k): _to_string_list(v) for k, v in raw.items()}


def _extract_hierarchical_taxonomy(
    payload: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]], dict[str, list[str]]]:
    """Walk an OB-* keyed taxonomy tree and flatten it into code maps.

    Expected shape per OB entry:
        { "ai_tech": [ { "code": ..., "description": ..., "ai_subtech": [...] } ] }
    """
    tech_map: dict[str, str] = {}
    subtech_map: dict[str, str] = {}
    tech_fw: dict[str, list[str]] = {}
    subtech_fw: dict[str, list[str]] = {}

    for key, body in payload.items():
        if not str(key).startswith("OB-") or not isinstance(body, dict):
            continue

        techniques = body.get("ai_tech", [])
        if not isinstance(techniques, list):
            continue

        for tech_entry in techniques:
            if not isinstance(tech_entry, dict):
                continue

            tc = tech_entry.get("code")
            td = tech_entry.get("description")
            tm = _to_string_list(tech_entry.get("mappings"))

            if isinstance(tc, str) and isinstance(td, str):
                if tc in tech_map and tech_map[tc] != td:
                    raise ValueError(
                        f"Conflicting AITech description for {tc}: "
                        f"{tech_map[tc]!r} vs {td!r}"
                    )
                tech_map[tc] = td
                accumulated = list(tech_fw.get(tc, []))
                for e in tm:
                    if e not in accumulated:
                        accumulated.append(e)
                tech_fw[tc] = accumulated

            for sub_entry in (tech_entry.get("ai_subtech") or []):
                if not isinstance(sub_entry, dict):
                    continue
                sc = sub_entry.get("code")
                sd = sub_entry.get("description")
                sm = _to_string_list(sub_entry.get("mappings"))
                if isinstance(sc, str) and isinstance(sd, str):
                    if sc in subtech_map and subtech_map[sc] != sd:
                        raise ValueError(
                            f"Conflicting AISubtech description for {sc}: "
                            f"{subtech_map[sc]!r} vs {sd!r}"
                        )
                    subtech_map[sc] = sd
                    accumulated = list(subtech_fw.get(sc, []))
                    for e in sm:
                        if e not in accumulated:
                            accumulated.append(e)
                    subtech_fw[sc] = accumulated

    if not tech_map:
        raise ValueError("No AITech codes found in OB-* framework taxonomy")
    if not subtech_map:
        raise ValueError("No AISubtech codes found in OB-* framework taxonomy")

    # Ensure every code has a framework-mapping entry (even if empty).
    for c in tech_map:
        tech_fw.setdefault(c, [])
    for c in subtech_map:
        subtech_fw.setdefault(c, [])

    return tech_map, subtech_map, tech_fw, subtech_fw


def _interpret_taxonomy_payload(
    data: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]], dict[str, list[str]]]:
    """Detect the format of a taxonomy payload and return canonical maps.

    Three formats are recognised:
      1. Upper-case keys  AITECH_TAXONOMY / AISUBTECH_TAXONOMY
      2. Lower-case keys  aitech_taxonomy / aisubtech_taxonomy
      3. Hierarchical OB-* structure
    """
    # Format 1 -- upper-case flat dicts
    if isinstance(data.get("AITECH_TAXONOMY"), dict) and isinstance(data.get("AISUBTECH_TAXONOMY"), dict):
        at = {str(k): str(v) for k, v in data["AITECH_TAXONOMY"].items()}
        ast = {str(k): str(v) for k, v in data["AISUBTECH_TAXONOMY"].items()}
        at_fw = _parse_mapping_dict(
            data.get("AITECH_FRAMEWORK_MAPPINGS") or data.get("AITECH_MAPPINGS"),
            "AITECH_FRAMEWORK_MAPPINGS",
        )
        ast_fw = _parse_mapping_dict(
            data.get("AISUBTECH_FRAMEWORK_MAPPINGS") or data.get("AISUBTECH_MAPPINGS"),
            "AISUBTECH_FRAMEWORK_MAPPINGS",
        )
        for c in at:
            at_fw.setdefault(c, [])
        for c in ast:
            ast_fw.setdefault(c, [])
        return at, ast, at_fw, ast_fw

    # Format 2 -- lower-case flat dicts
    if isinstance(data.get("aitech_taxonomy"), dict) and isinstance(data.get("aisubtech_taxonomy"), dict):
        at = {str(k): str(v) for k, v in data["aitech_taxonomy"].items()}
        ast = {str(k): str(v) for k, v in data["aisubtech_taxonomy"].items()}
        at_fw = _parse_mapping_dict(
            data.get("aitech_framework_mappings") or data.get("aitech_mappings"),
            "aitech_framework_mappings",
        )
        ast_fw = _parse_mapping_dict(
            data.get("aisubtech_framework_mappings") or data.get("aisubtech_mappings"),
            "aisubtech_framework_mappings",
        )
        for c in at:
            at_fw.setdefault(c, [])
        for c in ast:
            ast_fw.setdefault(c, [])
        return at, ast, at_fw, ast_fw

    # Format 3 -- hierarchical OB-* entries
    if any(str(k).startswith("OB-") for k in data):
        return _extract_hierarchical_taxonomy(data)

    raise ValueError(
        "Unsupported taxonomy format. Expected either "
        "{AITECH_TAXONOMY, AISUBTECH_TAXONOMY} maps or OB-* framework taxonomy."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def reload_taxonomy(path: str | Path | None = None) -> str:
    """Reset the active taxonomy to built-in defaults or load from a file.

    When *path* is given it takes precedence.  Otherwise the environment
    variable ``SKILL_SCANNER_TAXONOMY_PATH`` is consulted.  If neither is
    set the built-in defaults are restored.

    Returns the string ``"builtin"`` or the resolved file path.
    """
    global AITECH_TAXONOMY
    global AISUBTECH_TAXONOMY
    global AITECH_FRAMEWORK_MAPPINGS
    global AISUBTECH_FRAMEWORK_MAPPINGS
    global VALID_AITECH_CODES
    global VALID_AISUBTECH_CODES
    global _taxonomy_origin

    target = str(path) if path is not None else os.getenv(TAXONOMY_ENV_VAR)

    if not target:
        # Restore defaults
        AITECH_TAXONOMY = {k: v for k, v in _DEFAULT_AITECH.items()}
        AISUBTECH_TAXONOMY = {k: v for k, v in _DEFAULT_AISUBTECH.items()}
        AITECH_FRAMEWORK_MAPPINGS = {c: list(m) for c, m in _DEFAULT_AITECH_FW.items()}
        AISUBTECH_FRAMEWORK_MAPPINGS = {c: list(m) for c, m in _DEFAULT_AISUBTECH_FW.items()}
        VALID_AITECH_CODES = set(AITECH_TAXONOMY)
        VALID_AISUBTECH_CODES = set(AISUBTECH_TAXONOMY)
        _taxonomy_origin = "builtin"
        return _taxonomy_origin

    resolved = Path(target).expanduser().resolve()
    raw = _load_taxonomy_from_disk(resolved)
    at, ast, at_fw, ast_fw = _interpret_taxonomy_payload(raw)

    AITECH_TAXONOMY = at
    AISUBTECH_TAXONOMY = ast
    AITECH_FRAMEWORK_MAPPINGS = at_fw
    AISUBTECH_FRAMEWORK_MAPPINGS = ast_fw
    VALID_AITECH_CODES = set(AITECH_TAXONOMY)
    VALID_AISUBTECH_CODES = set(AISUBTECH_TAXONOMY)
    _taxonomy_origin = str(resolved)
    return _taxonomy_origin


def get_taxonomy_source() -> str:
    """Return a label describing where the active taxonomy was loaded from."""
    return _taxonomy_origin


# Run once at import time to pick up any env-var override.
reload_taxonomy()


# ---------------------------------------------------------------------------
# Convenience query helpers
# ---------------------------------------------------------------------------

def is_valid_aitech(code: str) -> bool:
    """Return True when *code* is a recognised AITech identifier."""
    return code in VALID_AITECH_CODES


def is_valid_aisubtech(code: str) -> bool:
    """Return True when *code* is a recognised AISubtech identifier."""
    return code in VALID_AISUBTECH_CODES


def get_aitech_name(code: str) -> str | None:
    """Look up the display name for an AITech code, or None if unknown."""
    return AITECH_TAXONOMY.get(code)


def get_aisubtech_name(code: str) -> str | None:
    """Look up the display name for an AISubtech code, or None if unknown."""
    return AISUBTECH_TAXONOMY.get(code)


def get_aitech_framework_mappings(code: str) -> list[str]:
    """Return a copy of the cross-framework references for an AITech code."""
    return list(AITECH_FRAMEWORK_MAPPINGS.get(code, []))


def get_aisubtech_framework_mappings(code: str) -> list[str]:
    """Return a copy of the cross-framework references for an AISubtech code."""
    return list(AISUBTECH_FRAMEWORK_MAPPINGS.get(code, []))


def get_framework_mappings(
    aitech_code: str | None = None,
    aisubtech_code: str | None = None,
) -> list[str]:
    """Collect unique framework mappings for the given technique/sub-technique pair."""
    result: list[str] = []
    if aitech_code:
        for entry in AITECH_FRAMEWORK_MAPPINGS.get(aitech_code, []):
            if entry not in result:
                result.append(entry)
    if aisubtech_code:
        for entry in AISUBTECH_FRAMEWORK_MAPPINGS.get(aisubtech_code, []):
            if entry not in result:
                result.append(entry)
    return result
