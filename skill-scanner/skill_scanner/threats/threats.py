"""
Scanner threat classification and severity assignment.

Maps threat names produced by different analyzers (LLM, YARA/static,
behavioural) to standardised AITech taxonomy codes, severity levels,
and human-readable descriptions.  Supports runtime overrides loaded
from an external JSON file.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core mapping class -- public name is ThreatMapping
# ---------------------------------------------------------------------------

class ThreatMapping:
    """Registry that associates scanner threat names with AITech codes and severity."""

    # -- LLM-based analyser findings --
    LLM_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override, replace, or modify the model's system instructions, "
            "operational directives, or behavioral guidelines through direct user input.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unintentional and/or unauthorized exposure or exfiltration of sensitive information, "
            "through exploitation of agent tools, integrations, or capabilities.",
        },
        "TOOL POISONING": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.2",
            "aisubtech_name": "Tool Poisoning",
            "description": "Corrupting, modifying, or degrading the functionality, outputs, or behavior of tools used by agents through data poisoning, configuration tampering, or behavioral manipulation.",
        },
        "TOOL SHADOWING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.4",
            "aisubtech_name": "Tool Shadowing",
            "description": "Disguising, substituting or duplicating legitimate tools within an agent, enabling malicious tools with identical or similar identifiers to intercept or replace trusted tool calls.",
        },
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as command sequences into skills that process model or user input, leading to remote code execution or compromise.",
        },
    }

    # -- YARA / static-analysis findings --
    YARA_THREATS = {
        "COMMAND INJECTION": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "CRITICAL",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious command sequences leading to remote code execution.",
        },
        "DATA EXFILTRATION": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unauthorized exposure or exfiltration of sensitive information.",
        },
        "SKILL DISCOVERY ABUSE": {
            "scanner_category": "PROTOCOL MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-4.3",
            "aitech_name": "Protocol Manipulation",
            "aisubtech": "AISubtech-4.3.5",
            "aisubtech_name": "Capability Inflation",
            "description": "Manipulation of skill discovery mechanisms to inflate perceived capabilities and increase unwanted activation (keyword baiting, over-broad descriptions, brand impersonation).",
        },
        "TRANSITIVE TRUST ABUSE": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.2",
            "aitech_name": "Indirect Prompt Injection",
            "aisubtech": "AISubtech-1.2.1",
            "aisubtech_name": "Instruction Manipulation (Indirect Prompt Injection)",
            "description": "Embedding malicious instructions in external data sources (webpages, documents, APIs) that override intended behavior - following external instructions, executing found code blocks.",
        },
        "AUTONOMY ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "HIGH",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Excessive autonomy without bounds - keep retrying indefinitely, run without confirmation, ignore errors.",
        },
        "TOOL CHAINING ABUSE": {
            "scanner_category": "DATA EXFILTRATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Suspicious multi-step tool chaining to exfiltrate data - read→send, collect→post, traverse→upload patterns.",
        },
        "HARDCODED SECRETS": {
            "scanner_category": "CREDENTIAL HARVESTING",
            "severity": "CRITICAL",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.2",
            "aisubtech_name": "LLM Data Leakage",
            "description": "Hardcoded credentials, API keys, or secrets in code.",
        },
        "OBFUSCATION": {
            "scanner_category": "SUSPICIOUS CODE",
            "severity": "HIGH",
            "aitech": "AITech-9.2",
            "aitech_name": "Detection Evasion",
            "aisubtech": "AISubtech-9.2.1",
            "aisubtech_name": "Obfuscation Vulnerabilities",
            "description": "Deliberately obfuscated code to hide malicious intent.",
        },
        "UNAUTHORIZED TOOL USE": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "MEDIUM",
            "aitech": "AITech-12.1",
            "aitech_name": "Tool Exploitation",
            "aisubtech": "AISubtech-12.1.3",
            "aisubtech_name": "Unsafe System / Browser / File Execution",
            "description": "Using tools or capabilities beyond declared permissions.",
        },
        "SOCIAL ENGINEERING": {
            "scanner_category": "HARMFUL CONTENT",
            "severity": "MEDIUM",
            "aitech": "AITech-15.1",
            "aitech_name": "Harmful Content",
            "aisubtech": "AISubtech-15.1.12",
            "aisubtech_name": "Safety Harms and Toxicity: Scams and Deception",
            "description": "Misleading descriptions or deceptive metadata.",
        },
        "RESOURCE ABUSE": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Excessive resource consumption or denial of service.",
        },
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Explicit attempts to override system instructions through direct input.",
        },
        "CODE EXECUTION": {
            "scanner_category": "SUSPICIOUS CODE EXECUTION",
            "severity": "LOW",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.1",
            "aisubtech_name": "Code Execution",
            "description": "Autonomously generating, interpreting, or executing code, leading to unsolicited or unauthorized code execution.",
        },
        "INJECTION ATTACK": {
            "scanner_category": "INJECTION ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.4",
            "aisubtech_name": "Injection Attacks (SQL, Command Execution, XSS)",
            "description": "Injecting malicious payloads such as SQL queries, command sequences, or scripts.",
        },
        "CREDENTIAL HARVESTING": {
            "scanner_category": "SECURITY VIOLATION",
            "severity": "HIGH",
            "aitech": "AITech-8.2",
            "aitech_name": "Data Exfiltration / Exposure",
            "aisubtech": "AISubtech-8.2.3",
            "aisubtech_name": "Data Exfiltration via Agent Tooling",
            "description": "Unauthorized exposure or exfiltration of credentials or sensitive information.",
        },
        "SYSTEM MANIPULATION": {
            "scanner_category": "SYSTEM MANIPULATION",
            "severity": "MEDIUM",
            "aitech": "AITech-9.1",
            "aitech_name": "Model or Agentic System Manipulation",
            "aisubtech": "AISubtech-9.1.2",
            "aisubtech_name": "Unauthorized or Unsolicited System Access",
            "description": "Manipulating or accessing underlying system resources without authorization.",
        },
        "SUPPLY CHAIN ATTACK": {
            "scanner_category": "SUPPLY CHAIN ATTACK",
            "severity": "HIGH",
            "aitech": "AITech-9.3",
            "aitech_name": "Dependency / Plugin Compromise",
            "aisubtech": "AISubtech-9.3.1",
            "aisubtech_name": "Malicious Package / Tool Injection",
            "description": "Bytecode poisoning, archive payload delivery, or dependency replacement "
            "that compromises the supply chain integrity of a skill package.",
        },
    }

    # -- Behavioural analyser findings --
    BEHAVIORAL_THREATS = {
        "PROMPT INJECTION": {
            "scanner_category": "PROMPT INJECTION",
            "severity": "HIGH",
            "aitech": "AITech-1.1",
            "aitech_name": "Direct Prompt Injection",
            "aisubtech": "AISubtech-1.1.1",
            "aisubtech_name": "Instruction Manipulation (Direct Prompt Injection)",
            "description": "Malicious manipulation of tool metadata or descriptions that mislead the LLM.",
        },
        "RESOURCE EXHAUSTION": {
            "scanner_category": "RESOURCE ABUSE",
            "severity": "MEDIUM",
            "aitech": "AITech-13.1",
            "aitech_name": "Disruption of Availability",
            "aisubtech": "AISubtech-13.1.1",
            "aisubtech_name": "Compute Exhaustion",
            "description": "Overloading the system via repeated invocations or large payloads to cause denial of service.",
        },
    }

    # Maps an AITech code to a short internal category tag.
    AITECH_TO_CATEGORY = {
        "AITech-1.1": "prompt_injection",
        "AITech-1.2": "prompt_injection",
        "AITech-2.1": "social_engineering",
        "AITech-4.3": "skill_discovery_abuse",
        "AITech-8.2": "data_exfiltration",
        "AITech-9.1": "command_injection",
        "AITech-9.2": "obfuscation",
        "AITech-9.3": "supply_chain_attack",
        "AITech-12.1": "unauthorized_tool_use",
        "AITech-13.1": "resource_abuse",
        "AITech-15.1": "harmful_content",
        "AITech-99.9": "policy_violation",
    }

    # -----------------------------------------------------------------
    # Lookup helpers
    # -----------------------------------------------------------------

    @classmethod
    def get_threat_mapping(cls, analyzer: str, threat_name: str) -> dict[str, Any]:
        """Resolve an analyser/threat pair to its full taxonomy record.

        Returns a dict with keys such as ``severity``, ``aitech``,
        ``aisubtech``, ``description``, etc.  If the threat name is not
        recognised a generic "unknown" record is returned instead of
        raising.
        """
        registry: dict[str, dict[str, dict[str, Any]]] = {
            "llm": cls.LLM_THREATS,
            "yara": cls.YARA_THREATS,
            "behavioral": cls.BEHAVIORAL_THREATS,
            "static": cls.YARA_THREATS,
        }

        norm_analyzer = analyzer.lower()
        if norm_analyzer not in registry:
            raise ValueError(f"Unknown analyzer: {analyzer}")

        pool = registry[norm_analyzer]
        norm_threat = threat_name.upper().replace("_", " ")

        if norm_threat in pool:
            return pool[norm_threat]

        return {
            "scanner_category": "UNKNOWN",
            "severity": "MEDIUM",
            "aitech": "AITech-99.9",
            "aitech_name": "Unknown Threat",
            "aisubtech": "AISubtech-99.9.9",
            "aisubtech_name": "Unclassified",
            "description": f"Unclassified threat: {threat_name}",
        }

    @classmethod
    def get_threat_category_from_aitech(cls, aitech_code: str) -> str:
        """Translate an AITech code into the matching internal category tag."""
        return cls.AITECH_TO_CATEGORY.get(aitech_code, "policy_violation")

    @classmethod
    def get_threat_mapping_by_aitech(cls, aitech_code: str) -> dict[str, Any]:
        """Find the first threat record that carries the given AITech code.

        Searches LLM, YARA, and behavioural dictionaries in order.  When
        no match exists a generic placeholder is returned.
        """
        for table in (cls.LLM_THREATS, cls.YARA_THREATS, cls.BEHAVIORAL_THREATS):
            for _name, info in table.items():
                if info.get("aitech") == aitech_code:
                    return info

        return {
            "scanner_category": "UNKNOWN",
            "severity": "MEDIUM",
            "aitech": aitech_code,
            "aitech_name": "Unknown Threat",
            "aisubtech": None,
            "aisubtech_name": None,
            "description": f"Unclassified threat with AITech code: {aitech_code}",
        }

    @classmethod
    def get_framework_mappings_for_threat(cls, analyzer: str, threat_name: str) -> list[str]:
        """Collect cross-framework references for a specific scanner finding."""
        from .threat_taxonomy import get_framework_mappings

        record = cls.get_threat_mapping(analyzer, threat_name)
        at_code = str(record.get("aitech") or "")
        ast_code = str(record.get("aisubtech") or "")
        return get_framework_mappings(
            aitech_code=at_code if at_code.startswith("AITech-") else None,
            aisubtech_code=ast_code if ast_code.startswith("AISubtech-") else None,
        )


# ---------------------------------------------------------------------------
# Runtime override machinery
# ---------------------------------------------------------------------------

_OVERRIDE_ENV_KEY = "SKILL_SCANNER_THREAT_MAPPING_PATH"
_ACTIVE_THREAT_MAPPING_SOURCE = "builtin"

# Snapshots of the original class-level dicts so we can roll back.
_ORIG_LLM: dict[str, dict[str, Any]] = {k: dict(v) for k, v in ThreatMapping.LLM_THREATS.items()}
_ORIG_YARA: dict[str, dict[str, Any]] = {k: dict(v) for k, v in ThreatMapping.YARA_THREATS.items()}
_ORIG_BEHAVIORAL: dict[str, dict[str, Any]] = {k: dict(v) for k, v in ThreatMapping.BEHAVIORAL_THREATS.items()}
_ORIG_CATEGORY_MAP: dict[str, str] = dict(ThreatMapping.AITECH_TO_CATEGORY)


def _restore_defaults() -> None:
    """Overwrite ThreatMapping class dicts with the original snapshots."""
    ThreatMapping.LLM_THREATS = {k: dict(v) for k, v in _ORIG_LLM.items()}
    ThreatMapping.YARA_THREATS = {k: dict(v) for k, v in _ORIG_YARA.items()}
    ThreatMapping.BEHAVIORAL_THREATS = {k: dict(v) for k, v in _ORIG_BEHAVIORAL.items()}
    ThreatMapping.AITECH_TO_CATEGORY = dict(_ORIG_CATEGORY_MAP)


def _read_override_file(filepath: Path) -> dict[str, Any]:
    """Parse a JSON override file into a Python dict."""
    if not filepath.exists():
        raise FileNotFoundError(f"Threat mapping file not found: {filepath}")
    content = json.loads(filepath.read_text(encoding="utf-8"))
    if not isinstance(content, dict):
        raise ValueError("Threat mapping payload must be a JSON object")
    return content


def _overlay_threat_dict(
    base: dict[str, dict[str, Any]],
    overrides: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Layer per-threat overrides on top of a base threat dictionary."""
    combined: dict[str, dict[str, Any]] = {k: dict(v) for k, v in base.items()}
    for name, info in overrides.items():
        if not isinstance(info, dict):
            raise ValueError(f"Threat override for {name!r} must be an object")
        key = str(name).upper().replace("_", " ")
        existing = dict(combined.get(key, {}))
        existing.update(info)
        combined[key] = existing
    return combined


def _apply_overrides(payload: dict[str, Any]) -> None:
    """Merge a parsed override payload into ThreatMapping's class dicts."""
    attr_aliases = {
        "llm_threats": "LLM_THREATS",
        "yara_threats": "YARA_THREATS",
        "behavioral_threats": "BEHAVIORAL_THREATS",
    }
    for key, section in payload.items():
        lowered = key.lower()
        if lowered in attr_aliases:
            if not isinstance(section, dict):
                raise ValueError(f"{key} override must be an object")
            attr = attr_aliases[lowered]
            current = getattr(ThreatMapping, attr)
            setattr(ThreatMapping, attr, _overlay_threat_dict(current, section))
        elif lowered in ("aitech_to_category", "aitech_category_map"):
            if not isinstance(section, dict):
                raise ValueError(f"{key} override must be an object")
            updated = dict(ThreatMapping.AITECH_TO_CATEGORY)
            updated.update({str(k): str(v) for k, v in section.items()})
            ThreatMapping.AITECH_TO_CATEGORY = updated


def _build_simple_mapping(full_threats: dict[str, dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Derive a lightweight threat_category/threat_type/severity view."""
    return {
        name: {
            "threat_category": record["scanner_category"],
            "threat_type": name.lower().replace("_", " "),
            "severity": record.get("severity", "UNKNOWN"),
        }
        for name, record in full_threats.items()
    }


# ---------------------------------------------------------------------------
# Public configuration entry-point
# ---------------------------------------------------------------------------

def configure_threat_mappings(path: str | Path | None = None) -> str:
    """Load threat-mapping overrides from a JSON file or reset to defaults.

    *path* takes precedence; otherwise ``SKILL_SCANNER_THREAT_MAPPING_PATH``
    is checked.  Returns ``"builtin"`` or the resolved override path.
    """
    global LLM_THREAT_MAPPING
    global YARA_THREAT_MAPPING
    global BEHAVIORAL_THREAT_MAPPING
    global STATIC_THREAT_MAPPING
    global _ACTIVE_THREAT_MAPPING_SOURCE

    target = str(path) if path is not None else os.getenv(_OVERRIDE_ENV_KEY)
    if path is not None:
        if target:
            os.environ[_OVERRIDE_ENV_KEY] = target
        else:
            os.environ.pop(_OVERRIDE_ENV_KEY, None)

    _restore_defaults()

    if target:
        resolved = Path(target).expanduser().resolve()
        data = _read_override_file(resolved)
        _apply_overrides(data)
        _ACTIVE_THREAT_MAPPING_SOURCE = str(resolved)
        _log.info("Loaded custom threat mappings from %s", resolved)
    else:
        _ACTIVE_THREAT_MAPPING_SOURCE = "builtin"

    LLM_THREAT_MAPPING = _build_simple_mapping(ThreatMapping.LLM_THREATS)
    YARA_THREAT_MAPPING = _build_simple_mapping(ThreatMapping.YARA_THREATS)
    BEHAVIORAL_THREAT_MAPPING = _build_simple_mapping(ThreatMapping.BEHAVIORAL_THREATS)
    STATIC_THREAT_MAPPING = YARA_THREAT_MAPPING
    return _ACTIVE_THREAT_MAPPING_SOURCE


def get_threat_mapping_source() -> str:
    """Return the label describing the active threat-mapping origin."""
    return _ACTIVE_THREAT_MAPPING_SOURCE


# Initialise on first import; swallow errors gracefully.
try:
    configure_threat_mappings()
except Exception as exc:
    _log.warning("Failed to load custom threat mapping overrides: %s", exc)
    _restore_defaults()
    _ACTIVE_THREAT_MAPPING_SOURCE = "builtin"
    LLM_THREAT_MAPPING = _build_simple_mapping(ThreatMapping.LLM_THREATS)
    YARA_THREAT_MAPPING = _build_simple_mapping(ThreatMapping.YARA_THREATS)
    BEHAVIORAL_THREAT_MAPPING = _build_simple_mapping(ThreatMapping.BEHAVIORAL_THREATS)
    STATIC_THREAT_MAPPING = YARA_THREAT_MAPPING


# ---------------------------------------------------------------------------
# Standalone severity / category helpers
# ---------------------------------------------------------------------------

def get_threat_severity(analyzer: str, threat_name: str) -> str:
    """Return the severity string for a given analyser + threat pair."""
    try:
        record = ThreatMapping.get_threat_mapping(analyzer, threat_name)
        sev = record.get("severity", "MEDIUM")
        return str(sev) if sev is not None else "MEDIUM"
    except ValueError:
        return "MEDIUM"


def get_threat_category(analyzer: str, threat_name: str) -> str:
    """Return the scanner category string for a given analyser + threat pair."""
    try:
        record = ThreatMapping.get_threat_mapping(analyzer, threat_name)
        cat = record.get("scanner_category", "UNKNOWN")
        return str(cat) if cat is not None else "UNKNOWN"
    except ValueError:
        return "UNKNOWN"
