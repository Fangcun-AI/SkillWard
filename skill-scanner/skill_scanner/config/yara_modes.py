"""
Preset and custom detection profiles for the YARA rule engine.

Three built-in profiles trade off sensitivity against noise:
  STRICT    -- maximise detection, tolerate more false positives
  BALANCED  -- default middle ground
  PERMISSIVE -- suppress noisy rules, prioritise precision

A CUSTOM profile lets callers set every knob individually.
"""

from dataclasses import dataclass, field
from enum import Enum


class YaraMode(Enum):
    """Identifies which detection profile is active."""

    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"
    CUSTOM = "custom"


# -- per-category tuning knobs -------------------------------------------- #

@dataclass
class UnicodeStegConfig:
    """Knobs for zero-width and invisible-character detection."""

    zerowidth_threshold_with_decode: int = 50
    zerowidth_threshold_alone: int = 200

    detect_rtl_override: bool = True
    detect_ltl_override: bool = True
    detect_line_separators: bool = True
    detect_unicode_tags: bool = True
    detect_variation_selectors: bool = True


@dataclass
class CredentialHarvestingConfig:
    """Knobs for secret / credential exfiltration rules."""

    filter_placeholder_patterns: bool = True

    detect_ai_api_keys: bool = True
    detect_aws_keys: bool = True
    detect_ssh_keys: bool = True
    detect_env_exfiltration: bool = True


@dataclass
class ToolChainingConfig:
    """Knobs for multi-tool abuse chain detection."""

    filter_api_documentation: bool = True
    filter_generic_http_verbs: bool = True
    filter_email_field_mentions: bool = True

    detect_read_send: bool = True
    detect_collect_exfil: bool = True
    detect_env_network: bool = True


# -- main config object --------------------------------------------------- #

@dataclass
class YaraModeConfig:
    """Aggregates all per-category knobs under a single detection profile."""

    mode: YaraMode = YaraMode.BALANCED
    description: str = ""

    unicode_steg: UnicodeStegConfig = field(default_factory=UnicodeStegConfig)
    credential_harvesting: CredentialHarvestingConfig = field(default_factory=CredentialHarvestingConfig)
    tool_chaining: ToolChainingConfig = field(default_factory=ToolChainingConfig)

    enabled_rules: set[str] = field(default_factory=set)   # empty -> everything on
    disabled_rules: set[str] = field(default_factory=set)

    # -- factory classmethods ---------------------------------------------- #

    @classmethod
    def strict(cls) -> "YaraModeConfig":
        """
        High-sensitivity profile that flags aggressively.

        Best suited for auditing untrusted third-party integrations or
        meeting compliance requirements where missing a finding is worse
        than a false alarm.
        """
        return cls(
            mode=YaraMode.STRICT,
            description="Aggressive detection -- more alerts, fewer misses",
            unicode_steg=UnicodeStegConfig(
                zerowidth_threshold_with_decode=20,
                zerowidth_threshold_alone=100,
            ),
            credential_harvesting=CredentialHarvestingConfig(
                filter_placeholder_patterns=False,
            ),
            tool_chaining=ToolChainingConfig(
                filter_api_documentation=False,
                filter_generic_http_verbs=False,
            ),
        )

    @classmethod
    def balanced(cls) -> "YaraModeConfig":
        """
        Middle-ground profile (the default).

        Appropriate for routine scanning in CI pipelines or day-to-day
        development work.
        """
        return cls(
            mode=YaraMode.BALANCED,
            description="Default profile -- reasonable trade-off",
            unicode_steg=UnicodeStegConfig(
                zerowidth_threshold_with_decode=50,
                zerowidth_threshold_alone=200,
            ),
            credential_harvesting=CredentialHarvestingConfig(
                filter_placeholder_patterns=True,
            ),
            tool_chaining=ToolChainingConfig(
                filter_api_documentation=True,
                filter_generic_http_verbs=True,
                filter_email_field_mentions=True,
            ),
        )

    @classmethod
    def permissive(cls) -> "YaraModeConfig":
        """
        Low-noise profile that suppresses borderline findings.

        Use when scanning trusted internal code or when alert fatigue
        from false positives is a concern.
        """
        return cls(
            mode=YaraMode.PERMISSIVE,
            description="Quiet mode -- fewer alerts, some threats may go unreported",
            unicode_steg=UnicodeStegConfig(
                zerowidth_threshold_with_decode=100,
                zerowidth_threshold_alone=500,
                detect_line_separators=False,
            ),
            credential_harvesting=CredentialHarvestingConfig(
                filter_placeholder_patterns=True,
            ),
            tool_chaining=ToolChainingConfig(
                filter_api_documentation=True,
                filter_generic_http_verbs=True,
                filter_email_field_mentions=True,
            ),
            disabled_rules={
                "capability_inflation_generic",
                "indirect_prompt_injection_generic",
            },
        )

    @classmethod
    def custom(
        cls,
        unicode_steg: UnicodeStegConfig | None = None,
        credential_harvesting: CredentialHarvestingConfig | None = None,
        tool_chaining: ToolChainingConfig | None = None,
        enabled_rules: set[str] | None = None,
        disabled_rules: set[str] | None = None,
    ) -> "YaraModeConfig":
        """
        Fully caller-controlled profile.

        Any parameter left as ``None`` gets the default sub-config.

        Parameters
        ----------
        unicode_steg:       Invisible-character detection settings.
        credential_harvesting: Secret-leak detection settings.
        tool_chaining:      Multi-tool abuse chain settings.
        enabled_rules:      Allowlist (empty means all rules are on).
        disabled_rules:     Denylist applied after the allowlist.
        """
        return cls(
            mode=YaraMode.CUSTOM,
            description="Caller-supplied configuration",
            unicode_steg=unicode_steg or UnicodeStegConfig(),
            credential_harvesting=credential_harvesting or CredentialHarvestingConfig(),
            tool_chaining=tool_chaining or ToolChainingConfig(),
            enabled_rules=enabled_rules or set(),
            disabled_rules=disabled_rules or set(),
        )

    @classmethod
    def from_mode_name(cls, mode_name: str) -> "YaraModeConfig":
        """Instantiate a profile by its string name (case-insensitive)."""
        _factories = {
            "strict": cls.strict,
            "balanced": cls.balanced,
            "permissive": cls.permissive,
        }
        key = mode_name.lower()
        if key in _factories:
            return _factories[key]()
        raise ValueError(
            f"No built-in profile called '{mode_name}'. "
            f"Choose from: strict, balanced, permissive, or use custom()."
        )

    # -- instance helpers -------------------------------------------------- #

    def is_rule_enabled(self, rule_name: str) -> bool:
        """Return whether *rule_name* should fire under this profile."""
        if self.enabled_rules and rule_name not in self.enabled_rules:
            return False
        return rule_name not in self.disabled_rules

    def to_dict(self) -> dict:
        """Serialise the full configuration to a plain dictionary."""
        return {
            "mode": self.mode.value,
            "description": self.description,
            "unicode_steg": {
                "zerowidth_threshold_with_decode": self.unicode_steg.zerowidth_threshold_with_decode,
                "zerowidth_threshold_alone": self.unicode_steg.zerowidth_threshold_alone,
                "detect_rtl_override": self.unicode_steg.detect_rtl_override,
                "detect_ltl_override": self.unicode_steg.detect_ltl_override,
                "detect_line_separators": self.unicode_steg.detect_line_separators,
                "detect_unicode_tags": self.unicode_steg.detect_unicode_tags,
                "detect_variation_selectors": self.unicode_steg.detect_variation_selectors,
            },
            "credential_harvesting": {
                "filter_placeholder_patterns": self.credential_harvesting.filter_placeholder_patterns,
                "detect_ai_api_keys": self.credential_harvesting.detect_ai_api_keys,
                "detect_aws_keys": self.credential_harvesting.detect_aws_keys,
                "detect_ssh_keys": self.credential_harvesting.detect_ssh_keys,
                "detect_env_exfiltration": self.credential_harvesting.detect_env_exfiltration,
            },
            "tool_chaining": {
                "filter_api_documentation": self.tool_chaining.filter_api_documentation,
                "filter_generic_http_verbs": self.tool_chaining.filter_generic_http_verbs,
                "filter_email_field_mentions": self.tool_chaining.filter_email_field_mentions,
                "detect_read_send": self.tool_chaining.detect_read_send,
                "detect_collect_exfil": self.tool_chaining.detect_collect_exfil,
                "detect_env_network": self.tool_chaining.detect_env_network,
            },
            "enabled_rules": list(self.enabled_rules),
            "disabled_rules": list(self.disabled_rules),
        }


# Convenience default instance
DEFAULT_YARA_MODE = YaraModeConfig.balanced()
