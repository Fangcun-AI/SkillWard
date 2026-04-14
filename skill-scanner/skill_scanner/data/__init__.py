"""Bundled policy presets, YARA rules, and signature definitions."""

from pathlib import Path

DATA_DIR = Path(__file__).parent

_CORE_PACK = DATA_DIR / "packs" / "core"
YARA_RULES_DIR = _CORE_PACK / "yara"
SIGNATURES_DIR = _CORE_PACK / "signatures"

__all__ = ["DATA_DIR", "YARA_RULES_DIR", "SIGNATURES_DIR"]
