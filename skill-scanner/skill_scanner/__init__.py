"""SkillWard static analysis engine for Agent Skill packages."""

try:
    from ._version import __version__
except ImportError:
    __version__ = "0.0.0+unknown"


def __getattr__(name: str):
    """Lazy-import public symbols to keep startup fast."""
    _symbols = {
        "SkillLoader": (".core.loader", "SkillLoader"),
        "load_skill": (".core.loader", "load_skill"),
        "Finding": (".core.models", "Finding"),
        "Report": (".core.models", "Report"),
        "ScanResult": (".core.models", "ScanResult"),
        "Severity": (".core.models", "Severity"),
        "Skill": (".core.models", "Skill"),
        "ThreatCategory": (".core.models", "ThreatCategory"),
        "SkillScanner": (".core.scanner", "SkillScanner"),
        "scan_skill": (".core.scanner", "scan_skill"),
        "scan_directory": (".core.scanner", "scan_directory"),
    }
    if name in _symbols:
        import importlib
        mod_path, attr = _symbols[name]
        obj = getattr(importlib.import_module(mod_path, __package__), attr)
        globals()[name] = obj
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "SkillScanner", "scan_skill", "scan_directory",
    "Skill", "Finding", "ScanResult", "Report",
    "Severity", "ThreatCategory",
    "SkillLoader", "load_skill",
]
