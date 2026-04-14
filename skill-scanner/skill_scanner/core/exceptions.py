"""Error hierarchy for skill scanning operations."""


class SkillScannerError(Exception):
    """Root error type for the scanning pipeline."""


class SkillLoadError(SkillScannerError):
    """A skill package could not be loaded from disk (missing manifest, bad YAML, I/O failure)."""


class SkillAnalysisError(SkillScannerError):
    """An analyzer encountered an unrecoverable error during inspection."""


class SkillValidationError(SkillScannerError):
    """The skill's manifest or directory structure violates required constraints."""
