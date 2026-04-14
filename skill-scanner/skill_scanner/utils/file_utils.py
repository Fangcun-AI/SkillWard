"""Helpers for reading and classifying files on disk."""

from pathlib import Path

_EXT_TO_LANG = {
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".md": "markdown",
    ".markdown": "markdown",
    ".exe": "binary",
    ".so": "binary",
    ".dylib": "binary",
    ".dll": "binary",
    ".bin": "binary",
}


def read_file_safe(file_path: Path, max_size_mb: int = 10) -> str | None:
    """Return the text content of *file_path*, or ``None`` when the file is
    too large, missing, or not decodable as UTF-8."""
    try:
        if file_path.stat().st_size > max_size_mb * 1024 * 1024:
            return None
        return file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def get_file_type(file_path: Path) -> str:
    """Map a file extension to a language / category label."""
    return _EXT_TO_LANG.get(file_path.suffix.lower(), "other")


def is_binary_file(file_path: Path) -> bool:
    """Return *True* when the extension indicates a compiled binary."""
    return get_file_type(file_path) == "binary"
