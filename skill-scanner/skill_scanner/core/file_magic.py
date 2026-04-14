"""
Binary and text content-type identification.

Leverages Google Magika's neural model for broad coverage (200+ formats),
falling back to deterministic magic-byte matching when the model reports
low confidence or is unavailable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import NamedTuple

_log = logging.getLogger(__name__)


class MagicMatch(NamedTuple):
    """Describes an identified content type."""

    content_type: str       # e.g. "executable/elf", "image/png"
    content_family: str     # e.g. "executable", "image", "archive"
    description: str        # human-readable label
    score: float = 1.0      # 0.0-1.0 confidence; 1.0 for byte-signature hits
    mime_type: str = ""     # MIME string from Magika when available


# -- Magika lazy singleton ------------------------------------------------- #

_magika_obj = None


def _magika():
    """Return or create the singleton Magika instance."""
    global _magika_obj
    if _magika_obj is None:
        from magika import Magika
        _magika_obj = Magika()
    return _magika_obj


# -- group-to-family mapping ---------------------------------------------- #

_GROUP_FAMILY_MAP: dict[str, str] = {
    "executable": "executable",
    "archive": "archive",
    "image": "image",
    "document": "document",
    "font": "font",
    "code": "code",
    "text": "text",
    "audio": "audio",
    "video": "video",
    "application": "application",
}

# Families that are interchangeable at the group level (e.g. code vs. text).
_TEXTLIKE_FAMILIES = frozenset({"text", "code"})


# -- extension lookups ----------------------------------------------------- #

_EXT_TO_FAMILY: dict[str, str] = {
    # images
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".bmp": "image", ".webp": "image", ".ico": "image", ".tiff": "image",
    ".tif": "image", ".svg": "image",
    # archives
    ".zip": "archive", ".gz": "archive", ".tar": "archive", ".tgz": "archive",
    ".bz2": "archive", ".xz": "archive", ".7z": "archive", ".rar": "archive",
    ".jar": "archive", ".war": "archive", ".apk": "archive",
    # ZIP-based office documents
    ".docx": "archive", ".xlsx": "archive", ".pptx": "archive",
    ".odt": "archive", ".ods": "archive", ".odp": "archive",
    # legacy office / PDF
    ".pdf": "document", ".doc": "document", ".xls": "document", ".ppt": "document",
    # executables / libraries
    ".exe": "executable", ".dll": "executable", ".so": "executable",
    ".dylib": "executable", ".bin": "executable",
    # fonts
    ".ttf": "font", ".otf": "font", ".woff": "font", ".woff2": "font",
    ".eot": "font",
    # source code / scripts
    ".py": "text", ".sh": "text", ".bash": "text", ".js": "text",
    ".ts": "text", ".rb": "text", ".pl": "text", ".php": "text",
    # text / config / data
    ".md": "text", ".txt": "text", ".json": "text", ".yaml": "text",
    ".yml": "text", ".xml": "text", ".html": "text", ".css": "text",
    ".csv": "text", ".rst": "text", ".toml": "text", ".cfg": "text",
    ".ini": "text", ".conf": "text",
    # audio
    ".mp3": "audio", ".wav": "audio", ".ogg": "audio", ".flac": "audio",
    # video
    ".mp4": "video", ".mkv": "video", ".webm": "video", ".avi": "video",
}

_EXT_LABEL_EXPECTATIONS: dict[str, frozenset[str]] = {
    ".py":   frozenset({"python"}),
    ".sh":   frozenset({"shell"}),
    ".bash": frozenset({"shell"}),
    ".js":   frozenset({"javascript", "jsx"}),
    ".ts":   frozenset({"typescript", "tsx"}),
    ".rb":   frozenset({"ruby"}),
    ".pl":   frozenset({"perl"}),
    ".php":  frozenset({"php"}),
    ".json": frozenset({"json", "jsonl", "jsonc"}),
    ".yaml": frozenset({"yaml"}),
    ".yml":  frozenset({"yaml"}),
    ".xml":  frozenset({"xml", "svg", "rdf"}),
    ".html": frozenset({"html"}),
    ".css":  frozenset({"css", "scss", "less"}),
    ".md":   frozenset({"markdown"}),
    ".txt":  frozenset({"txt", "txtascii", "txtutf8", "txtutf16"}),
    ".csv":  frozenset({"csv", "tsv"}),
    ".rst":  frozenset({"rst"}),
    ".toml": frozenset({"toml"}),
    ".ini":  frozenset({"ini"}),
    ".cfg":  frozenset({"ini", "txt", "txtascii", "txtutf8"}),
    ".conf": frozenset({"ini", "txt", "txtascii", "txtutf8", "shell"}),
}

# Extensions where a ``#!`` header is expected and not suspicious.
_SHEBANG_OK_EXTS = frozenset({
    ".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".php",
})


# -- byte-signature table ------------------------------------------------- #

_BYTE_SIGS: list[tuple[int, bytes, MagicMatch]] = [
    # executables
    (0, b"\x7fELF",             MagicMatch("executable/elf",            "executable", "ELF executable")),
    (0, b"MZ",                  MagicMatch("executable/pe",             "executable", "PE/Windows executable")),
    (0, b"\xfe\xed\xfa\xce",   MagicMatch("executable/macho32",        "executable", "Mach-O 32-bit executable")),
    (0, b"\xfe\xed\xfa\xcf",   MagicMatch("executable/macho64",        "executable", "Mach-O 64-bit executable")),
    (0, b"\xce\xfa\xed\xfe",   MagicMatch("executable/macho32le",      "executable", "Mach-O 32-bit (LE) executable")),
    (0, b"\xcf\xfa\xed\xfe",   MagicMatch("executable/macho64le",      "executable", "Mach-O 64-bit (LE) executable")),
    (0, b"\xca\xfe\xba\xbe",   MagicMatch("executable/macho_universal","executable", "Mach-O Universal binary")),
    (0, b"#!",                  MagicMatch("executable/script",         "executable", "Script with shebang")),
    # archives
    (0,   b"PK\x03\x04",       MagicMatch("archive/zip",              "archive", "ZIP archive")),
    (0,   b"PK\x05\x06",       MagicMatch("archive/zip_empty",        "archive", "ZIP archive (empty)")),
    (0,   b"PK\x07\x08",       MagicMatch("archive/zip_spanned",      "archive", "ZIP archive (spanned)")),
    (0,   b"\x1f\x8b",         MagicMatch("archive/gzip",             "archive", "GZIP compressed")),
    (0,   b"BZh",              MagicMatch("archive/bzip2",            "archive", "BZIP2 compressed")),
    (0,   b"\xfd7zXZ\x00",     MagicMatch("archive/xz",              "archive", "XZ compressed")),
    (0,   b"7z\xbc\xaf\x27\x1c", MagicMatch("archive/7z",           "archive", "7-Zip archive")),
    (0,   b"Rar!\x1a\x07",     MagicMatch("archive/rar",             "archive", "RAR archive")),
    (0,   b"ustar",            MagicMatch("archive/tar",              "archive", "TAR archive")),
    (257, b"ustar",            MagicMatch("archive/tar",              "archive", "TAR archive")),
    # images
    (0, b"\x89PNG\r\n\x1a\n",  MagicMatch("image/png",  "image", "PNG image")),
    (0, b"\xff\xd8\xff",       MagicMatch("image/jpeg", "image", "JPEG image")),
    (0, b"GIF87a",             MagicMatch("image/gif",  "image", "GIF image (87a)")),
    (0, b"GIF89a",             MagicMatch("image/gif",  "image", "GIF image (89a)")),
    (0, b"BM",                 MagicMatch("image/bmp",  "image", "BMP image")),
    (0, b"RIFF",               MagicMatch("image/webp", "image", "WebP image")),
    (0, b"II\x2a\x00",         MagicMatch("image/tiff", "image", "TIFF image (LE)")),
    (0, b"MM\x00\x2a",         MagicMatch("image/tiff", "image", "TIFF image (BE)")),
    (0, b"\x00\x00\x01\x00",   MagicMatch("image/ico",  "image", "ICO image")),
    # documents
    (0, b"%PDF",                                MagicMatch("document/pdf", "document", "PDF document")),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",   MagicMatch("document/ole", "document", "OLE/MS Office document")),
    # java class
    (0, b"\xca\xfe\xba\xbe",   MagicMatch("executable/java_class", "executable", "Java class file")),
    # python bytecode
    (0, b"\xa7\r\r\n",         MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.11)")),
    (0, b"\xcb\r\r\n",         MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.12)")),
    (0, b"\xef\r\r\n",         MagicMatch("bytecode/python", "bytecode", "Python bytecode (3.13)")),
    # fonts
    (0, b"\x00\x01\x00\x00",   MagicMatch("font/ttf",   "font", "TrueType font")),
    (0, b"OTTO",               MagicMatch("font/otf",   "font", "OpenType font")),
    (0, b"wOFF",               MagicMatch("font/woff",  "font", "WOFF font")),
    (0, b"wOF2",               MagicMatch("font/woff2", "font", "WOFF2 font")),
]


# -- byte-signature helpers ----------------------------------------------- #

def _scan_signatures(data: bytes) -> MagicMatch | None:
    """Walk the signature table and return the first match, or ``None``."""
    for offset, sig, result in _BYTE_SIGS:
        end = offset + len(sig)
        if len(data) >= end and data[offset:end] == sig:
            return result
    return None


def _legacy_from_path(fpath: Path) -> MagicMatch | None:
    """Read up to 300 bytes from *fpath* and attempt byte-signature matching."""
    try:
        with open(fpath, "rb") as fh:
            header = fh.read(300)
    except (OSError, PermissionError):
        return None
    return _scan_signatures(header) if header else None


def _legacy_from_bytes(data: bytes) -> MagicMatch | None:
    """Byte-signature matching on an in-memory buffer."""
    return _scan_signatures(data) if data else None


# -- Magika confidence floor ----------------------------------------------- #

# Below this threshold the neural model is not trusted; deterministic
# byte-signature results take precedence.
_MIN_MAGIKA_SCORE: float = 0.85


def _convert_magika(result) -> MagicMatch | None:
    """Translate a raw Magika result into a ``MagicMatch``, or ``None``."""
    if not result.ok:
        return None
    grp = result.output.group
    if grp in ("unknown", "inode"):
        return None
    family = _GROUP_FAMILY_MAP.get(grp, grp)
    return MagicMatch(
        content_type=f"{grp}/{result.output.label}",
        content_family=family,
        description=result.output.description,
        score=result.score,
        mime_type=result.output.mime_type,
    )


# -- public API ------------------------------------------------------------ #

def detect_magic(file_path: Path) -> MagicMatch | None:
    """
    Identify the true content type of a file on disk.

    The neural model is preferred when it reports high confidence.
    Byte-signature matching is used when the model is uncertain or
    unavailable, and the model's low-confidence answer is returned
    only as a last resort.

    Parameters
    ----------
    file_path:
        Filesystem path to inspect.

    Returns
    -------
    MagicMatch or None
    """
    nn_match: MagicMatch | None = None
    try:
        nn_match = _convert_magika(_magika().identify_path(file_path))
    except Exception:
        _log.debug("Neural identification failed for %s; trying signatures", file_path)

    if nn_match is not None and nn_match.score >= _MIN_MAGIKA_SCORE:
        return nn_match

    sig_match = _legacy_from_path(file_path)
    if sig_match is not None:
        return sig_match

    return nn_match


def detect_magic_from_bytes(data: bytes) -> MagicMatch | None:
    """
    Identify content type from raw bytes already in memory.

    Same confidence-floor / fallback strategy as :func:`detect_magic`.

    Parameters
    ----------
    data:
        Raw file content (a few hundred bytes minimum for best accuracy).

    Returns
    -------
    MagicMatch or None
    """
    if not data:
        return None

    nn_match: MagicMatch | None = None
    try:
        nn_match = _convert_magika(_magika().identify_bytes(data))
    except Exception:
        _log.debug("Neural byte-identification failed; trying signatures")

    if nn_match is not None and nn_match.score >= _MIN_MAGIKA_SCORE:
        return nn_match

    sig_match = _legacy_from_bytes(data)
    if sig_match is not None:
        return sig_match

    return nn_match


def get_extension_family(ext: str) -> str | None:
    """
    Map a file extension to its expected content family.

    Parameters
    ----------
    ext:
        Dot-prefixed extension, e.g. ``".png"``.

    Returns
    -------
    str or None
        Family string such as ``"image"`` or ``"executable"``.
    """
    return _EXT_TO_FAMILY.get(ext.lower())


def check_extension_mismatch(
    file_path: Path,
    min_confidence: float = 0.8,
    allow_script_shebang_text_extensions: bool = True,
    shebang_compatible_extensions: set[str] | frozenset[str] | None = None,
) -> tuple[str, str, MagicMatch] | None:
    """
    Flag a file whose extension disagrees with its detected content.

    Both binary-vs-binary and text-format-vs-text-format mismatches are
    reported.  Returns ``None`` when the extension and content agree.

    Parameters
    ----------
    file_path:
        Path to the target file.
    min_confidence:
        Minimum neural-model score required before a mismatch is reported
        (does not apply to byte-signature hits whose score is always 1.0).
    allow_script_shebang_text_extensions:
        When ``True``, a shebang header inside a script-like extension
        (e.g. ``.js`` with ``#!/usr/bin/env node``) is treated as normal.
    shebang_compatible_extensions:
        Override the built-in set of extensions considered shebang-safe.

    Returns
    -------
    tuple[str, str, MagicMatch] or None
        ``(severity, description, match)`` when a mismatch is found.
        *severity* is one of ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``.
    """
    ok_shebang = (
        set(shebang_compatible_extensions)
        if shebang_compatible_extensions is not None
        else set(_SHEBANG_OK_EXTS)
    )

    ext = file_path.suffix.lower()
    if file_path.name.endswith(".tar.gz"):
        ext = ".tar.gz"

    expected = get_extension_family(ext)
    if expected is None:
        return None

    magic = detect_magic(file_path)
    if magic is None:
        return None

    if magic.score < min_confidence:
        return None

    detected = magic.content_family

    # --- group-level comparison ---
    if expected == detected:
        pass  # may still have a label-level issue for text files
    elif expected in _TEXTLIKE_FAMILIES and detected in _TEXTLIKE_FAMILIES:
        pass  # text/code interchange is fine at group level
    else:
        return _group_mismatch_severity(
            file_path, ext, expected, detected, magic,
            allow_script_shebang_text_extensions=allow_script_shebang_text_extensions,
            shebang_compatible_extensions=ok_shebang,
        )

    # --- label-level comparison (text/code only) ---
    if expected in _TEXTLIKE_FAMILIES and detected in _TEXTLIKE_FAMILIES:
        return _label_mismatch(file_path, ext, magic)

    return None


# -- internal mismatch helpers --------------------------------------------- #

def _group_mismatch_severity(
    file_path: Path,
    ext: str,
    expected: str,
    detected: str,
    magic: MagicMatch,
    allow_script_shebang_text_extensions: bool = True,
    shebang_compatible_extensions: set[str] | frozenset[str] | None = None,
) -> tuple[str, str, MagicMatch] | None:
    """Assign a severity string to a family-level content mismatch."""
    fname = file_path.name
    ok_shebang = (
        set(shebang_compatible_extensions)
        if shebang_compatible_extensions is not None
        else set(_SHEBANG_OK_EXTS)
    )

    # Shebangs in script extensions are legitimate
    if (
        allow_script_shebang_text_extensions
        and expected in _TEXTLIKE_FAMILIES
        and detected == "executable"
        and ext in ok_shebang
        and magic.content_type.startswith("executable/script")
    ):
        return None

    # text/code extension hiding an executable -> most severe
    if expected in _TEXTLIKE_FAMILIES and detected == "executable":
        return (
            "CRITICAL",
            f"'{fname}' has a text/code extension ({ext}) but contains "
            f"executable content ({magic.description}), strongly suggesting deception.",
            magic,
        )

    # text/code extension hiding an archive
    if expected in _TEXTLIKE_FAMILIES and detected == "archive":
        return (
            "HIGH",
            f"'{fname}' has a text/code extension ({ext}) but is actually "
            f"an archive ({magic.description}); embedded payloads may be hidden inside.",
            magic,
        )

    # image extension hiding an executable
    if expected == "image" and detected == "executable":
        return (
            "CRITICAL",
            f"'{fname}' appears to be an image ({ext}) but is really "
            f"an executable ({magic.description}), strongly suggesting deception.",
            magic,
        )

    # image extension hiding an archive
    if expected == "image" and detected == "archive":
        return (
            "HIGH",
            f"'{fname}' appears to be an image ({ext}) but is really "
            f"an archive ({magic.description}); embedded files may be concealed.",
            magic,
        )

    # document extension hiding an executable
    if expected == "document" and detected == "executable":
        return (
            "CRITICAL",
            f"'{fname}' appears to be a document ({ext}) but is really "
            f"an executable ({magic.description}), strongly suggesting deception.",
            magic,
        )

    # non-text file with executable payload
    if detected == "executable" and expected in ("image", "document", "font"):
        return (
            "CRITICAL",
            f"'{fname}' claims to be {expected} ({ext}) but holds "
            f"executable content ({magic.description}).",
            magic,
        )

    # catch-all
    return (
        "MEDIUM",
        f"'{fname}' extension ({ext}, expected {expected}) conflicts with "
        f"detected content ({magic.description}, {detected}).",
        magic,
    )


_INNOCUOUS_TEXT_LABELS = frozenset({
    "txt", "txtascii", "txtutf8", "txtutf16",
    "randomascii", "randomtxt", "empty",
})


def _label_mismatch(
    file_path: Path,
    ext: str,
    magic: MagicMatch,
) -> tuple[str, str, MagicMatch] | None:
    """Detect label-level discrepancies within text/code files."""
    wanted = _EXT_LABEL_EXPECTATIONS.get(ext)
    if wanted is None:
        return None

    actual_label = magic.content_type.split("/", 1)[-1] if "/" in magic.content_type else magic.content_type

    if actual_label in wanted:
        return None

    if actual_label in _INNOCUOUS_TEXT_LABELS:
        return None

    fname = file_path.name
    return (
        "MEDIUM",
        f"'{fname}' extension ({ext}) implies one text format but the content "
        f"was identified as a different one: {magic.description} ({actual_label}). "
        f"The file may be misnamed or deliberately obfuscated.",
        magic,
    )
