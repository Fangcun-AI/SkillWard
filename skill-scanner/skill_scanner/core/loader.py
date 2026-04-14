"""
Ingestion and parsing of agent skill packages from disk.
"""

import logging
import re
import sys
from pathlib import Path

import frontmatter

from ..utils.file_utils import get_file_type
from .exceptions import SkillLoadError
from .models import Skill, SkillFile, SkillManifest

_log = logging.getLogger(__name__)

# Standard library and popular third-party modules that should never be treated
# as local file references when encountered in import statements.
_WELL_KNOWN_PACKAGES = frozenset({
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "pydantic",
    "boto3",
    "httpx",
    "aiohttp",
    "celery",
    "sqlalchemy",
    "pytest",
    "click",
    "rich",
    "typer",
    "litellm",
    "openai",
    "anthropic",
})

# Fields that belong to the manifest schema itself and should not be collected
# into the free-form metadata bucket.
_RESERVED_MANIFEST_KEYS = frozenset([
    "name",
    "description",
    "license",
    "compatibility",
    "allowed-tools",
    "allowed_tools",
    "metadata",
    "disable-model-invocation",
    "disable_model_invocation",
])


class SkillLoader:
    """Reads an agent skill directory, parses its manifest, and catalogues
    every file contained within the package boundary."""

    def __init__(self, max_file_size_mb: int = 10, *, max_file_size_bytes: int | None = None):
        """Set up the loader with a content-size ceiling.

        Parameters
        ----------
        max_file_size_mb:
            Upper bound (in megabytes) for files to read into memory.
            Ignored when *max_file_size_bytes* is supplied.
        max_file_size_bytes:
            Exact upper bound in bytes.  Takes priority over the MB variant.
        """
        self._size_cap = (
            max_file_size_bytes
            if max_file_size_bytes is not None
            else max_file_size_mb * 1024 * 1024
        )

    def load_skill(self, skill_directory: str | Path, *, lenient: bool = False) -> Skill:
        """Ingest a full skill package rooted at *skill_directory*.

        Parameters
        ----------
        skill_directory:
            Filesystem path to the skill root folder.
        lenient:
            If ``True``, missing or malformed manifest fields are patched with
            sensible defaults rather than raising an error.

        Returns
        -------
        Skill
            A fully populated skill descriptor.

        Raises
        ------
        SkillLoadError
            When the directory or its manifest cannot be processed (strict mode).
        """
        pkg_path = Path(skill_directory) if not isinstance(skill_directory, Path) else skill_directory

        if not pkg_path.exists():
            raise SkillLoadError(f"Skill directory does not exist: {pkg_path}")
        if not pkg_path.is_dir():
            raise SkillLoadError(f"Path is not a directory: {pkg_path}")

        md_file = pkg_path / "SKILL.md"
        if not md_file.exists():
            raise SkillLoadError(f"SKILL.md not found in {pkg_path}")

        parsed_manifest, body_text = self._parse_skill_md(md_file, lenient=lenient)
        catalogued_files = self._discover_files(pkg_path)
        mentioned_paths = self._extract_referenced_files(body_text)

        return Skill(
            directory=pkg_path,
            manifest=parsed_manifest,
            skill_md_path=md_file,
            instruction_body=body_text,
            files=catalogued_files,
            referenced_files=mentioned_paths,
        )

    def _parse_skill_md(self, skill_md_path: Path, *, lenient: bool = False) -> tuple[SkillManifest, str]:
        """Interpret the YAML front matter and markdown body of a SKILL.md file.

        Parameters
        ----------
        skill_md_path:
            Absolute or relative path to the SKILL.md file.
        lenient:
            Fill in placeholder values for absent required fields instead
            of raising.

        Returns
        -------
        tuple
            ``(SkillManifest, instruction_body_text)``

        Raises
        ------
        SkillLoadError
            On I/O or parsing failures in strict mode.
        """
        try:
            raw_text = skill_md_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SkillLoadError(f"Failed to read SKILL.md: {exc}")

        try:
            parsed = frontmatter.loads(raw_text)
            header = parsed.metadata
            body = parsed.content
        except Exception as exc:
            if not lenient:
                raise SkillLoadError(f"Failed to parse YAML frontmatter: {exc}")
            _log.warning("YAML frontmatter unparseable in %s: %s – falling back to raw body", skill_md_path, exc)
            header = {}
            body = raw_text

        # --- required fields ---
        if "name" not in header:
            if not lenient:
                raise SkillLoadError("SKILL.md missing required field: name")
            header["name"] = skill_md_path.parent.name
            _log.warning("SKILL.md missing 'name'; using directory name: %s", header["name"])

        if "description" not in header:
            if not lenient:
                raise SkillLoadError("SKILL.md missing required field: description")
            header["description"] = "(no description)"
            _log.warning("SKILL.md missing 'description'; using placeholder")

        # --- extra metadata bucket ---
        if "metadata" in header and isinstance(header["metadata"], dict):
            extra_meta = header["metadata"]
        else:
            extra_meta = {k: v for k, v in header.items() if k not in _RESERVED_MANIFEST_KEYS}
            if not extra_meta:
                extra_meta = None

        # --- model-invocation flag (kebab-case or snake_case) ---
        disable_flag = header.get("disable-model-invocation")
        if disable_flag is None:
            disable_flag = header.get("disable_model_invocation", False)

        # Force name and description to plain strings
        skill_name = header["name"] if isinstance(header["name"], str) else str(header["name"])
        skill_desc = header["description"] if isinstance(header["description"], str) else str(header["description"])

        manifest = SkillManifest(
            name=skill_name,
            description=skill_desc,
            license=header.get("license"),
            compatibility=header.get("compatibility"),
            allowed_tools=header.get("allowed-tools") or header.get("allowed_tools"),
            metadata=extra_meta,
            disable_model_invocation=bool(disable_flag),
        )

        return manifest, body

    def _discover_files(self, skill_directory: Path) -> list[SkillFile]:
        """Walk *skill_directory* recursively and build a catalogue of every
        regular file inside the package boundary.

        Symlinks and paths that escape the resolved root are silently skipped.
        Only ``.git`` sub-trees are excluded; other hidden files and
        ``__pycache__`` directories are included so downstream analyzers can
        flag them.

        Parameters
        ----------
        skill_directory:
            Root of the skill package.

        Returns
        -------
        list[SkillFile]
            One entry per discovered file.
        """
        resolved_root = skill_directory.resolve()
        result: list[SkillFile] = []

        for entry in skill_directory.rglob("*"):
            if not entry.is_file() or entry.is_symlink():
                continue

            try:
                abs_entry = entry.resolve()
                if not abs_entry.is_relative_to(resolved_root):
                    continue
            except (OSError, ValueError):
                continue

            # Ignore .git internals but keep everything else
            relative_parts = entry.relative_to(skill_directory).parts
            if ".git" in relative_parts:
                continue

            rel_str = str(entry.relative_to(skill_directory))
            ftype = get_file_type(entry)
            nbytes = entry.stat().st_size

            text_content = None
            if nbytes < self._size_cap and ftype != "binary":
                try:
                    text_content = entry.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    ftype = "binary"

            result.append(
                SkillFile(
                    path=entry,
                    relative_path=rel_str,
                    file_type=ftype,
                    content=text_content,
                    size_bytes=nbytes,
                )
            )

        return result

    def _extract_referenced_files(self, instruction_body: str) -> list[str]:
        """Scan the instruction markdown for paths that look like file
        references and return a deduplicated list.

        Recognized patterns include markdown links, prose directives
        (``see``, ``refer to``, etc.), script invocation commands,
        ``@reference:`` / ``include:`` directives, bare import statements,
        and ``references/`` / ``assets/`` path fragments.

        Parameters
        ----------
        instruction_body:
            Raw markdown text from the SKILL.md body.

        Returns
        -------
        list[str]
            Unique referenced file paths (order not guaranteed).
        """
        found: set[str] = set()

        # Markdown-style links: [label](target)
        for _, target in re.findall(r"\[([^\]]+)\]\(([^\)]+)\)", instruction_body):
            if not target.startswith(("http://", "https://", "ftp://", "#")):
                found.add(target)

        # Prose directives with quoted/backticked file names
        for hit in re.findall(
            r"(?:see|refer to|check|read)\s+[`'\"]([A-Za-z0-9_\-./]+\.(?:md|py|sh|txt))[`'\"]",
            instruction_body,
            re.IGNORECASE,
        ):
            found.add(hit)

        # Execution directives
        for hit in re.findall(
            r"(?:run|execute|invoke)\s+([A-Za-z0-9_\-./]+\.(?:py|sh))",
            instruction_body,
            re.IGNORECASE,
        ):
            found.add(hit)

        # @reference: directives
        for hit in re.findall(r"@reference:\s*([A-Za-z0-9_\-./]+)", instruction_body, re.IGNORECASE):
            found.add(hit)

        # include/import/load: directives
        for hit in re.findall(
            r"(?:include|import|load):\s*([A-Za-z0-9_\-./]+\.(?:md|py|sh|txt|yaml|json))",
            instruction_body,
            re.IGNORECASE,
        ):
            found.add(hit)

        # Bare Python imports that might be local modules
        stdlib_set = getattr(sys, "stdlib_module_names", set())
        ignore_set = stdlib_set | _WELL_KNOWN_PACKAGES
        for mod_name in re.findall(r"(?:from|import)\s+([A-Za-z0-9_]+)\s", instruction_body):
            if mod_name.lower() not in ignore_set:
                found.add(f"{mod_name}.py")

        # Paths under references/ / assets/ / templates/
        for fragment in re.findall(r"(?:references|assets|templates)/([A-Za-z0-9_\-./]+)", instruction_body):
            found.add(f"references/{fragment}")
            found.add(f"assets/{fragment}")
            found.add(f"templates/{fragment}")

        return list(found)

    def extract_references_from_file(self, file_path: Path, content: str) -> list[str]:
        """Locate file references inside *content* based on the file's
        extension.

        Parameters
        ----------
        file_path:
            The on-disk path (used only for its suffix).
        content:
            Full text of the file.

        Returns
        -------
        list[str]
            Deduplicated list of referenced paths.
        """
        found: set[str] = set()
        ext = file_path.suffix.lower()

        if ext in (".md", ".markdown"):
            found.update(self._extract_referenced_files(content))

        elif ext == ".py":
            abs_imports = re.findall(r"^from\s+([A-Za-z0-9_.]+)\s+import", content, re.MULTILINE)
            rel_imports = re.findall(r"^from\s+\.([A-Za-z0-9_.]*)\s+import", content, re.MULTILINE)

            stdlib_set = getattr(sys, "stdlib_module_names", set())
            ignore_set = stdlib_set | _WELL_KNOWN_PACKAGES
            for module_path in abs_imports:
                top = module_path.split(".")[0]
                if top.lower() not in ignore_set:
                    found.add(f"{top}.py")
            for module_path in rel_imports:
                if module_path:
                    found.add(f"{module_path}.py")

        elif ext in (".sh", ".bash"):
            for sourced in re.findall(r"(?:source|\.)\s+([A-Za-z0-9_\-./]+\.(?:sh|bash))", content):
                found.add(sourced)

        return list(found)


def load_skill(
    skill_directory: str | Path, max_file_size_mb: int = 10, *, max_file_size_bytes: int | None = None
) -> Skill:
    """Shorthand helper that creates a :class:`SkillLoader` and immediately
    ingests the given directory.

    Parameters
    ----------
    skill_directory:
        Root folder of the skill package.
    max_file_size_mb:
        Per-file size ceiling in megabytes (ignored when *max_file_size_bytes*
        is provided).
    max_file_size_bytes:
        Exact per-file ceiling in bytes.

    Returns
    -------
    Skill
        The fully loaded skill descriptor.
    """
    loader = SkillLoader(max_file_size_mb=max_file_size_mb, max_file_size_bytes=max_file_size_bytes)
    return loader.load_skill(skill_directory)
