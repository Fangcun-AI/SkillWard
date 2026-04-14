"""
YARA-X powered content scanner for detecting known-bad byte sequences.
"""

import logging
from pathlib import Path
from typing import Any

import yara_x

_log = logging.getLogger(__name__)

# Upper bound on binary file size that the scanner will process.
_BINARY_SIZE_CEILING = 50 * 1024 * 1024


class YaraScanner:
    """Compiles a directory of ``.yara`` rule files and exposes content and
    file scanning against the resulting ruleset."""

    def __init__(self, rules_dir: Path | None = None, *, max_scan_file_size: int = 50 * 1024 * 1024):
        """Set up the scanner and eagerly compile the ruleset.

        Parameters
        ----------
        rules_dir:
            Folder containing ``.yara`` source files.  Falls back to the
            built-in core pack when *None*.
        max_scan_file_size:
            Files larger than this (bytes) are skipped during binary scanning.
        """
        self._scan_size_limit = max_scan_file_size

        if rules_dir is None:
            from ...data import DATA_DIR
            pack_path = DATA_DIR / "packs" / "core" / "yara"
            if pack_path.is_dir():
                rules_dir = pack_path
            else:
                from ...data import YARA_RULES_DIR
                rules_dir = YARA_RULES_DIR

        self.rules_dir = Path(rules_dir)
        self.rules: yara_x.Rules | None = None
        self._compile_all()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compile_all(self) -> None:
        """Find and compile every ``.yara`` file in :attr:`rules_dir`."""
        if not self.rules_dir.exists():
            raise FileNotFoundError(f"YARA rules directory not found: {self.rules_dir}")

        sources = list(self.rules_dir.glob("*.yara"))
        if not sources:
            raise FileNotFoundError(f"No .yara files found in {self.rules_dir}")

        comp = yara_x.Compiler()
        try:
            for src_file in sources:
                comp.new_namespace(src_file.stem)
                comp.add_source(src_file.read_text(encoding="utf-8"), origin=str(src_file))
            self.rules = comp.build()
        except yara_x.CompileError as exc:
            raise RuntimeError(f"Failed to compile YARA rules: {exc}")

    @staticmethod
    def _build_rule_meta(rule) -> dict[str, Any]:
        """Extract metadata fields from a YARA-X matching rule object."""
        return {
            "rule_name": rule.identifier,
            "namespace": rule.namespace,
            "tags": list(rule.tags),
            "meta": dict(rule.metadata),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_content(self, content: str, file_path: str | None = None) -> list[dict[str, Any]]:
        """Evaluate all compiled rules against UTF-8 text *content*.

        Parameters
        ----------
        content:
            The text to scan.
        file_path:
            An optional identifier used in result records for traceability.

        Returns
        -------
        list[dict]
            One entry per matching rule, each containing ``rule_name``,
            ``namespace``, ``file_path``, ``meta``, and ``strings``.
        """
        if self.rules is None:
            return []

        encoded = content.encode("utf-8")
        detections: list[dict[str, Any]] = []

        try:
            results = self.rules.scan(encoded)
        except yara_x.ScanError as exc:
            _log.warning("YARA scanning error: %s", exc)
            return []

        for matched_rule in results.matching_rules:
            meta_block = self._build_rule_meta(matched_rule)
            string_hits: list[dict[str, Any]] = []

            for pat in matched_rule.patterns:
                for hit in pat.matches:
                    raw_bytes = encoded[hit.offset: hit.offset + hit.length]
                    line_idx = encoded[:hit.offset].count(b"\n") + 1

                    # Derive the source line containing the match
                    sol = encoded.rfind(b"\n", 0, hit.offset) + 1
                    eol = encoded.find(b"\n", hit.offset)
                    if eol == -1:
                        eol = len(encoded)
                    source_line = encoded[sol:eol].decode("utf-8", errors="ignore").strip()

                    string_hits.append({
                        "identifier": pat.identifier,
                        "offset": hit.offset,
                        "matched_data": raw_bytes.decode("utf-8", errors="ignore"),
                        "line_number": line_idx,
                        "line_content": source_line,
                    })

            detections.append({
                "rule_name": matched_rule.identifier,
                "namespace": matched_rule.namespace,
                "file_path": file_path,
                "meta": meta_block,
                "strings": string_hits,
            })

        return detections

    def scan_file(self, file_path: Path | str, display_path: str | None = None) -> list[dict[str, Any]]:
        """Scan a single file on disk.

        Text files (valid UTF-8) are routed through :meth:`scan_content` so
        that line-level location data is available.  Files that fail UTF-8
        decoding are handled via a raw-bytes fallback path.

        Parameters
        ----------
        file_path:
            On-disk location of the target file.
        display_path:
            Cosmetic path surfaced in result records instead of *file_path*.

        Returns
        -------
        list[dict]
            Same structure as :meth:`scan_content`.
        """
        target = str(file_path)
        label = display_path if display_path is not None else target

        try:
            with open(target, encoding="utf-8") as fh:
                text = fh.read()
            return self.scan_content(text, label)
        except UnicodeDecodeError:
            pass
        except OSError as exc:
            _log.warning("Could not read file %s: %s", target, exc)
            return []

        return self._handle_binary_scan(target, label)

    def _handle_binary_scan(self, file_path: str, display_path: str) -> list[dict[str, Any]]:
        """Perform a raw-bytes scan on a non-UTF-8 file.

        Since the content is not text, line numbers are set to ``0`` and the
        line_content field describes the byte offset instead.
        """
        if self.rules is None:
            return []

        fsize = Path(file_path).stat().st_size
        if fsize > self._scan_size_limit:
            _log.warning("Skipping %s: file size %d bytes exceeds scan limit", file_path, fsize)
            return []

        detections: list[dict[str, Any]] = []
        try:
            with open(file_path, "rb") as fh:
                raw = fh.read()

            scanner = yara_x.Scanner(self.rules)
            results = scanner.scan(raw)

            for matched_rule in results.matching_rules:
                meta_block = self._build_rule_meta(matched_rule)
                string_hits: list[dict[str, Any]] = []

                for pat in matched_rule.patterns:
                    for hit in pat.matches:
                        raw_bytes = raw[hit.offset: hit.offset + hit.length]
                        string_hits.append({
                            "identifier": pat.identifier,
                            "offset": hit.offset,
                            "matched_data": raw_bytes.decode("utf-8", errors="ignore"),
                            "line_number": 0,
                            "line_content": f"[binary file at byte offset {hit.offset}]",
                        })

                detections.append({
                    "rule_name": matched_rule.identifier,
                    "namespace": matched_rule.namespace,
                    "file_path": display_path,
                    "meta": meta_block,
                    "strings": string_hits,
                })

        except yara_x.ScanError as exc:
            _log.warning("YARA binary scanning error for %s: %s", file_path, exc)

        return detections

    def get_loaded_rules(self) -> list[str]:
        """Return the namespace identifiers of all compiled rule files."""
        if self.rules is None:
            return []
        return [f.stem for f in self.rules_dir.glob("*.yara")]
