"""
Regex-based detection engine for security rule evaluation.
"""

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from ...core.models import Severity, ThreatCategory

_log = logging.getLogger(__name__)

# Strips the interior of bracket-delimited character classes so that a
# subsequent check for literal ``\\n`` only fires on genuine cross-line
# anchors rather than negated-newline classes like ``[^\\n]``.
_BRACKET_CLASS_PAT = re.compile(r"\[[^\]]*\]")


class SecurityRule:
    """A single detection rule backed by one or more regex patterns."""

    def __init__(self, rule_data: dict[str, Any]):
        self.id = rule_data["id"]
        self.category = ThreatCategory(rule_data["category"])
        self.severity = Severity(rule_data["severity"])
        self.patterns = rule_data["patterns"]
        self.exclude_patterns = rule_data.get("exclude_patterns", [])
        self.file_types = rule_data.get("file_types", [])
        self.description = rule_data["description"]
        self.remediation = rule_data.get("remediation", "")

        # Pre-compile detection patterns
        self._compiled_detect: list[re.Pattern] = []
        for raw in self.patterns:
            try:
                self._compiled_detect.append(re.compile(raw))
            except re.error as err:
                _log.warning("Pattern compilation failed for rule %s ('%s'): %s", self.id, raw, err)

        # Pre-compile exclusion patterns
        self._compiled_excl: list[re.Pattern] = []
        for raw in self.exclude_patterns:
            try:
                self._compiled_excl.append(re.compile(raw))
            except re.error as err:
                _log.warning("Exclusion pattern failed for rule %s ('%s'): %s", self.id, raw, err)

    def matches_file_type(self, file_type: str) -> bool:
        """Return ``True`` when this rule should be applied to *file_type*."""
        return (not self.file_types) or (file_type in self.file_types)

    def scan_content(self, content: str, file_path: str | None = None) -> list[dict[str, Any]]:
        """Run every detection pattern against *content* and collect hits.

        A two-phase approach is used: the fast path iterates line-by-line for
        single-line patterns; a second sweep handles patterns that genuinely
        span multiple lines (those containing ``\\n`` outside bracket classes).

        Returns
        -------
        list[dict]
            Each entry contains ``line_number``, ``line_content``,
            ``matched_pattern``, ``matched_text``, and ``file_path``.
        """
        all_lines = content.split("\n")
        hits: list[dict[str, Any]] = []

        # --- Phase 1: per-line matching ---
        for idx, line_text in enumerate(all_lines, 1):
            # Check exclusion list first
            if any(ep.search(line_text) for ep in self._compiled_excl):
                continue

            for pat in self._compiled_detect:
                m = pat.search(line_text)
                if m is not None:
                    hits.append({
                        "line_number": idx,
                        "line_content": line_text.strip(),
                        "matched_pattern": pat.pattern,
                        "matched_text": m.group(0),
                        "file_path": file_path,
                    })

        # --- Phase 2: multiline patterns ---
        for pat in self._compiled_detect:
            cleaned = _BRACKET_CLASS_PAT.sub("", pat.pattern)
            if "\\n" not in cleaned:
                continue

            for m in pat.finditer(content):
                captured = m.group(0)
                if any(ep.search(captured) for ep in self._compiled_excl):
                    continue

                origin_line = content.count("\n", 0, m.start()) + 1
                snippet = (
                    all_lines[origin_line - 1].strip()
                    if 0 < origin_line <= len(all_lines)
                    else ""
                )
                hits.append({
                    "line_number": origin_line,
                    "line_content": snippet,
                    "matched_pattern": pat.pattern,
                    "matched_text": captured[:200],
                    "file_path": file_path,
                })

        return hits


class RuleLoader:
    """Reads security rule definitions from YAML and provides indexed access."""

    def __init__(self, rules_file: Path | None = None):
        """Prepare the loader.

        Parameters
        ----------
        rules_file:
            Either a single YAML file or a directory holding multiple
            ``*.yaml`` rule files.  When *None* the built-in core
            signature pack is used.
        """
        if rules_file is None:
            from ...data import DATA_DIR
            rules_file = DATA_DIR / "packs" / "core" / "signatures"

        self.rules_file = rules_file
        self.rules: list[SecurityRule] = []
        self._index_by_id: dict[str, SecurityRule] = {}
        self._index_by_cat: dict[ThreatCategory, list[SecurityRule]] = {}

    def load_rules(self) -> list[SecurityRule]:
        """Parse every YAML source and build the rule collection.

        Returns
        -------
        list[SecurityRule]
            All successfully loaded rules.

        Raises
        ------
        RuntimeError
            On I/O errors or unexpected YAML structure.
        """
        source = Path(self.rules_file)

        if source.is_dir():
            yaml_paths = sorted(source.glob("*.yaml"))
            if not yaml_paths:
                raise RuntimeError(f"No .yaml rule files found in {source}")

            raw_entries: list[dict] = []
            for yp in yaml_paths:
                try:
                    with open(yp, encoding="utf-8") as fh:
                        payload = yaml.safe_load(fh)
                except Exception as exc:
                    raise RuntimeError(f"Failed to load rules from {yp}: {exc}") from exc
                if not isinstance(payload, list):
                    raise RuntimeError(f"Failed to load rules from {yp}: expected a YAML list of rule objects")
                raw_entries.extend(payload)
        else:
            try:
                with open(source, encoding="utf-8") as fh:
                    raw_entries = yaml.safe_load(fh)
            except Exception as exc:
                raise RuntimeError(f"Failed to load rules from {source}: {exc}")
            if not isinstance(raw_entries, list):
                raise RuntimeError(f"Failed to load rules from {source}: expected a YAML list of rule objects")

        # Reset indices
        self.rules = []
        self._index_by_id = {}
        self._index_by_cat = {}

        for entry in raw_entries:
            try:
                rule_obj = SecurityRule(entry)
            except Exception as exc:
                _log.warning("Failed to load rule %s: %s", entry.get("id", "unknown"), exc)
                continue

            self.rules.append(rule_obj)
            self._index_by_id[rule_obj.id] = rule_obj
            self._index_by_cat.setdefault(rule_obj.category, []).append(rule_obj)

        return self.rules

    def get_rule(self, rule_id: str) -> SecurityRule | None:
        """Look up a single rule by its identifier string."""
        return self._index_by_id.get(rule_id)

    def get_rules_for_file_type(self, file_type: str) -> list[SecurityRule]:
        """Return every rule whose file-type filter includes *file_type*."""
        return [r for r in self.rules if r.matches_file_type(file_type)]

    def get_rules_for_category(self, category: ThreatCategory) -> list[SecurityRule]:
        """Return all rules belonging to a given threat category."""
        return self._index_by_cat.get(category, [])
