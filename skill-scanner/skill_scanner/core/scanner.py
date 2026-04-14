"""Skill analysis orchestration engine."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any

from .analyzability import AnalyzabilityReport, compute_analyzability
from .analyzer_factory import build_core_analyzers
from .analyzers.base import BaseAnalyzer
from .extractors.content_extractor import ContentExtractor
from .loader import SkillLoader, SkillLoadError
from .models import Finding, Report, ScanResult, Severity, Skill, ThreatCategory
from .scan_policy import ScanPolicy

_log = logging.getLogger(__name__)

_TRIVIAL_TOKENS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "can", "may", "might", "must", "shall", "to", "of", "in",
    "for", "on", "with", "at", "by", "from", "as", "into", "through",
    "and", "or", "but", "if", "then", "else", "when", "up", "down",
    "out", "that", "this", "these", "those", "it", "its", "they",
    "them", "their",
})


class SkillScanner:
    """Primary entry point that coordinates multiple analyzers against skill packages."""

    def __init__(
        self,
        analyzers: list[BaseAnalyzer] | None = None,
        use_virustotal: bool = False,
        virustotal_api_key: str | None = None,
        virustotal_upload_files: bool = False,
        policy: ScanPolicy | None = None,
    ):
        """Set up the scanner with the given analyzer chain and configuration.

        Parameters
        ----------
        analyzers:
            Explicit list of analyzer instances.  When *None*, the default
            static analysis stack is constructed automatically.
        use_virustotal:
            Activate the VirusTotal binary-file checker.
        virustotal_api_key:
            Credential for the VT v3 API (required when *use_virustotal* is set).
        virustotal_upload_files:
            When *True*, unknown binaries are uploaded to VT for scanning.
            Otherwise only pre-existing hash reports are queried.
        policy:
            Organisational scan policy.  Falls back to built-in defaults.
        """
        self.policy = policy or ScanPolicy.default()

        if analyzers is None:
            self.analyzers: list[BaseAnalyzer] = build_core_analyzers(self.policy)

            if use_virustotal and virustotal_api_key:
                from .analyzers.virustotal_analyzer import VirusTotalAnalyzer

                vt = VirusTotalAnalyzer(
                    api_key=virustotal_api_key,
                    enabled=True,
                    upload_files=virustotal_upload_files,
                )
                self.analyzers.append(vt)
        else:
            self.analyzers = analyzers

        for a in self.analyzers:
            if a.get_name() == "meta_analyzer":
                _log.warning(
                    "MetaAnalyzer is present in the analyzer list but cannot "
                    "emit findings through the standard analyze() path.  It "
                    "will be ignored during scanning.  Invoke "
                    "MetaAnalyzer.analyze_with_findings() separately."
                )
                break

        max_bytes = self.policy.file_limits.max_loader_file_size_bytes
        self.loader = SkillLoader(max_file_size_bytes=max_bytes)
        self.content_extractor = ContentExtractor()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan_skill(self, skill_directory: str | Path, *, lenient: bool = False) -> ScanResult:
        """Analyse a single skill package located at *skill_directory*.

        Parameters
        ----------
        skill_directory:
            Filesystem path that contains the skill manifest and resources.
        lenient:
            When *True*, malformed YAML or missing manifest fields are
            tolerated instead of raising.

        Returns
        -------
        ScanResult
            Aggregated findings, timing data, and analyzability metrics.

        Raises
        ------
        SkillLoadError
            If the skill cannot be parsed and *lenient* is *False*.
        """
        skill_directory = Path(skill_directory) if not isinstance(skill_directory, Path) else skill_directory
        skill = self.loader.load_skill(skill_directory, lenient=lenient)
        return self._execute_pipeline(skill, skill_directory)

    def scan_directory(
        self,
        skills_directory: str | Path,
        recursive: bool = False,
        check_overlap: bool = False,
        *,
        lenient: bool = False,
        max_workers: int = 1,
    ) -> Report:
        """Analyse every skill package found under *skills_directory*.

        Parameters
        ----------
        skills_directory:
            Root directory to search for skill packages.
        recursive:
            Descend into sub-directories when looking for SKILL.md files.
        check_overlap:
            Run cross-skill description-similarity checks.
        lenient:
            Tolerate broken manifests.
        max_workers:
            Thread pool width.  ``1`` means sequential execution.

        Returns
        -------
        Report
            Combined report spanning all discovered skills.
        """
        skills_directory = Path(skills_directory) if not isinstance(skills_directory, Path) else skills_directory

        if not skills_directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {skills_directory}")

        dirs = self._locate_skill_roots(skills_directory, recursive)
        report = Report()
        collected_skills: list[Skill] = []

        if max_workers > 1:
            self._process_dirs_threaded(dirs, report, collected_skills, check_overlap, lenient, max_workers)
        else:
            self._process_dirs_sequential(dirs, report, collected_skills, check_overlap, lenient)

        self._perform_cross_skill_checks(report, collected_skills, check_overlap)
        return report

    def add_analyzer(self, analyzer: BaseAnalyzer):
        """Register an additional analyzer in the pipeline."""
        self.analyzers.append(analyzer)

    def list_analyzers(self) -> list[str]:
        """Return the names of all currently registered analyzers."""
        return [a.get_name() for a in self.analyzers]

    # ------------------------------------------------------------------
    # Internal: full pipeline on a single loaded skill
    # ------------------------------------------------------------------

    def _execute_pipeline(self, skill: Skill, skill_directory: Path) -> ScanResult:
        """Run every registered analyzer against *skill* and post-process results.

        The pipeline has two phases.  Phase 1 runs deterministic (non-LLM)
        analyzers.  Phase 2 feeds their output as contextual enrichment into
        any LLM-backed analyzers.
        """
        t0 = time.time()

        extraction = self.content_extractor.extract_skill_archives(skill.files)
        if extraction.extracted_files:
            skill.files.extend(extraction.extracted_files)

        try:
            collected: list[Finding] = list(extraction.findings)
            used_analyzers: list[str] = []
            failed_analyzers: list[dict[str, str]] = []
            vt_validated: set[str] = set()
            deferred_llm: list[BaseAnalyzer] = []
            orphan_scripts: list[str] = []
            llm_meta: dict[str, Any] = {}

            # --- Phase 1: deterministic analyzers ---
            for analyzer in self.analyzers:
                if analyzer.get_name() in ("llm_analyzer", "meta_analyzer"):
                    deferred_llm.append(analyzer)
                    continue

                phase1_findings = analyzer.analyze(skill)
                collected.extend(phase1_findings)
                used_analyzers.append(analyzer.get_name())

                if hasattr(analyzer, "validated_binary_files"):
                    vt_validated.update(analyzer.validated_binary_files)

                if hasattr(analyzer, "get_unreferenced_scripts"):
                    orphan_scripts = analyzer.get_unreferenced_scripts()

            # --- Phase 2: LLM-backed analyzers (with enrichment) ---
            if deferred_llm:
                has_context = self._has_enrichment_signal(skill, collected, orphan_scripts)
                for analyzer in deferred_llm:
                    if hasattr(analyzer, "set_enrichment_context") and has_context:
                        ext_counts: dict[str, int] = {}
                        for sf in skill.files:
                            ext_counts[sf.file_type] = ext_counts.get(sf.file_type, 0) + 1

                        magic_issues = [
                            f.file_path
                            for f in collected
                            if f.rule_id and "MAGIC" in f.rule_id and f.file_path
                        ]
                        top_static = [
                            f"{f.rule_id}: {f.title}"
                            for f in collected
                            if f.severity in (Severity.CRITICAL, Severity.HIGH)
                        ][:10]

                        analyzer.set_enrichment_context(
                            file_inventory={
                                "total_files": len(skill.files),
                                "types": ext_counts,
                                "unreferenced_scripts": orphan_scripts,
                            },
                            magic_mismatches=magic_issues or None,
                            static_findings_summary=top_static or None,
                        )

                    llm_findings = analyzer.analyze(skill)
                    collected.extend(llm_findings)
                    used_analyzers.append(analyzer.get_name())

                    if hasattr(analyzer, "last_error") and analyzer.last_error:
                        failed_analyzers.append({
                            "analyzer": analyzer.get_name(),
                            "error": analyzer.last_error,
                        })

                    if hasattr(analyzer, "last_overall_assessment"):
                        llm_meta["llm_overall_assessment"] = analyzer.last_overall_assessment
                        llm_meta["llm_primary_threats"] = getattr(analyzer, "last_primary_threats", [])

            # --- Post-processing ---
            # Suppress binary warnings for VT-validated files
            if vt_validated:
                collected = [
                    f for f in collected
                    if not (f.rule_id == "BINARY_FILE_DETECTED" and f.file_path in vt_validated)
                ]

            # Enforce globally disabled rules
            if self.policy.disabled_rules:
                collected = [f for f in collected if f.rule_id not in self.policy.disabled_rules]

            self._override_severities(collected)

            analyzability = compute_analyzability(skill, policy=self.policy)
            collected.extend(self._emit_analyzability_findings(analyzability))

            collected = self._deduplicate(collected)
            self._tag_cooccurring_rules(collected)

            scan_meta = self._compute_policy_digest()
            if llm_meta:
                scan_meta.update(llm_meta)
            self._stamp_policy_on_findings(collected, scan_meta)

        finally:
            self.content_extractor.cleanup()

        elapsed = time.time() - t0

        return ScanResult(
            skill_name=skill.name,
            skill_directory=str(skill_directory.absolute()),
            findings=collected,
            scan_duration_seconds=elapsed,
            analyzers_used=used_analyzers,
            analyzers_failed=failed_analyzers,
            analyzability_score=analyzability.score,
            analyzability_details=analyzability.to_dict(),
            scan_metadata=scan_meta,
        )

    # ------------------------------------------------------------------
    # Analyzability -> Finding promotion
    # ------------------------------------------------------------------

    def _emit_analyzability_findings(self, report: AnalyzabilityReport) -> list[Finding]:
        """Convert low-analyzability conditions into actionable findings.

        Uninspectable content is flagged rather than silently trusted
        (fail-closed posture).
        """
        out: list[Finding] = []

        binary_rule_active = "UNANALYZABLE_BINARY" not in self.policy.disabled_rules
        skip_inert = self.policy.file_classification.skip_inert_extensions
        inert_set = set(self.policy.file_classification.inert_extensions) if skip_inert else set()
        doc_markers = set(self.policy.rule_scoping.doc_path_indicators)

        for fd in report.file_details:
            if not (fd.is_analyzable is False and fd.skip_reason and "Binary file" in fd.skip_reason):
                continue
            if not binary_rule_active:
                continue

            ext = Path(fd.relative_path).suffix.lower()
            if skip_inert and ext in inert_set:
                continue

            path_parts = Path(fd.relative_path).parts
            if any(seg.lower() in doc_markers for seg in path_parts):
                continue

            out.append(Finding(
                id=f"UNANALYZABLE_BINARY_{fd.relative_path}",
                rule_id="UNANALYZABLE_BINARY",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.MEDIUM,
                title="Unanalyzable binary file",
                description=(
                    f"Binary file '{fd.relative_path}' cannot be inspected by the scanner. "
                    f"Reason: {fd.skip_reason}. Binary files resist static analysis "
                    f"and may contain hidden functionality."
                ),
                file_path=fd.relative_path,
                remediation=(
                    "Replace binary files with source code, or submit the binary "
                    "to VirusTotal for independent verification (--use-virustotal)."
                ),
                analyzer="analyzability",
                metadata={"skip_reason": fd.skip_reason, "weight": fd.weight},
            ))

        if "LOW_ANALYZABILITY" in self.policy.disabled_rules:
            return out

        if report.risk_level == "HIGH":
            out.append(Finding(
                id="LOW_ANALYZABILITY_CRITICAL",
                rule_id="LOW_ANALYZABILITY",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.HIGH,
                title="Critically low analyzability score",
                description=(
                    f"Only {report.score:.0f}% of skill content could be analyzed. "
                    f"{report.unanalyzable_files} of {report.total_files} files are opaque "
                    f"to the scanner. The safety assessment has low confidence."
                ),
                remediation=(
                    "Replace opaque files (binaries, encrypted content) with "
                    "inspectable source code to improve scan confidence."
                ),
                analyzer="analyzability",
                metadata={
                    "score": round(report.score, 1),
                    "unanalyzable_files": report.unanalyzable_files,
                    "total_files": report.total_files,
                    "risk_level": report.risk_level,
                },
            ))
        elif report.risk_level == "MEDIUM":
            out.append(Finding(
                id="LOW_ANALYZABILITY_MODERATE",
                rule_id="LOW_ANALYZABILITY",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.MEDIUM,
                title="Moderate analyzability score",
                description=(
                    f"Only {report.score:.0f}% of skill content could be analyzed. "
                    f"{report.unanalyzable_files} of {report.total_files} files are opaque "
                    f"to the scanner. Some content could not be verified as safe."
                ),
                remediation="Review opaque files and replace with inspectable formats where possible.",
                analyzer="analyzability",
                metadata={
                    "score": round(report.score, 1),
                    "unanalyzable_files": report.unanalyzable_files,
                    "total_files": report.total_files,
                    "risk_level": report.risk_level,
                },
            ))

        return out

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _has_enrichment_signal(
        skill: Skill,
        findings: list[Finding],
        orphan_scripts: list[str] | None = None,
    ) -> bool:
        """Decide whether Phase-1 output warrants enriching the LLM context."""
        if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
            return True
        if orphan_scripts:
            return True
        return any(f.rule_id and "MAGIC" in (f.rule_id or "") for f in findings)

    # ------------------------------------------------------------------
    # Severity overrides
    # ------------------------------------------------------------------

    def _override_severities(self, findings: list[Finding]) -> None:
        """Apply per-rule severity overrides declared in the scan policy."""
        for f in findings:
            replacement = self.policy.get_severity_override(f.rule_id)
            if replacement is None:
                continue
            try:
                f.severity = Severity(replacement)
            except (ValueError, KeyError):
                _log.warning("Ignoring invalid severity override '%s' for rule %s", replacement, f.rule_id)

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _compact_snippet(snippet: str | None) -> str:
        """Produce a normalised snippet suitable for dedup key construction."""
        if not snippet:
            return ""
        return re.sub(r"\s+", " ", snippet.lower()).strip()[:240]

    @staticmethod
    def _sev_weight(severity: Severity) -> int:
        """Map severity to a numeric weight for comparison."""
        _weights = {
            Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
            Severity.LOW: 2, Severity.INFO: 1, Severity.SAFE: 0,
        }
        return _weights.get(severity, 0)

    def _analyzer_priority(self, name: str | None) -> int:
        """Compute policy-driven precedence for an analyzer name."""
        if not name:
            return 0
        lower = name.lower()
        preferred = [p.lower() for p in self.policy.finding_output.same_issue_preferred_analyzers]
        for pos, token in enumerate(preferred):
            if token and token in lower:
                return len(preferred) - pos
        return 0

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove exact and near-duplicate findings (controlled by policy)."""
        cfg = self.policy.finding_output
        if not findings or (not cfg.dedupe_exact_findings and not cfg.dedupe_same_issue_per_location):
            return findings

        result = list(findings)

        # Pass 1: exact duplicates
        if cfg.dedupe_exact_findings:
            seen: set[tuple[object, ...]] = set()
            unique: list[Finding] = []
            for f in result:
                key = (
                    f.rule_id,
                    f.category.value,
                    f.severity.value,
                    (f.file_path or "").lower(),
                    int(f.line_number or 0),
                    self._compact_snippet(f.snippet),
                    (f.analyzer or "").lower(),
                )
                if key not in seen:
                    seen.add(key)
                    unique.append(f)
            result = unique

        if not cfg.dedupe_same_issue_per_location:
            return result

        # Pass 2: same-issue-per-location collapse
        buckets: dict[tuple[object, ...], list[Finding]] = {}
        ungrouped: list[Finding] = []
        for f in result:
            fp = (f.file_path or "").lower()
            ln = int(f.line_number or 0)
            snip = self._compact_snippet(f.snippet)
            if fp and (ln > 0 or snip):
                bucket_key = (fp, ln, snip, f.category.value)
                buckets.setdefault(bucket_key, []).append(f)
            else:
                ungrouped.append(f)

        collapsed: list[Finding] = []
        for members in buckets.values():
            if len(members) == 1:
                collapsed.append(members[0])
                continue

            distinct_analyzers = {(f.analyzer or "").lower() for f in members if (f.analyzer or "").strip()}
            if len(distinct_analyzers) <= 1 and not cfg.same_issue_collapse_within_analyzer:
                members.sort(key=lambda f: (-self._sev_weight(f.severity), f.rule_id))
                collapsed.extend(members)
                continue

            best = max(
                members,
                key=lambda f: (self._analyzer_priority(f.analyzer), self._sev_weight(f.severity), f.rule_id),
            )
            peak_sev = max((f.severity for f in members), key=self._sev_weight)
            if self._sev_weight(peak_sev) > self._sev_weight(best.severity):
                best.metadata["deduped_original_severity"] = best.severity.value
                best.severity = peak_sev

            extra_rules = sorted({f.rule_id for f in members if f.rule_id != best.rule_id})
            extra_analyzers = sorted(
                {(f.analyzer or "") for f in members if (f.analyzer or "") != (best.analyzer or "")}
            )

            if not best.remediation:
                donor = max(
                    members,
                    key=lambda f: (self._sev_weight(f.severity), self._analyzer_priority(f.analyzer), bool(f.remediation)),
                )
                if donor.remediation:
                    best.remediation = donor.remediation

            if extra_rules:
                best.metadata["deduped_rule_ids"] = extra_rules
            if extra_analyzers:
                best.metadata["deduped_analyzers"] = extra_analyzers
            best.metadata["deduped_count"] = len(members) - 1
            collapsed.append(best)

        final = collapsed + ungrouped
        final.sort(key=lambda f: (f.file_path or "", int(f.line_number or 0), -self._sev_weight(f.severity), f.rule_id))
        return final

    # ------------------------------------------------------------------
    # Co-occurrence tagging
    # ------------------------------------------------------------------

    @staticmethod
    def _all_rule_ids(finding: Finding) -> set[str]:
        """Collect every rule ID a finding represents, including dedup aliases."""
        ids = {finding.rule_id}
        merged = finding.metadata.get("deduped_rule_ids")
        if isinstance(merged, list):
            ids.update(rid for rid in merged if isinstance(rid, str) and rid)
        return ids

    def _tag_cooccurring_rules(self, findings: list[Finding]) -> None:
        """Annotate each finding with other rules that fired on the same path."""
        if not self.policy.finding_output.annotate_same_path_rule_cooccurrence:
            return
        if not findings:
            return

        by_path: dict[str, list[Finding]] = {}
        for f in findings:
            p = (f.file_path or "").strip()
            if p:
                by_path.setdefault(p.lower(), []).append(f)

        for group in by_path.values():
            all_ids: set[str] = set()
            for f in group:
                all_ids.update(self._all_rule_ids(f))
            if len(all_ids) < 2:
                continue
            ordered = sorted(all_ids)
            for f in group:
                others = sorted(all_ids - self._all_rule_ids(f))
                if others:
                    f.metadata["same_path_other_rule_ids"] = others
                    f.metadata["same_path_unique_rule_count"] = len(ordered)
                    f.metadata["same_path_findings_count"] = len(group)

    # ------------------------------------------------------------------
    # Policy fingerprint and stamping
    # ------------------------------------------------------------------

    def _compute_policy_digest(self) -> dict[str, str]:
        """Produce a deterministic hash identifying the active policy."""
        raw = self.policy._serialize()
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "policy_name": self.policy.policy_name,
            "policy_version": self.policy.policy_version,
            "policy_preset_base": self.policy.preset_base,
            "policy_fingerprint_sha256": sha,
        }

    def _stamp_policy_on_findings(self, findings: list[Finding], meta: dict[str, str]) -> None:
        """Embed policy traceability data into each finding when enabled."""
        if not self.policy.finding_output.attach_policy_fingerprint:
            return
        for f in findings:
            f.metadata.setdefault("scan_policy_name", meta["policy_name"])
            f.metadata.setdefault("scan_policy_version", meta["policy_version"])
            f.metadata.setdefault("scan_policy_preset_base", meta["policy_preset_base"])
            f.metadata.setdefault("scan_policy_fingerprint_sha256", meta["policy_fingerprint_sha256"])

    # ------------------------------------------------------------------
    # Directory traversal helpers
    # ------------------------------------------------------------------

    def _locate_skill_roots(self, directory: Path, recursive: bool) -> list[Path]:
        """Return directories that contain a SKILL.md manifest."""
        if recursive:
            return [p.parent for p in directory.rglob("SKILL.md")]

        return [
            child for child in directory.iterdir()
            if child.is_dir() and (child / "SKILL.md").exists()
        ]

    def _process_dirs_sequential(
        self,
        dirs: list[Path],
        report: Report,
        collected_skills: list[Skill],
        check_overlap: bool,
        lenient: bool,
    ) -> None:
        """Walk *dirs* one at a time, appending results to *report*."""
        for d in dirs:
            try:
                skill = self.loader.load_skill(d, lenient=lenient)
                report.add_scan_result(self._execute_pipeline(skill, d))
                if check_overlap:
                    collected_skills.append(skill)
            except SkillLoadError as exc:
                _log.warning("Could not load %s: %s", d, exc)
                report.skills_skipped.append({"skill": str(d), "reason": str(exc)})
            except Exception as exc:
                _log.error("Unexpected failure scanning %s: %s", d, exc, exc_info=True)
                report.skills_skipped.append({"skill": str(d), "reason": str(exc)})

    def _process_dirs_threaded(
        self,
        dirs: list[Path],
        report: Report,
        collected_skills: list[Skill],
        check_overlap: bool,
        lenient: bool,
        max_workers: int,
    ) -> None:
        """Scan *dirs* concurrently via a thread pool."""
        mu = Lock()

        def _worker(skill_dir: Path) -> None:
            try:
                ldr = SkillLoader(max_file_size_bytes=self.policy.file_limits.max_loader_file_size_bytes)
                skill = ldr.load_skill(skill_dir, lenient=lenient)
                result = self._execute_pipeline(skill, skill_dir)
                with mu:
                    report.add_scan_result(result)
                    if check_overlap:
                        collected_skills.append(skill)
            except SkillLoadError as exc:
                _log.warning("Could not load %s: %s", skill_dir, exc)
                with mu:
                    report.skills_skipped.append({"skill": str(skill_dir), "reason": str(exc)})
            except Exception as exc:
                _log.error("Unexpected failure scanning %s: %s", skill_dir, exc, exc_info=True)
                with mu:
                    report.skills_skipped.append({"skill": str(skill_dir), "reason": str(exc)})

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_worker, d) for d in dirs]
            for fut in as_completed(futures):
                err = fut.exception()
                if err:
                    _log.error("Worker thread crashed: %s", err)

    # ------------------------------------------------------------------
    # Cross-skill analysis
    # ------------------------------------------------------------------

    def _perform_cross_skill_checks(
        self,
        report: Report,
        skills: list[Skill],
        check_overlap: bool,
    ) -> None:
        """Detect inter-skill issues like description similarity and shared patterns."""
        overlap: list[Finding] = []
        pattern_findings: list[Finding] = []

        if check_overlap and len(skills) > 1:
            try:
                overlap = self._detect_description_similarity(skills)
            except Exception as exc:
                _log.error("Description similarity check failed: %s", exc)

            try:
                from .analyzers.cross_skill_scanner import CrossSkillScanner
                pattern_findings = CrossSkillScanner().analyze_skill_set(skills)
            except ImportError:
                pass
            except Exception as exc:
                _log.error("Cross-skill pattern analysis failed: %s", exc)

        combined = list(overlap) + list(pattern_findings)
        if combined:
            if self.policy.disabled_rules:
                combined = [f for f in combined if f.rule_id not in self.policy.disabled_rules]
            self._override_severities(combined)
            report.add_cross_skill_findings(combined)

    def _detect_description_similarity(self, skills: list[Skill]) -> list[Finding]:
        """Flag skill pairs whose descriptions are suspiciously similar.

        High similarity can enable trigger-hijacking where a rogue skill
        intercepts requests meant for a legitimate one.
        """
        results: list[Finding] = []

        for idx in range(len(skills)):
            for jdx in range(idx + 1, len(skills)):
                sa, sb = skills[idx], skills[jdx]
                sim = self._token_overlap_ratio(sa.description, sb.description)

                if sim > 0.7:
                    tag = hashlib.sha256((sa.name + sb.name).encode()).hexdigest()[:8]
                    results.append(Finding(
                        id=f"OVERLAP_{tag}",
                        rule_id="TRIGGER_OVERLAP_RISK",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=Severity.MEDIUM,
                        title="Skills have overlapping descriptions",
                        description=(
                            f"Skills '{sa.name}' and '{sb.name}' share {sim:.0%} "
                            f"description similarity.  This could confuse routing "
                            f"or enable trigger hijacking."
                        ),
                        file_path=f"{sa.name}/SKILL.md",
                        remediation=(
                            "Make skill descriptions more distinct by clearly specifying "
                            "the unique capabilities, file types, or use cases for each skill."
                        ),
                        metadata={"skill_a": sa.name, "skill_b": sb.name, "similarity": sim},
                    ))
                elif sim > 0.5:
                    tag = hashlib.sha256((sa.name + sb.name).encode()).hexdigest()[:8]
                    results.append(Finding(
                        id=f"OVERLAP_WARN_{tag}",
                        rule_id="TRIGGER_OVERLAP_WARNING",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=Severity.LOW,
                        title="Skills have somewhat similar descriptions",
                        description=(
                            f"Skills '{sa.name}' and '{sb.name}' share {sim:.0%} "
                            f"description similarity.  Consider differentiating them."
                        ),
                        file_path=f"{sa.name}/SKILL.md",
                        remediation="Consider making skill descriptions more distinct",
                        metadata={"skill_a": sa.name, "skill_b": sb.name, "similarity": sim},
                    ))

        return results

    def _token_overlap_ratio(self, text_a: str, text_b: str) -> float:
        """Compute Jaccard index between two texts after stop-word removal."""
        words_a = set(re.findall(r"\b[a-zA-Z]+\b", str(text_a).lower())) - _TRIVIAL_TOKENS
        words_b = set(re.findall(r"\b[a-zA-Z]+\b", str(text_b).lower())) - _TRIVIAL_TOKENS

        if not words_a or not words_b:
            return 0.0

        shared = len(words_a & words_b)
        total = len(words_a | words_b)
        return shared / total if total else 0.0


# ======================================================================
# Module-level convenience wrappers
# ======================================================================

def scan_skill(
    skill_directory: str | Path,
    analyzers: list[BaseAnalyzer] | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    """Shorthand for constructing a `SkillScanner` and scanning one skill.

    Parameters
    ----------
    skill_directory:
        Path to the skill package.
    analyzers:
        Optional explicit analyzer list.
    policy:
        Optional scan policy.  When *None* and *analyzers* are given,
        the policy attached to the first analyzer is used if available.

    Returns
    -------
    ScanResult
    """
    effective_policy = policy
    if effective_policy is None and analyzers:
        effective_policy = getattr(analyzers[0], "policy", None)
    return SkillScanner(analyzers=analyzers, policy=effective_policy).scan_skill(skill_directory)


def scan_directory(
    skills_directory: str | Path,
    recursive: bool = False,
    analyzers: list[BaseAnalyzer] | None = None,
    check_overlap: bool = False,
    policy: ScanPolicy | None = None,
    max_workers: int = 1,
) -> Report:
    """Shorthand for constructing a `SkillScanner` and scanning a directory tree.

    Parameters
    ----------
    skills_directory:
        Root directory containing skill packages.
    recursive:
        Recurse into sub-directories.
    analyzers:
        Optional explicit analyzer list.
    check_overlap:
        Run inter-skill description similarity checks.
    policy:
        Optional scan policy.
    max_workers:
        Thread pool width (``1`` = sequential).

    Returns
    -------
    Report
    """
    effective_policy = policy
    if effective_policy is None and analyzers:
        effective_policy = getattr(analyzers[0], "policy", None)
    scanner = SkillScanner(analyzers=analyzers, policy=effective_policy)
    return scanner.scan_directory(
        skills_directory, recursive=recursive, check_overlap=check_overlap, max_workers=max_workers,
    )
