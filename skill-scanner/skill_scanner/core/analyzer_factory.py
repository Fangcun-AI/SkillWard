"""
Provides unified construction of the analyzer pipeline.

All consumers -- command-line interface, REST gateway, pre-commit hooks,
evaluation harness, and the scanner fallback path -- should obtain their
analyzer instances exclusively through the functions exposed here.  This
guarantees consistent policy enforcement and simplifies maintenance when
analyzers are added or retired.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .analyzers.base import BaseAnalyzer
from .analyzers.bytecode_analyzer import BytecodeAnalyzer
from .analyzers.pipeline_analyzer import PipelineAnalyzer
from .analyzers.static import StaticAnalyzer
from .scan_policy import ScanPolicy

_log = logging.getLogger(__name__)


def build_core_analyzers(
    policy: ScanPolicy,
    *,
    custom_yara_rules_path: str | Path | None = None,
    use_parallel_static_engines: bool = False,
) -> list[BaseAnalyzer]:
    """Instantiate the standard set of analyzers governed by *policy*.

    Each analyzer toggle in ``policy.analyzers`` is honoured so that
    individual stages can be disabled without touching calling code.

    Parameters
    ----------
    policy:
        Active scanning policy that controls which stages run.
    custom_yara_rules_path:
        Directory holding additional ``.yara`` rule files passed
        through to the static analysis stage.
    use_parallel_static_engines:
        If ``True``, insert the parallel first-pass group ahead of the
        main static stage and suppress duplicate pattern work inside it.

    Returns
    -------
    list[BaseAnalyzer]
        Ordered analyzer instances ready for execution.
    """
    result: list[BaseAnalyzer] = []

    run_parallel = use_parallel_static_engines or getattr(
        policy.analyzers, "use_parallel_static_engines", False
    )

    if run_parallel:
        try:
            from .analyzers.phase1_parallel_group import Phase1ParallelGroup

            result.append(Phase1ParallelGroup(policy=policy))
        except (ImportError, Exception) as err:
            _log.warning("Phase1ParallelGroup unavailable: %s", err)

    if policy.analyzers.static:
        result.append(
            StaticAnalyzer(
                custom_yara_rules_path=custom_yara_rules_path,
                _skip_text_pattern_checks=run_parallel,
                policy=policy,
            )
        )

    if policy.analyzers.bytecode:
        result.append(BytecodeAnalyzer(policy=policy))

    if policy.analyzers.pipeline:
        result.append(PipelineAnalyzer(policy=policy))

    return result


def build_analyzers(
    policy: ScanPolicy,
    *,
    custom_yara_rules_path: str | Path | None = None,
) -> list[BaseAnalyzer]:
    """Convenience wrapper that returns the default analyzer stack.

    Returns
    -------
    list[BaseAnalyzer]
        The same list produced by :func:`build_core_analyzers` with
        default parallel-engine settings.
    """
    return build_core_analyzers(
        policy, custom_yara_rules_path=custom_yara_rules_path
    )
