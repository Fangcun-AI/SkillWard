# Copyright 2026 FangcunGuard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Phase 1 Parallel Group: Orchestrates three static analysis engines in parallel.

Runs PatternAnalyzer, StructureValidatorAnalyzer, and CapabilityRiskAnalyzer
concurrently using a ThreadPoolExecutor, then merges results.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Finding, Skill
from ..scan_policy import ScanPolicy
from .base import BaseAnalyzer
from .capability_risk_analyzer import CapabilityRiskAnalyzer
from .pattern_analyzer import PatternAnalyzer
from .structure_validator import StructureValidatorAnalyzer

logger = logging.getLogger(__name__)


class Phase1ParallelGroup(BaseAnalyzer):
    """Runs PatternAnalyzer, StructureValidatorAnalyzer, and CapabilityRiskAnalyzer in parallel."""

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__("phase1_parallel_group", policy=policy)
        self._engines: dict[str, BaseAnalyzer] = {
            "pattern": PatternAnalyzer(policy=policy),
            "structure": StructureValidatorAnalyzer(policy=policy),
            "capability": CapabilityRiskAnalyzer(policy=policy),
        }

    def analyze(self, skill: Skill) -> list[Finding]:
        # Pre-load all file content to eliminate lazy-read race conditions
        for sf in skill.files:
            sf.read_content()

        all_findings: list[Finding] = []

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(engine.analyze, skill): name
                for name, engine in self._engines.items()
            }
            for future in as_completed(futures):
                engine_name = futures[future]
                try:
                    all_findings.extend(future.result())
                except Exception as exc:
                    logger.error("Phase1 engine '%s' raised an exception: %s", engine_name, exc)

        return all_findings
