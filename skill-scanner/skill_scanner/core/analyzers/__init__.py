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
Analyzer modules for detecting security vulnerabilities in agent skills.

Structure mirrors MCP Scanner's analyzer organization.
"""

from .base import BaseAnalyzer

__all__ = ["BaseAnalyzer"]

# Import available analyzers (re-exported via __all__)
try:
    from .static import StaticAnalyzer  # noqa: F401

    __all__.append("StaticAnalyzer")
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .llm_analyzer import LLMAnalyzer, LLMProvider  # noqa: F401

    __all__.extend(["LLMAnalyzer", "LLMProvider"])
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .behavioral_analyzer import BehavioralAnalyzer  # noqa: F401

    __all__.append("BehavioralAnalyzer")
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .cloud_defense_analyzer import CloudDefenseAnalyzer  # noqa: F401

    __all__.append("CloudDefenseAnalyzer")
except (ImportError, ModuleNotFoundError, NameError, AttributeError):
    pass

try:
    from .trigger_analyzer import TriggerAnalyzer  # noqa: F401

    __all__.append("TriggerAnalyzer")
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .cross_skill_scanner import CrossSkillScanner  # noqa: F401

    __all__.append("CrossSkillScanner")
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .meta_analyzer import MetaAnalysisResult, MetaAnalyzer, apply_meta_analysis_to_results  # noqa: F401

    __all__.extend(["MetaAnalyzer", "MetaAnalysisResult", "apply_meta_analysis_to_results"])
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .pattern_analyzer import PatternAnalyzer  # noqa: F401

    __all__.append("PatternAnalyzer")
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .structure_validator import StructureValidatorAnalyzer  # noqa: F401

    __all__.append("StructureValidatorAnalyzer")
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .capability_risk_analyzer import CapabilityRiskAnalyzer  # noqa: F401

    __all__.append("CapabilityRiskAnalyzer")
except (ImportError, ModuleNotFoundError):
    pass

try:
    from .phase1_parallel_group import Phase1ParallelGroup  # noqa: F401

    __all__.append("Phase1ParallelGroup")
except (ImportError, ModuleNotFoundError):
    pass
