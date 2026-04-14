"""Abstract interface that every security analyzer must implement."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Finding, Skill
from ..scan_policy import ScanPolicy


class BaseAnalyzer(ABC):
    """Common contract for pluggable analyzers in the scanning pipeline."""

    def __init__(self, name: str, policy: ScanPolicy | None = None):
        self.name = name
        self.policy = policy or ScanPolicy.default()

    @abstractmethod
    def analyze(self, skill: Skill) -> list[Finding]:
        """Inspect *skill* and return any security findings."""

    def get_name(self) -> str:
        return self.name
