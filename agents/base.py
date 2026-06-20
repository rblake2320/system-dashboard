"""Abstract LLM agent interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class DiagnosisResult:
    summary: str
    root_cause: str
    suggested_fix: str
    fixer_id: str | None
    fix_params: dict
    confidence: str  # high | medium | low
    raw: str = ""


class AgentBase(ABC):
    @abstractmethod
    def diagnose(self, issue: dict, context: dict) -> DiagnosisResult:
        """Analyze an issue and return a structured diagnosis."""
        ...

    @abstractmethod
    def available(self) -> bool:
        """Return True if the LLM backend is reachable."""
        ...
