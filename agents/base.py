"""Abstract LLM agent interface."""
from __future__ import annotations

import json
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


_CHAT_SYSTEM = """\
You are an AI assistant embedded in a live system dashboard for an AI-dev workstation \
(RTX 5090, 128GB RAM, Windows 11). You have access to the current system snapshot \
(CPU/RAM/GPU usage, active issues, storage state). Answer questions about the machine, \
diagnose problems, suggest commands, or just help with anything the user asks. \
Be concise and direct. Plain text only — no markdown headers."""


class AgentBase(ABC):
    @abstractmethod
    def diagnose(self, issue: dict, context: dict) -> DiagnosisResult:
        """Analyze an issue and return a structured diagnosis."""
        ...

    @abstractmethod
    def available(self) -> bool:
        """Return True if the LLM backend is reachable."""
        ...

    def chat(self, message: str, history: list[dict], system_context: dict) -> str:
        """Free-form chat. Subclasses may override for richer history support."""
        # Default: prepend context to the message and call diagnose-like flow
        ctx_str = json.dumps(system_context, default=str)[:800]
        full_msg = f"[System snapshot]\n{ctx_str}\n\n[User]\n{message}"
        # Build a synthetic issue so diagnose() can handle it
        fake_issue = {"title": "User question", "description": full_msg, "severity": "info"}
        result = self.diagnose(fake_issue, {})
        # Return the most relevant field
        return result.suggested_fix or result.summary or result.root_cause
