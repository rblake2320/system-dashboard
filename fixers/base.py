"""Abstract fixer interface — all fixers yield log lines for SSE streaming."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Generator


class FixerBase(ABC):
    fixer_id: str = ""

    @abstractmethod
    def can_fix(self, issue: dict) -> bool: ...

    @abstractmethod
    def fix(self, issue: dict) -> Generator[str, None, None]:
        """Yield status lines (plain text). Last line should be 'DONE' or 'FAILED: reason'."""
        ...
