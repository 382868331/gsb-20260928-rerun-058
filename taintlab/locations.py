from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Loc:
    """源文位置（行、列均从 1 开始，offset 为字符偏移）。"""

    line: int
    col: int
    offset: int

    def __str__(self) -> str:
        return f"{self.line}:{self.col}"


@dataclass(frozen=True)
class Span:
    start: Loc
    end: Loc

    def __str__(self) -> str:
        return f"{self.start}-{self.end}"
