from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Position:
    offset: int
    line: int
    column: int


@dataclass(frozen=True)
class Span:
    start: Position
    end: Position

    @property
    def line(self) -> int:
        return self.start.line

    @property
    def column(self) -> int:
        return self.start.column


@dataclass(frozen=True)
class LocatedText:
    text: str
    span: Span
