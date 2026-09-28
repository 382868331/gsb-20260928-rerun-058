from __future__ import annotations

from dataclasses import dataclass
from .positions import Span


@dataclass(frozen=True)
class Node:
    span: Span


@dataclass(frozen=True)
class Number(Node):
    value: int


@dataclass(frozen=True)
class String(Node):
    value: str


@dataclass(frozen=True)
class Boolean(Node):
    value: bool


@dataclass(frozen=True)
class Identifier(Node):
    name: str


@dataclass(frozen=True)
class Binary(Node):
    left: "Expr"
    operator: str
    right: "Expr"


@dataclass(frozen=True)
class Unary(Node):
    operator: str
    operand: "Expr"


@dataclass(frozen=True)
class Call(Node):
    callee: str
    arguments: tuple["Expr", ...]


Expr = Number | String | Boolean | Identifier | Binary | Unary | Call


@dataclass(frozen=True)
class Let(Node):
    name: str
    value: Expr


@dataclass(frozen=True)
class Assign(Node):
    name: str
    value: Expr


@dataclass(frozen=True)
class ExpressionStatement(Node):
    expression: Expr


@dataclass(frozen=True)
class Return(Node):
    value: Expr | None


@dataclass(frozen=True)
class If(Node):
    condition: Expr
    then_body: tuple["Stmt", ...]
    else_body: tuple["Stmt", ...]


Stmt = Let | Assign | ExpressionStatement | Return | If


@dataclass(frozen=True)
class Function(Node):
    name: str
    parameters: tuple[str, ...]
    body: tuple[Stmt, ...]


@dataclass(frozen=True)
class Program(Node):
    functions: tuple[Function, ...]
