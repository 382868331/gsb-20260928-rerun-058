"""TaintLab 语言的抽象语法树。

语言文法（v1，无循环的结构化小型语言）::

    program     := func*
    func        := 'def' IDENT '(' params? ')' block
    params      := IDENT (',' IDENT)*
    block       := '{' stmt* '}'
    stmt        := 'if' '(' expr ')' block ('else' block)?
                 | 'return' expr? ';'
                 | expr ';'                       // 仅调用表达式有副作用
                 | IDENT '=' expr ';'
    expr        := binary（优先级: || < && < 比较 < 加减 < 乘除 < 一元 < 基本）
    primary     := NUMBER | STRING | 'true' | 'false'
                 | IDENT ( '(' args? ')' )?
                 | '(' expr ')' | '-' unary | '!' unary
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .locations import Loc, Span


@dataclass(frozen=True)
class Node:
    loc: Loc = field(compare=False, default=Loc(0, 0, 0))


@dataclass(frozen=True)
class NumberLit(Node):
    value: int = 0


@dataclass(frozen=True)
class StringLit(Node):
    value: str = ""


@dataclass(frozen=True)
class BoolLit(Node):
    value: bool = False


@dataclass(frozen=True)
class Var(Node):
    name: str = ""


@dataclass(frozen=True)
class Call(Node):
    func: str = ""
    args: tuple[Expr, ...] = ()


@dataclass(frozen=True)
class Unary(Node):
    op: str = ""
    operand: Expr | None = None


@dataclass(frozen=True)
class Binary(Node):
    op: str = ""
    left: Expr | None = None
    right: Expr | None = None


Expr = NumberLit | StringLit | BoolLit | Var | Call | Unary | Binary


@dataclass(frozen=True)
class IfStmt:
    loc: Loc
    cond: Expr
    then_block: tuple[Stmt, ...]
    else_block: tuple[Stmt, ...]


@dataclass(frozen=True)
class ReturnStmt:
    loc: Loc
    value: Expr | None


@dataclass(frozen=True)
class AssignStmt:
    loc: Loc
    target: str
    value: Expr


@dataclass(frozen=True)
class ExprStmt:
    loc: Loc
    expr: Call


Stmt = IfStmt | ReturnStmt | AssignStmt | ExprStmt


@dataclass(frozen=True)
class FuncDef:
    loc: Loc
    name: str
    params: tuple[str, ...]
    body: tuple[Stmt, ...]
    span: Span | None = None


@dataclass(frozen=True)
class Program:
    funcs: tuple[FuncDef, ...]
