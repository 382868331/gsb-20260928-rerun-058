from __future__ import annotations

from dataclasses import dataclass

from .ast_nodes import Call, Function, Program
from .analyzer import BUILTIN_NAMES


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    line: int
    column: int
    builtin: bool


def _calls(function: Function) -> list[Call]:
    calls: list[Call] = []

    def visit_expression(expression):
        if isinstance(expression, Call):
            calls.append(expression)
            for argument in expression.arguments:
                visit_expression(argument)
            return
        if hasattr(expression, "left"):
            visit_expression(expression.left)
        if hasattr(expression, "right"):
            visit_expression(expression.right)
        if hasattr(expression, "operand"):
            visit_expression(expression.operand)

    def visit_statement(statement):
        if hasattr(statement, "value") and statement.value is not None:
            visit_expression(statement.value)
        if hasattr(statement, "expression"):
            visit_expression(statement.expression)
        if hasattr(statement, "condition"):
            visit_expression(statement.condition)
        if hasattr(statement, "then_body"):
            for child in statement.then_body:
                visit_statement(child)
            for child in statement.else_body:
                visit_statement(child)
    for statement in function.body:
        visit_statement(statement)
    return calls


def build_call_graph(program: Program) -> tuple[CallEdge, ...]:
    edges: list[CallEdge] = []
    for function in program.functions:
        for call in _calls(function):
            edges.append(CallEdge(
                caller=function.name,
                callee=call.callee,
                line=call.span.start.line,
                column=call.span.start.column,
                builtin=call.callee in BUILTIN_NAMES,
            ))
    return tuple(edges)
