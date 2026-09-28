from __future__ import annotations

from dataclasses import dataclass

from .ast_nodes import Call, FuncDef, Program, Stmt


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    loc_desc: str


def _calls_in_stmts(stmts: tuple[Stmt, ...]) -> list[Call]:
    calls: list[Call] = []
    for stmt in stmts:
        kind = type(stmt).__name__
        if kind == "IfStmt":
            calls.extend(_expr_calls(stmt.cond))
            calls.extend(_calls_in_stmts(stmt.then_block))
            calls.extend(_calls_in_stmts(stmt.else_block))
        elif kind == "ReturnStmt" and stmt.value is not None:
            calls.extend(_expr_calls(stmt.value))
        elif kind == "AssignStmt":
            calls.extend(_expr_calls(stmt.value))
        elif kind == "ExprStmt":
            calls.append(stmt.expr)
    return calls


def _expr_calls(expr) -> list[Call]:
    kind = type(expr).__name__
    if kind == "Call":
        out = [expr]
        for arg in expr.args:
            out.extend(_expr_calls(arg))
        return out
    if kind == "Binary":
        return _expr_calls(expr.left) + _expr_calls(expr.right)
    if kind == "Unary":
        return _expr_calls(expr.operand)
    return []


def build_call_graph(program: Program) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {f.name: set() for f in program.funcs}
    for func in program.funcs:
        for call in _calls_in_stmts(func.body):
            if any(ff.name == call.func for ff in program.funcs):
                graph[func.name].add(call.func)
    return graph


def all_edges(program: Program) -> list[CallEdge]:
    edges: list[CallEdge] = []
    for func in program.funcs:
        for call in _calls_in_stmts(func.body):
            if any(ff.name == call.func for ff in program.funcs):
                edges.append(CallEdge(func.name, call.func, str(call.loc)))
    return edges
