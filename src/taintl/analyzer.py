from __future__ import annotations

from dataclasses import dataclass, field
from itertools import count
from typing import Iterable

from .ast_nodes import (
    Assign, Binary, Boolean, Call, ExpressionStatement, Function, Identifier,
    If, Let, Number, Program, Return, Stmt, String, Unary,
)
from .positions import Span


SOURCE_NAMES = frozenset({"read_input", "source"})
SINK_NAMES = frozenset({"danger", "sink"})
SANITIZER_NAMES = frozenset({"sanitize", "clean"})
BUILTIN_NAMES = SOURCE_NAMES | SINK_NAMES | SANITIZER_NAMES

TAINTED = "tainted"
SANITIZED = "sanitized"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class PathNode:
    kind: str
    label: str
    line: int
    column: int
    detail: str = ""


@dataclass(frozen=True)
class Tag:
    tag_id: int
    kind: str
    path: tuple[PathNode, ...]

    def extended(self, kind: str, node: PathNode) -> "Tag":
        return Tag(self.tag_id, kind, self.path + (node,))


@dataclass(frozen=True)
class FlowValue:
    tags: frozenset[Tag] = frozenset()

    @property
    def kinds(self) -> frozenset[str]:
        return frozenset(tag.kind for tag in self.tags)

    def dangerous_tags(self) -> tuple[Tag, ...]:
        return tuple(sorted((tag for tag in self.tags if tag.kind in {TAINTED, UNKNOWN}), key=lambda item: item.tag_id))


@dataclass(frozen=True)
class Diagnostic:
    rule: str
    severity: str
    message: str
    line: int
    column: int
    path: tuple[PathNode, ...] = ()


@dataclass
class AnalysisResult:
    diagnostics: list[Diagnostic] = field(default_factory=list)
    complete: bool = True
    call_edges: list[tuple[str, str, int, int]] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return self.complete and not any(item.severity == "error" for item in self.diagnostics)


def _span_node(kind: str, label: str, span: Span, detail: str = "") -> PathNode:
    return PathNode(kind, label, span.start.line, span.start.column, detail)


def _join(values: Iterable[FlowValue]) -> FlowValue:
    tags: set[Tag] = set()
    for value in values:
        tags.update(value.tags)
    return FlowValue(frozenset(tags))


class Analyzer:
    def __init__(self, program: Program, max_depth: int = 32, max_call_steps: int = 500):
        self.program = program
        self.max_depth = max_depth
        self.max_call_steps = max_call_steps
        self.functions = {function.name: function for function in program.functions}
        self.result = AnalysisResult()
        self.ids = count(1)
        self.call_steps = 0

    def analyze(self) -> AnalysisResult:
        validation_error = self._validate_program()
        if validation_error:
            return self.result
        entry = self.functions.get("main")
        if entry is None:
            self.result.complete = False
            self.result.diagnostics.append(Diagnostic(
                "missing-entry", "error", "program has no main function", 1, 1
            ))
            return self.result
        self._exec_function_body(entry, (), (), requires_return=False)
        return self.result

    def _diagnostic(self, rule: str, severity: str, message: str, span: Span) -> None:
        self.result.complete = False
        self.result.diagnostics.append(Diagnostic(
            rule, severity, message, span.start.line, span.start.column
        ))

    def _validate_program(self) -> bool:
        seen: set[str] = set()
        for function in self.program.functions:
            if function.name in seen:
                self._diagnostic("duplicate-function", "error", f"duplicate function {function.name}", function.span)
            seen.add(function.name)
            parameter_seen: set[str] = set()
            for parameter in function.parameters:
                if parameter in parameter_seen:
                    self._diagnostic("duplicate-parameter", "error", f"duplicate parameter {parameter}", function.span)
                parameter_seen.add(parameter)

            def expressions(statements):
                for statement in statements:
                    if hasattr(statement, "value") and statement.value is not None:
                        yield statement.value
                    if hasattr(statement, "expression"):
                        yield statement.expression
                    if hasattr(statement, "condition"):
                        yield statement.condition
                    if hasattr(statement, "then_body"):
                        yield from expressions(statement.then_body)
                        yield from expressions(statement.else_body)

            def calls(expression):
                if isinstance(expression, Call):
                    yield expression
                    for argument in expression.arguments:
                        yield from calls(argument)
                if hasattr(expression, "left"):
                    yield from calls(expression.left)
                if hasattr(expression, "right"):
                    yield from calls(expression.right)
                if hasattr(expression, "operand"):
                    yield from calls(expression.operand)

            for expression in expressions(function.body):
                for call in calls(expression):
                    if call.callee in SOURCE_NAMES:
                        expected_arity = 0
                    elif call.callee in SANITIZER_NAMES | SINK_NAMES:
                        expected_arity = 1
                    elif call.callee in self.functions:
                        expected_arity = len(self.functions[call.callee].parameters)
                    else:
                        expected_arity = None
                    if expected_arity is not None and len(call.arguments) != expected_arity:
                        self._diagnostic("bad-arity", "error", f"{call.callee} expects {expected_arity} arguments", call.span)
        return bool(self.result.diagnostics)

    def _new_tag(self, kind: str, path: tuple[PathNode, ...]) -> Tag:
        return Tag(next(self.ids), kind, path)

    def _exec_function_body(
        self,
        function: Function,
        argument_values: tuple[FlowValue, ...],
        call_stack: tuple[str, ...],
        requires_return: bool,
    ):
        env = {
            name: argument_values[index] if index < len(argument_values) else FlowValue()
            for index, name in enumerate(function.parameters)
        }
        returned, _ = self._exec_block(function.body, env, call_stack)
        if returned is None and requires_return:
            self.result.complete = False
            tag = self._new_tag(UNKNOWN, (_span_node("missing-return", function.name, function.span, "not all paths return a value"),))
            self.result.diagnostics.append(Diagnostic(
                "missing-return", "warning", f"{function.name} does not return on all paths",
                function.span.start.line, function.span.start.column, tag.path
            ))
            returned = FlowValue(frozenset({tag}))
        return returned

    def _exec_block(
        self,
        statements: tuple[Stmt, ...],
        env: dict[str, FlowValue],
        call_stack: tuple[str, ...],
    ) -> tuple[FlowValue | None, dict[str, FlowValue]]:
        for statement in statements:
            returned = self._exec_statement(statement, env, call_stack)
            if returned is not None:
                return returned, env
        return None, env

    def _exec_statement(self, statement: Stmt, env: dict[str, FlowValue], call_stack: tuple[str, ...]) -> FlowValue | None:
        if isinstance(statement, Let):
            env[statement.name] = self._eval(statement.value, env, call_stack)
            return None
        if isinstance(statement, Assign):
            env[statement.name] = self._eval(statement.value, env, call_stack)
            return None
        if isinstance(statement, ExpressionStatement):
            self._eval(statement.expression, env, call_stack)
            return None
        if isinstance(statement, Return):
            if statement.value is None:
                return FlowValue()
            return self._eval(statement.value, env, call_stack)
        if isinstance(statement, If):
            self._eval(statement.condition, env, call_stack)
            then_env = dict(env)
            else_env = dict(env)
            then_return, then_env = self._exec_block(statement.then_body, then_env, call_stack)
            else_return, else_env = self._exec_block(statement.else_body, else_env, call_stack)
            if then_return is not None and else_return is not None:
                return _join([then_return, else_return]), env
            if then_return is not None:
                env.clear()
                env.update(else_env)
                return None
            if else_return is not None:
                env.clear()
                env.update(then_env)
                return None
            names = set(env) | set(then_env) | set(else_env)
            for name in names:
                before = env.get(name, FlowValue())
                env[name] = _join([then_env.get(name, before), else_env.get(name, before)])
            return None
        raise TypeError(f"unsupported statement type: {type(statement)!r}")

    def _eval(self, expression, env: dict[str, FlowValue], call_stack: tuple[str, ...]) -> FlowValue:
        if isinstance(expression, (Number, String, Boolean)):
            return FlowValue()
        if isinstance(expression, Identifier):
            value = env.get(expression.name)
            if value is None:
                self.result.complete = False
                tag = self._new_tag(UNKNOWN, (_span_node("unresolved-variable", expression.name, expression.span, "variable has no analyzed definition"),))
                self.result.diagnostics.append(Diagnostic(
                    "unresolved-variable", "warning", f"variable {expression.name} has no analyzed definition",
                    expression.span.start.line, expression.span.start.column, tag.path
                ))
                value = FlowValue(frozenset({tag}))
            return value
        if isinstance(expression, Unary):
            return self._propagate_unary(expression, env, call_stack)
        if isinstance(expression, Binary):
            left = self._eval(expression.left, env, call_stack)
            right = self._eval(expression.right, env, call_stack)
            if expression.operator in {"==", "!=", "<", ">", "<=", ">="}:
                return FlowValue()
            return self._through_operation(_join([left, right]), expression.span, f"operator {expression.operator}")
        if isinstance(expression, Call):
            return self._eval_call(expression, env, call_stack)
        raise TypeError(f"unsupported expression type: {type(expression)!r}")

    def _propagate_unary(self, expression: Unary, env: dict[str, FlowValue], call_stack: tuple[str, ...]) -> FlowValue:
        value = self._eval(expression.operand, env, call_stack)
        if expression.operator == "!":
            return FlowValue()
        return self._through_operation(value, expression.span, f"operator {expression.operator}")

    def _through_operation(self, value: FlowValue, span: Span, detail: str) -> FlowValue:
        tags = {
            tag.extended(tag.kind, _span_node("operation", detail, span))
            for tag in value.tags
        }
        return FlowValue(frozenset(tags))

    def _eval_call(self, call: Call, env: dict[str, FlowValue], call_stack: tuple[str, ...]) -> FlowValue:
        argument_values = tuple(self._eval(argument, env, call_stack) for argument in call.arguments)
        call_node = _span_node("call", call.callee, call.span)

        if call.callee in SOURCE_NAMES:
            tag = self._new_tag(TAINTED, (_span_node("source", call.callee, call.span, "untrusted input"),))
            return FlowValue(frozenset({tag}))

        if call.callee in SANITIZER_NAMES:
            tags = set()
            for tag in argument_values[0].tags if argument_values else set():
                next_kind = SANITIZED if tag.kind == TAINTED else tag.kind
                tags.add(tag.extended(next_kind, _span_node("sanitizer", call.callee, call.span, "explicit sanitization")))
            return FlowValue(frozenset(tags))

        if call.callee in SINK_NAMES:
            value = argument_values[0] if argument_values else FlowValue()
            self._check_sink(call, value)
            return FlowValue()

        function = self.functions.get(call.callee)
        if function is None:
            self.result.complete = False
            tag = self._new_tag(UNKNOWN, (
                _span_node("unknown", call.callee, call.span, "unresolved call"),
                call_node,
            ))
            self.result.diagnostics.append(Diagnostic(
                "unresolved-call", "warning", f"unresolved call to {call.callee}",
                call.span.start.line, call.span.start.column, tag.path
            ))
            return FlowValue(frozenset({tag}))

        self.result.call_edges.append((
            call_stack[-1] if call_stack else "main", call.callee,
            call.span.start.line, call.span.start.column,
        ))

        if call.callee in call_stack or len(call_stack) >= self.max_depth or self.call_steps >= self.max_call_steps:
            self.result.complete = False
            tags = set()
            for argument_value in argument_values:
                for tag in argument_value.dangerous_tags():
                    reason = (
                        "recursive call limit reached"
                        if call.callee in call_stack or len(call_stack) >= self.max_depth
                        else "global call-step limit reached"
                    )
                    tags.add(tag.extended(UNKNOWN, _span_node("limit", call.callee, call.span, reason)))
            if not tags:
                tags.add(self._new_tag(UNKNOWN, (_span_node("limit", call.callee, call.span, "analysis limit reached"),)))
            self.result.diagnostics.append(Diagnostic(
                "analysis-limit", "warning", f"analysis of {call.callee} was not completed",
                call.span.start.line, call.span.start.column, tuple(path for tag in tags for path in tag.path)
            ))
            return FlowValue(frozenset(tags))

        self.call_steps += 1
        requires_return = not self._is_statement_call(call, call_stack)
        returned = self._exec_function_body(function, argument_values, call_stack + (call.callee,), requires_return)
        tags = {
            tag
            .extended(tag.kind, call_node)
            .extended(tag.kind, _span_node("return-to-call", call.callee, call.span, "cross-function result"))
            for tag in returned.tags
        }
        return FlowValue(frozenset(tags))

    def _check_sink(self, call: Call, value: FlowValue):
        for tag in value.dangerous_tags():
            if tag.kind == TAINTED:
                severity = "error"
                rule = "tainted-sink"
                message = f"untrusted data reaches dangerous operation {call.callee}"
            else:
                severity = "warning"
                rule = "unknown-sink"
                message = f"not fully analyzed data reaches dangerous operation {call.callee}"
            path = tag.path + (_span_node("sink", call.callee, call.span, "dangerous operation"),)
            self.result.diagnostics.append(Diagnostic(
                rule, severity, message, call.span.start.line, call.span.start.column, path
            ))

    def _is_statement_call(self, call: Call, call_stack: tuple[str, ...]) -> bool:
        current = self.functions.get(call_stack[-1] if call_stack else "main")
        if current is None:
            return False
        return self._statement_contains(current.body, call)

    def _statement_contains(self, statements: tuple[Stmt, ...], target: Call) -> bool:
        for statement in statements:
            if isinstance(statement, ExpressionStatement) and statement.expression is target:
                return True
            if isinstance(statement, If):
                if self._statement_contains(statement.then_body, target) or self._statement_contains(statement.else_body, target):
                    return True
        return False


def analyze_program(program: Program, max_depth: int = 32, max_call_steps: int = 500) -> AnalysisResult:
    return Analyzer(program, max_depth=max_depth, max_call_steps=max_call_steps).analyze()
