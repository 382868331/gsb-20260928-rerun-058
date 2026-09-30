"""静态污点分析器（只分析文本，不执行被分析程序）。

设计要点：

* 不可信来源（source）产生污点事实，危险操作（sink）消费污点事实；
  净化函数（sanitizer）返回干净值，污点一经净化即与原值分离（不合并）。
* 跨函数：调用点把实参污点事实绑定到形参，污点事实自带到当前位置的
  完整传播路径；返回值把被调函数内部的路径带回调用点（上下文敏感）。
* 分支：分别分析两个分支，汇合时对变量做并集（保守地认为任一分支
  赋值都可能发生），并记录一条 join 路径跳。
* 递归/深度：沿调用栈分析，遇到递归或达到 ``max_call_depth`` 时停止展开，
  该次调用按“潜在不可信”处理并给出 WARNING；只要有未分析完的部分，
  最终结论只能是 INCOMPLETE，绝不判 SAFE。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .ast_nodes import (
    AssignStmt,
    Binary,
    BoolLit,
    Call,
    ExprStmt,
    FuncDef,
    IfStmt,
    NumberLit,
    Program,
    ReturnStmt,
    StringLit,
    Unary,
    Var,
)
from .locations import Loc
from .model import (
    BASIS_ASSUMPTION,
    BASIS_CONFIRMED,
    BASIS_UNKNOWN,
    Diagnostic,
    PathHop,
    Severity,
    TaintPath,
    Verdict,
)
from .parser import parse

# 内置函数建模：整个分析过程不执行任何被分析代码。
SOURCES = {
    "read_input": "不可信输入 read_input()",
}
SANITIZERS = {
    "sanitize": "净化函数 sanitize()，返回值视为干净数据",
}
SINKS = {
    "exec": "危险操作 exec()：以不可信数据执行命令",
    "eval_sql": "危险操作 eval_sql()：以不可信数据拼接 SQL",
}


@dataclass(frozen=True)
class ExternalSpec:
    """部分外部调用的受限行为说明（由使用者显式提供，分析器不臆测）。

    返回值策略 ``returns``：

    * ``"clean"``：无论实参如何，返回值视为干净数据（如净化类库函数）；
    * ``"tainted"``：返回值视为不可信数据（如读网络/环境的库函数）；
    * ``"propagate"``：仅当任一实参带污点时返回值带污点。

    说明只描述返回值是否携带污点，不替被分析程序执行任何代码。
    """

    name: str
    description: str
    returns: str = "propagate"

    def __post_init__(self) -> None:
        if self.returns not in ("clean", "tainted", "propagate"):
            raise ValueError(f"外部调用说明 {self.name} 的返回值策略非法: {self.returns}")


@dataclass(frozen=True)
class Fact:
    """一个污点事实：来自某处不可信来源，携带到当前位置的路径。

    ``basis`` 区分三类依据：

    * ``confirmed``：路径上每一步语义都已由语言/程序确定；
    * ``assumption``：路径成立依赖 ``assumptions`` 中列出的外部行为说明；
    * ``unknown``：经过行为未知的外部调用或未展开调用，风险尚不能排除，
      但并未被证实。
    """

    key: tuple
    path: tuple[PathHop, ...]
    basis: str = BASIS_CONFIRMED
    assumptions: frozenset[str] = frozenset()

    def extended(self, hop: PathHop) -> "Fact":
        return replace(self, path=self.path + (hop,))

    def as_basis(self, basis: str, assumptions: frozenset[str] = frozenset()) -> "Fact":
        return replace(self, basis=basis, assumptions=frozenset(assumptions))


@dataclass(frozen=True)
class DiagnosticChange:
    """两版外部行为说明下，单个 sink 诊断的变化。"""

    sink: str
    loc: Loc
    before_basis: str | None
    after_basis: str | None
    before_assumptions: tuple[str, ...]
    after_assumptions: tuple[str, ...]
    before_paths: tuple[TaintPath, ...]
    after_paths: tuple[TaintPath, ...]
    reason: str


@dataclass
class VersionDiff:
    """同一程序在两版外部行为说明下的结论差异。"""

    before_verdict: Verdict
    after_verdict: Verdict
    changes: list[DiagnosticChange] = field(default_factory=list)

    @property
    def unchanged(self) -> bool:
        return (
            self.before_verdict == self.after_verdict
            and not self.changes
        )

    def format_text(self) -> str:
        lines = [
            f"结论变化: {self.before_verdict.value} -> {self.after_verdict.value}",
        ]
        if not self.changes:
            lines.append("各 sink 诊断的依据均未变化。")
        for change in self.changes:
            before = change.before_basis or "无诊断"
            after = change.after_basis or "无诊断"
            lines.append(
                f"- {change.sink}() {change.loc}: 依据 {before} -> {after}；{change.reason}"
            )
            if change.before_assumptions:
                lines.append(f"    旧版假设: {', '.join(change.before_assumptions)}")
            if change.after_assumptions:
                lines.append(f"    新版假设: {', '.join(change.after_assumptions)}")
            for path in change.before_paths:
                lines.append("    旧版调用链:")
                for hop in path.hops:
                    lines.append(f"      {hop.loc}  [{hop.kind}] {hop.text}")
            for path in change.after_paths:
                lines.append("    新版调用链:")
                for hop in path.hops:
                    lines.append(f"      {hop.loc}  [{hop.kind}] {hop.text}")
        return "\n".join(lines)


# 变量环境：变量名 -> 该变量当前携带的污点事实集合（空集合 = 干净）。
Env = dict[str, frozenset[Fact]]


@dataclass
class AnalysisConfig:
    max_call_depth: int = 32
    external_specs: dict[str, ExternalSpec] | None = None

    def __post_init__(self) -> None:
        if self.external_specs is None:
            self.external_specs = {}


class Analyzer:
    def __init__(self, program: Program, config: AnalysisConfig) -> None:
        self.program = program
        self.config = config
        self.funcs: dict[str, FuncDef] = {f.name: f for f in program.funcs}
        self.diagnostics: list[Diagnostic] = []
        self.notes: list[str] = []
        self.incomplete = False
        self._seen_diag: set[tuple] = set()
        self._noted_unknown: set[tuple] = set()
        self._spec_deps: set[str] = set()

    # ---------- 对外入口 ----------

    def run(self) -> tuple[Verdict, list[Diagnostic], list[str]]:
        entries = [f.name for f in self.program.funcs if f.name == "main"]
        if not entries:
            # 没有 main 时每个函数都当作可能的入口，形参按干净数据处理。
            entries = [f.name for f in self.program.funcs]
        for name in entries:
            self._analyze_body(self.funcs[name], {}, depth=0, stack=frozenset())
        used = sorted(
            self._spec_deps
            | {name for diag in self.diagnostics for name in diag.assumptions}
        )
        if used:
            detail = "; ".join(
                f"{s.name}(returns={s.returns})"
                for s in (self.config.external_specs[n] for n in used)
            )
            self.notes.append(
                "本次以下诊断依赖外部调用行为说明，说明被撤回或修改后这些结论失效：" + detail
            )
        # 结论优先级：
        # 无法判断的部分（未知调用/递归截断）必须呈现为 INCOMPLETE；
        # 仅依赖外部说明的风险路径为 ASSUMED_UNSAFE；
        # 已证实路径为 UNSAFE。三者独立呈现，互不吞没。
        bases = {d.basis for d in self.diagnostics}
        if self.incomplete or BASIS_UNKNOWN in bases:
            verdict = Verdict.INCOMPLETE
        elif BASIS_CONFIRMED in bases:
            verdict = Verdict.UNSAFE
        elif BASIS_ASSUMPTION in bases:
            verdict = Verdict.ASSUMED_UNSAFE
        else:
            verdict = Verdict.SAFE
        return verdict, self.diagnostics, self.notes, tuple(used)

    # ---------- 语句 ----------

    def _analyze_body(
        self,
        func: FuncDef,
        env: Env,
        depth: int,
        stack: frozenset[str],
    ) -> tuple[Env, frozenset[Fact]]:
        """分析函数体，返回 (结束时环境, 所有 return 语句返回值的并集)。"""

        env = dict(env)
        returned: frozenset[Fact] = frozenset()
        for stmt in func.body:
            if isinstance(stmt, IfStmt):
                # 条件里的调用同样要分析（可能内部触发 sink）。
                self._eval(stmt.cond, env, depth, stack)
                env_then, ret_then = self._analyze_body(
                    self._inline(func, stmt.then_block), env, depth, stack
                )
                if stmt.else_block:
                    env_else, ret_else = self._analyze_body(
                        self._inline(func, stmt.else_block), env, depth, stack
                    )
                else:
                    env_else, ret_else = env, frozenset()
                env = self._merge(env, env_then, env_else, stmt.loc)
                returned = returned | ret_then | ret_else
            elif isinstance(stmt, ReturnStmt):
                if stmt.value is not None:
                    facts = self._eval(stmt.value, env, depth, stack)
                    hop = PathHop(stmt.loc, "call_out", "return 将值交回调用处")
                    returned = returned | frozenset(f.extended(hop) for f in facts)
            elif isinstance(stmt, AssignStmt):
                facts = self._eval(stmt.value, env, depth, stack)
                hop = PathHop(stmt.loc, "assign", f"赋值给变量 {stmt.target}")
                env[stmt.target] = frozenset(f.extended(hop) for f in facts)
            elif isinstance(stmt, ExprStmt):
                self._eval(stmt.expr, env, depth, stack)
        return env, returned

    @staticmethod
    def _inline(func: FuncDef, stmts) -> FuncDef:
        return replace(func, body=stmts)

    def _merge(self, before: Env, then_env: Env, else_env: Env, if_loc: Loc) -> Env:
        """分支汇合：变量污点取并集；只在一个分支被赋值时，另一分支保留旧值。"""

        merged: Env = {}
        for name in set(before) | set(then_env) | set(else_env):
            left = then_env.get(name, before.get(name, frozenset()))
            right = else_env.get(name, before.get(name, frozenset()))
            facts = left | right
            if facts and (left != right or name in then_env or name in else_env):
                hop = PathHop(if_loc, "join", f"分支汇合，变量 {name} 可能取任一分支的值")
                facts = frozenset(f.extended(hop) for f in facts)
            merged[name] = facts
        return merged

    # ---------- 表达式 ----------

    def _eval(self, expr, env: Env, depth: int, stack: frozenset[str]) -> frozenset[Fact]:
        if isinstance(expr, (NumberLit, StringLit, BoolLit)):
            return frozenset()
        if isinstance(expr, Var):
            return env.get(expr.name, frozenset())
        if isinstance(expr, Unary):
            return self._eval(expr.operand, env, depth, stack)
        if isinstance(expr, Binary):
            left = self._eval(expr.left, env, depth, stack)
            right = self._eval(expr.right, env, depth, stack)
            facts = left | right
            if facts:
                hop = PathHop(expr.loc, "expr", f"经运算符 {expr.op} 传播")
                facts = frozenset(f.extended(hop) for f in facts)
            return facts
        if isinstance(expr, Call):
            return self._eval_call(expr, env, depth, stack)
        raise TypeError(f"未知表达式节点 {type(expr).__name__}")

    def _eval_call(
        self, call: Call, env: Env, depth: int, stack: frozenset[str]
    ) -> frozenset[Fact]:
        # 实参先求值（参数之间不互相影响，这里顺序无关）。
        arg_facts = [self._eval(a, env, depth, stack) for a in call.args]

        if call.func in SOURCES:
            origin = ("source", call.func, call.loc.line, call.loc.col)
            hop = PathHop(call.loc, "source", SOURCES[call.func])
            return frozenset({Fact(origin, (hop,))})

        if call.func in SANITIZERS:
            # 明确净化：返回值不带任何原污点，净化后的值不能和原值混成一份。
            self.notes.append(f"{call.loc}: 调用 {call.func}() 对 {len(arg_facts)} 个值进行了净化")
            return frozenset()

        if call.func in SINKS:
            tainted = frozenset().union(*arg_facts) if arg_facts else frozenset()
            self._report_sink(call, tainted)
            return frozenset()  # sink 无返回值

        callee = self.funcs.get(call.func)
        if callee is None:
            return self._eval_external(call, arg_facts)

        # 用户自定义函数：递归/深度上限保护。
        if call.func in stack or depth >= self.config.max_call_depth:
            self.incomplete = True
            reason = (
                f"递归调用 {call.func}() 未展开"
                if call.func in stack
                else f"调用深度达到上限 {self.config.max_call_depth}，{call.func}() 未展开"
            )
            self.notes.append(f"{call.loc}: {reason}，该调用结果按潜在不可信处理")
            key = ("truncated", call.func, depth, call.loc.line, call.loc.col)
            hop = PathHop(call.loc, "truncated", reason + "（按潜在不可信处理）")
            return frozenset(
                {Fact(key, (hop,), basis=BASIS_UNKNOWN)}.union(
                    f.as_basis(BASIS_UNKNOWN).extended(
                        PathHop(call.loc, "truncated", reason + "，已传播污点是否原样返回无法判断")
                    )
                    for facts in arg_facts
                    for f in facts
                )
            )

        if len(call.args) != len(callee.params):
            self.incomplete = True
            self.notes.append(
                f"{call.loc}: 调用 {call.func}() 参数个数 {len(call.args)} 与定义 {len(callee.params)} 不符，未展开"
            )
            key = ("truncated", call.func, depth, call.loc.line, call.loc.col)
            hop = PathHop(call.loc, "truncated", "参数个数不符，调用未展开（按潜在不可信处理）")
            return frozenset({Fact(key, (hop,), basis=BASIS_UNKNOWN)})

        # 绑定形参：把调用点位置记录为 call_in 一跳。
        callee_env: Env = {}
        for param, facts in zip(callee.params, arg_facts):
            hop = PathHop(call.loc, "call_in", f"实参传入 {call.func}() 的形参 {param}")
            callee_env[param] = frozenset(f.extended(hop) for f in facts)

        _, returned = self._analyze_body(
            callee, callee_env, depth + 1, stack | {call.func}
        )
        hop = PathHop(call.loc, "call_out", f"{call.func}() 返回值回到调用处")
        return frozenset(f.extended(hop) for f in returned)

    def _eval_external(
        self, call: Call, arg_facts: list[frozenset[Fact]]
    ) -> frozenset[Fact]:
        """处理用户未定义的外部调用（无参/带参/分支合流结论一致）。

        有显式行为说明时严格按说明判定，结论事实标记为“依赖假设”；
        没有说明时，外部函数可能净化、忽略或改写实参，因此既不能把返回
        值当成干净数据，也不能把实参污点穿过未知函数后仍当成已证实路径。
        返回值一律按“无法判断（潜在不可信）”处理，已有的实参调用链作为
        背景保留，但依据降级为 unknown。
        """

        spec = self.config.external_specs.get(call.func)
        if spec is not None:
            self._spec_deps.add(call.func)
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 按提供的行为说明 "
                f"(returns={spec.returns}) 判定：{spec.description}"
            )
            if spec.returns == "clean":
                return frozenset()
            if spec.returns == "tainted":
                origin = ("spec_source", call.func, call.loc.line, call.loc.col)
                hop = PathHop(
                    call.loc,
                    "external",
                    f"外部调用 {call.func}() 按说明视为不可信来源：{spec.description}",
                )
                return frozenset(
                    {
                        Fact(
                            origin,
                            (hop,),
                            basis=BASIS_ASSUMPTION,
                            assumptions=frozenset({call.func}),
                        )
                    }
                )
            # propagate：仅当实参带污点时返回值带污点；结论依赖该说明。
            return frozenset(
                f.as_basis(
                    BASIS_ASSUMPTION if f.basis == BASIS_CONFIRMED else f.basis,
                    f.assumptions | {call.func},
                ).extended(
                    PathHop(
                        call.loc,
                        "external",
                        f"外部调用 {call.func}() 按说明原样传播实参污点：{spec.description}",
                    )
                )
                for facts in arg_facts
                for f in facts
            )

        propagated = frozenset().union(*arg_facts) if arg_facts else frozenset()
        note_key = (call.func, call.loc.line, call.loc.col)
        if note_key not in self._noted_unknown:
            self._noted_unknown.add(note_key)
            # 程序中出现缺少说明的外部调用：无论返回值是否流入 sink，
            # 分析都不能给出无依据的 SAFE（常量等已证实安全路径仍不报）。
            self.incomplete = True
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 缺少行为说明，"
                f"其可能净化、忽略或改变实参，返回值是否带污点无法判断；"
                f"实参调用链仅作背景保留，不构成已证实的风险路径"
            )
        key = ("unknown", call.func, call.loc.line, call.loc.col)
        unknown_hop = PathHop(
            call.loc,
            "unknown",
            f"外部调用 {call.func}() 语义未知（缺少行为说明）：返回值是否带污点无法判断",
        )
        result: set[Fact] = set()
        if propagated:
            # 实参调用链保留为背景，但在未知调用处依据降级为无法判断。
            for fact in propagated:
                result.add(fact.as_basis(BASIS_UNKNOWN).extended(unknown_hop))
        else:
            # 无实参或实参干净：无参未知调用的返回值同样无法判断。
            result.add(Fact(key, (unknown_hop,), basis=BASIS_UNKNOWN))
        return frozenset(result)

    # ---------- 诊断 ----------

    def _report_sink(self, call: Call, facts: frozenset[Fact]) -> None:
        if not facts:
            return
        groups = (
            (
                BASIS_CONFIRMED,
                Severity.ERROR,
                "TAINT-FLOW",
                "不可信数据",
                "",
            ),
            (
                BASIS_ASSUMPTION,
                Severity.WARNING,
                "TAINT-ASSUMED",
                "按外部行为说明视为不可信的数据",
                "",
            ),
            (
                BASIS_UNKNOWN,
                Severity.WARNING,
                "TAINT-UNCERTAIN",
                "无法判定是否干净的数据",
                "路径经过行为未知的外部调用或未展开调用，函数可能净化、忽略或改变该数据",
            ),
        )
        for basis, severity, rule, suffix, uncertainty in groups:
            group = frozenset(f for f in facts if f.basis == basis)
            if not group:
                continue
            assumptions = tuple(sorted({a for f in group for a in f.assumptions}))
            paths = tuple(
                TaintPath(f.path + (PathHop(call.loc, "sink", f"{suffix}流入 {call.func}()"),))
                for f in group
            )
            dedup_key = (rule, call.func, call.loc.line, call.loc.col, tuple(p.hops for p in paths))
            if dedup_key in self._seen_diag:
                continue
            self._seen_diag.add(dedup_key)
            self.diagnostics.append(
                Diagnostic(
                    severity=severity,
                    message=SINKS[call.func],
                    loc=call.loc,
                    sink=call.func,
                    paths=paths,
                    rule=rule,
                    basis=basis,
                    assumptions=assumptions,
                    uncertainty=uncertainty,
                )
            )
            if basis == BASIS_UNKNOWN:
                self.incomplete = True


def analyze_program(program: Program, config: AnalysisConfig | None = None):
    analyzer = Analyzer(program, config or AnalysisConfig())
    verdict, diagnostics, notes, assumptions_used = analyzer.run()
    from .model import AnalysisResult

    return AnalysisResult(
        verdict=verdict,
        diagnostics=diagnostics,
        notes=notes,
        assumptions_used=assumptions_used,
    )


def analyze_source(source: str, config: AnalysisConfig | None = None) -> "AnalysisResult":
    from .model import AnalysisResult

    try:
        program = parse(source)
    except Exception as exc:  # LexerError / ParseError
        loc = getattr(exc, "loc", Loc(0, 0, 0))
        return AnalysisResult(
            verdict=Verdict.PARSE_ERROR,
            diagnostics=[
                Diagnostic(Severity.ERROR, str(exc), loc, sink="", rule="PARSE")
            ],
            notes=[],
        )
    return analyze_program(program, config)


def compare_spec_versions(
    source: str,
    before: AnalysisConfig,
    after: AnalysisConfig,
) -> VersionDiff:
    """比较同一程序在两版外部行为说明下的结论。

    某项说明被撤回或修改后，只有依赖该说明的 sink 诊断会被标记为变化；
    不依赖它的已证实风险路径与常量安全路径保持原样。
    """

    before_result = analyze_source(source, before)
    after_result = analyze_source(source, after)
    before_map = _diag_sink_map(before_result)
    after_map = _diag_sink_map(after_result)

    before_specs = set(before.external_specs or {})
    after_specs = set(after.external_specs or {})
    withdrawn = before_specs - after_specs
    changed_specs = {
        name
        for name in before_specs & after_specs
        if before.external_specs[name] != after.external_specs[name]
    }

    changes: list[DiagnosticChange] = []
    for identity in sorted(before_map.keys() | after_map.keys(), key=lambda x: (x[1].line, x[1].col, x[0])):
        sink, loc = identity
        old = before_map.get(identity)
        new = after_map.get(identity)
        old_basis = old.basis if old else None
        new_basis = new.basis if new else None
        old_assumptions = old.assumptions if old else ()
        new_assumptions = new.assumptions if new else ()
        affected = (set(old_assumptions) | set(new_assumptions)) & (withdrawn | changed_specs)
        if old_basis == new_basis and old_assumptions == new_assumptions:
            continue
        if old is not None and not affected:
            # 说明版本变化与该诊断无关（例如已证实路径），结论不得受影响。
            continue
        if affected & withdrawn:
            reason = f"依赖的说明 {', '.join(sorted(affected & withdrawn))} 已被撤回"
        elif affected & changed_specs:
            reason = f"说明 {', '.join(sorted(affected & changed_specs))} 被修改"
        elif new is not None:
            reason = "新版说明引入了对该调用的假设"
        else:
            reason = "依据发生变化"
        changes.append(
            DiagnosticChange(
                sink=sink,
                loc=loc,
                before_basis=old_basis,
                after_basis=new_basis,
                before_assumptions=old_assumptions,
                after_assumptions=new_assumptions,
                before_paths=old.paths if old else (),
                after_paths=new.paths if new else (),
                reason=reason,
            )
        )
    return VersionDiff(
        before_verdict=before_result.verdict,
        after_verdict=after_result.verdict,
        changes=changes,
    )


def _diag_sink_map(result) -> dict[tuple[str, Loc], Diagnostic]:
    """以 (sink, 位置) 归并诊断；同一 sink 取依据优先级最高者用于比较。"""

    priority = {BASIS_CONFIRMED: 0, BASIS_ASSUMPTION: 1, BASIS_UNKNOWN: 2}
    grouped: dict[tuple[str, Loc], Diagnostic] = {}
    for diag in result.diagnostics:
        identity = (diag.sink, diag.loc)
        current = grouped.get(identity)
        if current is None or priority.get(diag.basis, 3) < priority.get(current.basis, 3):
            grouped[identity] = diag
    return grouped
