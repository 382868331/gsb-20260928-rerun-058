"""静态污点分析器（只分析文本，不执行被分析程序）。

设计要点：

* 不可信来源（source）产生污点事实，危险操作（sink）消费污点事实；
  净化函数（sanitizer）返回干净值，污点一经净化即与原值分离（不合并）。
* 跨函数：调用点把实参污点事实绑定到形参，污点事实自带到当前位置的
  完整传播路径；返回值把被调函数内部的路径带回调用点（上下文敏感）。
* 分支：分别分析两个分支，汇合时对变量做并集（保守地认为任一分支
  赋值都可能发生），并记录一条 join 路径跳。
* 递归/深度：沿调用栈分析，遇到递归或达到 ``max_call_depth`` 时停止展开，
  该次调用按 UNKNOWN 事实处理并给出 WARNING；只要有未分析完的部分，
  最终结论只能是 INCOMPLETE，绝不判 SAFE。
* 外部调用：缺少行为说明时，不把返回值当干净值，也不把它流到 sink 当作
  已证实漏洞；统一标为 UNKNOWN。提供说明后，由说明推出的事实标为 ASSUMED，
  调用位置、版本和完整路径随假设记录输出。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path

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
    AssumptionRecord,
    Diagnostic,
    Evidence,
    PathHop,
    ConclusionExplanation,
    PathBasis,
    SavedStudy,
    Severity,
    StudyRevisionResult,
    ConclusionRevision,
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
    version: str | None = None
    groups: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.returns not in ("clean", "tainted", "propagate"):
            raise ValueError(f"外部调用说明 {self.name} 的返回值策略非法: {self.returns}")


@dataclass(frozen=True)
class Fact:
    """一个污点事实：来自某处不可信来源，携带到当前位置的路径。"""

    key: tuple
    path: tuple[PathHop, ...]
    evidence: Evidence = Evidence.CONFIRMED
    assumptions: frozenset[str] = frozenset()
    safe: bool = False

    def extended(self, hop: PathHop) -> "Fact":
        return replace(self, path=self.path + (hop,))

    def with_evidence(
        self,
        evidence: Evidence,
        assumptions: frozenset[str] | None = None,
    ) -> "Fact":
        return replace(
            self,
            evidence=evidence,
            assumptions=self.assumptions | (assumptions or frozenset()),
        )


@dataclass(frozen=True)
class SpecVersionChange:
    name: str
    status: str
    old_version: str | None = None
    new_version: str | None = None
    changed_fields: tuple[str, ...] = ()

    @property
    def invalidated_assumptions(self) -> tuple[str, ...]:
        if self.status not in ("changed", "withdrawn"):
            return ()
        return (spec_assumption_id(self.name, self.old_version),)


def spec_assumption_id(name: str, version: str | None) -> str:
    return f"{name}@{version}" if version is not None else name


def compare_external_specs(
    old_specs: dict[str, ExternalSpec] | None,
    new_specs: dict[str, ExternalSpec] | None,
) -> list[SpecVersionChange]:
    """比较两版外部行为说明；撤回只返回被撤回名称对应的假设 ID。"""

    old_specs = old_specs or {}
    new_specs = new_specs or {}
    changes: list[SpecVersionChange] = []
    for name in sorted(set(old_specs) | set(new_specs)):
        old = old_specs.get(name)
        new = new_specs.get(name)
        if old is None:
            changes.append(SpecVersionChange(name, "added", new_version=new.version))
            continue
        if new is None:
            changes.append(
                SpecVersionChange(name, "withdrawn", old_version=old.version)
            )
            continue
        changed_fields = tuple(
            field
            for field in ("version", "returns", "description", "groups")
            if getattr(old, field) != getattr(new, field)
        )
        if changed_fields:
            changes.append(
                SpecVersionChange(
                    name,
                    "changed",
                    old.version,
                    new.version,
                    changed_fields,
                )
            )
        else:
            changes.append(
                SpecVersionChange(name, "unchanged", old.version, new.version)
            )
    return changes


# 变量环境：变量名 -> 该变量当前携带的污点事实集合（空集合 = 干净）。
Env = dict[str, frozenset[Fact]]


@dataclass
class AnalysisConfig:
    max_call_depth: int = 32
    external_specs: dict[str, ExternalSpec] | None = None
    disabled_assumptions: frozenset[str] | tuple[str, ...] | list[str] | set[str] | None = None

    def __post_init__(self) -> None:
        if self.external_specs is None:
            self.external_specs = {}
        if self.disabled_assumptions is None:
            self.disabled_assumptions = frozenset()
        else:
            self.disabled_assumptions = frozenset(self.disabled_assumptions)


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
        self._spec_uses: dict[str, dict] = {}
        self.explanations: list[ConclusionExplanation] = []

    # ---------- 对外入口 ----------

    def run(
        self,
    ) -> tuple[
        Verdict,
        list[Diagnostic],
        list[str],
        tuple[AssumptionRecord, ...],
    ]:
        entries = [f.name for f in self.program.funcs if f.name == "main"]
        if not entries:
            # 没有 main 时每个函数都当作可能的入口，形参按干净数据处理。
            entries = [f.name for f in self.program.funcs]
        for name in entries:
            self._analyze_body(self.funcs[name], {}, depth=0, stack=frozenset())
        assumptions = self._build_assumptions()
        if self.incomplete:
            verdict = Verdict.INCOMPLETE
        elif any(
            d.evidence == Evidence.CONFIRMED and d.severity == Severity.ERROR
            for d in self.diagnostics
        ):
            verdict = Verdict.UNSAFE
        elif assumptions or any(
            d.evidence == Evidence.ASSUMED for d in self.diagnostics
        ):
            verdict = Verdict.ASSUMED
        else:
            verdict = Verdict.SAFE
        return verdict, self.diagnostics, self.notes, assumptions

    def _build_assumptions(self) -> tuple[AssumptionRecord, ...]:
        records = []
        for assumption_id in sorted(self._spec_uses):
            use = self._spec_uses[assumption_id]
            spec = use["spec"]
            records.append(
                AssumptionRecord(
                    assumption_id=assumption_id,
                    name=spec.name,
                    version=spec.version,
                    returns=spec.returns,
                    description=spec.description,
                    locations=tuple(use["locations"]),
                    paths=tuple(use["paths"]),
                )
            )
        return tuple(records)

    def _record_spec_use(
        self,
        spec: ExternalSpec,
        loc: Loc,
        paths: tuple[TaintPath, ...] = (),
    ) -> str:
        assumption_id = spec_assumption_id(spec.name, spec.version)
        use = self._spec_uses.setdefault(
            assumption_id,
            {"spec": spec, "locations": [], "paths": []},
        )
        if loc not in use["locations"]:
            use["locations"].append(loc)
        use["paths"].extend(paths)
        self._spec_deps.add(spec.name)
        return assumption_id

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

    @staticmethod
    def _safe_fact(expr, hop_kind: str, text: str, evidence=Evidence.CONFIRMED, assumptions=frozenset()):
        hop = PathHop(expr.loc, hop_kind, text)
        key = ("safe", hop_kind, expr.loc.line, expr.loc.col)
        return Fact(
            key,
            (hop,),
            evidence=evidence,
            assumptions=assumptions,
            safe=True,
        )

    # ---------- 表达式 ----------

    def _eval(self, expr, env: Env, depth: int, stack: frozenset[str]) -> frozenset[Fact]:
        if isinstance(expr, NumberLit):
            return frozenset({
                self._safe_fact(expr, "constant", f"数字常量 {expr.value}")
            })
        if isinstance(expr, StringLit):
            return frozenset({
                self._safe_fact(expr, "constant", f'字符串常量 "{expr.value}"')
            })
        if isinstance(expr, BoolLit):
            return frozenset({
                self._safe_fact(expr, "constant", f"布尔常量 {expr.value}")
            })
        if isinstance(expr, Var):
            return env.get(expr.name, frozenset())
        if isinstance(expr, Unary):
            facts = self._eval(expr.operand, env, depth, stack)
            if facts:
                hop = PathHop(expr.loc, "expr", f"经一元运算符 {expr.op} 传播")
                facts = frozenset(f.extended(hop) for f in facts)
            return facts
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
            return frozenset({
                self._safe_fact(
                    call,
                    "sanitizer",
                    f"净化函数 {call.func}() 返回值与原污点分离，按干净数据处理",
                )
            })

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
            return frozenset({Fact(key, (hop,), evidence=Evidence.UNKNOWN)})

        if len(call.args) != len(callee.params):
            self.incomplete = True
            self.notes.append(
                f"{call.loc}: 调用 {call.func}() 参数个数 {len(call.args)} 与定义 {len(callee.params)} 不符，未展开"
            )
            key = ("truncated", call.func, depth, call.loc.line, call.loc.col)
            hop = PathHop(call.loc, "truncated", "参数个数不符，调用未展开（按潜在不可信处理）")
            return frozenset({Fact(key, (hop,), evidence=Evidence.UNKNOWN)})

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
        """处理用户未定义的外部调用。

        有显式行为说明时严格按说明判定并记录依赖；没有说明时返回值语义
        未知：既不能当成干净数据（会漏掉真实风险），也不能直接当成已
        发生的漏洞（缺少依据）。按“无法判定的潜在不可信值”处理，并令
        整体结论退化为 INCOMPLETE。
        """

        propagated = frozenset().union(*arg_facts) if arg_facts else frozenset()
        spec = self.config.external_specs.get(call.func)
        assumption_id = (
            spec_assumption_id(spec.name, spec.version)
            if spec is not None
            else None
        )
        if (
            spec is not None
            and (
                assumption_id in self.config.disabled_assumptions
                or set(spec.groups) & set(self.config.disabled_assumptions)
            )
        ):
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 的假设 {assumption_id} 已被临时关闭，按缺少行为说明处理"
            )
            spec = None
        if spec is not None:
            external_hop = PathHop(
                call.loc,
                "external",
                "外部调用 "
                f"{call.func}() 按说明 "
                f"{spec_assumption_id(spec.name, spec.version)} 判定",
            )
            incoming_paths = tuple(
                TaintPath(f.path + (external_hop,))
                for facts in arg_facts
                for f in facts
            )
            assumption_id = self._record_spec_use(spec, call.loc, incoming_paths)
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 按提供的行为说明 "
                f"({assumption_id}, returns={spec.returns}) 判定：{spec.description}"
            )
            if spec.returns == "clean":
                return frozenset({
                    Fact(
                        ("spec_clean", call.func, call.loc.line, call.loc.col),
                        (
                            PathHop(
                                call.loc,
                                "external",
                                f"外部调用 {call.func}() 按说明返回干净值：{spec.description}",
                            ),
                        ),
                        evidence=Evidence.ASSUMED,
                        assumptions=frozenset({assumption_id}),
                        safe=True,
                    )
                })
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
                            evidence=Evidence.ASSUMED,
                            assumptions=frozenset({assumption_id}),
                        )
                    }
                )
            result = set()
            for fact in propagated:
                extended = fact.extended(external_hop)
                if fact.safe or fact.evidence == Evidence.CONFIRMED:
                    result.add(
                        extended.with_evidence(
                            Evidence.ASSUMED,
                            frozenset({assumption_id}),
                        )
                    )
                elif fact.evidence == Evidence.UNKNOWN:
                    result.add(extended)
                else:
                    result.add(
                        extended.with_evidence(
                            Evidence.ASSUMED,
                            frozenset({assumption_id}),
                        )
                    )
            return frozenset(result)

        self.incomplete = True
        note_key = (call.func, call.loc.line, call.loc.col)
        if note_key not in self._noted_unknown:
            self._noted_unknown.add(note_key)
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 缺少行为说明，返回值语义未知，"
                f"只能按潜在不可信保守追踪；该路径不是已证实风险，分析不能据此给出安全结论"
            )
        key = ("unknown", call.func, call.loc.line, call.loc.col)
        hop = PathHop(
            call.loc,
            "unknown",
            f"外部调用 {call.func}() 语义未知（缺少行为说明），其净化、忽略或改写实参的行为均无法排除",
        )
        risk_propagated = frozenset(f for f in propagated if not f.safe)
        facts = frozenset(
            f.extended(hop).with_evidence(Evidence.UNKNOWN)
            for f in risk_propagated
        )
        unknown_fact = Fact(key, (hop,), evidence=Evidence.UNKNOWN)
        return facts if risk_propagated else frozenset({unknown_fact})

    # ---------- 诊断 ----------

    def _report_sink(self, call: Call, facts: frozenset[Fact]) -> None:
        risk_facts = frozenset(f for f in facts if not f.safe)
        safe_facts = frozenset(f for f in facts if f.safe)
        if not risk_facts and not safe_facts:
            safe_facts = frozenset({
                Fact(
                    ("clean", call.func, call.loc.line, call.loc.col),
                    (
                        PathHop(
                            call.loc,
                            "clean",
                            f"{call.func}() 的实参未携带任何风险依据",
                        ),
                    ),
                    safe=True,
                )
            })
        confirmed = frozenset(f for f in risk_facts if f.evidence == Evidence.CONFIRMED)
        assumed = frozenset(f for f in risk_facts if f.evidence == Evidence.ASSUMED)
        unknown = frozenset(f for f in risk_facts if f.evidence == Evidence.UNKNOWN)
        for group, severity, rule, suffix in (
            (confirmed, Severity.ERROR, "TAINT-FLOW", "不可信数据"),
            (assumed, Severity.WARNING, "TAINT-ASSUMED", "按外部行为说明视为不可信的数据"),
            (unknown, Severity.WARNING, "TAINT-UNCERTAIN", "无法判定是否干净的数据"),
        ):
            if not group:
                continue
            sink_hop = PathHop(call.loc, "sink", f"{suffix}流入 {call.func}()")
            paths = tuple(TaintPath(f.path + (sink_hop,)) for f in group)
            evidence = {
                "TAINT-FLOW": Evidence.CONFIRMED,
                "TAINT-ASSUMED": Evidence.ASSUMED,
                "TAINT-UNCERTAIN": Evidence.UNKNOWN,
            }[rule]
            dedup_key = (
                rule,
                call.func,
                call.loc.line,
                call.loc.col,
                tuple(p.hops for p in paths),
            )
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
                    evidence=evidence,
                    assumptions=tuple(
                        sorted({a for f in group for a in f.assumptions})
                    ),
                )
            )
            if severity is Severity.WARNING and rule != "TAINT-ASSUMED":
                self.incomplete = True
        self._explain_sink(call, confirmed, assumed, unknown, safe_facts)

    def _explain_sink(
        self,
        call: Call,
        confirmed: frozenset[Fact],
        assumed: frozenset[Fact],
        unknown: frozenset[Fact],
        safe_facts: frozenset[Fact],
    ) -> None:
        sink_hop = PathHop(call.loc, "sink", f"结论位置 {call.func}()")
        groups = (
            (confirmed, Evidence.CONFIRMED),
            (assumed, Evidence.ASSUMED),
            (unknown, Evidence.UNKNOWN),
        )
        risk_bases = tuple(
            PathBasis(
                path=TaintPath(f.path + (sink_hop,)),
                evidence=evidence,
                safe=False,
                assumptions=tuple(sorted(f.assumptions)),
            )
            for group, evidence in groups
            for f in sorted(group, key=lambda item: tuple((h.loc.line, h.loc.col, h.kind, h.text) for h in item.path))
        )
        safe_bases = tuple(
            PathBasis(
                path=TaintPath(f.path + (sink_hop,)),
                evidence=f.evidence,
                safe=True,
                assumptions=tuple(sorted(f.assumptions)),
            )
            for f in sorted(safe_facts, key=lambda item: tuple((h.loc.line, h.loc.col, h.kind, h.text) for h in item.path))
        )
        raw_assumption_sets = {
            basis.assumptions
            for basis in risk_bases
            if basis.assumptions
        }
        raw_assumption_values = [set(item) for item in raw_assumption_sets]
        assumption_sets = tuple(
            sorted(
                assumption_set
                for assumption_set in raw_assumption_sets
                if not any(
                    other < set(assumption_set)
                    for other in raw_assumption_values
                )
            )
        )
        requirement_sets = [set(basis.assumptions) for basis in risk_bases]
        assumption_versions = {
            assumption: assumption
            for basis in risk_bases
            for assumption in basis.assumptions
        }
        indispensable = (
            tuple(sorted(set.intersection(*requirement_sets)))
            if requirement_sets
            else ()
        )
        risk_hop_sets = [
            {
                (hop.loc.line, hop.loc.col, hop.kind, hop.text)
                for hop in basis.path.hops[:-1]
            }
            for basis in risk_bases
        ]
        common_keys = set.intersection(*risk_hop_sets) if risk_hop_sets else set()
        common_hops = (
            tuple(
                hop
                for hop in risk_bases[0].path.hops[:-1]
                if (hop.loc.line, hop.loc.col, hop.kind, hop.text) in common_keys
            )
            if risk_bases
            else ()
        )
        alternative_hops = tuple(
            dict.fromkeys(
                hop
                for basis in risk_bases
                for hop in basis.path.hops[:-1]
                if (hop.loc.line, hop.loc.col, hop.kind, hop.text) not in common_keys
            )
        )
        risk_bases = tuple(
            replace(
                basis,
                common=not any(
                    (hop.loc.line, hop.loc.col, hop.kind, hop.text) not in common_keys
                    for hop in basis.path.hops[:-1]
                ),
            )
            for basis in risk_bases
        )
        if confirmed:
            status = "CONFIRMED_RISK"
        elif assumed:
            status = "CONDITIONAL_RISK"
        elif unknown:
            status = "UNKNOWN"
        elif any(b.evidence == Evidence.ASSUMED for b in safe_bases):
            status = "ASSUMED_SAFE"
        else:
            status = "SAFE"
        self.explanations.append(
            ConclusionExplanation(
                sink=call.func,
                loc=call.loc,
                status=status,
                risk_bases=risk_bases,
                safe_bases=safe_bases,
                minimal_assumption_sets=assumption_sets,
                indispensable_assumptions=indispensable,
                common_basis=common_hops,
                alternative_basis=alternative_hops,
                disabled_assumptions=tuple(sorted(self.config.disabled_assumptions)),
                assumption_versions=assumption_versions,
            )
        )

def analyze_program(program: Program, config: AnalysisConfig | None = None):
    analyzer = Analyzer(program, config or AnalysisConfig())
    verdict, diagnostics, notes, assumptions = analyzer.run()
    from .model import AnalysisResult

    return AnalysisResult(
        verdict=verdict,
        diagnostics=diagnostics,
        notes=notes,
        assumptions=assumptions,
        explanations=analyzer.explanations,
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


def save_study(path, source, specs, result, revision="baseline"):
    payload = {
        "source": source,
        "revision": revision,
        "external_specs": {
            name: {
                "name": spec.name,
                "description": spec.description,
                "returns": spec.returns,
                "version": spec.version,
                "groups": list(spec.groups),
            }
            for name, spec in specs.items()
        },
        "result": asdict(result),
    }
    Path(path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default),
        encoding="utf-8",
    )


def load_study(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    specs = {
        name: ExternalSpec(
            name=item["name"],
            description=item["description"],
            returns=item["returns"],
            version=item.get("version"),
            groups=tuple(item.get("groups", ())),
        )
        for name, item in payload["external_specs"].items()
    }
    return SavedStudy(
        source=payload["source"],
        result=_result_from_dict(payload["result"]),
        external_specs=specs,
        revision=payload.get("revision", "baseline"),
    )


def revise_study(study, new_specs, disabled_assumptions=(), max_call_depth=32):
    invalid = tuple(
        aid
        for change in compare_external_specs(study.external_specs, new_specs)
        for aid in change.invalidated_assumptions
    )
    cfg = AnalysisConfig(
        max_call_depth=max_call_depth,
        external_specs=new_specs,
        disabled_assumptions=disabled_assumptions,
    )
    fresh = analyze_source(study.source, cfg)
    old_by_id = {(e.sink, e.loc.line, e.loc.col): e for e in study.result.explanations}
    new_by_id = {(e.sink, e.loc.line, e.loc.col): e for e in fresh.explanations}
    version_changes = compare_external_specs(study.external_specs, new_specs)
    changed_names = {
        change.name
        for change in version_changes
        if change.status != "unchanged"
    }
    affected = {
        key
        for mapping in (old_by_id, new_by_id)
        for key, explanation in mapping.items()
        if (
            set(_explanation_assumptions(explanation)) & set(invalid)
            or _explanation_uses_changed_external(explanation, changed_names)
        )
    }
    revisions = []
    explanations = []
    for key in sorted(set(old_by_id) | set(new_by_id)):
        old = old_by_id.get(key)
        new = new_by_id.get(key)
        if key in affected:
            if new is not None:
                explanations.append(new)
            elif old is not None:
                explanations.append(old)
            current = new or old
            old_assumptions = _explanation_assumptions(old) if old else ()
            new_assumptions = _explanation_assumptions(new) if new else ()
            revisions.append(
                ConclusionRevision(
                    conclusion_id=current.conclusion_id,
                    loc=current.loc,
                    old_status=old.status if old else None,
                    new_status=new.status if new else None,
                    old_assumptions=old_assumptions,
                    new_assumptions=new_assumptions,
                    reused=False,
                    invalidated_assumptions=tuple(
                        sorted(set(invalid) & set(old_assumptions + new_assumptions))
                    ),
                )
            )
        elif old is not None:
            explanations.append(old)
    result = _merge_result(study.result, fresh, tuple(explanations), affected)
    return StudyRevisionResult(
        result=result,
        changes=tuple(revisions),
        invalidated_assumptions=invalid,
    )


def _explanation_assumptions(explanation):
    return tuple(
        sorted(
            {
                *explanation.indispensable_assumptions,
                *(aid for group in explanation.minimal_assumption_sets for aid in group),
                *(aid for basis in explanation.risk_bases for aid in basis.assumptions),
                *(aid for basis in explanation.safe_bases for aid in basis.assumptions),
            }
        )
    )


def _explanation_uses_changed_external(explanation, names):
    if not names:
        return False
    external_texts = [
        hop.text
        for basis in (*explanation.risk_bases, *explanation.safe_bases)
        for hop in basis.path.hops
        if hop.kind == "external" or hop.kind == "unknown"
    ]
    return any(
        any(text.startswith("外部调用 " + name + "()") for text in external_texts)
        for name in names
    )


def _merge_result(old, fresh, explanations, affected):
    return replace(fresh, explanations=tuple(explanations))


def _json_default(value):
    if hasattr(value, "value"):
        return value.value
    return str(value)


def _result_from_dict(data):
    from .model import AnalysisResult

    def make_loc(item):
        return Loc(item["line"], item["col"], item["offset"])

    def make_hop(item):
        return PathHop(make_loc(item["loc"]), item["kind"], item["text"])

    def make_path(item):
        return TaintPath(tuple(make_hop(h) for h in item["hops"]))

    def make_basis(item):
        return PathBasis(
            path=make_path(item["path"]),
            evidence=Evidence(item["evidence"]),
            safe=item["safe"],
            assumptions=tuple(item["assumptions"]),
            common=item["common"],
        )

    diagnostics = tuple(
        Diagnostic(
            severity=Severity(item["severity"]),
            message=item["message"],
            loc=make_loc(item["loc"]),
            sink=item["sink"],
            paths=tuple(make_path(p) for p in item["paths"]),
            rule=item["rule"],
            evidence=Evidence(item["evidence"]),
            assumptions=tuple(item["assumptions"]),
        )
        for item in data["diagnostics"]
    )
    assumptions = tuple(
        AssumptionRecord(
            assumption_id=item["assumption_id"],
            name=item["name"],
            version=item["version"],
            returns=item["returns"],
            description=item["description"],
            locations=tuple(make_loc(x) for x in item["locations"]),
            paths=tuple(make_path(p) for p in item["paths"]),
        )
        for item in data["assumptions"]
    )
    explanations = tuple(
        ConclusionExplanation(
            sink=item["sink"],
            loc=make_loc(item["loc"]),
            status=item["status"],
            risk_bases=tuple(make_basis(x) for x in item["risk_bases"]),
            safe_bases=tuple(make_basis(x) for x in item["safe_bases"]),
            minimal_assumption_sets=tuple(
                tuple(x) for x in item["minimal_assumption_sets"]
            ),
            indispensable_assumptions=tuple(item["indispensable_assumptions"]),
            common_basis=tuple(make_hop(x) for x in item["common_basis"]),
            alternative_basis=tuple(make_hop(x) for x in item["alternative_basis"]),
            disabled_assumptions=tuple(item["disabled_assumptions"]),
            assumption_versions=item.get("assumption_versions", {}),
        )
        for item in data.get("explanations", ())
    )
    return AnalysisResult(
        verdict=Verdict(data["verdict"]),
        diagnostics=diagnostics,
        notes=list(data.get("notes", [])),
        assumptions=assumptions,
        explanations=explanations,
    )
