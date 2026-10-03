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

import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone

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
    ConflictRecord,
    ConclusionExplanation,
    Diagnostic,
    Evidence,
    PathExplanation,
    PathHop,
    ScenarioConclusion,
    ScenarioReport,
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
    version: str | None = None

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


@dataclass(frozen=True)
class BehaviorHypothesis:
    """研究者提出的一条外部行为假设，可与其他假设共同组成情景。

    与 ``ExternalSpec``（被整体采纳的说明）不同，假设允许成组提出、
    并可能互相矛盾：两条假设若对**同一次调用实例**给出互斥结果，
    分析器记录冲突，既不把二者拼成一条可行风险路径，也不因剩余路径
    为空就宣称安全。``site``（``行:列``）可把假设限定到具体调用
    实例；不同调用实例上的相似假设不会被误判为同一处矛盾。
    """

    name: str
    returns: str
    description: str = ""
    version: str | None = None
    site: str | None = None
    hypothesis_id: str | None = None

    def __post_init__(self) -> None:
        if self.returns not in ("clean", "tainted", "propagate"):
            raise ValueError(
                f"行为假设 {self.name} 的返回值策略非法: {self.returns}"
            )

    @property
    def hid(self) -> str:
        if self.hypothesis_id is not None:
            return self.hypothesis_id
        base = spec_assumption_id(self.name, self.version)
        return f"{base}#{self.site}" if self.site else base


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
            for field in ("version", "returns", "description")
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


def _spec_dict(specs):
    return dict(specs or {})


@dataclass(frozen=True)
class ResearchSnapshot:
    source: str
    specs: dict[str, ExternalSpec]
    disabled_assumptions: frozenset[str]
    verdict: str
    explanations: tuple[ConclusionExplanation, ...]
    assumptions: tuple[AssumptionRecord, ...]
    created_at: str
    hypotheses: tuple[BehaviorHypothesis, ...] = ()
    conflicts: tuple[ConflictRecord, ...] = ()
    scenarios: tuple[ScenarioReport, ...] = ()

    @classmethod
    def from_result(
        cls, source, result, specs, disabled_assumptions=(), hypotheses=()
    ):
        return cls(
            source=source,
            specs=_spec_dict(specs),
            disabled_assumptions=frozenset(disabled_assumptions),
            verdict=result.verdict.value,
            explanations=result.explanations,
            assumptions=result.assumptions,
            created_at=datetime.now(timezone.utc).isoformat(),
            hypotheses=tuple(hypotheses),
            conflicts=tuple(result.conflicts),
            scenarios=tuple(result.scenarios),
        )

    def to_json(self):
        return json.dumps(
            asdict(self),
            ensure_ascii=False,
            default=_json_default,
            indent=2,
        )

    def save(self, path):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_json())

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    @classmethod
    def from_dict(cls, data):
        return cls(
            source=data["source"],
            specs={
                name: ExternalSpec(
                    spec["name"],
                    spec["description"],
                    spec["returns"],
                    spec.get("version"),
                )
                for name, spec in data["specs"].items()
            },
            disabled_assumptions=frozenset(data.get("disabled_assumptions", ())),
            verdict=data["verdict"],
            explanations=tuple(
                _decode_explanation(item) for item in data["explanations"]
            ),
            assumptions=tuple(
                _decode_assumption(item) for item in data["assumptions"]
            ),
            created_at=data["created_at"],
            hypotheses=tuple(
                BehaviorHypothesis(
                    item["name"],
                    item["returns"],
                    item.get("description", ""),
                    item.get("version"),
                    item.get("site"),
                    item.get("hypothesis_id"),
                )
                for item in data.get("hypotheses", ())
            ),
            conflicts=tuple(
                _decode_conflict(item) for item in data.get("conflicts", ())
            ),
            scenarios=tuple(
                _decode_scenario(item) for item in data.get("scenarios", ())
            ),
        )


@dataclass(frozen=True)
class RevisionReport:
    old_snapshot: ResearchSnapshot
    new_snapshot: ResearchSnapshot
    changes: tuple[SpecVersionChange, ...]
    affected_conclusions: tuple[str, ...]
    reused_conclusions: tuple[str, ...]
    resolved_conflicts: tuple[str, ...] = ()
    new_conflicts: tuple[str, ...] = ()
    risk_changes: tuple["ConclusionChange", ...] = ()


@dataclass(frozen=True)
class ConclusionChange:
    """修订前后同一结论位置的风险变化及其来源。"""

    conclusion_id: str
    old_state: str
    new_state: str
    causes: tuple[str, ...]  # conflict_resolved | conflict_introduced | path_changed | spec_changed

def _json_default(value):
    if isinstance(value, frozenset):
        return sorted(value)
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"不能序列化 {type(value)!r}")


def _decode_loc(data):
    return Loc(data["line"], data["col"], data["offset"])


def _decode_path(data):
    return TaintPath(
        tuple(
            PathHop(
                _decode_loc(hop["loc"]),
                hop["kind"],
                hop["text"],
            )
            for hop in data["hops"]
        )
    )


def _decode_explanation(data):
    return ConclusionExplanation(
        conclusion_id=data["conclusion_id"],
        sink=data["sink"],
        loc=_decode_loc(data["loc"]),
        state=data["state"],
        path_explanations=tuple(
            PathExplanation(
                path=_decode_path(item["path"]),
                evidence=Evidence(item["evidence"]),
                assumptions=tuple(item["assumptions"]),
                kind=item["kind"],
            )
            for item in data["path_explanations"]
        ),
        assumption_groups=tuple(
            tuple(group) for group in data["assumption_groups"]
        ),
        indispensable_assumptions=tuple(data["indispensable_assumptions"]),
        common_assumptions=tuple(data["common_assumptions"]),
    )


def _decode_assumption(data):
    return AssumptionRecord(
        assumption_id=data["assumption_id"],
        name=data["name"],
        version=data.get("version"),
        returns=data["returns"],
        description=data["description"],
        locations=tuple(_decode_loc(item) for item in data["locations"]),
        paths=tuple(_decode_path(item) for item in data["paths"]),
    )


def _decode_path_explanation(item):
    return PathExplanation(
        path=_decode_path(item["path"]),
        evidence=Evidence(item["evidence"]),
        assumptions=tuple(item["assumptions"]),
        kind=item["kind"],
    )


def _decode_conflict(data):
    return ConflictRecord(
        conflict_id=data["conflict_id"],
        call=data["call"],
        loc=_decode_loc(data["loc"]),
        hypotheses=tuple(data["hypotheses"]),
        constraints=tuple(data["constraints"]),
        detail=data["detail"],
    )


def _decode_scenario(data):
    return ScenarioReport(
        scenario_id=data["scenario_id"],
        hypotheses=tuple(data["hypotheses"]),
        state=data["state"],
        conflicts=tuple(data.get("conflicts", ())),
        conclusions=tuple(
            ScenarioConclusion(
                conclusion_id=item["conclusion_id"],
                state=item["state"],
                feasible_paths=tuple(
                    _decode_path_explanation(p)
                    for p in item.get("feasible_paths", ())
                ),
                blocked_paths=tuple(
                    _decode_path_explanation(p)
                    for p in item.get("blocked_paths", ())
                ),
            )
            for item in data.get("conclusions", ())
        ),
    )


def snapshot_analysis(source, config=None):
    config = config or AnalysisConfig()
    result = analyze_source(source, config)
    snapshot = ResearchSnapshot.from_result(
        source,
        result,
        config.external_specs,
        config.disabled_assumptions,
        config.hypotheses,
    )
    return result, snapshot


# 变量环境：变量名 -> 该变量当前携带的污点事实集合（空集合 = 干净）。
Env = dict[str, frozenset[Fact]]


@dataclass
class AnalysisConfig:
    max_call_depth: int = 32
    external_specs: dict[str, ExternalSpec] | None = None
    disabled_assumptions: frozenset[str] | set[str] | tuple[str, ...] = ()
    hypotheses: tuple[BehaviorHypothesis, ...] = ()

    def __post_init__(self) -> None:
        if self.external_specs is None:
            self.external_specs = {}
        self.disabled_assumptions = frozenset(self.disabled_assumptions)
        self.hypotheses = tuple(self.hypotheses)
        seen: set[str] = set()
        for hypothesis in self.hypotheses:
            if hypothesis.hid in seen:
                raise ValueError(
                    f"行为假设 ID 重复: {hypothesis.hid}，请显式指定 hypothesis_id"
                )
            seen.add(hypothesis.hid)


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
        self._explanations: list[ConclusionExplanation] = []
        self._conflicts: list[ConflictRecord] = []
        self._conflict_keys: set[tuple] = set()

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
        elif any(
            d.evidence == Evidence.ASSUMED
            and self._assumptions_feasible(d.assumptions)
            for d in self.diagnostics
        ):
            verdict = Verdict.ASSUMED
        elif self._conflicts:
            # 互斥假设使所有条件风险路径都无法同时成立：既不能拼成一条
            # 实际可行的风险路径，也不能因没有剩余路径就宣称程序安全。
            self.notes.append(
                f"发现 {len(self._conflicts)} 处互斥行为假设，相关路径在任何 "
                "自洽情景下都无法同时成立；结论不能据此判为安全，需撤回或 "
                "修订假设后按情景分别查看"
            )
            verdict = Verdict.INCOMPLETE
        elif assumptions or any(
            d.evidence == Evidence.ASSUMED for d in self.diagnostics
        ):
            verdict = Verdict.ASSUMED
        else:
            verdict = Verdict.SAFE
        return verdict, self.diagnostics, self.notes, assumptions

    def explanations_result(self) -> tuple[ConclusionExplanation, ...]:
        return tuple(self._explanations)

    def conflicts_result(self) -> tuple[ConflictRecord, ...]:
        return tuple(self._conflicts)

    def _conflict_pairs(self) -> list[frozenset[str]]:
        return [frozenset(c.hypotheses) for c in self._conflicts]

    def _assumptions_feasible(self, assumptions) -> bool:
        chosen = set(assumptions)
        return not any(pair <= chosen for pair in self._conflict_pairs())

    def _build_assumptions(self) -> tuple[AssumptionRecord, ...]:
        records = []
        for assumption_id in sorted(self._spec_uses):
            use = self._spec_uses[assumption_id]
            records.append(
                AssumptionRecord(
                    assumption_id=assumption_id,
                    name=use["name"],
                    version=use["version"],
                    returns=use["returns"],
                    description=use["description"],
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
        self._record_use(
            assumption_id, spec.name, spec.version, spec.returns,
            spec.description, loc, paths,
        )
        self._spec_deps.add(spec.name)
        return assumption_id

    def _record_use(
        self,
        assumption_id: str,
        name: str,
        version: str | None,
        returns: str,
        description: str,
        loc: Loc,
        paths: tuple[TaintPath, ...] = (),
    ) -> None:
        use = self._spec_uses.setdefault(
            assumption_id,
            {
                "name": name,
                "version": version,
                "returns": returns,
                "description": description,
                "locations": [],
                "paths": [],
            },
        )
        if loc not in use["locations"]:
            use["locations"].append(loc)
        use["paths"].extend(paths)

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
            hop = PathHop(expr.loc, "constant", "程序内常量，不依赖外部返回值")
            return frozenset(
                {
                    Fact(
                        ("constant", expr.loc.line, expr.loc.col),
                        (hop,),
                        safe=True,
                    )
                }
            )
        if isinstance(expr, Var):
            return env.get(expr.name, frozenset())
        if isinstance(expr, Unary):
            return self._eval(expr.operand, env, depth, stack)
        if isinstance(expr, Binary):
            left = self._eval(expr.left, env, depth, stack)
            right = self._eval(expr.right, env, depth, stack)
            unsafe = frozenset(f for f in left | right if not f.safe)
            safe = frozenset(f for f in left | right if f.safe)
            facts = unsafe if unsafe else safe
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
            hop = PathHop(
                call.loc,
                "sanitizer",
                f"{call.func}() 的语言语义保证返回值干净",
            )
            return frozenset(
                {
                    Fact(
                        ("sanitizer", call.func, call.loc.line, call.loc.col),
                        (hop,),
                        safe=True,
                    )
                }
            )

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
        hypotheses = self._applicable_hypotheses(call)
        if hypotheses:
            return self._eval_hypotheses(call, propagated, hypotheses)
        spec = self.config.external_specs.get(call.func)
        if spec is not None:
            assumption_id = spec_assumption_id(spec.name, spec.version)
            if assumption_id in self.config.disabled_assumptions:
                spec = None
        if spec is not None:
            assumption_id = spec_assumption_id(spec.name, spec.version)
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
            self._record_spec_use(spec, call.loc, incoming_paths)
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 按提供的行为说明 "
                f"({assumption_id}, returns={spec.returns}) 判定：{spec.description}"
            )
            if spec.returns == "clean":
                return frozenset(
                    {
                        Fact(
                            ("spec_safe", call.func, call.loc.line, call.loc.col),
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
                    }
                )
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
            unsafe = frozenset(f for f in propagated if not f.safe)
            for fact in unsafe:
                extended = fact.extended(external_hop)
                if fact.evidence == Evidence.UNKNOWN:
                    result.add(extended)
                else:
                    result.add(
                        extended.with_evidence(
                            Evidence.ASSUMED,
                            frozenset({assumption_id}),
                        )
                    )
            if not unsafe:
                result.add(
                    Fact(
                        ("spec_safe", call.func, call.loc.line, call.loc.col),
                        (external_hop,),
                        evidence=Evidence.ASSUMED,
                        assumptions=frozenset({assumption_id}),
                        safe=True,
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
        unsafe = frozenset(f for f in propagated if not f.safe)
        facts = frozenset(
            f.extended(hop).with_evidence(Evidence.UNKNOWN)
            for f in unsafe
        )
        unknown_fact = Fact(key, (hop,), evidence=Evidence.UNKNOWN)
        return facts | frozenset({unknown_fact})

    # ---------- 行为假设与冲突 ----------

    def _applicable_hypotheses(self, call: Call) -> list[BehaviorHypothesis]:
        site = f"{call.loc.line}:{call.loc.col}"
        return [
            hypothesis
            for hypothesis in self.config.hypotheses
            if hypothesis.name == call.func
            and (hypothesis.site is None or hypothesis.site == site)
            and hypothesis.hid not in self.config.disabled_assumptions
        ]

    @staticmethod
    def _hypothesis_outcome(
        hypothesis: BehaviorHypothesis, has_unsafe_args: bool
    ) -> tuple[str, str]:
        """返回 (结果类别, 可读的约束描述)。"""

        if hypothesis.returns == "clean":
            return "clean", f"{hypothesis.hid}: returns=clean ⇒ 返回值干净"
        if hypothesis.returns == "tainted":
            return "tainted", f"{hypothesis.hid}: returns=tainted ⇒ 返回值不可信"
        if has_unsafe_args:
            return (
                "tainted",
                f"{hypothesis.hid}: returns=propagate 且实参带污点 ⇒ 返回值不可信",
            )
        return (
            "clean",
            f"{hypothesis.hid}: returns=propagate 且实参无污点 ⇒ 返回值干净",
        )

    def _record_conflict(
        self,
        call: Call,
        first: BehaviorHypothesis,
        second: BehaviorHypothesis,
        constraints: dict[str, str],
    ) -> None:
        key = (call.loc.line, call.loc.col, first.hid, second.hid)
        if key in self._conflict_keys:
            return
        self._conflict_keys.add(key)
        conflict_id = (
            f"conflict:{call.func}:{call.loc.line}:{call.loc.col}:"
            f"{first.hid}~{second.hid}"
        )
        self._conflicts.append(
            ConflictRecord(
                conflict_id=conflict_id,
                call=call.func,
                loc=call.loc,
                hypotheses=(first.hid, second.hid),
                constraints=(constraints[first.hid], constraints[second.hid]),
                detail=(
                    f"假设 {first.hid} 与 {second.hid} 对 {call.func}() 的"
                    "同一次调用给出互斥结果"
                ),
            )
        )

    def _eval_hypotheses(
        self,
        call: Call,
        propagated: frozenset[Fact],
        hypotheses: list[BehaviorHypothesis],
    ) -> frozenset[Fact]:
        """按研究者提出的一组假设求值；互斥假设各自成事实并记录冲突。

        每条结果事实只携带推出它所需的那部分假设 ID：下游路径若同时
        依赖一对互斥假设，则该路径在任何自洽情景下都不可行。
        """

        unsafe = [f for f in propagated if not f.safe]
        groups: dict[str, list[BehaviorHypothesis]] = {"clean": [], "tainted": []}
        constraints: dict[str, str] = {}
        for hypothesis in hypotheses:
            outcome, constraint = self._hypothesis_outcome(hypothesis, bool(unsafe))
            groups[outcome].append(hypothesis)
            constraints[hypothesis.hid] = constraint
        for first in groups["clean"]:
            for second in groups["tainted"]:
                self._record_conflict(call, first, second, constraints)
        if groups["clean"] and groups["tainted"]:
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 上的一组假设互相矛盾，"
                "按情景分别求值，不合并为同一条路径"
            )
        incoming_paths = tuple(
            TaintPath(f.path)
            for f in propagated
        )
        for hypothesis in hypotheses:
            self._record_use(
                hypothesis.hid,
                hypothesis.name,
                hypothesis.version,
                hypothesis.returns,
                hypothesis.description or "研究者提出的行为假设",
                call.loc,
                incoming_paths,
            )
            self.notes.append(
                f"{call.loc}: 外部调用 {call.func}() 按行为假设 {hypothesis.hid} "
                f"(returns={hypothesis.returns}) 判定"
            )
        facts: set[Fact] = set()
        if groups["clean"]:
            ids = frozenset(h.hid for h in groups["clean"])
            hop = PathHop(
                call.loc,
                "external",
                f"外部调用 {call.func}() 按假设 {', '.join(sorted(ids))} 返回干净值",
            )
            facts.add(
                Fact(
                    ("hyp_safe", call.func, call.loc.line, call.loc.col),
                    (hop,),
                    evidence=Evidence.ASSUMED,
                    assumptions=ids,
                    safe=True,
                )
            )
        tainted_ids = frozenset(
            h.hid for h in groups["tainted"] if h.returns == "tainted"
        )
        propagate_ids = frozenset(
            h.hid for h in groups["tainted"] if h.returns == "propagate"
        )
        if tainted_ids:
            hop = PathHop(
                call.loc,
                "external",
                f"外部调用 {call.func}() 按假设 {', '.join(sorted(tainted_ids))} "
                "视为不可信来源",
            )
            facts.add(
                Fact(
                    ("hyp_source", call.func, call.loc.line, call.loc.col),
                    (hop,),
                    evidence=Evidence.ASSUMED,
                    assumptions=tainted_ids,
                )
            )
        if propagate_ids:
            external_hop = PathHop(
                call.loc,
                "external",
                f"外部调用 {call.func}() 按假设 {', '.join(sorted(propagate_ids))} "
                "传播实参污点",
            )
            for fact in unsafe:
                extended = fact.extended(external_hop)
                if fact.evidence == Evidence.UNKNOWN:
                    # 未知返回值不靠补默认结果消除不确定性。
                    facts.add(extended)
                else:
                    facts.add(
                        extended.with_evidence(Evidence.ASSUMED, propagate_ids)
                    )
        return frozenset(facts)

    # ---------- 诊断 ----------

    def _report_sink(self, call: Call, facts: frozenset[Fact]) -> None:
        if not facts:
            hop = PathHop(
                call.loc,
                "constant",
                f"传入 {call.func}() 的表达式不含可达风险依据",
            )
            self._add_conclusion(
                call,
                (
                    PathExplanation(
                        TaintPath((hop,)),
                        Evidence.CONFIRMED,
                        (),
                        "safe",
                    ),
                ),
            )
            return
        safe = frozenset(f for f in facts if f.safe)
        risk_facts = frozenset(f for f in facts if not f.safe)
        confirmed = frozenset(f for f in risk_facts if f.evidence == Evidence.CONFIRMED)
        assumed = frozenset(f for f in risk_facts if f.evidence == Evidence.ASSUMED)
        unknown = frozenset(f for f in risk_facts if f.evidence == Evidence.UNKNOWN)
        all_explanations: list[PathExplanation] = []
        for group, severity, rule, suffix in (
            (confirmed, Severity.ERROR, "TAINT-FLOW", "不可信数据"),
            (assumed, Severity.WARNING, "TAINT-ASSUMED", "按外部行为说明视为不可信的数据"),
            (unknown, Severity.WARNING, "TAINT-UNCERTAIN", "无法判定是否干净的数据"),
        ):
            if not group:
                continue
            ordered_group = sorted(
                group,
                key=lambda fact: (
                    fact.path[0].kind == "unknown",
                    len(fact.path),
                    fact.key,
                ),
            )
            paths = tuple(
                TaintPath(
                    f.path
                    + (
                        PathHop(
                            call.loc,
                            "sink",
                            f"{suffix}流入 {call.func}()",
                        ),
                    )
                )
                for f in ordered_group
            )
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
            for fact, path in zip(ordered_group, paths):
                all_explanations.append(
                    PathExplanation(
                        path=path,
                        evidence=evidence,
                        assumptions=tuple(sorted(fact.assumptions)),
                        kind="risk",
                    )
                )
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
        for fact in sorted(safe, key=lambda item: item.key):
            path = TaintPath(
                fact.path
                + (
                    PathHop(
                        call.loc,
                        "safe",
                        f"独立安全依据传入 {call.func}()，不与风险路径合并",
                    ),
                )
            )
            all_explanations.append(
                PathExplanation(
                    path=path,
                    evidence=fact.evidence,
                    assumptions=tuple(sorted(fact.assumptions)),
                    kind="safe",
                )
            )
        self._add_conclusion(call, tuple(all_explanations))

    def _add_conclusion(
        self,
        call: Call,
        path_explanations: tuple[PathExplanation, ...],
    ) -> None:
        risky = tuple(item for item in path_explanations if item.kind == "risk")
        safe = tuple(item for item in path_explanations if item.kind == "safe")
        has_confirmed = any(item.evidence == Evidence.CONFIRMED for item in risky)
        has_assumed = any(item.evidence == Evidence.ASSUMED for item in risky)
        has_unknown = any(item.evidence == Evidence.UNKNOWN for item in risky)
        if has_confirmed and has_assumed:
            state = "CONFIRMED_AND_CONDITIONAL_RISK"
        elif has_confirmed and has_unknown:
            state = "CONFIRMED_RISK_WITH_UNKNOWN_PATH"
        elif has_assumed and has_unknown:
            state = "CONDITIONAL_RISK_WITH_UNKNOWN_PATH"
        elif has_confirmed:
            state = "CONFIRMED_RISK"
        elif has_assumed:
            state = "CONDITIONAL_RISK"
        elif has_unknown:
            state = "UNKNOWN_RISK"
        elif any(item.evidence == Evidence.ASSUMED for item in safe):
            state = "CONDITIONALLY_SAFE"
        else:
            state = "CONFIRMED_SAFE"

        assumption_sets = [
            frozenset(item.assumptions)
            for item in risky
            if item.evidence == Evidence.ASSUMED
        ]
        groups = self._minimal_assumption_groups(assumption_sets)
        if groups:
            common = frozenset.intersection(*groups)
            indispensable = tuple(
                assumption
                for assumption in sorted(common)
                if any(group == frozenset({assumption}) for group in groups)
                or not any(
                    group - frozenset({assumption}) in groups
                    for group in groups
                    if assumption in group
                )
            )
        else:
            indispensable = ()
        self._explanations.append(
            ConclusionExplanation(
                conclusion_id=self._conclusion_id(call),
                sink=call.func,
                loc=call.loc,
                state=state,
                path_explanations=path_explanations,
                assumption_groups=tuple(tuple(sorted(group)) for group in groups),
                indispensable_assumptions=indispensable,
                common_assumptions=(
                    tuple(sorted(frozenset.intersection(*groups))) if groups else ()
                ),
            )
        )

    @staticmethod
    def _minimal_assumption_groups(groups: list[frozenset[str]]) -> list[frozenset[str]]:
        unique = set(group for group in groups if group)
        return sorted(
            (
                group
                for group in unique
                if not any(other < group for other in unique)
            ),
            key=lambda group: tuple(sorted(group)),
        )

    @staticmethod
    def _conclusion_id(call: Call) -> str:
        return f"{call.func}:{call.loc.line}:{call.loc.col}"


def analyze_program(program: Program, config: AnalysisConfig | None = None):
    config = config or AnalysisConfig()
    analyzer = Analyzer(program, config)
    verdict, diagnostics, notes, assumptions = analyzer.run()
    from .model import AnalysisResult

    explanations = analyzer.explanations_result()
    conflicts = analyzer.conflicts_result()
    return AnalysisResult(
        verdict=verdict,
        diagnostics=diagnostics,
        notes=notes,
        assumptions=assumptions,
        explanations=explanations,
        conflicts=conflicts,
        scenarios=build_scenarios(config.hypotheses, conflicts, explanations),
    )


def build_scenarios(
    hypotheses,
    conflicts,
    explanations,
    max_scenarios: int = 32,
) -> tuple[ScenarioReport, ...]:
    """把一组假设组织成需要共同成立的情景并分别判定。

    * 若整组假设存在互斥对，先给出 CONTRADICTORY 的总情景，
      其最小冲突依据可追到具体调用与约束；
    * 之后枚举所有最大无冲突子集作为自洽情景，分别报告
      可行风险、当前依据下未发现风险、以及仍无法判断的范围；
    * 多处独立冲突各自记录，解决一处不会清除其他冲突。
    """

    universe = sorted({hypothesis.hid for hypothesis in hypotheses})
    pairs = [frozenset(conflict.hypotheses) for conflict in conflicts]
    reports: list[ScenarioReport] = []
    if conflicts:
        reports.append(
            ScenarioReport(
                scenario_id="ALL",
                hypotheses=tuple(universe),
                state="CONTRADICTORY",
                conflicts=tuple(conflict.conflict_id for conflict in conflicts),
                conclusions=(),
            )
        )
    if not universe:
        return tuple(reports)

    maximal: list[frozenset[str]] = []

    def extend(chosen: frozenset[str], rest: tuple[str, ...]) -> None:
        if len(maximal) > 256:
            return
        if not rest:
            maximal.append(chosen)
            return
        head, tail = rest[0], rest[1:]
        if not any(head in pair and pair <= (chosen | {head}) for pair in pairs):
            extend(chosen | {head}, tail)
        extend(chosen, tail)

    extend(frozenset(), tuple(universe))
    maximal = [
        candidate
        for candidate in maximal
        if not any(candidate < other for other in maximal)
    ]
    maximal.sort(key=lambda item: (-len(item), tuple(sorted(item))))
    for index, scenario_set in enumerate(maximal[:max_scenarios], start=1):
        conclusions = tuple(
            _scenario_conclusion(explanation, scenario_set, pairs)
            for explanation in explanations
        )
        states = {conclusion.state for conclusion in conclusions}
        if "FEASIBLE_RISK" in states:
            state = "FEASIBLE_RISK"
        elif "UNDECIDABLE" in states:
            state = "UNDECIDABLE"
        else:
            state = "NO_RISK_FOUND"
        reports.append(
            ScenarioReport(
                scenario_id=f"S{index}",
                hypotheses=tuple(sorted(scenario_set)),
                state=state,
                conflicts=(),
                conclusions=conclusions,
            )
        )
    return tuple(reports)


def _scenario_conclusion(
    explanation: ConclusionExplanation,
    scenario_set: frozenset[str],
    pairs: list[frozenset[str]],
) -> ScenarioConclusion:
    feasible: list[PathExplanation] = []
    blocked: list[PathExplanation] = []
    for item in explanation.path_explanations:
        needed = set(item.assumptions)
        if needed <= scenario_set and not any(pair <= needed for pair in pairs):
            feasible.append(item)
        else:
            blocked.append(item)
    risk = [item for item in feasible if item.kind == "risk"]
    if any(item.evidence != Evidence.UNKNOWN for item in risk):
        state = "FEASIBLE_RISK"
    elif any(item.evidence == Evidence.UNKNOWN for item in risk):
        state = "UNDECIDABLE"
    else:
        state = "NO_RISK_FOUND"
    return ScenarioConclusion(
        conclusion_id=explanation.conclusion_id,
        state=state,
        feasible_paths=tuple(feasible),
        blocked_paths=tuple(blocked),
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


def revise_specs(snapshot, new_specs=None, disabled_assumptions=(), hypotheses=None):
    """修订行为说明/假设后重算，并按稳定结论位置标记受影响/可复用解释。

    旧情景与旧结论保留在 old_snapshot 中可单独回看；新报告通过
    risk_changes 区分风险变化来自冲突解除/引入还是程序路径变化。
    """

    if hypotheses is None:
        hypotheses = snapshot.hypotheses
    config = AnalysisConfig(
        external_specs=_spec_dict(new_specs),
        disabled_assumptions=frozenset(disabled_assumptions),
        hypotheses=tuple(hypotheses),
    )
    result = analyze_source(snapshot.source, config)
    new_snapshot = ResearchSnapshot.from_result(
        snapshot.source,
        result,
        new_specs,
        disabled_assumptions,
        hypotheses,
    )
    changes = tuple(compare_external_specs(snapshot.specs, new_specs))
    changed_names = {
        change.name for change in changes if change.status != "unchanged"
    }
    changed_ids = {
        assumption
        for change in changes
        for assumption in change.invalidated_assumptions
    }

    def uses_changed_spec(explanation):
        assumption_values = {
            assumption
            for group in explanation.assumption_groups
            for assumption in group
        }
        if assumption_values & changed_ids:
            return True
        for item in explanation.path_explanations:
            if set(item.assumptions) & changed_ids:
                return True
            for hop in item.path.hops:
                if hop.kind in ("external", "unknown") and any(
                    f" {name}()" in hop.text for name in changed_names
                ):
                    return True
        return False

    old_ids = {item.conclusion_id for item in snapshot.explanations}
    affected = {
        item.conclusion_id
        for item in tuple(snapshot.explanations) + tuple(result.explanations)
        if uses_changed_spec(item)
    }
    reused = tuple(
        sorted(
            old_ids
            & {item.conclusion_id for item in result.explanations}
            - affected
        )
    )
    old_by_id = {item.conclusion_id: item for item in snapshot.explanations}
    reused_set = set(reused)
    reused_explanations = tuple(
        old_by_id.get(item.conclusion_id, item)
        if item.conclusion_id in reused_set
        else item
        for item in result.explanations
    )
    result.explanations = reused_explanations
    new_snapshot = replace(new_snapshot, explanations=reused_explanations)
    old_conflicts = {c.conflict_id: c for c in snapshot.conflicts}
    new_conflicts_map = {c.conflict_id: c for c in result.conflicts}
    resolved_conflicts = tuple(
        sorted(k for k in old_conflicts if k not in new_conflicts_map)
    )
    introduced_conflicts = tuple(
        sorted(k for k in new_conflicts_map if k not in old_conflicts)
    )
    resolved_hypotheses = {
        hypothesis
        for conflict_id in resolved_conflicts
        for hypothesis in old_conflicts[conflict_id].hypotheses
    }
    introduced_hypotheses = {
        hypothesis
        for conflict_id in introduced_conflicts
        for hypothesis in new_conflicts_map[conflict_id].hypotheses
    }
    old_pairs = [frozenset(c.hypotheses) for c in snapshot.conflicts]
    new_pairs = [frozenset(c.hypotheses) for c in result.conflicts]

    def feasible_risks(explanation, pairs):
        if explanation is None:
            return {}
        return {
            item.path.render(): set(item.assumptions)
            for item in explanation.path_explanations
            if item.kind == "risk"
            and not any(pair <= set(item.assumptions) for pair in pairs)
        }

    def feasible_unknowns(explanation, pairs):
        if explanation is None:
            return set()
        return {
            item.path.render()
            for item in explanation.path_explanations
            if item.kind == "risk" and item.evidence == Evidence.UNKNOWN
            and not any(pair <= set(item.assumptions) for pair in pairs)
        }

    new_by_id = {item.conclusion_id: item for item in result.explanations}
    risk_changes = []
    for conclusion_id in sorted(old_ids | set(new_by_id)):
        old_expl = old_by_id.get(conclusion_id)
        new_expl = new_by_id.get(conclusion_id)
        old_risk = feasible_risks(old_expl, old_pairs)
        new_risk = feasible_risks(new_expl, new_pairs)
        old_unknown = feasible_unknowns(old_expl, old_pairs)
        new_unknown = feasible_unknowns(new_expl, new_pairs)
        used_hypotheses = {
            assumption
            for explanation in (old_expl, new_expl)
            if explanation is not None
            for item in explanation.path_explanations
            for assumption in item.assumptions
        }
        touches_resolved = bool(used_hypotheses & resolved_hypotheses)
        touches_introduced = bool(used_hypotheses & introduced_hypotheses)
        if (
            old_risk == new_risk
            and old_unknown == new_unknown
            and conclusion_id not in affected
            and not touches_resolved
            and not touches_introduced
        ):
            continue
        causes = []
        appeared = set(new_risk) - set(old_risk)
        disappeared = set(old_risk) - set(new_risk)
        if touches_resolved:
            causes.append("conflict_resolved")
            appeared = {
                path
                for path in appeared
                if not (new_risk[path] & resolved_hypotheses)
            }
            disappeared = {
                path
                for path in disappeared
                if not (old_risk[path] & resolved_hypotheses)
            }
        if touches_introduced:
            causes.append("conflict_introduced")
            appeared = {
                path
                for path in appeared
                if not (new_risk[path] & introduced_hypotheses)
            }
            disappeared = {
                path
                for path in disappeared
                if not (old_risk[path] & introduced_hypotheses)
            }
        if conclusion_id in affected:
            causes.append("spec_changed")
        if appeared or disappeared or old_unknown != new_unknown:
            causes.append("path_changed")
        if not causes:
            continue
        old_state = old_expl.state if old_expl else "ABSENT"
        new_state = new_expl.state if new_expl else "ABSENT"
        risk_changes.append(
            ConclusionChange(
                conclusion_id=conclusion_id,
                old_state=old_state,
                new_state=new_state,
                causes=tuple(causes),
            )
        )
    report = RevisionReport(
        old_snapshot=snapshot,
        new_snapshot=new_snapshot,
        changes=changes,
        affected_conclusions=tuple(sorted(affected)),
        reused_conclusions=reused,
        resolved_conflicts=resolved_conflicts,
        new_conflicts=introduced_conflicts,
        risk_changes=tuple(risk_changes),
    )
    return result, report, new_snapshot
