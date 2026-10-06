"""外部行为说明的范围覆盖规划。

研究者指定一组需要解释的输出位置（sink 结论 ID，形如 "函数名:行:列"）
与可采用的库版本说明，规划器寻找能够覆盖这些位置、且内部没有重叠矛盾
的说明组合，并明确哪些外部调用仍依赖未知行为。

两种策略可比较：

* minimal：最少新增说明——必要时用新说明替换与所需说明冲突的现有
  说明（被替换者记入 dropped_existing）；
* preserve：尽量保留现有说明——新增说明不得驱逐现有说明，冲突时
  放弃新增并保留冲突依据。

互不相交（作用于不同调用实例）的不同版本可以共同采用；同一调用实例上
互斥的说明会阻止形成可行情景（feasible=False）。采用方案只是把说明
放进分析配置，条件安全结论仍判为 ASSUMED，不会提升为无条件安全。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import (
    SANITIZERS,
    SINKS,
    SOURCES,
    AnalysisConfig,
    ExternalSpec,
    _decode_conflict,
    _decode_loc,
    _json_default,
    _spec_from_data,
    analyze_source,
    scoped_spec_assumption_id,
    spec_assumption_id,
)
from .ast_nodes import (
    AssignStmt,
    Binary,
    Call,
    ExprStmt,
    IfStmt,
    ReturnStmt,
    Unary,
)
from .locations import Loc
from .model import AssumptionConflict, Evidence
from .parser import parse


@dataclass(frozen=True)
class CallSiteApplicability:
    """某个外部调用点上实际适用的说明（或仍未知）。

    逐调用点展示：文件级说明只在其匹配的位置上出现为 applied，
    不会扩展到其它文件或覆盖已明确的局部风险说明。
    """

    name: str
    loc: Loc
    status: str  # "applied" | "unknown"
    assumption_id: str | None = None
    version: str | None = None
    scope: str | None = None
    returns: str | None = None


@dataclass(frozen=True)
class TargetCoverage:
    """一个目标输出位置在方案下的覆盖情况。

    state 取值：covered（风险/安全已被证实或说明解释）/
    unknown（仍依赖未知行为，unknown_calls 给出位置）/
    safe（该位置无任何风险结论）。
    """

    sink_id: str
    sink: str
    loc: Loc
    state: str
    required_assumptions: tuple[str, ...] = ()
    unknown_calls: tuple[Loc, ...] = ()


@dataclass(frozen=True)
class CoveragePlan:
    """一份范围覆盖规划方案：一组可共同采用的说明版本及其覆盖结果。"""

    source: str
    targets: tuple[str, ...]
    strategy: str  # "minimal" | "preserve"
    chosen_specs: tuple[ExternalSpec, ...]
    kept_existing: tuple[str, ...]
    dropped_existing: tuple[str, ...]
    feasible: bool
    blocking_conflicts: tuple[AssumptionConflict, ...]
    target_coverages: tuple[TargetCoverage, ...]
    applicability: tuple[CallSiteApplicability, ...]
    verdict: str
    created_at: str

    @property
    def unknown_positions(self) -> tuple[CallSiteApplicability, ...]:
        """仍依赖未知行为的外部调用位置。"""

        return tuple(a for a in self.applicability if a.status == "unknown")

    @property
    def chosen_assumptions(self) -> tuple[str, ...]:
        return tuple(scoped_spec_assumption_id(s) for s in self.chosen_specs)

    def adopt_config(self, disabled_assumptions=()) -> AnalysisConfig:
        """把方案采用为分析配置。

        说明仍是外部假设：由说明推出的安全结论判为 ASSUMED，
        不会被提升为无条件 SAFE。
        """

        return AnalysisConfig(
            external_specs=list(self.chosen_specs),
            disabled_assumptions=frozenset(disabled_assumptions),
        )

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "targets": list(self.targets),
            "strategy": self.strategy,
            "chosen_specs": [asdict(s) for s in self.chosen_specs],
            "kept_existing": list(self.kept_existing),
            "dropped_existing": list(self.dropped_existing),
            "feasible": self.feasible,
            "blocking_conflicts": [asdict(c) for c in self.blocking_conflicts],
            "target_coverages": [asdict(t) for t in self.target_coverages],
            "applicability": [asdict(a) for a in self.applicability],
            "verdict": self.verdict,
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2,
                          default=_json_default)

    def save(self, path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: dict) -> "CoveragePlan":
        return cls(
            source=data["source"],
            targets=tuple(data["targets"]),
            strategy=data["strategy"],
            chosen_specs=tuple(_spec_from_data(s) for s in data["chosen_specs"]),
            kept_existing=tuple(data.get("kept_existing", ())),
            dropped_existing=tuple(data.get("dropped_existing", ())),
            feasible=data["feasible"],
            blocking_conflicts=tuple(
                _decode_conflict(c) for c in data.get("blocking_conflicts", ())
            ),
            target_coverages=tuple(
                TargetCoverage(
                    sink_id=t["sink_id"],
                    sink=t["sink"],
                    loc=_decode_loc(t["loc"]),
                    state=t["state"],
                    required_assumptions=tuple(t.get("required_assumptions", ())),
                    unknown_calls=tuple(
                        _decode_loc(loc) for loc in t.get("unknown_calls", ())
                    ),
                )
                for t in data.get("target_coverages", ())
            ),
            applicability=tuple(
                CallSiteApplicability(
                    name=a["name"],
                    loc=_decode_loc(a["loc"]),
                    status=a["status"],
                    assumption_id=a.get("assumption_id"),
                    version=a.get("version"),
                    scope=a.get("scope"),
                    returns=a.get("returns"),
                )
                for a in data.get("applicability", ())
            ),
            verdict=data["verdict"],
            created_at=data.get("created_at", ""),
        )

    @classmethod
    def load(cls, path) -> "CoveragePlan":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass(frozen=True)
class CoveragePlanComparison:
    """两种策略的方案比较：最少新增说明 vs 尽量保留现有说明。"""

    minimal: CoveragePlan
    preserve: CoveragePlan


@dataclass(frozen=True)
class PlanRevisionReport:
    """撤销依据后的增量重算报告：只有受影响的目标被重算。"""

    old_plan: CoveragePlan
    new_plan: CoveragePlan
    revoked: tuple[str, ...]
    affected_targets: tuple[str, ...]
    reused_targets: tuple[str, ...]


# ---------- 外部调用点与适用关系 ----------

_BUILTINS = set(SOURCES) | set(SANITIZERS) | set(SINKS)


def _external_call_sites(program) -> list[tuple[str, Loc]]:
    """收集程序中所有未知外部调用的（函数名, 位置）。"""

    defined = {f.name for f in program.funcs}
    sites: list[tuple[str, Loc]] = []

    def walk_expr(expr) -> None:
        if isinstance(expr, Call):
            if expr.func not in defined and expr.func not in _BUILTINS:
                sites.append((expr.func, expr.loc))
            for arg in expr.args:
                walk_expr(arg)
        elif isinstance(expr, Unary):
            walk_expr(expr.operand)
        elif isinstance(expr, Binary):
            walk_expr(expr.left)
            walk_expr(expr.right)

    def walk_stmt(stmt) -> None:
        if isinstance(stmt, IfStmt):
            walk_expr(stmt.cond)
            for item in stmt.then_block:
                walk_stmt(item)
            for item in stmt.else_block:
                walk_stmt(item)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                walk_expr(stmt.value)
        elif isinstance(stmt, AssignStmt):
            walk_expr(stmt.value)
        elif isinstance(stmt, ExprStmt):
            walk_expr(stmt.expr)

    for func in program.funcs:
        for stmt in func.body:
            walk_stmt(stmt)
    return sites


def _plan_config(chosen: tuple[ExternalSpec, ...], max_call_depth: int = 32):
    # 选用的说明同时登记为候选：同一调用实例上互斥的说明会被
    # 分析器记为冲突，从而阻止形成可行情景；互不相交的版本各自
    # 作用于自己的调用实例，可以共同采用。
    return AnalysisConfig(
        max_call_depth=max_call_depth,
        external_specs=list(chosen),
        spec_alternatives=tuple(chosen),
    )


def _applicability(config, program) -> tuple[CallSiteApplicability, ...]:
    """逐调用点展示实际适用的说明；未覆盖的调用保持未知。"""

    entries: list[CallSiteApplicability] = []
    for name, loc in _external_call_sites(program):
        spec = config.matching_primary_spec(name, loc)
        if spec is None:
            entries.append(CallSiteApplicability(name=name, loc=loc, status="unknown"))
            continue
        entries.append(
            CallSiteApplicability(
                name=name,
                loc=loc,
                status="applied",
                assumption_id=scoped_spec_assumption_id(spec),
                version=spec.version,
                scope=spec.scope.label,
                returns=spec.returns,
            )
        )
    return tuple(entries)


def _target_coverages(result, targets: tuple[str, ...]) -> tuple[TargetCoverage, ...]:
    by_id = {e.conclusion_id: e for e in result.explanations}
    coverages: list[TargetCoverage] = []
    for sink_id in targets:
        explanation = by_id.get(sink_id)
        if explanation is None:
            # 分析未在该位置产生任何结论：无风险也未涉及未知行为。
            coverages.append(
                TargetCoverage(sink_id=sink_id, sink="", loc=Loc(0, 0, 0), state="safe")
            )
            continue
        risky = [i for i in explanation.path_explanations if i.kind == "risk"]
        unknown_items = [i for i in risky if i.evidence == Evidence.UNKNOWN]
        if unknown_items:
            unknown_calls = tuple(
                dict.fromkeys(
                    hop.loc
                    for item in unknown_items
                    for hop in item.path.hops
                    if hop.kind == "unknown"
                )
            )
            required = tuple(
                sorted({a for i in risky for a in i.assumptions})
            )
            coverages.append(
                TargetCoverage(
                    sink_id=sink_id,
                    sink=explanation.sink,
                    loc=explanation.loc,
                    state="unknown",
                    required_assumptions=required,
                    unknown_calls=unknown_calls,
                )
            )
            continue
        required = tuple(
            sorted(
                {
                    a
                    for i in explanation.path_explanations
                    for a in i.assumptions
                }
            )
        )
        state = "covered" if risky or required else "safe"
        coverages.append(
            TargetCoverage(
                sink_id=sink_id,
                sink=explanation.sink,
                loc=explanation.loc,
                state=state,
                required_assumptions=required,
            )
        )
    return tuple(coverages)


def _evaluate(
    source: str,
    targets: tuple[str, ...],
    chosen: tuple[ExternalSpec, ...],
    strategy: str,
    kept_existing: tuple[str, ...],
    dropped_existing: tuple[str, ...],
    max_call_depth: int = 32,
) -> CoveragePlan:
    config = _plan_config(chosen, max_call_depth)
    result = analyze_source(source, config)
    chosen_ids = {scoped_spec_assumption_id(s) for s in chosen}
    conflicts = tuple(
        c for c in result.conflicts if set(c.assumptions) <= chosen_ids
    )
    feasible = not conflicts
    program = parse(source)
    verdict = result.verdict.value if feasible else "INFEASIBLE"
    return CoveragePlan(
        source=source,
        targets=targets,
        strategy=strategy,
        chosen_specs=chosen,
        kept_existing=kept_existing,
        dropped_existing=dropped_existing,
        feasible=feasible,
        blocking_conflicts=conflicts,
        target_coverages=_target_coverages(result, targets),
        applicability=_applicability(config, program),
        verdict=verdict,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _unknown_target_count(plan: CoveragePlan) -> int:
    return sum(1 for t in plan.target_coverages if t.state == "unknown")


def _plan_score(plan: CoveragePlan) -> tuple[int, int, int]:
    """方案评分（越小越好）：不可行最差，其次未知目标数、未知调用数。"""

    return (
        0 if plan.feasible else 1,
        _unknown_target_count(plan),
        len(plan.unknown_positions),
    )


# ---------- 规划入口 ----------

def _default_targets(source: str) -> tuple[str, ...]:
    result = analyze_source(source, AnalysisConfig())
    return tuple(e.conclusion_id for e in result.explanations)


def plan_coverage(
    source: str,
    targets=None,
    available_specs=(),
    config=None,
    existing_specs=(),
    strategy: str = "minimal",
) -> CoveragePlan:
    """为一组输出位置规划可共同采用、无重叠矛盾的说明组合。

    targets 为需要解释的 sink 结论 ID（缺省时取全部结论位置）；
    available_specs 为可采用的库版本说明；existing_specs 为现有说明。
    strategy="minimal" 追求最少新增说明（允许用新说明替换冲突的
    现有说明）；"preserve" 尽量保留现有说明（新增说明不得驱逐
    现有说明）。
    """

    if strategy not in ("minimal", "preserve"):
        raise ValueError(f"未知覆盖规划策略: {strategy}")
    max_depth = config.max_call_depth if config is not None else 32
    if targets is None:
        targets = _default_targets(source)
    targets = tuple(targets)
    existing = tuple(existing_specs)
    pool = [
        s for s in tuple(available_specs)
        if scoped_spec_assumption_id(s)
        not in {scoped_spec_assumption_id(e) for e in existing}
    ]

    chosen_adds: list[ExternalSpec] = []
    dropped: list[ExternalSpec] = []

    def current() -> tuple[ExternalSpec, ...]:
        dropped_ids = {scoped_spec_assumption_id(s) for s in dropped}
        kept = tuple(
            s for s in existing if scoped_spec_assumption_id(s) not in dropped_ids
        )
        return kept + tuple(chosen_adds)

    def kept_ids() -> tuple[str, ...]:
        dropped_ids = {scoped_spec_assumption_id(s) for s in dropped}
        return tuple(
            scoped_spec_assumption_id(s) for s in existing
            if scoped_spec_assumption_id(s) not in dropped_ids
        )

    def dropped_ids() -> tuple[str, ...]:
        return tuple(scoped_spec_assumption_id(s) for s in dropped)

    while True:
        base_plan = _evaluate(
            source, targets, current(), strategy, kept_ids(),
            dropped_ids(), max_depth,
        )
        base_score = _plan_score(base_plan)
        if base_score == (0, 0, 0):
            break
        best = None
        for cand in pool:
            if any(
                scoped_spec_assumption_id(cand) == scoped_spec_assumption_id(s)
                for s in chosen_adds
            ):
                continue
            trial = current() + (cand,)
            trial_plan = _evaluate(
                source, targets, trial, strategy, kept_ids(),
                dropped_ids(), max_depth,
            )
            cand_id = scoped_spec_assumption_id(cand)
            clashing = [
                c for c in trial_plan.blocking_conflicts if cand_id in c.assumptions
            ]
            drop_ids: set[str] = set()
            if clashing:
                existing_ids = {scoped_spec_assumption_id(s) for s in existing}
                opponents = {
                    a for c in clashing for a in c.assumptions if a != cand_id
                }
                if strategy == "preserve" or not opponents <= existing_ids:
                    # preserve：新增不得驱逐现有说明；或冲突对象不是
                    # 现有说明（新增之间互斥）——放弃该候选。
                    continue
                drop_ids = opponents
            final_specs = tuple(
                s for s in trial
                if scoped_spec_assumption_id(s) not in drop_ids
            )
            final_plan = _evaluate(
                source, targets, final_specs, strategy, kept_ids(),
                dropped_ids(), max_depth,
            )
            score = _plan_score(final_plan)
            if best is None or score < best[0]:
                best = (score, cand, drop_ids)
        if best is None:
            break
        score, cand, drop_ids = best
        if score >= base_score:
            break  # 没有候选能改善覆盖，剩余位置保持未知
        chosen_adds.append(cand)
        dropped.extend(s for s in existing if scoped_spec_assumption_id(s) in drop_ids)

    return _evaluate(
        source, targets, current(), strategy, kept_ids(),
        tuple(scoped_spec_assumption_id(s) for s in dropped), max_depth,
    )


def compare_coverage_strategies(
    source: str,
    targets=None,
    available_specs=(),
    config=None,
    existing_specs=(),
) -> CoveragePlanComparison:
    """比较最少新增说明与尽量保留现有说明两种方案。"""

    return CoveragePlanComparison(
        minimal=plan_coverage(
            source, targets, available_specs, config, existing_specs, "minimal"
        ),
        preserve=plan_coverage(
            source, targets, available_specs, config, existing_specs, "preserve"
        ),
    )


def revise_plan(
    plan: CoveragePlan,
    disabled_assumptions=(),
) -> tuple[CoveragePlan, PlanRevisionReport]:
    """撤销一条（或一组）依据后只重算受影响的输出。

    未受影响目标的 TargetCoverage 复用旧方案对象；受影响目标在
    新方案中重新求值。
    """

    disabled = frozenset(disabled_assumptions)
    chosen = tuple(
        s for s in plan.chosen_specs
        if scoped_spec_assumption_id(s) not in disabled
        and spec_assumption_id(s.name, s.version) not in disabled
    )
    kept = tuple(
        kept_id for kept_id in plan.kept_existing
        if any(scoped_spec_assumption_id(s) == kept_id for s in chosen)
    )
    new_plan = _evaluate(
        plan.source, plan.targets, chosen, plan.strategy, kept,
        plan.dropped_existing,
    )
    old_by_id = {t.sink_id: t for t in plan.target_coverages}
    affected: list[str] = []
    reused: list[str] = []
    coverages: list[TargetCoverage] = []
    for coverage in new_plan.target_coverages:
        old = old_by_id.get(coverage.sink_id)
        if old is not None and old == coverage:
            reused.append(coverage.sink_id)
            coverages.append(old)  # 未受影响：沿用旧对象，不重算
        else:
            affected.append(coverage.sink_id)
            coverages.append(coverage)
    new_plan = replace(new_plan, target_coverages=tuple(coverages))
    report = PlanRevisionReport(
        old_plan=plan,
        new_plan=new_plan,
        revoked=tuple(sorted(disabled)),
        affected_targets=tuple(affected),
        reused_targets=tuple(reused),
    )
    return new_plan, report


def format_plan_text(plan: CoveragePlan) -> str:
    """把覆盖规划方案渲染为可比较的文本结论。"""

    lines = [f"覆盖规划 [{plan.strategy}] 总判: {plan.verdict}"]
    lines.append(
        "    采用说明: "
        + (", ".join(plan.chosen_assumptions) or "（无）")
    )
    if plan.dropped_existing:
        lines.append("    被替换的现有说明: " + ", ".join(plan.dropped_existing))
    if not plan.feasible:
        lines.append("    方案不可行，互斥说明:")
        for conflict in plan.blocking_conflicts:
            lines.append(
                f"        CONFLICT {conflict.conflict_id}: "
                f"{conflict.assumptions[0]} 与 {conflict.assumptions[1]} "
                f"在 {conflict.name}() {conflict.loc} 上互斥"
            )
    for coverage in plan.target_coverages:
        lines.append(f"    目标 {coverage.sink_id}: {coverage.state}")
        if coverage.required_assumptions:
            lines.append(
                "        依赖说明: " + ", ".join(coverage.required_assumptions)
            )
        for loc in coverage.unknown_calls:
            lines.append(f"        仍未知调用 @ {loc}")
    for entry in plan.applicability:
        if entry.status == "applied":
            lines.append(
                f"    调用点 {entry.name}() @ {entry.loc}: 适用 "
                f"{entry.assumption_id}（作用域 {entry.scope}）"
            )
        else:
            lines.append(f"    调用点 {entry.name}() @ {entry.loc}: 未知行为")
    return "\n".join(lines)
