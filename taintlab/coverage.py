"""外部行为说明的范围覆盖规划。

研究者指定一组需要解释的输出位置（sink 结论 ID，如 "exec:3:5"）与
可采用的库版本说明，系统在说明空间中搜索能够覆盖这些位置、且不含
重叠矛盾的说明组合：

* 覆盖：目标位置的全部依据都由语言语义或已采用说明解释，不再依赖
  未知外部行为，也不依赖互斥假设；
* 逐调用点适用关系：文件范围与局部调用说明同时存在时，按实际匹配
  （窄作用域优先）展示每个调用点适用哪条说明；文件级结论不会扩展
  到另一文件，也不会覆盖已明确的局部风险；
* 互不相交的不同版本可以共同采用；同一调用实例上互斥的说明会使
  包含它们的组合成为不可行方案，被阻止进入可行情景；
* 两种策略可比较："min_new"（最少新增说明）与 "max_keep"
  （尽量保留现有说明）；
* 撤销一条依据后只重算受影响的输出位置，其余位置的结论沿用旧对象；
* 方案可持久化，重开后保留未知位置与版本选择；采用方案不会把
  条件安全提升为无条件安全。
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from itertools import combinations

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
from .analyzer import (
    AnalysisConfig,
    ExternalSpec,
    ExternalSpecScope,
    _decode_conflict,
    _json_default,
    _spec_from_data,
    analyze_source,
    scoped_spec_assumption_id,
)

MIN_NEW = "min_new"
MAX_KEEP = "max_keep"
DEFAULT_STRATEGIES = (MIN_NEW, MAX_KEEP)

_UNKNOWN_NOTE = re.compile(r"^(\d+):(\d+): 外部调用 (\w+)\(\) 缺少行为说明")


@dataclass(frozen=True)
class CallSiteCoverage:
    """一个外部调用点在方案下的实际适用关系。"""

    name: str
    loc: Loc
    status: str  # "covered"（适用某条说明）| "unknown"（仍依赖未知行为）
    assumption_id: str | None = None
    version: str | None = None
    scope: str | None = None


@dataclass(frozen=True)
class TargetCoverage:
    """一个目标输出位置在方案下的覆盖情况。"""

    target: str
    state: str
    covered: bool
    assumptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoveragePlan:
    """一个可覆盖目标位置的可行说明组合。"""

    strategy: str
    specs: tuple[ExternalSpec, ...]
    feasible: bool
    verdict: str
    targets: tuple[TargetCoverage, ...]
    call_sites: tuple[CallSiteCoverage, ...]
    unknown_sites: tuple[CallSiteCoverage, ...]
    conflicts: tuple[AssumptionConflict, ...] = ()
    kept_assumptions: tuple[str, ...] = ()
    added_assumptions: tuple[str, ...] = ()

    @property
    def assumption_ids(self) -> tuple[str, ...]:
        return tuple(sorted(scoped_spec_assumption_id(spec) for spec in self.specs))

    @property
    def covered_targets(self) -> tuple[str, ...]:
        return tuple(item.target for item in self.targets if item.covered)

    @property
    def uncovered_targets(self) -> tuple[str, ...]:
        return tuple(item.target for item in self.targets if not item.covered)


@dataclass(frozen=True)
class CoveragePlanRevision:
    """撤销依据后单个方案的增量重算结果。"""

    strategy: str
    revoked: tuple[str, ...]
    plan: CoveragePlan
    affected_conclusions: tuple[str, ...]
    reused_conclusions: tuple[str, ...]


@dataclass(frozen=True)
class CoverageRevision:
    old_study: "CoveragePlanStudy"
    new_study: "CoveragePlanStudy"
    revoked: tuple[str, ...]
    revisions: tuple[CoveragePlanRevision, ...]


@dataclass(frozen=True)
class CoveragePlanStudy:
    """一次覆盖规划：目标位置、可采用说明与搜索到的可行方案。"""

    source: str
    targets: tuple[str, ...]
    available_specs: tuple[ExternalSpec, ...]
    existing_specs: tuple[ExternalSpec, ...]
    plans: tuple[CoveragePlan, ...]
    # 被阻止的组合：同一调用实例上互斥、不能共同成立的最小说明集。
    blocked_combinations: tuple[tuple[str, ...], ...] = ()
    created_at: str = ""

    def by_strategy(self, strategy: str) -> CoveragePlan | None:
        for plan in self.plans:
            if plan.strategy == strategy:
                return plan
        return None

    def to_json(self) -> str:
        return json.dumps(
            {
                "source": self.source,
                "targets": list(self.targets),
                "available_specs": [asdict(spec) for spec in self.available_specs],
                "existing_specs": [asdict(spec) for spec in self.existing_specs],
                "plans": [_encode_plan(plan) for plan in self.plans],
                "blocked_combinations": [
                    list(combo) for combo in self.blocked_combinations
                ],
                "created_at": self.created_at,
            },
            ensure_ascii=False,
            default=_json_default,
            indent=2,
        )

    def save(self, path) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_json())

    @classmethod
    def from_dict(cls, data) -> "CoveragePlanStudy":
        return cls(
            source=data["source"],
            targets=tuple(data["targets"]),
            available_specs=tuple(
                _spec_from_data(spec) for spec in data.get("available_specs", ())
            ),
            existing_specs=tuple(
                _spec_from_data(spec) for spec in data.get("existing_specs", ())
            ),
            plans=tuple(_decode_plan(item) for item in data.get("plans", ())),
            blocked_combinations=tuple(
                tuple(combo) for combo in data.get("blocked_combinations", ())
            ),
            created_at=data.get("created_at", ""),
        )

    @classmethod
    def load(cls, path) -> "CoveragePlanStudy":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))


def _encode_call_site(site: CallSiteCoverage) -> dict:
    return {
        "name": site.name,
        "loc": asdict(site.loc),
        "status": site.status,
        "assumption_id": site.assumption_id,
        "version": site.version,
        "scope": site.scope,
    }


def _decode_call_site(data) -> CallSiteCoverage:
    loc = data["loc"]
    return CallSiteCoverage(
        name=data["name"],
        loc=Loc(loc["line"], loc["col"], loc["offset"]),
        status=data["status"],
        assumption_id=data.get("assumption_id"),
        version=data.get("version"),
        scope=data.get("scope"),
    )


def _encode_plan(plan: CoveragePlan) -> dict:
    return {
        "strategy": plan.strategy,
        "specs": [asdict(spec) for spec in plan.specs],
        "feasible": plan.feasible,
        "verdict": plan.verdict,
        "targets": [asdict(item) for item in plan.targets],
        "call_sites": [_encode_call_site(site) for site in plan.call_sites],
        "unknown_sites": [_encode_call_site(site) for site in plan.unknown_sites],
        "conflicts": [asdict(item) for item in plan.conflicts],
        "kept_assumptions": list(plan.kept_assumptions),
        "added_assumptions": list(plan.added_assumptions),
    }


def _decode_plan(data) -> CoveragePlan:
    return CoveragePlan(
        strategy=data["strategy"],
        specs=tuple(_spec_from_data(spec) for spec in data.get("specs", ())),
        feasible=data["feasible"],
        verdict=data["verdict"],
        targets=tuple(
            TargetCoverage(
                target=item["target"],
                state=item["state"],
                covered=item["covered"],
                assumptions=tuple(item.get("assumptions", ())),
            )
            for item in data.get("targets", ())
        ),
        call_sites=tuple(
            _decode_call_site(site) for site in data.get("call_sites", ())
        ),
        unknown_sites=tuple(
            _decode_call_site(site) for site in data.get("unknown_sites", ())
        ),
        conflicts=tuple(
            _decode_conflict(item) for item in data.get("conflicts", ())
        ),
        kept_assumptions=tuple(data.get("kept_assumptions", ())),
        added_assumptions=tuple(data.get("added_assumptions", ())),
    )


def _external_call_names(source: str) -> frozenset[str]:
    """程序中既非内置、也未在程序内定义的调用名。"""

    from .analyzer import SANITIZERS, SINKS, SOURCES
    from .parser import parse

    program = parse(source)
    defined = {func.name for func in program.funcs}
    builtin = set(SOURCES) | set(SANITIZERS) | set(SINKS)
    names: set[str] = set()

    def walk_expr(expr) -> None:
        if isinstance(expr, Call):
            names.add(expr.func)
            for arg in expr.args:
                walk_expr(arg)
        elif isinstance(expr, Unary):
            walk_expr(expr.operand)
        elif isinstance(expr, Binary):
            walk_expr(expr.left)
            walk_expr(expr.right)

    def walk_stmt(stmt) -> None:
        if isinstance(stmt, AssignStmt):
            walk_expr(stmt.value)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                walk_expr(stmt.value)
        elif isinstance(stmt, ExprStmt):
            walk_expr(stmt.expr)
        elif isinstance(stmt, IfStmt):
            walk_expr(stmt.cond)
            for inner in stmt.then_block + stmt.else_block:
                walk_stmt(inner)

    for func in program.funcs:
        for stmt in func.body:
            walk_stmt(stmt)
    return frozenset(names - defined - builtin)


def _spec_key(spec: ExternalSpec) -> tuple:
    scope = spec.scope or ExternalSpecScope.global_scope()
    return (spec.name, spec.version, spec.returns, scope.label)


def _evaluate_specs(
    source: str,
    targets: tuple[str, ...],
    specs: tuple[ExternalSpec, ...],
    strategy: str,
    existing_ids: frozenset[str],
) -> CoveragePlan:
    """在指定说明组合下分析，并给出逐目标、逐调用点的覆盖情况。"""

    config = AnalysisConfig(
        external_specs=specs,
        # 同名同范围的多个版本同时进入候选空间，使同一调用实例上的
        # 互斥说明被检测为冲突，从而阻止该组合形成可行情景。
        spec_alternatives=specs,
    )
    result = analyze_source(source, config)
    conflicts = result.conflicts
    feasible = not conflicts

    by_id = {item.conclusion_id: item for item in result.explanations}
    target_items: list[TargetCoverage] = []
    for target in targets:
        explanation = by_id.get(target)
        if explanation is None:
            target_items.append(
                TargetCoverage(target=target, state="NO_SUCH_SINK", covered=False)
            )
            continue
        has_unknown = any(
            item.kind == "risk" and item.evidence == Evidence.UNKNOWN
            for item in explanation.path_explanations
        )
        contradictory = explanation.state == "CONTRADICTORY_RISK"
        covered = feasible and not has_unknown and not contradictory
        assumptions = tuple(
            sorted(
                {
                    assumption
                    for item in explanation.path_explanations
                    for assumption in item.assumptions
                }
            )
        )
        target_items.append(
            TargetCoverage(
                target=target,
                state=explanation.state,
                covered=covered,
                assumptions=assumptions,
            )
        )

    def site_key(site: CallSiteCoverage) -> tuple:
        return (site.loc.line, site.loc.col, site.name)

    call_sites: list[CallSiteCoverage] = []
    for record in result.assumptions:
        for loc in record.locations:
            call_sites.append(
                CallSiteCoverage(
                    name=record.name,
                    loc=loc,
                    status="covered",
                    assumption_id=record.assumption_id,
                    version=record.version,
                    scope=record.scope,
                )
            )
    unknown_sites: list[CallSiteCoverage] = []
    for note in result.notes:
        match = _UNKNOWN_NOTE.match(note)
        if match:
            line, col, name = match.groups()
            unknown_sites.append(
                CallSiteCoverage(
                    name=name,
                    loc=Loc(int(line), int(col), 0),
                    status="unknown",
                )
            )

    assumption_ids = {scoped_spec_assumption_id(spec) for spec in specs}
    return CoveragePlan(
        strategy=strategy,
        specs=specs,
        feasible=feasible,
        verdict=result.verdict.value,
        targets=tuple(target_items),
        call_sites=tuple(sorted(call_sites, key=site_key)),
        unknown_sites=tuple(sorted(unknown_sites, key=site_key)),
        conflicts=conflicts,
        kept_assumptions=tuple(sorted(assumption_ids & existing_ids)),
        added_assumptions=tuple(sorted(assumption_ids - existing_ids)),
    )


def plan_coverage(
    source: str,
    targets,
    available_specs,
    config: AnalysisConfig | None = None,
    strategies=DEFAULT_STRATEGIES,
) -> CoveragePlanStudy:
    """搜索覆盖目标输出位置且无重叠矛盾的说明组合。

    targets 为需要解释的结论位置 ID（"函数名:行:列"）；available_specs
    为可采用的库版本说明；config.external_specs 中的说明视为现有说明。
    返回的研究按策略各保留一个最优方案。
    """

    config = config or AnalysisConfig()
    targets = tuple(targets)
    existing = tuple(config.external_specs)
    existing_ids = frozenset(scoped_spec_assumption_id(spec) for spec in existing)

    relevant_names = _external_call_names(source)
    universe: list[ExternalSpec] = []
    seen: set[tuple] = set()
    for spec in tuple(existing) + tuple(available_specs):
        if spec.name not in relevant_names:
            continue
        key = _spec_key(spec)
        if key in seen:
            continue
        seen.add(key)
        universe.append(spec)

    feasible_plans: list[CoveragePlan] = []
    blocked: set[tuple[str, ...]] = set()
    for size in range(len(universe) + 1):
        for combo in combinations(universe, size):
            plan = _evaluate_specs(source, targets, combo, "", existing_ids)
            if not plan.feasible:
                for conflict in plan.conflicts:
                    blocked.add(tuple(sorted(conflict.assumptions)))
                continue
            if all(item.covered for item in plan.targets):
                feasible_plans.append(plan)

    def rank_of(spec: ExternalSpec) -> int:
        scope = spec.scope or ExternalSpecScope.global_scope()
        return {"global": 0, "file": 1, "call": 2}[scope.kind]

    def respects_local_specs(plan: CoveragePlan) -> bool:
        # 文件级/全局安全结论不得覆盖已明确的局部风险：某调用点上
        # 若可采用的说明中存在更窄作用域的版本，方案不能只采用更宽
        # 作用域的说明而把宽结论扩展到该调用点。
        adopted = set(plan.assumption_ids)
        for site in plan.call_sites:
            matching = [
                spec
                for spec in universe
                if spec.name == site.name
                and (spec.scope or ExternalSpecScope.global_scope()).matches(site.loc)
            ]
            if not matching:
                continue
            narrowest = max(rank_of(spec) for spec in matching)
            adopted_ranks = [
                rank_of(spec)
                for spec in matching
                if scoped_spec_assumption_id(spec) in adopted
            ]
            if adopted_ranks and max(adopted_ranks) < narrowest:
                return False
        return True

    feasible_plans = [plan for plan in feasible_plans if respects_local_specs(plan)]

    plans: list[CoveragePlan] = []
    for strategy in strategies:
        if not feasible_plans:
            break
        if strategy == MIN_NEW:
            best = min(
                feasible_plans,
                key=lambda plan: (
                    len(plan.added_assumptions),
                    len(plan.specs),
                    plan.assumption_ids,
                ),
            )
        elif strategy == MAX_KEEP:
            best = max(
                feasible_plans,
                key=lambda plan: (
                    len(plan.kept_assumptions),
                    -len(plan.added_assumptions),
                ),
            )
        else:
            raise ValueError(f"未知覆盖规划策略: {strategy}")
        plans.append(
            CoveragePlan(
                strategy=strategy,
                specs=best.specs,
                feasible=best.feasible,
                verdict=best.verdict,
                targets=best.targets,
                call_sites=best.call_sites,
                unknown_sites=best.unknown_sites,
                conflicts=best.conflicts,
                kept_assumptions=best.kept_assumptions,
                added_assumptions=best.added_assumptions,
            )
        )

    return CoveragePlanStudy(
        source=source,
        targets=targets,
        available_specs=tuple(available_specs),
        existing_specs=existing,
        plans=tuple(plans),
        blocked_combinations=tuple(sorted(blocked)),
        created_at=datetime.now(timezone.utc).isoformat(),
    )




def revise_coverage(study: CoveragePlanStudy, revoked) -> CoverageRevision:
    """撤销一条（或一组）依据后，只重算受影响的输出位置。

    其余目标位置的 TargetCoverage 沿用旧方案中的对象，报告按
    affected_conclusions / reused_conclusions 区分。
    """

    revoked = tuple(revoked)
    revoked_ids = set(revoked)

    def is_revoked(spec: ExternalSpec) -> bool:
        return (
            scoped_spec_assumption_id(spec) in revoked_ids
            or spec_assumption_base(spec) in revoked_ids
        )

    def spec_assumption_base(spec: ExternalSpec) -> str:
        from .analyzer import spec_assumption_id

        return spec_assumption_id(spec.name, spec.version)

    revisions: list[CoveragePlanRevision] = []
    new_plans: list[CoveragePlan] = []
    for plan in study.plans:
        remaining = tuple(spec for spec in plan.specs if not is_revoked(spec))
        existing_ids = frozenset(
            scoped_spec_assumption_id(spec) for spec in study.existing_specs
        )
        recomputed = _evaluate_specs(
            study.source, study.targets, remaining, plan.strategy, existing_ids
        )
        old_by_target = {item.target: item for item in plan.targets}
        affected: list[str] = []
        reused: list[str] = []
        merged_targets: list[TargetCoverage] = []
        for new_item in recomputed.targets:
            old_item = old_by_target.get(new_item.target)
            touches_revoked = old_item is not None and bool(
                set(old_item.assumptions) & revoked_ids
            )
            changed = old_item is None or (
                old_item.state != new_item.state
                or old_item.covered != new_item.covered
                or old_item.assumptions != new_item.assumptions
            )
            if touches_revoked or changed:
                affected.append(new_item.target)
                merged_targets.append(new_item)
            else:
                # 未受撤销影响的输出位置沿用旧结论对象，不重算。
                reused.append(new_item.target)
                merged_targets.append(old_item)
        merged_plan = CoveragePlan(
            strategy=plan.strategy,
            specs=remaining,
            feasible=recomputed.feasible,
            verdict=recomputed.verdict,
            targets=tuple(merged_targets),
            call_sites=recomputed.call_sites,
            unknown_sites=recomputed.unknown_sites,
            conflicts=recomputed.conflicts,
            kept_assumptions=recomputed.kept_assumptions,
            added_assumptions=recomputed.added_assumptions,
        )
        new_plans.append(merged_plan)
        revisions.append(
            CoveragePlanRevision(
                strategy=plan.strategy,
                revoked=revoked,
                plan=merged_plan,
                affected_conclusions=tuple(sorted(affected)),
                reused_conclusions=tuple(sorted(reused)),
            )
        )
    new_study = CoveragePlanStudy(
        source=study.source,
        targets=study.targets,
        available_specs=study.available_specs,
        existing_specs=study.existing_specs,
        plans=tuple(new_plans),
        blocked_combinations=study.blocked_combinations,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    return CoverageRevision(
        old_study=study,
        new_study=new_study,
        revoked=revoked,
        revisions=tuple(revisions),
    )


def adopt_coverage_plan(plan: CoveragePlan, source: str):
    """采用一个方案重新分析；条件安全不会被提升为无条件安全。"""

    from .model import Verdict

    config = AnalysisConfig(external_specs=plan.specs)
    result = analyze_source(source, config)
    conditionally_safe = any(
        item.state == "CONDITIONALLY_SAFE" for item in plan.targets
    )
    if result.verdict is Verdict.SAFE and (plan.specs or conditionally_safe):
        # 防御：方案依赖外部说明时，结论最高只能是 ASSUMED。
        result.verdict = Verdict.ASSUMED
        result.notes.append(
            "采用覆盖方案：结论依赖外部行为说明，条件安全不提升为无条件安全"
        )
    return result


def format_coverage_text(study: CoveragePlanStudy) -> str:
    """把覆盖规划研究渲染为可比较的文本结论。"""

    lines = ["覆盖规划: 目标位置 " + (", ".join(study.targets) or "（无）")]
    for plan in study.plans:
        lines.append(
            f"方案 [{plan.strategy}] 总判={plan.verdict} "
            f"采用说明: {', '.join(plan.assumption_ids) or '（无）'}"
        )
        for item in plan.targets:
            marker = "已覆盖" if item.covered else "未覆盖"
            lines.append(f"    {item.target}: {item.state}（{marker}）")
        for site in plan.call_sites:
            lines.append(
                f"    调用点 {site.name}() @ {site.loc}: 适用 "
                f"{site.assumption_id}（范围 {site.scope}）"
            )
        for site in plan.unknown_sites:
            lines.append(
                f"    调用点 {site.name}() @ {site.loc}: 仍依赖未知行为"
            )
    for combo in study.blocked_combinations:
        lines.append("被阻止的互斥组合: " + " 与 ".join(combo))
    return "\n".join(lines)
