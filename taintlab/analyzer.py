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
    ConclusionExplanation,
    Diagnostic,
    Evidence,
    PathExplanation,
    PathHop,
    Severity,
    TaintPath,
    Verdict,
    AssumptionConflict,
    Scenario,
)
from .model import NamedScenario, NamedScenarioResult, ScenarioSinkConclusion
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
class ExternalSpecScope:
    """外部行为说明的适用范围。

    kind 取值：``global`` / ``file`` / ``call``。``call`` 必须给出
    ``line`` 与 ``col``；``path`` 为 None 时表示当前被分析文件。
    """

    kind: str = "global"
    line: int | None = None
    col: int | None = None
    path: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("global", "file", "call"):
            raise ValueError(f"外部说明作用域非法: {self.kind}")
        if self.kind == "call" and (self.line is None or self.col is None):
            raise ValueError("调用点作用域必须提供 line 和 col")

    @classmethod
    def global_scope(cls) -> "ExternalSpecScope":
        return cls("global")

    @classmethod
    def file(cls, path: str | None = None) -> "ExternalSpecScope":
        return cls("file", path=path)

    @classmethod
    def call_site(
        cls, line: int, col: int, path: str | None = None
    ) -> "ExternalSpecScope":
        return cls("call", line=line, col=col, path=path)

    @property
    def label(self) -> str:
        if self.kind == "global":
            return "global"
        location = f":{self.line}:{self.col}" if self.kind == "call" else ""
        path = f"{self.path}:" if self.path is not None else ""
        return f"{self.kind}:{path}{location}"

    def matches(self, loc: Loc) -> bool:
        if self.kind == "global":
            return True
        if self.kind == "file":
            return True
        return self.line == loc.line and self.col == loc.col


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
    scope: ExternalSpecScope | None = None

    def __post_init__(self) -> None:
        if self.returns not in ("clean", "tainted", "propagate"):
            raise ValueError(f"外部调用说明 {self.name} 的返回值策略非法: {self.returns}")
        scope = self.scope or ExternalSpecScope.global_scope()
        if isinstance(scope, dict):
            scope = ExternalSpecScope(**scope)
        object.__setattr__(self, "scope", scope)


@dataclass(frozen=True)
class Fact:
    """一个污点事实：来自某处不可信来源，携带到当前位置的路径。"""

    key: tuple
    path: tuple[PathHop, ...]
    evidence: Evidence = Evidence.CONFIRMED
    assumptions: frozenset[str] = frozenset()
    safe: bool = False
    # 假设作用的调用实例：(假设 ID, 行, 列)，冲突按调用实例判定。
    sites: frozenset = frozenset()

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

    def with_sites(self, sites: frozenset) -> "Fact":
        return replace(self, sites=self.sites | sites)


@dataclass(frozen=True)
class SpecVersionChange:
    name: str
    status: str
    old_version: str | None = None
    new_version: str | None = None
    changed_fields: tuple[str, ...] = ()
    old_scope: str = "global"
    new_scope: str = "global"

    @property
    def invalidated_assumptions(self) -> tuple[str, ...]:
        if self.status not in ("changed", "withdrawn"):
            return ()
        base = spec_assumption_id(self.name, self.old_version)
        if self.old_scope == "global":
            return (base,)
        return (f"{base}[{self.old_scope}]",)


def _normalize_spec_collection(specs) -> tuple[ExternalSpec, ...]:
    if specs is None:
        return ()
    if isinstance(specs, dict):
        return tuple(specs.values())
    return tuple(specs)


def _spec_key(spec: ExternalSpec) -> tuple[str, str, int | None, int | None, str | None]:
    scope = spec.scope
    return (
        spec.name,
        scope.kind,
        scope.line,
        scope.col,
        scope.path,
    )


def spec_assumption_id(name: str, version: str | None) -> str:
    return f"{name}@{version}" if version is not None else name


def scoped_spec_assumption_id(spec: ExternalSpec) -> str:
    base = spec_assumption_id(spec.name, spec.version)
    if spec.scope is None or spec.scope.kind == "global":
        return base
    return f"{base}[{spec.scope.label}]"


def _spec_from_data(data: dict) -> ExternalSpec:
    return ExternalSpec(
        data["name"],
        data["description"],
        data["returns"],
        data.get("version"),
        ExternalSpecScope(**data["scope"]) if data.get("scope") else None,
    )


def compare_external_specs(
    old_specs: dict[str, ExternalSpec] | None,
    new_specs: dict[str, ExternalSpec] | None,
) -> list[SpecVersionChange]:
    """比较两版外部行为说明；撤回只返回被撤回名称对应的假设 ID。"""

    old_specs = _normalize_spec_collection(old_specs)
    new_specs = _normalize_spec_collection(new_specs)
    changes: list[SpecVersionChange] = []
    old_by_key = {_spec_key(spec): spec for spec in old_specs}
    new_by_key = {_spec_key(spec): spec for spec in new_specs}
    for key in sorted(set(old_by_key) | set(new_by_key)):
        old = old_by_key.get(key)
        new = new_by_key.get(key)
        name = key[0]
        if old is None:
            changes.append(
                SpecVersionChange(
                    name,
                    "added",
                    new_version=new.version,
                    new_scope=new.scope.label,
                )
            )
            continue
        if new is None:
            changes.append(
                SpecVersionChange(
                    name,
                    "withdrawn",
                    old_version=old.version,
                    old_scope=old.scope.label,
                )
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
                    old.scope.label,
                    new.scope.label,
                )
            )
        else:
            changes.append(
                SpecVersionChange(
                    name,
                    "unchanged",
                    old.version,
                    new.version,
                    old_scope=old.scope.label,
                    new_scope=new.scope.label,
                )
            )
    return changes


def _spec_dict(specs):
    return _normalize_spec_collection(specs)


class ExternalSpecCollection(tuple):
    """主说明集合；按名称访问保留给旧版 dict API。"""

    def __getitem__(self, key):
        if isinstance(key, str):
            for spec in self:
                if spec.name == key:
                    return spec
            raise KeyError(key)
        return tuple.__getitem__(self, key)


@dataclass(frozen=True)
class ResearchSnapshot:
    source: str
    specs: tuple[ExternalSpec, ...]
    disabled_assumptions: frozenset[str]
    verdict: str
    explanations: tuple[ConclusionExplanation, ...]
    assumptions: tuple[AssumptionRecord, ...]
    created_at: str
    conflicts: tuple[AssumptionConflict, ...] = ()
    scenarios: tuple[Scenario, ...] = ()
    alternatives: tuple[ExternalSpec, ...] = ()

    @classmethod
    def from_result(cls, source, result, specs, disabled_assumptions=(), alternatives=()):
        return cls(
            source=source,
            specs=_spec_dict(specs),
            disabled_assumptions=frozenset(disabled_assumptions),
            verdict=result.verdict.value,
            explanations=result.explanations,
            assumptions=result.assumptions,
            created_at=datetime.now(timezone.utc).isoformat(),
            conflicts=result.conflicts,
            scenarios=result.scenarios,
            alternatives=tuple(alternatives),
        )

    def to_json(self):
        return json.dumps(
            {
                **asdict(self),
                "specs": [asdict(spec) for spec in self.specs],
            },
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
            specs=tuple(
                _spec_from_data(spec if isinstance(spec, dict) else {"name": name, **spec})
                for name, spec in (
                    data["specs"].items()
                    if isinstance(data["specs"], dict)
                    else ((item["name"], item) for item in data["specs"])
                )
            ),
            disabled_assumptions=frozenset(data.get("disabled_assumptions", ())),
            verdict=data["verdict"],
            explanations=tuple(
                _decode_explanation(item) for item in data["explanations"]
            ),
            assumptions=tuple(
                _decode_assumption(item) for item in data["assumptions"]
            ),
            created_at=data["created_at"],
            conflicts=tuple(
                _decode_conflict(item) for item in data.get("conflicts", ())
            ),
            scenarios=tuple(
                _decode_scenario(item) for item in data.get("scenarios", ())
            ),
            alternatives=tuple(_spec_from_data(spec) for spec in data.get("alternatives", ())),
        )


@dataclass(frozen=True)
class RevisionReport:
    old_snapshot: ResearchSnapshot
    new_snapshot: ResearchSnapshot
    changes: tuple[SpecVersionChange, ...]
    affected_conclusions: tuple[str, ...]
    reused_conclusions: tuple[str, ...]
    # 修订后解除 / 新增 / 仍然存在的假设冲突（按冲突 ID）。
    resolved_conflicts: tuple[str, ...] = ()
    new_conflicts: tuple[str, ...] = ()
    remaining_conflicts: tuple[str, ...] = ()
    # 风险变化归因：来自冲突解除的结论与来自程序路径变化的结论。
    conflict_driven_conclusions: tuple[str, ...] = ()
    path_driven_conclusions: tuple[str, ...] = ()


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
                assumption_sites=tuple(
                    tuple(site) for site in item.get("assumption_sites", ())
                ),
            )
            for item in data["path_explanations"]
        ),
        assumption_groups=tuple(
            tuple(group) for group in data["assumption_groups"]
        ),
        indispensable_assumptions=tuple(data["indispensable_assumptions"]),
        common_assumptions=tuple(data["common_assumptions"]),
        infeasible_assumption_groups=tuple(
            tuple(group)
            for group in data.get("infeasible_assumption_groups", ())
        ),
        compatible_groups=tuple(
            tuple(group) for group in data.get("compatible_groups", ())
        ),
        scenario_only_groups=tuple(
            tuple(group) for group in data.get("scenario_only_groups", ())
        ),
    )


def _decode_conflict(data):
    return AssumptionConflict(
        conflict_id=data["conflict_id"],
        name=data["name"],
        loc=_decode_loc(data["loc"]),
        assumptions=tuple(data["assumptions"]),
        constraints=tuple(data["constraints"]),
    )


def _decode_scenario(data):
    return Scenario(
        scenario_id=data["scenario_id"],
        conclusion_id=data["conclusion_id"],
        assumptions=tuple(data["assumptions"]),
        state=data["state"],
        conflicts=tuple(data.get("conflicts", ())),
    )


def _decode_assumption(data):
    return AssumptionRecord(
        assumption_id=data["assumption_id"],
        name=data["name"],
        version=data.get("version"),
        returns=data["returns"],
        description=data["description"],
        scope=data.get("scope", "global"),
        locations=tuple(_decode_loc(item) for item in data["locations"]),
        paths=tuple(_decode_path(item) for item in data["paths"]),
    )


def snapshot_analysis(source, config=None):
    config = config or AnalysisConfig()
    result = analyze_source(source, config)
    snapshot = ResearchSnapshot.from_result(
        source,
        result,
        config.external_specs,
        config.disabled_assumptions,
        config.spec_alternatives,
    )
    return result, snapshot


@dataclass(frozen=True)
class ScenarioStudy:
    """把若干外部行为说明组成有名称的联合情景所做的比较研究。

    研究者在 ``scenarios`` 中给出需共同成立的说明版本组合；评估后每个
    情景独立给出可行性、导致不可行的最小冲突依据以及逐 sink 的情景化
    结论。同一外部返回值在不同情景下分别标注，某情景下的无风险结论
    不会扩展到其它备选；未知外部返回（``undecidable``）与没有任何
    可行风险情景（整体 ``INCOMPLETE``）是两种不同状态。

    ``base_result`` 是在全部启用说明 + 候选说明上做的一次基础分析，
    各情景只是对其逐路径依据做“投影”：只有路径所需说明全部包含在
    情景中的依据才在该情景成立，从而保证风险路径注明情景与版本。
    """

    source: str
    scenarios: tuple[NamedScenario, ...]
    base_config: AnalysisConfig
    base_result: "object"
    results: tuple[NamedScenarioResult, ...]
    created_at: str

    @property
    def verdict(self) -> str:
        """跨情景总判：保留仍然可行的其它情景，区分未知与无可行情景。"""

        feasible = [item for item in self.results if item.feasible]
        if not feasible:
            # 没有任何可行联合情景：与“未知外部返回”不同，不能归成安全。
            return "INCOMPLETE"
        verdicts = {item.verdict for item in feasible}
        for value in ("UNSAFE", "INCOMPLETE", "ASSUMED"):
            if value in verdicts:
                return value
        return "SAFE"

    def by_name(self, name: str) -> NamedScenarioResult | None:
        for item in self.results:
            if item.scenario.name == name:
                return item
        return None

    def to_json(self) -> str:
        return json.dumps(
            {
                "source": self.source,
                "created_at": self.created_at,
                "scenarios": [asdict(scenario) for scenario in self.scenarios],
                "results": [_encode_study_result(item) for item in self.results],
                "base_config": {
                    "external_specs": {
                        f"{spec.name}#{index}": asdict(spec)
                        for index, spec in enumerate(self.base_config.external_specs)
                    },
                    "disabled_assumptions": sorted(
                        self.base_config.disabled_assumptions
                    ),
                    "spec_alternatives": [
                        asdict(spec) for spec in self.base_config.spec_alternatives
                    ],
                },
            },
            ensure_ascii=False,
            default=_json_default,
            indent=2,
        )

    def save(self, path) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_json())

    @classmethod
    def from_dict(cls, data) -> "ScenarioStudy":
        scenarios = tuple(
            NamedScenario(
                name=item["name"],
                description=item["description"],
                assumptions=tuple(item["assumptions"]),
            )
            for item in data["scenarios"]
        )
        results = tuple(
            _decode_study_result(item) for item in data["results"]
        )
        config_data = data.get("base_config", {})
        config = AnalysisConfig(
            external_specs=tuple(
                _spec_from_data(spec)
                for spec in config_data.get("external_specs", {}).values()
            ),
            disabled_assumptions=frozenset(
                config_data.get("disabled_assumptions", ())
            ),
            spec_alternatives=tuple(
                _spec_from_data(spec)
                for spec in config_data.get("spec_alternatives", ())
            ),
        )
        study = cls(
            source=data["source"],
            scenarios=scenarios,
            base_config=config,
            base_result=analyze_source(data["source"], config),
            results=results,
            created_at=data["created_at"],
        )
        return study

    @classmethod
    def load(cls, path) -> "ScenarioStudy":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))


def study_scenarios(source, scenarios, config=None) -> ScenarioStudy:
    """把若干有名称的联合情景放在同一基础分析上做比较研究。

    两个输出点共享同一份外部返回分析（``base_result``），但按各自情景
    对依据做投影，风险与矛盾不会互相掩盖。
    """

    config = config or AnalysisConfig()
    base_result = analyze_source(source, config)
    results = tuple(
        _evaluate_named_scenario(scenario, base_result) for scenario in scenarios
    )
    return ScenarioStudy(
        source=source,
        scenarios=tuple(scenarios),
        base_config=config,
        base_result=base_result,
        results=results,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _path_under_scenario(item: PathExplanation, chosen: frozenset[str]) -> bool:
    """一条依据是否在所选情景内成立：其全部假设都被情景包含。"""

    return frozenset(item.assumptions) <= chosen


def _evaluate_named_scenario(
    scenario: NamedScenario, base_result
) -> NamedScenarioResult:
    chosen = frozenset(scenario.assumptions)

    # 最小冲突依据：只保留两个互斥假设都被本情景共同采用、且作用于
    # 同一次调用实例的冲突。多组独立冲突各自独立列出。
    conflicts: list[AssumptionConflict] = []
    for conflict in base_result.conflicts:
        first, second = conflict.assumptions
        line, col = conflict.loc.line, conflict.loc.col
        if first in chosen and second in chosen:
            conflicts.append(conflict)

    if conflicts:
        # 不可行情景不给出逐 sink 安全/风险结论；最小冲突即其依据。
        return NamedScenarioResult(
            scenario=scenario,
            feasible=False,
            minimal_conflicts=tuple(conflicts),
            verdict="INFEASIBLE",
        )

    sink_conclusions: list[ScenarioSinkConclusion] = []
    verdict_has_confirmed = False
    verdict_has_unknown = False
    verdict_has_assumed = False
    for explanation in base_result.explanations:
        risk_items = [
            item
            for item in explanation.path_explanations
            if item.kind == "risk" and _path_under_scenario(item, chosen)
        ]
        safe_items = [
            item
            for item in explanation.path_explanations
            if item.kind == "safe" and _path_under_scenario(item, chosen)
        ]

        confirmed = [
            i for i in risk_items if i.evidence == Evidence.CONFIRMED
        ]
        assumed = [i for i in risk_items if i.evidence == Evidence.ASSUMED]
        unknown = [i for i in risk_items if i.evidence == Evidence.UNKNOWN]

        if confirmed:
            state = "confirmed_risk"
            verdict_has_confirmed = True
        elif assumed:
            state = "conditional_risk"
            verdict_has_assumed = True
        elif unknown:
            state = "undecidable"
            verdict_has_unknown = True
        else:
            state = "no_risk"

        def tagged(item: PathExplanation) -> PathExplanation:
            return replace(item, scenario=scenario.name)

        required = tuple(
            sorted(
                {
                    assumption
                    for item in risk_items + safe_items
                    for assumption in item.assumptions
                }
            )
        )
        sink_conclusions.append(
            ScenarioSinkConclusion(
                sink_id=explanation.conclusion_id,
                sink=explanation.sink,
                loc=explanation.loc,
                state=state,
                risk_explanations=tuple(tagged(i) for i in risk_items),
                safe_explanations=tuple(tagged(i) for i in safe_items),
                required_assumptions=required,
            )
        )

    if verdict_has_confirmed:
        verdict = "UNSAFE"
    elif verdict_has_unknown:
        verdict = "INCOMPLETE"
    elif verdict_has_assumed:
        verdict = "ASSUMED"
    else:
        verdict = "SAFE"
    return NamedScenarioResult(
        scenario=scenario,
        feasible=True,
        sink_conclusions=tuple(sink_conclusions),
        verdict=verdict,
    )


def _encode_study_result(result: NamedScenarioResult) -> dict:
    return {
        "scenario": asdict(result.scenario),
        "feasible": result.feasible,
        "verdict": result.verdict,
        "minimal_conflicts": [asdict(item) for item in result.minimal_conflicts],
        "sink_conclusions": [
            {
                "sink_id": item.sink_id,
                "sink": item.sink,
                "loc": asdict(item.loc),
                "state": item.state,
                "required_assumptions": item.required_assumptions,
                "risk_explanations": [
                    asdict(
                        _encode_path_explanation(part),
                    )
                    for part in item.risk_explanations
                ],
                "safe_explanations": [
                    asdict(_encode_path_explanation(part))
                    for part in item.safe_explanations
                ],
            }
            for item in result.sink_conclusions
        ],
    }


def _encode_path_explanation(item: PathExplanation) -> PathExplanation:
    # PathExplanation 本身直接 asdict：Loc/PathHop 是 dataclass，
    # Evidence 枚举在 json.dumps 时由 _json_default 处理。
    return item


def _decode_study_result(data) -> NamedScenarioResult:
    scenario = NamedScenario(
        name=data["scenario"]["name"],
        description=data["scenario"]["description"],
        assumptions=tuple(data["scenario"]["assumptions"]),
    )
    conflicts = tuple(
        _decode_conflict(item) for item in data.get("minimal_conflicts", ())
    )
    conclusions = tuple(
        ScenarioSinkConclusion(
            sink_id=item["sink_id"],
            sink=item["sink"],
            loc=_decode_loc(item["loc"]),
            state=item["state"],
            risk_explanations=tuple(
                _decode_path_explanation(part)
                for part in item.get("risk_explanations", ())
            ),
            safe_explanations=tuple(
                _decode_path_explanation(part)
                for part in item.get("safe_explanations", ())
            ),
            required_assumptions=tuple(item.get("required_assumptions", ())),
        )
        for item in data.get("sink_conclusions", ())
    )
    return NamedScenarioResult(
        scenario=scenario,
        feasible=data["feasible"],
        minimal_conflicts=conflicts,
        sink_conclusions=conclusions,
        verdict=data["verdict"],
    )


def _decode_path_explanation(data) -> PathExplanation:
    return PathExplanation(
        path=_decode_path(data["path"]),
        evidence=Evidence(data["evidence"]),
        assumptions=tuple(data["assumptions"]),
        kind=data["kind"],
        assumption_sites=tuple(
            tuple(site) for site in data.get("assumption_sites", ())
        ),
        scenario=data.get("scenario"),
    )


def format_study_text(study: ScenarioStudy) -> str:
    """把命名联合情景研究渲染为可比较的文本结论。"""

    lines = [f"情景研究总判: {study.verdict}"]
    for result in study.results:
        scenario = result.scenario
        header = (
            f"情景 {scenario.name} [{result.verdict}]: {scenario.description}"
        )
        lines.append(header)
        lines.append(
            "    联合说明: " + (", ".join(scenario.assumptions) or "（无）")
        )
        if not result.feasible:
            lines.append("    情景不可行，最小冲突依据:")
            for conflict in result.minimal_conflicts:
                lines.append(
                    f"        CONFLICT {conflict.conflict_id}: "
                    f"{conflict.assumptions[0]} 与 {conflict.assumptions[1]} "
                    f"在 {conflict.name}() {conflict.loc} 上互斥"
                )
            continue
        for conclusion in result.sink_conclusions:
            lines.append(
                f"    {conclusion.sink_id}: {conclusion.state}"
            )
            for item in conclusion.risk_explanations:
                version = ", ".join(item.assumptions) or "语言内置语义"
                lines.append(
                    f"        风险依据 [情景={item.scenario}; 说明={version}] "
                    f"证据={item.evidence.value}"
                )
    return "\n".join(lines)


def revise_study(
    study: ScenarioStudy,
    new_specs=None,
    scenarios=None,
    disabled_assumptions=(),
    spec_alternatives=None,
) -> tuple[object, "ScenarioStudy"]:
    """修改说明后派生新的比较研究，旧研究（旧查询）保持原依据。

    复用 ``revise_specs`` 对基础快照做增量修订，再在新的基础分析上按
    命名情景重新投影；未显式给出的候选说明沿用旧研究，旧研究对象不被
    修改，可单独回看。
    """

    _, old_snapshot = snapshot_analysis(study.source, study.base_config)
    if spec_alternatives is None:
        spec_alternatives = study.base_config.spec_alternatives
    new_result, _, _ = revise_specs(
        old_snapshot,
        new_specs if new_specs is not None else study.base_config.external_specs,
        disabled_assumptions=disabled_assumptions,
        spec_alternatives=spec_alternatives,
    )
    new_config = AnalysisConfig(
        external_specs=_spec_dict(
            new_specs if new_specs is not None else study.base_config.external_specs
        ),
        disabled_assumptions=frozenset(disabled_assumptions),
        spec_alternatives=tuple(spec_alternatives),
    )
    chosen_scenarios = scenarios if scenarios is not None else study.scenarios
    new_study = ScenarioStudy(
        source=study.source,
        scenarios=tuple(chosen_scenarios),
        base_config=new_config,
        base_result=new_result,
        results=tuple(
            _evaluate_named_scenario(scenario, new_result)
            for scenario in chosen_scenarios
        ),
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    return new_result, new_study


# 变量环境：变量名 -> 该变量当前携带的污点事实集合（空集合 = 干净）。
Env = dict[str, frozenset[Fact]]


@dataclass
class AnalysisConfig:
    max_call_depth: int = 32
    external_specs: dict[str, ExternalSpec] | tuple[ExternalSpec, ...] | list[ExternalSpec] | None = None
    disabled_assumptions: frozenset[str] | set[str] | tuple[str, ...] = ()
    # 额外的候选行为假设（如同一函数的不同版本），与 external_specs 一起
    # 构成假设空间；对同一次调用给出互斥结果的候选会被记为冲突。
    spec_alternatives: tuple[ExternalSpec, ...] = ()

    def __post_init__(self) -> None:
        if self.external_specs is None:
            self.external_specs = ExternalSpecCollection()
        elif isinstance(self.external_specs, dict):
            self.external_specs = ExternalSpecCollection(self.external_specs.values())
        else:
            self.external_specs = ExternalSpecCollection(self.external_specs)
        self.disabled_assumptions = frozenset(self.disabled_assumptions)
        self.spec_alternatives = tuple(self.spec_alternatives)

    def specs_by_name(self) -> dict[str, ExternalSpec]:
        """以名称暴露主说明，供旧 API 与 JSON 序列化使用。

        同一名称存在局部和全局主说明时保留全局项；匹配时通过
        ``matching_primary_spec`` 让局部项覆盖全局项。
        """

        primary: dict[str, ExternalSpec] = {}
        for spec in self.external_specs:
            primary.setdefault(spec.name, spec)
        return primary

    def matching_primary_spec(self, name: str, loc: Loc) -> ExternalSpec | None:
        matching = [
            spec
            for spec in self.external_specs
            if spec.name == name and spec.scope.matches(loc)
        ]
        if not matching:
            return None

        def rank(spec: ExternalSpec) -> tuple:
            scope_kind = spec.scope.kind
            return (
                2 if scope_kind == "call" else 1 if scope_kind == "file" else 0,
                spec.scope.col or 0,
            )

        return sorted(matching, key=rank, reverse=True)[0]


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
        self._conflicts: dict[str, AssumptionConflict] = {}
        self._scenarios: list[Scenario] = []
        self._contradiction_only = False
        self._has_feasible_assumed_risk = False

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
        elif (
            self._contradiction_only
            and not self._has_feasible_assumed_risk
        ):
            # 剩余风险路径全部依赖互斥假设：既不能拼成可行风险路径，
            # 也不能因为前提矛盾就宣称程序安全（空洞的安全结论）。
            verdict = Verdict.INCOMPLETE
            self.notes.append(
                "所有风险路径都依赖互相矛盾的假设，不存在实际可行的风险路径；"
                "但矛盾前提不能推出安全结论，整体无法判定"
            )
        elif assumptions or any(
            d.evidence == Evidence.ASSUMED for d in self.diagnostics
        ):
            verdict = Verdict.ASSUMED
        else:
            verdict = Verdict.SAFE
        return verdict, self.diagnostics, self.notes, assumptions

    def conflicts_result(self) -> tuple[AssumptionConflict, ...]:
        return tuple(self._conflicts.values())

    def scenarios_result(self) -> tuple[Scenario, ...]:
        return tuple(self._scenarios)

    def explanations_result(self) -> tuple[ConclusionExplanation, ...]:
        return tuple(self._explanations)

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
                    scope=spec.scope.label,
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
        assumption_id = scoped_spec_assumption_id(spec)
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
        candidates = self._spec_candidates(call.func, call.loc)
        if candidates:
            self._detect_conflicts(call, candidates, propagated)
            result: set[Fact] = set()
            for spec in candidates:
                assumption_id = scoped_spec_assumption_id(spec)
                external_hop = PathHop(
                    call.loc,
                    "external",
                    "外部调用 "
                    f"{call.func}() 按说明 {assumption_id} 判定",
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
                result |= set(
                    self._apply_spec(spec, call, propagated, external_hop)
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

    def _spec_candidates(self, name: str, loc: Loc) -> list[ExternalSpec]:
        """当前生效的候选行为假设：启用的说明 + 未撤回的候选版本。"""

        disabled = self.config.disabled_assumptions
        candidates: list[ExternalSpec] = []
        seen: set[str] = set()
        active = self.config.matching_primary_spec(name, loc)
        all_matching = tuple(
            spec
            for spec in tuple(self.config.external_specs) + tuple(self.config.spec_alternatives)
            if spec.name == name and spec.scope.matches(loc)
        )
        if not all_matching:
            return []

        def scope_rank(spec: ExternalSpec) -> int:
            return {"global": 0, "file": 1, "call": 2}[spec.scope.kind]

        active_rank = scope_rank(active) if active is not None else -1
        narrowest_rank = max(scope_rank(spec) for spec in all_matching)
        if active is not None:
            assumption_id = scoped_spec_assumption_id(active)
            unversioned = spec_assumption_id(active.name, active.version)
            if (
                active_rank == narrowest_rank
                and assumption_id not in disabled
                and unversioned not in disabled
            ):
                candidates.append(active)
                seen.add(assumption_id)
        for alt in self.config.spec_alternatives:
            if alt.name != name or not alt.scope.matches(loc):
                continue
            if scope_rank(alt) != narrowest_rank:
                continue
            assumption_id = scoped_spec_assumption_id(alt)
            unversioned = spec_assumption_id(alt.name, alt.version)
            if (
                assumption_id in disabled
                or unversioned in disabled
                or assumption_id in seen
            ):
                continue
            candidates.append(alt)
            seen.add(assumption_id)
        return candidates

    @staticmethod
    def _spec_outcome(spec: ExternalSpec, has_unsafe_args: bool) -> str:
        """某条假设对本次调用的判定结果：干净值还是不可信值。"""

        if spec.returns == "clean":
            return "clean"
        if spec.returns == "tainted":
            return "tainted"
        return "tainted" if has_unsafe_args else "clean"

    def _detect_conflicts(
        self,
        call: Call,
        candidates: list[ExternalSpec],
        propagated: frozenset[Fact],
    ) -> None:
        """对同一次调用给出互斥结果的候选假设记为冲突（按调用实例）。"""

        has_unsafe = any(not f.safe for f in propagated)
        outcomes = {
            scoped_spec_assumption_id(spec): (
                spec,
                self._spec_outcome(spec, has_unsafe),
            )
            for spec in candidates
        }
        ids = sorted(outcomes)
        for index, first in enumerate(ids):
            for second in ids[index + 1:]:
                spec_first, outcome_first = outcomes[first]
                spec_second, outcome_second = outcomes[second]
                if outcome_first == outcome_second:
                    continue
                conflict_id = (
                    f"{call.func}:{call.loc.line}:{call.loc.col}"
                    f"#{first}|{second}"
                )
                if conflict_id in self._conflicts:
                    continue
                label = {"clean": "干净值", "tainted": "不可信值"}
                self._conflicts[conflict_id] = AssumptionConflict(
                    conflict_id=conflict_id,
                    name=call.func,
                    loc=call.loc,
                    assumptions=(first, second),
                    constraints=(
                        f"{first}: returns={spec_first.returns}，"
                        f"本次调用结果判定为{label[outcome_first]}",
                        f"{second}: returns={spec_second.returns}，"
                        f"本次调用结果判定为{label[outcome_second]}",
                    ),
                )
                self.notes.append(
                    f"{call.loc}: 假设 {first} 与 {second} 对同一次 "
                    f"{call.func}() 调用给出互斥结果，二者不能同时成立"
                )

    def _apply_spec(
        self,
        spec: ExternalSpec,
        call: Call,
        propagated: frozenset[Fact],
        external_hop: PathHop,
    ) -> frozenset[Fact]:
        """按单条行为说明求本次调用的返回值事实，并绑定调用实例。"""

        assumption_id = scoped_spec_assumption_id(spec)
        site = frozenset({(assumption_id, call.loc.line, call.loc.col)})
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
                        sites=site,
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
                        sites=site,
                    )
                }
            )
        result: set[Fact] = set()
        unsafe = frozenset(f for f in propagated if not f.safe)
        for fact in unsafe:
            extended = fact.extended(external_hop).with_sites(site)
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
                    sites=site,
                )
            )
        return frozenset(result)

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
                        assumption_sites=tuple(sorted(fact.sites)),
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
                    assumption_sites=tuple(sorted(fact.sites)),
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

        risky_assumed = [
            item for item in risky if item.evidence == Evidence.ASSUMED
        ]
        # 按调用实例检查每条风险依据是否自相矛盾（同一调用被两条假设
        # 赋予互斥结果时，该依据无法共同成立，不能拼成可行风险路径）。
        infeasible_items = [
            item
            for item in risky_assumed
            if self._conflicts_for_sites(item.assumption_sites)
        ]
        feasible_items = [
            item for item in risky_assumed if item not in infeasible_items
        ]
        if (
            infeasible_items
            and not feasible_items
            and not has_confirmed
            and not has_unknown
        ):
            state = "CONTRADICTORY_RISK"
            self._contradiction_only = True
        if feasible_items:
            self._has_feasible_assumed_risk = True

        assumption_sets = [frozenset(item.assumptions) for item in risky_assumed]
        groups = self._minimal_assumption_groups(assumption_sets)
        infeasible_groups = self._minimal_assumption_groups(
            [frozenset(item.assumptions) for item in infeasible_items]
        )
        feasible_groups = self._minimal_assumption_groups(
            [frozenset(item.assumptions) for item in feasible_items]
        )
        # 替代依据之间的相容性：两组假设若在同一调用实例上互斥，
        # 则只能分情景讨论，否则可以共同采用。
        sites_by_group: dict[frozenset[str], set] = {}
        for item in feasible_items:
            sites_by_group.setdefault(
                frozenset(item.assumptions), set()
            ).update(item.assumption_sites)
        scenario_only: set[frozenset[str]] = set()
        for index, first in enumerate(feasible_groups):
            for second in feasible_groups[index + 1:]:
                merged_sites = list(sites_by_group.get(first, ())) + list(
                    sites_by_group.get(second, ())
                )
                if self._conflicts_for_sites(merged_sites):
                    scenario_only.add(first)
                    scenario_only.add(second)
        scenario_only_groups = [
            group for group in feasible_groups if group in scenario_only
        ]
        compatible_groups = [
            group for group in feasible_groups if group not in scenario_only
        ]
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
        conclusion_id = self._conclusion_id(call)
        self._explanations.append(
            ConclusionExplanation(
                conclusion_id=conclusion_id,
                sink=call.func,
                loc=call.loc,
                state=state,
                path_explanations=path_explanations,
                assumption_groups=tuple(tuple(sorted(group)) for group in groups),
                indispensable_assumptions=indispensable,
                common_assumptions=(
                    tuple(sorted(frozenset.intersection(*groups))) if groups else ()
                ),
                infeasible_assumption_groups=tuple(
                    tuple(sorted(group)) for group in infeasible_groups
                ),
                compatible_groups=tuple(
                    tuple(sorted(group)) for group in compatible_groups
                ),
                scenario_only_groups=tuple(
                    tuple(sorted(group)) for group in scenario_only_groups
                ),
            )
        )
        self._build_scenarios(
            conclusion_id, risky, safe, infeasible_items, feasible_groups
        )

    def _conflicts_for_sites(self, sites) -> list[AssumptionConflict]:
        """假设-调用实例集合内部存在的互斥冲突。"""

        site_set = set(sites)
        found = []
        for conflict in self._conflicts.values():
            first, second = conflict.assumptions
            line, col = conflict.loc.line, conflict.loc.col
            if (first, line, col) in site_set and (second, line, col) in site_set:
                found.append(conflict)
        return found

    def _build_scenarios(
        self,
        conclusion_id: str,
        risky,
        safe,
        infeasible_items,
        feasible_groups,
    ) -> None:
        """把结论位置上的依据组织成需要共同成立的情景。"""

        scenarios: list[Scenario] = []
        if any(item.evidence == Evidence.CONFIRMED for item in risky):
            scenarios.append(
                Scenario(conclusion_id, conclusion_id, (), "risk")
            )
        for group in feasible_groups:
            scenarios.append(
                Scenario(
                    conclusion_id,
                    conclusion_id,
                    tuple(sorted(group)),
                    "risk",
                )
            )
        for item in infeasible_items:
            conflicts = self._conflicts_for_sites(item.assumption_sites)
            scenarios.append(
                Scenario(
                    conclusion_id,
                    conclusion_id,
                    tuple(sorted(item.assumptions)),
                    "contradictory",
                    tuple(c.conflict_id for c in conflicts),
                )
            )
        if any(item.evidence == Evidence.UNKNOWN for item in risky):
            scenarios.append(
                Scenario(conclusion_id, conclusion_id, (), "undecidable")
            )
        if not risky:
            safe_groups = {
                tuple(sorted(item.assumptions)) for item in safe
            } or {()}
            for group in sorted(safe_groups):
                scenarios.append(
                    Scenario(conclusion_id, conclusion_id, group, "no_risk")
                )
        for index, scenario in enumerate(scenarios):
            self._scenarios.append(
                replace(
                    scenario,
                    scenario_id=f"{conclusion_id}#S{index + 1}",
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
    analyzer = Analyzer(program, config or AnalysisConfig())
    verdict, diagnostics, notes, assumptions = analyzer.run()
    from .model import AnalysisResult

    return AnalysisResult(
        verdict=verdict,
        diagnostics=diagnostics,
        notes=notes,
        assumptions=assumptions,
        explanations=analyzer.explanations_result(),
        conflicts=analyzer.conflicts_result(),
        scenarios=analyzer.scenarios_result(),
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


def revise_specs(snapshot, new_specs=None, disabled_assumptions=(), spec_alternatives=None):
    """修订行为说明后重算，并按稳定结论位置标记受影响/可复用解释。

    未显式给出 ``spec_alternatives`` 时沿用快照中的候选假设；旧情景、
    旧冲突保留在 ``old_snapshot`` 中可单独回看，报告按冲突解除与
    程序路径变化归因结论变化。
    """

    if spec_alternatives is None:
        spec_alternatives = snapshot.alternatives
    config = AnalysisConfig(
        external_specs=_spec_dict(new_specs),
        disabled_assumptions=frozenset(disabled_assumptions),
        spec_alternatives=tuple(spec_alternatives),
    )
    result = analyze_source(snapshot.source, config)
    new_snapshot = ResearchSnapshot.from_result(
        snapshot.source,
        result,
        new_specs,
        disabled_assumptions,
        spec_alternatives,
    )
    changes = tuple(compare_external_specs(snapshot.specs, new_specs))
    changed_names = {
        change.name
        for change in changes
        if change.status != "unchanged"
        and change.old_scope.startswith("global")
        and change.new_scope.startswith("global")
    }
    changed_ids = {
        assumption
        for change in changes
        for assumption in change.invalidated_assumptions
    }
    changed_scopes = {
        (
            change.name,
            change.old_scope if change.status == "withdrawn" else change.new_scope,
        )
        for change in changes
        if change.status != "unchanged"
    }
    # 候选假设（spec_alternatives）的新增/撤回同样令相关结论失效。
    old_alt_ids = {
        scoped_spec_assumption_id(a) for a in snapshot.alternatives
    }
    new_alt_ids = {
        scoped_spec_assumption_id(a) for a in spec_alternatives
    }
    changed_ids |= old_alt_ids ^ new_alt_ids
    changed_names |= {
        a.name
        for a in tuple(snapshot.alternatives) + tuple(spec_alternatives)
        if scoped_spec_assumption_id(a) in (old_alt_ids ^ new_alt_ids)
    }
    for spec in tuple(snapshot.alternatives) + tuple(spec_alternatives):
        if scoped_spec_assumption_id(spec) in (old_alt_ids ^ new_alt_ids):
            changed_scopes.add((spec.name, spec.scope.label))

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
                if hop.kind not in ("external", "unknown"):
                    continue
                if any(f" {name}()" in hop.text for name in changed_names):
                    return True
                call_label = f"call::{hop.loc.line}:{hop.loc.col}"
                if any(
                    f" {name}()" in hop.text and label == call_label
                    for name, label in changed_scopes
                    if label.startswith("call:")
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
    old_conflict_ids = {c.conflict_id for c in snapshot.conflicts}
    new_conflict_ids = {c.conflict_id for c in result.conflicts}
    resolved_conflicts = tuple(sorted(old_conflict_ids - new_conflict_ids))
    introduced_conflicts = tuple(sorted(new_conflict_ids - old_conflict_ids))
    remaining_conflicts = tuple(sorted(old_conflict_ids & new_conflict_ids))

    # 归因：假设组本身变化记为程序路径变化；假设组不变而可行性/
    # 状态变化（或涉及已解除冲突的假设）记为冲突解除带来的变化。
    resolved_assumptions = {
        assumption
        for conflict in snapshot.conflicts
        if conflict.conflict_id in resolved_conflicts
        for assumption in conflict.assumptions
    }
    old_by_cid = {e.conclusion_id: e for e in snapshot.explanations}
    new_by_cid = {e.conclusion_id: e for e in result.explanations}
    conflict_driven: list[str] = []
    path_driven: list[str] = []
    for cid in sorted(affected):
        old_expl = old_by_cid.get(cid)
        new_expl = new_by_cid.get(cid)
        old_groups = set(old_expl.assumption_groups) if old_expl else set()
        new_groups = set(new_expl.assumption_groups) if new_expl else set()
        involved = (old_groups | new_groups)
        flat = {a for group in involved for a in group}
        if old_groups != new_groups:
            path_driven.append(cid)
        if (
            old_expl is not None
            and new_expl is not None
            and old_groups == new_groups
            and (
                old_expl.state != new_expl.state
                or old_expl.infeasible_assumption_groups
                != new_expl.infeasible_assumption_groups
            )
        ) or (flat & resolved_assumptions):
            conflict_driven.append(cid)

    report = RevisionReport(
        old_snapshot=snapshot,
        new_snapshot=new_snapshot,
        changes=changes,
        affected_conclusions=tuple(sorted(affected)),
        reused_conclusions=reused,
        resolved_conflicts=resolved_conflicts,
        new_conflicts=introduced_conflicts,
        remaining_conflicts=remaining_conflicts,
        conflict_driven_conclusions=tuple(conflict_driven),
        path_driven_conclusions=tuple(path_driven),
    )
    return result, report, new_snapshot
