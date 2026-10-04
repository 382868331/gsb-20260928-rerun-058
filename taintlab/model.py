from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .locations import Loc


class Severity(str, Enum):
    ERROR = "error"        # 已确认：不可信数据到达危险操作
    WARNING = "warning"    # 未能排除（递归/深度上限等导致分析不完整）
    INFO = "info"


class Evidence(str, Enum):
    CONFIRMED = "CONFIRMED"      # 由语言/内置语义直接证实
    ASSUMED = "ASSUMED"          # 依赖使用者提供的外部行为说明
    UNKNOWN = "UNKNOWN"          # 外部行为或分析截断导致无法判断


@dataclass(frozen=True)
class PathHop:
    """传播路径上的一跳，可回到源文位置。"""

    loc: Loc
    kind: str   # source | assign | call_in | call_out | branch | join | sink
    text: str


@dataclass(frozen=True)
class TaintPath:
    hops: tuple[PathHop, ...]

    def render(self) -> str:
        return " -> ".join(f"[{h.kind}] {h.text} @ {h.loc}" for h in self.hops)


@dataclass(frozen=True)
class Diagnostic:
    severity: Severity
    message: str
    loc: Loc
    sink: str
    paths: tuple[TaintPath, ...] = ()
    rule: str = ""
    evidence: Evidence = Evidence.CONFIRMED
    assumptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssumptionRecord:
    assumption_id: str
    name: str
    version: str | None
    returns: str
    description: str
    scope: str = "global"
    locations: tuple[Loc, ...] = ()
    paths: tuple[TaintPath, ...] = ()


@dataclass(frozen=True)
class PathExplanation:
    """一条到达结论位置的独立依据。"""

    path: TaintPath
    evidence: Evidence
    assumptions: tuple[str, ...] = ()
    kind: str = "risk"  # risk | safe | unknown
    assumption_sites: tuple[tuple[str, int, int], ...] = ()
    # 该风险依据所在的命名情景名称（仅命名情景研究填写，
    # 自动情景分析保持为空）；同一返回值在不同情景下分别标注。
    scenario: str | None = None


@dataclass(frozen=True)
class ConclusionExplanation:
    """同一风险位置上已证实、条件、未知与安全依据的最小解释。"""

    conclusion_id: str
    sink: str
    loc: Loc
    state: str
    path_explanations: tuple[PathExplanation, ...] = ()
    assumption_groups: tuple[tuple[str, ...], ...] = ()
    indispensable_assumptions: tuple[str, ...] = ()
    common_assumptions: tuple[str, ...] = ()
    infeasible_assumption_groups: tuple[tuple[str, ...], ...] = ()
    compatible_groups: tuple[tuple[str, ...], ...] = ()
    scenario_only_groups: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class AssumptionConflict:
    """两条假设对同一次调用给出互斥结果的最小依据。"""

    conflict_id: str
    name: str
    loc: Loc
    assumptions: tuple[str, ...]
    constraints: tuple[str, ...]


@dataclass(frozen=True)
class Scenario:
    """一个需要共同成立的情景：一组假设在某个结论位置上的组合。"""

    scenario_id: str
    conclusion_id: str
    assumptions: tuple[str, ...]
    state: str  # contradictory | risk | no_risk | undecidable
    conflicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class NamedScenario:
    """有名称的联合情景：研究者显式命名、需共同采用的一组说明版本。

    ``assumptions`` 中的每条说明（``名称@版本``）都必须同时成立；
    未列入的候选说明在该情景中不被采用。情景可行性由其内部是否包含
    对同一次调用给出互斥结果的最小冲突依据决定。
    """

    name: str
    description: str
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class ScenarioSinkConclusion:
    """某个命名情景下、某个 sink 位置的结论及其依据版本。

    ``state`` 取值：
    ``confirmed_risk``（已证实风险，与说明无关）/
    ``conditional_risk``（依赖本情景说明版本的风险）/
    ``undecidable``（本情景下仍含未知外部返回值）/
    ``no_risk``（本情景下未发现风险）。
    风险路径必须注明情景名称与其依赖的说明版本，故风险依据的
    ``PathExplanation.scenario`` 被填写为该情景名称。
    """

    sink_id: str
    sink: str
    loc: Loc
    state: str
    risk_explanations: tuple[PathExplanation, ...] = ()
    safe_explanations: tuple[PathExplanation, ...] = ()
    required_assumptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class NamedScenarioResult:
    """一个命名联合情景评估后的完整结果。"""

    scenario: NamedScenario
    feasible: bool
    # 不可行时，导致该情景不成立的最小冲突依据（逐个独立冲突）；
    # 撤销其中一条说明只解除涉及它的冲突，其余冲突保留。
    minimal_conflicts: tuple[AssumptionConflict, ...] = ()
    # 仅在可行时给出逐 sink 的情景化结论。
    sink_conclusions: tuple[ScenarioSinkConclusion, ...] = ()
    # 情景总判：UNSAFE / ASSUMED / INCOMPLETE / SAFE / INFEASIBLE。
    verdict: str = "INFEASIBLE"


class Verdict(str, Enum):
    UNSAFE = "UNSAFE"        # 发现污点到达 sink
    ASSUMED = "ASSUMED"      # 风险或安全结论依赖外部行为假设
    INCOMPLETE = "INCOMPLETE"  # 达到分析上限，无法判定安全
    SAFE = "SAFE"            # 完整分析且无污点到达 sink
    PARSE_ERROR = "PARSE_ERROR"


@dataclass
class AnalysisResult:
    verdict: Verdict
    diagnostics: list[Diagnostic]
    notes: list[str]
    assumptions: tuple[AssumptionRecord, ...] = ()
    explanations: tuple[ConclusionExplanation, ...] = ()
    conflicts: tuple[AssumptionConflict, ...] = ()
    scenarios: tuple[Scenario, ...] = ()

    def format_text(self) -> str:
        lines = [f"分析结论: {self.verdict.value}"]
        for d in self.diagnostics:
            lines.append(
                f"{d.severity.value.upper()} ({d.rule}/{d.evidence.value}) "
                f"{d.loc}: {d.message}"
            )
            if d.assumptions:
                lines.append("    依赖假设: " + ", ".join(d.assumptions))
            for path in d.paths:
                for hop in path.hops:
                    lines.append(f"    {hop.loc}  [{hop.kind}] {hop.text}")
        for assumption in self.assumptions:
            version = f"@ {assumption.version}" if assumption.version else ""
            lines.append(
                f"ASSUMPTION: {assumption.assumption_id} {assumption.name}{version} "
                f"returns={assumption.returns}: {assumption.description}"
            )
            for loc in assumption.locations:
                lines.append(f"    {loc}  使用该说明的外部调用")
            for path in assumption.paths:
                for hop in path.hops:
                    lines.append(f"    {hop.loc}  [{hop.kind}] {hop.text}")
        for note in self.notes:
            lines.append(f"NOTE: {note}")
        for explanation in self.explanations:
            lines.append(
                f"CONCLUSION {explanation.conclusion_id}: {explanation.state} "
                f"at {explanation.loc} ({explanation.sink})"
            )
            if explanation.assumption_groups:
                lines.append(
                    "    最小替代假设组: "
                    + " 或 ".join(
                        "(" + ", ".join(group) + ")"
                        for group in explanation.assumption_groups
                    )
                )
            if explanation.indispensable_assumptions:
                lines.append(
                    "    共同且不可或缺的假设: "
                    + ", ".join(explanation.indispensable_assumptions)
                )
            if explanation.infeasible_assumption_groups:
                lines.append(
                    "    互斥假设组（无法共同成立）: "
                    + " 或 ".join(
                        "(" + ", ".join(group) + ")"
                        for group in explanation.infeasible_assumption_groups
                    )
                )
            if explanation.compatible_groups:
                lines.append(
                    "    可共同采用的替代依据: "
                    + " 或 ".join(
                        "(" + ", ".join(group) + ")"
                        for group in explanation.compatible_groups
                    )
                )
            if explanation.scenario_only_groups:
                lines.append(
                    "    只能分情景讨论的依据: "
                    + " 或 ".join(
                        "(" + ", ".join(group) + ")"
                        for group in explanation.scenario_only_groups
                    )
                )
        for conflict in self.conflicts:
            lines.append(
                "CONFLICT " + conflict.conflict_id + ": " + conflict.name
                + " 于 " + str(conflict.loc) + " 假设 "
                + " 与 ".join(conflict.assumptions) + " 互斥"
            )
            for constraint in conflict.constraints:
                lines.append("    " + constraint)
        for scenario in self.scenarios:
            lines.append(
                "SCENARIO " + scenario.scenario_id + " [" + scenario.state + "]: "
                + (", ".join(scenario.assumptions) or "（无外部假设）")
            )
            for conflict_id in scenario.conflicts:
                lines.append("    涉及冲突: " + conflict_id)
        return "\n".join(lines)
