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
class JointScenario:
    """研究者命名的联合情景：一组同时采纳的说明假设（含版本）。

    情景内部若含有对同一次调用互斥的假设，则该情景不可行；
    minimal_conflicts 给出导致不可行的最小冲突依据（成对的互斥假设，
    去掉其中任意一条该组矛盾即消失）。未知外部返回导致的无法判断结论
    与“无可行情景”是不同状态，分别记录，互不归类。
    """

    name: str
    assumptions: tuple[str, ...]
    withdrawn: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    minimal_conflicts: tuple[tuple[str, ...], ...] = ()
    feasible: bool = True
    risk_conclusions: tuple[str, ...] = ()
    undecidable_conclusions: tuple[str, ...] = ()


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
    joint_scenarios: tuple[JointScenario, ...] = ()

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
        for joint in self.joint_scenarios:
            state = "feasible" if joint.feasible else "infeasible"
            lines.append(
                "JOINT " + joint.name + " [" + state + "]: "
                + (", ".join(joint.assumptions) or "（无外部假设）")
            )
            if joint.withdrawn:
                lines.append("    已局部撤销: " + ", ".join(joint.withdrawn))
            for pair in joint.minimal_conflicts:
                lines.append("    最小冲突依据: " + " 与 ".join(pair) + " 互斥")
            if joint.risk_conclusions:
                lines.append("    风险结论: " + ", ".join(joint.risk_conclusions))
            if joint.undecidable_conclusions:
                lines.append(
                    "    无法判断结论（未知外部返回，非无可行情景）: "
                    + ", ".join(joint.undecidable_conclusions)
                )
        return "\n".join(lines)
