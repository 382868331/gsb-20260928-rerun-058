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
        return "\n".join(lines)
