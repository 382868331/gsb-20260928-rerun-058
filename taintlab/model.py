from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .locations import Loc


class Severity(str, Enum):
    ERROR = "error"        # 已确认：不可信数据到达危险操作
    WARNING = "warning"    # 未能排除（递归/深度上限等导致分析不完整）
    INFO = "info"

#: 结论依据三态：已证实 / 依赖外部行为说明（假设） / 无法判断。
BASIS_CONFIRMED = "confirmed"
BASIS_ASSUMPTION = "assumption"
BASIS_UNKNOWN = "unknown"


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
    #: 该诊断的依据：confirmed | assumption | unknown。
    basis: str = BASIS_CONFIRMED
    #: 诊断所依赖的外部行为说明名称（basis == assumption 时非空）。
    assumptions: tuple[str, ...] = ()
    #: 当依据为“无法判断”时，说明尚不能排除风险的具体原因。
    uncertainty: str = ""


class Verdict(str, Enum):
    UNSAFE = "UNSAFE"        # 发现污点到达 sink
    ASSUMED_UNSAFE = "ASSUMED_UNSAFE"  # 风险路径依赖外部行为说明才成立
    INCOMPLETE = "INCOMPLETE"  # 达到分析上限，无法判定安全
    SAFE = "SAFE"            # 完整分析且无污点到达 sink
    PARSE_ERROR = "PARSE_ERROR"


@dataclass
class AnalysisResult:
    verdict: Verdict
    diagnostics: list[Diagnostic]
    notes: list[str]
    #: 本次分析实际依赖到的外部行为说明名称（去重、有序）。
    assumptions_used: tuple[str, ...] = ()

    def format_text(self) -> str:
        lines = [f"分析结论: {self.verdict.value}"]
        for d in self.diagnostics:
            lines.append(f"{d.severity.value.upper()} ({d.rule}) {d.loc}: {d.message}")
            if d.assumptions:
                lines.append(f"    依据假设: {', '.join(d.assumptions)}")
            if d.uncertainty:
                lines.append(f"    无法判定原因: {d.uncertainty}")
            for path in d.paths:
                for hop in path.hops:
                    lines.append(f"    {hop.loc}  [{hop.kind}] {hop.text}")
        for note in self.notes:
            lines.append(f"NOTE: {note}")
        return "\n".join(lines)
