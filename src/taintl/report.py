from __future__ import annotations

from dataclasses import asdict

from .analyzer import AnalysisResult


def result_to_dict(result: AnalysisResult) -> dict:
    return {
        "complete": result.complete,
        "safe": result.safe,
        "diagnostics": [asdict(diagnostic) for diagnostic in result.diagnostics],
        "call_edges": [
            {"caller": caller, "callee": callee, "line": line, "column": column}
            for caller, callee, line, column in result.call_edges
        ],
    }


def format_text(result: AnalysisResult) -> str:
    lines = []
    for diagnostic in result.diagnostics:
        location = f"{diagnostic.line}:{diagnostic.column}"
        lines.append(f"{diagnostic.severity}: {location}: {diagnostic.rule}: {diagnostic.message}")
        for node in diagnostic.path:
            suffix = f" {node.detail}" if node.detail else ""
            lines.append(f"  {node.line}:{node.column} {node.kind} {node.label}{suffix}")
    if result.complete:
        lines.append("analysis complete: no proven unsafe flow was reported" if result.safe else "analysis complete with findings")
    else:
        lines.append("analysis incomplete: this program must not be reported as safe")
    return "\n".join(lines)
