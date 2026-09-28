from __future__ import annotations

from pathlib import Path

from .analyzer import AnalysisResult, analyze_program
from .callgraph import build_call_graph
from .parser import parse_source


def load_program(path: str | Path):
    source = Path(path).read_text(encoding="utf-8")
    return parse_source(source)


def analyze_source(source: str, *, max_depth: int = 32, max_call_steps: int = 500) -> AnalysisResult:
    program = parse_source(source)
    return analyze_program(program, max_depth=max_depth, max_call_steps=max_call_steps)


def analyze_file(path: str | Path, *, max_depth: int = 32, max_call_steps: int = 500):
    program = load_program(path)
    result = analyze_program(program, max_depth=max_depth, max_call_steps=max_call_steps)
    return program, build_call_graph(program), result
