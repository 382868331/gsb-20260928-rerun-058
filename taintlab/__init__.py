"""TaintLab: 小型教学语言的静态污点分析基础库。

只分析文本源程序，不执行被分析的程序。
"""

from .model import (
    AnalysisResult,
    AssumptionRecord,
    ConclusionExplanation,
    Diagnostic,
    Evidence,
    PathExplanation,
    Severity,
    TaintPath,
    Verdict,
)
from .model import AssumptionConflict, JointScenario, Scenario
from .analyzer import (
    analyze_source,
    analyze_program,
    AnalysisConfig,
    compare_external_specs,
    ExternalSpec,
    ResearchSnapshot,
    RevisionReport,
    SpecVersionChange,
    revise_specs,
    snapshot_analysis,
)
from .parser import parse
from .lexer import LexerError
from .parser import ParseError

__all__ = [
    "analyze_source",
    "analyze_program",
    "AnalysisConfig",
    "AnalysisResult",
    "AssumptionRecord",
    "AssumptionConflict",
    "JointScenario",
    "ConclusionExplanation",
    "Evidence",
    "ExternalSpec",
    "PathExplanation",
    "ResearchSnapshot",
    "RevisionReport",
    "Scenario",
    "SpecVersionChange",
    "compare_external_specs",
    "revise_specs",
    "snapshot_analysis",
    "Diagnostic",
    "Severity",
    "TaintPath",
    "Verdict",
    "parse",
    "LexerError",
    "ParseError",
]
