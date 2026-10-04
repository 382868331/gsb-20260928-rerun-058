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
from .model import AssumptionConflict, Scenario
from .model import NamedScenario, NamedScenarioResult, ScenarioSinkConclusion
from .analyzer import (
    analyze_source,
    analyze_program,
    AnalysisConfig,
    compare_external_specs,
    ExternalSpec,
    ExternalSpecScope,
    ResearchSnapshot,
    RevisionReport,
    SpecVersionChange,
    revise_specs,
    snapshot_analysis,
    study_scenarios,
    revise_study,
    ScenarioStudy,
    format_study_text,
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
    "ConclusionExplanation",
    "Evidence",
    "ExternalSpec",
    "ExternalSpecScope",
    "PathExplanation",
    "ResearchSnapshot",
    "RevisionReport",
    "Scenario",
    "NamedScenario",
    "NamedScenarioResult",
    "ScenarioSinkConclusion",
    "ScenarioStudy",
    "SpecVersionChange",
    "compare_external_specs",
    "revise_specs",
    "revise_study",
    "snapshot_analysis",
    "study_scenarios",
    "format_study_text",
    "Diagnostic",
    "Severity",
    "TaintPath",
    "Verdict",
    "parse",
    "LexerError",
    "ParseError",
]
