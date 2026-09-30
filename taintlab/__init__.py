"""TaintLab: 小型教学语言的静态污点分析基础库。

只分析文本源程序，不执行被分析的程序。
"""

from .model import (
    AnalysisResult,
    Diagnostic,
    Severity,
    TaintPath,
    Verdict,
)
from .analyzer import (
    analyze_source,
    analyze_program,
    compare_spec_versions,
    AnalysisConfig,
    DiagnosticChange,
    ExternalSpec,
    VersionDiff,
)
from .parser import parse
from .lexer import LexerError
from .parser import ParseError

__all__ = [
    "analyze_source",
    "analyze_program",
    "AnalysisConfig",
    "AnalysisResult",
    "ExternalSpec",
    "Diagnostic",
    "DiagnosticChange",
    "Severity",
    "TaintPath",
    "Verdict",
    "VersionDiff",
    "compare_spec_versions",
    "parse",
    "LexerError",
    "ParseError",
]
