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
from .analyzer import EXTERNAL_BEHAVIORS, analyze_source, analyze_program, AnalysisConfig
from .parser import parse
from .lexer import LexerError
from .parser import ParseError

__all__ = [
    "analyze_source",
    "analyze_program",
    "AnalysisConfig",
    "EXTERNAL_BEHAVIORS",
    "AnalysisResult",
    "Diagnostic",
    "Severity",
    "TaintPath",
    "Verdict",
    "parse",
    "LexerError",
    "ParseError",
]
