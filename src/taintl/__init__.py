"""Static taint analysis for the TaintL teaching language."""

from .api import analyze_file, analyze_source, load_program

__all__ = ["analyze_file", "analyze_source", "load_program"]
__version__ = "0.1.0"
