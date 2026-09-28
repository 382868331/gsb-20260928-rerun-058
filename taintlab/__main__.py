import argparse
import sys

from .analyzer import AnalysisConfig, analyze_source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taintlab",
        description="TaintLab 小型教学语言静态污点分析器（只分析文本，不执行程序）",
    )
    parser.add_argument("file", help="TaintLab 源文件路径（- 表示从标准输入读取）")
    parser.add_argument(
        "--max-depth", type=int, default=32, help="跨函数分析的最大调用深度（默认 32）"
    )
    args = parser.parse_args(argv)

    if args.file == "-":
        source = sys.stdin.read()
    else:
        with open(args.file, "r", encoding="utf-8") as fh:
            source = fh.read()

    result = analyze_source(source, AnalysisConfig(max_call_depth=args.max_depth))
    print(result.format_text())
    if result.verdict.value == "PARSE_ERROR":
        return 2
    return 1 if result.verdict.value != "SAFE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
