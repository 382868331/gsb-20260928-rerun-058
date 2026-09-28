from __future__ import annotations

import argparse
import json
import sys

from .api import analyze_file
from .report import format_text, result_to_dict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static taint analysis for TaintL source text")
    parser.add_argument("source", help="path to a TaintL source file; the file is only read, never executed")
    parser.add_argument("--json", action="store_true", help="emit JSON diagnostics")
    parser.add_argument("--max-depth", type=int, default=32, help="recursive-call analysis depth limit")
    parser.add_argument("--max-call-steps", type=int, default=500, help="global analyzed call-step limit")
    args = parser.parse_args(argv)

    try:
        _, _, result = analyze_file(args.source, max_depth=args.max_depth, max_call_steps=args.max_call_steps)
    except (OSError, ValueError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result_to_dict(result), ensure_ascii=False, indent=2))
    else:
        print(format_text(result))
    if any(diagnostic.severity == "error" for diagnostic in result.diagnostics):
        return 1
    if not result.complete:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
