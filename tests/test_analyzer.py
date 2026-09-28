import unittest

from taintlab import (
    AnalysisConfig,
    LexerError,
    ParseError,
    Severity,
    Verdict,
    analyze_source,
    parse,
)
from taintlab.callgraph import build_call_graph


class TaintAnalysisTests(unittest.TestCase):
    def test_direct_taint(self):
        result = analyze_source("def main(){ x = read_input(); exec(x); }")
        self.assertIs(result.verdict, Verdict.UNSAFE)
        self.assertEqual(result.diagnostics[0].severity, Severity.ERROR)
        self.assertEqual(result.diagnostics[0].rule, "TAINT-FLOW")
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertEqual(kinds, ["source", "assign", "sink"])

    def test_clean_constant_is_safe(self):
        result = analyze_source('def main(){ exec("ls"); }')
        self.assertIs(result.verdict, Verdict.SAFE)
        self.assertEqual(result.diagnostics, [])

    def test_cross_function_propagation(self):
        source = (
            "def wrap(c){ return c; }"
            "def main(){ x = read_input(); y = wrap(x); exec(y); }"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.UNSAFE)
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertIn("call_in", kinds)
        self.assertIn("call_out", kinds)

    def test_sanitized_value_separated_from_original(self):
        # 净化值干净，原变量仍带污点：二者不能混成一份。
        source = (
            "def clean(v){ return sanitize(v); }"
            "def main(){"
            " x = read_input();"
            " y = clean(x);"
            " exec(y);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.SAFE)

        source2 = (
            "def main(){"
            " x = read_input();"
            " y = sanitize(x);"
            " exec(y);"
            " exec(x);"
            "}"
        )
        result2 = analyze_source(source2)
        self.assertIs(result2.verdict, Verdict.UNSAFE)
        # 只有原始 x 的 sink 被报告，净化后的 y 不产生诊断。
        self.assertEqual(len(result2.diagnostics), 1)

    def test_branch_join_union(self):
        source = (
            "def main(){"
            " x = read_input();"
            " if (1 == 1) { y = x; } else { y = \"c\"; }"
            " exec(y);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.UNSAFE)
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertIn("join", kinds)

    def test_both_branches_tainted_join(self):
        source = (
            "def main(){"
            " x = read_input();"
            " if (x) { y = x; } else { y = x + 1; }"
            " exec(y);"
            "}"
        )
        self.assertIs(analyze_source(source).verdict, Verdict.UNSAFE)

    def test_both_branches_constant_is_safe(self):
        # 两个分支都只赋常量：汇合后干净。
        source = (
            "def main(){"
            " if (1) { y = \"a\"; } else { y = \"b\"; }"
            " exec(y);"
            "}"
        )
        self.assertIs(analyze_source(source).verdict, Verdict.SAFE)

    def test_recursion_is_incomplete_never_safe(self):
        source = (
            "def loop(n){"
            " if (n == 0) { return n; } else { return loop(n - 1); }"
            "}"
            "def main(){ v = loop(read_input()); exec(v); }"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertTrue(any("递归" in note for note in result.notes))
        self.assertTrue(any(d.severity == Severity.WARNING for d in result.diagnostics))

    def test_depth_limit_is_incomplete(self):
        source = (
            "def a(x){ return b(x); }"
            "def b(x){ return x; }"
            "def main(){ exec(a(read_input())); }"
        )
        result = analyze_source(source, AnalysisConfig(max_call_depth=0))
        self.assertIs(result.verdict, Verdict.INCOMPLETE)

    def test_depth_limit_allows_normal_result_within_budget(self):
        source = (
            "def a(x){ return b(x); }"
            "def b(x){ return x; }"
            "def main(){ exec(a(read_input())); }"
        )
        self.assertIs(
            analyze_source(source, AnalysisConfig(max_call_depth=5)).verdict,
            Verdict.UNSAFE,
        )

    def test_no_main_every_function_is_entry_params_clean(self):
        # 无 main：形参按干净数据，程序无 source 即 SAFE。
        self.assertIs(
            analyze_source("def f(x){ exec(x); }").verdict, Verdict.SAFE
        )

    def test_binary_propagation(self):
        source = (
            "def main(){"
            " x = read_input();"
            " y = x + \"suffix\";"
            " eval_sql(y);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.UNSAFE)
        self.assertEqual(result.diagnostics[0].sink, "eval_sql")

    def test_path_locations_point_back_to_source(self):
        source = "def main(){\n  x = read_input();\n  exec(x);\n}\n"
        result = analyze_source(source)
        hops = result.diagnostics[0].paths[0].hops
        self.assertEqual(hops[0].loc.line, 2)
        self.assertEqual(hops[-1].loc.line, 3)

    def test_call_graph(self):
        program = parse("def a(){ b(); } def b(){ c(); } def c(){ }")
        graph = build_call_graph(program)
        self.assertEqual(graph["a"], {"b"})
        self.assertEqual(graph["b"], {"c"})
        self.assertEqual(graph["c"], set())

    def test_parse_errors(self):
        result = analyze_source("def main( { }")
        self.assertIs(result.verdict, Verdict.PARSE_ERROR)
        with self.assertRaises(ParseError):
            parse("def 1() {}")
        with self.assertRaises(LexerError):
            parse("def main(){ x = @; }")

    def test_unknown_function_propagates_taint_conservatively(self):
        source = "def main(){ exec(mystery(read_input())); }"
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.UNSAFE)


if __name__ == "__main__":
    unittest.main()
