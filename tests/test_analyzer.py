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
        # 无说明的未知调用：实参污点仍保守传播到返回值，但调用本身语义未知，
        # 结论只能是 INCOMPLETE（诊断含确认污点路径，但整体不夸大为已确认漏洞）。
        source = "def main(){ exec(mystery(read_input())); }"
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertTrue(any(d.severity == Severity.WARNING for d in result.diagnostics))
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertIn("source", kinds)

    def test_unknown_zero_arg_return_is_not_clean(self):
        # 未知函数无参调用的返回值不能当作干净数据。
        source = "def main(){ x = mystery(); exec(x); }"
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual(len(result.diagnostics), 1)
        self.assertEqual(result.diagnostics[0].severity, Severity.WARNING)
        self.assertEqual(result.diagnostics[0].rule, "TAINT-UNCERTAIN")
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertEqual(kinds, ["unknown", "assign", "sink"])
        self.assertTrue(any("缺少行为说明" in note for note in result.notes))

    def test_unknown_call_without_spec_never_safe(self):
        # 即使返回值没有流入 sink，缺少说明的未知调用也不得判 SAFE。
        source = 'def main(){ mystery(); exec("ls"); }'
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual(result.diagnostics, [])

    def test_unknown_return_sanitized_branch_join_still_incomplete(self):
        # 未知返回值经净化、分支汇合后 sink 无污点，但未知调用本身
        # 缺少说明，结论仍不得是无依据的 SAFE。
        source = (
            "def main(){"
            " x = mystery();"
            " y = sanitize(x);"
            " if (1 == 1) { z = y; } else { z = \"c\"; }"
            " exec(z);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual(result.diagnostics, [])

    def test_unknown_return_with_taint_join_at_sink(self):
        # 未知返回值与确认污点在分支汇合后一起到达 sink：
        # 路径混入不确定事实，不夸大为已确认漏洞：WARNING + INCOMPLETE。
        source = (
            "def main(){"
            " a = read_input();"
            " b = mystery();"
            " if (1 == 1) { z = a; } else { z = b; }"
            " exec(z);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertTrue(any(d.severity == Severity.WARNING for d in result.diagnostics))

    def test_external_spec_clean_allows_safe_and_records_assumption(self):
        source = "def main(){ x = mystery(); exec(x); }"
        result = analyze_source(
            source, AnalysisConfig(external_specs={"mystery": "clean"})
        )
        self.assertIs(result.verdict, Verdict.SAFE)
        self.assertEqual(result.diagnostics, [])
        self.assertEqual(len(result.assumptions), 1)
        self.assertIn("mystery", result.assumptions[0])
        self.assertIn("clean", result.assumptions[0])

    def test_external_spec_tainted_reports_flow(self):
        source = "def main(){ x = mystery(); exec(x); }"
        result = analyze_source(
            source, AnalysisConfig(external_specs={"mystery": "tainted"})
        )
        self.assertIs(result.verdict, Verdict.UNSAFE)
        self.assertEqual(result.diagnostics[0].rule, "TAINT-FLOW")
        self.assertTrue(result.assumptions)

    def test_external_spec_propagate_keeps_conservative_taint(self):
        source = "def main(){ exec(mystery(read_input())); }"
        result = analyze_source(
            source, AnalysisConfig(external_specs={"mystery": "propagate"})
        )
        self.assertIs(result.verdict, Verdict.UNSAFE)
        self.assertTrue(result.assumptions)

    def test_external_spec_invalid_behavior_rejected(self):
        with self.assertRaises(ValueError):
            AnalysisConfig(external_specs={"mystery": "magic"})


if __name__ == "__main__":
    unittest.main()
