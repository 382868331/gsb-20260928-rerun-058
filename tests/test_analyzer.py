import unittest

from taintlab import (
    AnalysisConfig,
    ExternalSpec,
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
        self.assertTrue(any(d.rule == "TAINT-FLOW" for d in result.diagnostics))

    def test_unknown_zero_arg_return_to_sink_is_not_safe(self):
        # 回归：无参数的未知函数返回值曾被当成干净数据，导致漏报。
        source = "def main(){ token = get_token(); exec(token); }"
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual(
            [d.rule for d in result.diagnostics], ["TAINT-UNCERTAIN"]
        )
        self.assertTrue(
            any("缺少行为说明" in n for n in result.notes)
        )
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertIn("unknown", kinds)
        self.assertEqual(kinds[-1], "sink")

    def test_unknown_zero_arg_return_unused_is_still_incomplete(self):
        # 仅出现未知调用（未流入 sink）也不能输出无依据的 SAFE。
        result = analyze_source("def main(){ x = get_token(); } def f(){ helper(); }")
        self.assertIs(result.verdict, Verdict.INCOMPLETE)

    def test_external_spec_clean_makes_verdict_safe_and_records_dependency(self):
        source = "def main(){ token = get_token(); exec(token); }"
        cfg = AnalysisConfig(
            external_specs={
                "get_token": ExternalSpec(
                    "get_token", "框架保证返回已编码的常量令牌", returns="clean"
                )
            }
        )
        result = analyze_source(source, cfg)
        self.assertIs(result.verdict, Verdict.SAFE)
        self.assertEqual(result.diagnostics, [])
        self.assertTrue(
            any("依赖以下外部调用行为说明" in n and "get_token" in n for n in result.notes)
        )

    def test_external_spec_tainted_reports_confirmed_flow(self):
        source = "def main(){ exec(fetch_url()); }"
        cfg = AnalysisConfig(
            external_specs={
                "fetch_url": ExternalSpec("fetch_url", "读取网络响应", returns="tainted")
            }
        )
        result = analyze_source(source, cfg)
        self.assertIs(result.verdict, Verdict.UNSAFE)
        self.assertEqual(result.diagnostics[0].rule, "TAINT-FLOW")

    def test_external_spec_propagate(self):
        safe_cfg = AnalysisConfig(
            external_specs={"echo": ExternalSpec("echo", "原样返回实参")}
        )
        self.assertIs(
            analyze_source('def main(){ exec(echo("ls")); }', safe_cfg).verdict,
            Verdict.SAFE,
        )
        unsafe = analyze_source(
            "def main(){ exec(echo(read_input())); }", safe_cfg
        )
        self.assertIs(unsafe.verdict, Verdict.UNSAFE)

    def test_unknown_return_through_sanitized_branch_join(self):
        # 未知返回值：净化分支与污点分支合流，仍应识别合流后的风险与未知性。
        source = (
            "def main(){"
            " raw = read_input();"
            " if (1) { v = sanitize(raw); } else { v = get_token(); }"
            " exec(v);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        rules = {d.rule for d in result.diagnostics}
        self.assertEqual(rules, {"TAINT-UNCERTAIN"})
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertIn("join", kinds)

    def test_sanitized_branch_vs_tainted_branch_join_still_unsafe(self):
        source = (
            "def main(){"
            " raw = read_input();"
            " if (1) { v = sanitize(raw); } else { v = raw; }"
            " exec(v);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.UNSAFE)
        self.assertEqual(result.diagnostics[0].rule, "TAINT-FLOW")

    def test_confirmed_and_uncertain_paths_reported_separately(self):
        source = (
            "def main(){"
            " exec(mystery(read_input()));"
            " exec(get_token());"
            "}"
        )
        result = analyze_source(source)
        # get_token 无说明使整体结论 INCOMPLETE；已证实风险仍以 TAINT-FLOW 呈现。
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        rules = {d.rule for d in result.diagnostics}
        self.assertEqual(rules, {"TAINT-FLOW", "TAINT-UNCERTAIN"})
        severities = {d.severity for d in result.diagnostics}
        self.assertEqual(len(severities), 2)


if __name__ == "__main__":
    unittest.main()
