import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from taintlab import (
    AnalysisConfig,
    Evidence,
    ExternalSpec,
    LexerError,
    ParseError,
    Severity,
    Verdict,
    analyze_source,
    compare_external_specs,
    parse,
    revise_specs,
    snapshot_analysis,
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
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual([d.rule for d in result.diagnostics], ["TAINT-UNCERTAIN"])
        diagnostic = result.diagnostics[0]
        self.assertIs(diagnostic.evidence, Evidence.UNKNOWN)
        kinds = [h.kind for h in diagnostic.paths[0].hops]
        self.assertEqual(kinds, ["source", "unknown", "sink"])

    def test_conflicting_specs_traced_to_call_and_constraints(self):
        source = "def main(){ x = read_input(); y = lib(x); exec(y); }"
        config = AnalysisConfig(
            external_specs={
                "lib": ExternalSpec("lib", "v1 返回干净值", "clean", version="v1")
            },
            spec_alternatives=(
                ExternalSpec("lib", "v2 返回不可信值", "tainted", version="v2"),
            ),
        )
        result = analyze_source(source, config)
        self.assertEqual(len(result.conflicts), 1)
        conflict = result.conflicts[0]
        self.assertEqual(conflict.name, "lib")
        self.assertEqual((conflict.loc.line, conflict.loc.col), (1, 35))
        self.assertEqual(set(conflict.assumptions), {"lib@v1", "lib@v2"})
        self.assertTrue(any("干净值" in c for c in conflict.constraints))
        self.assertTrue(any("不可信值" in c for c in conflict.constraints))
        self.assertTrue(any("互斥" in note for note in result.notes))

    def test_contradictory_premise_yields_no_vacuous_safety(self):
        source = "def main(){ x = read_input(); y = lib(x); exec(y); }"
        config = AnalysisConfig(
            external_specs={
                "lib": ExternalSpec("lib", "v1 干净", "clean", version="v1")
            },
            spec_alternatives=(
                ExternalSpec("lib", "v2 不可信", "tainted", version="v2"),
            ),
        )
        result = analyze_source(source, config)
        self.assertIs(result.verdict, Verdict.ASSUMED)
        risk_scenarios = [s for s in result.scenarios if s.state == "risk"]
        self.assertEqual(len(risk_scenarios), 1)
        self.assertEqual(risk_scenarios[0].assumptions, ("lib@v2",))
        explanation = result.explanations[0]
        self.assertEqual(explanation.compatible_groups, (("lib@v2",),))
        self.assertEqual(explanation.infeasible_assumption_groups, ())

    def test_retracting_assumption_reopens_paths(self):
        source = "def main(){ x = read_input(); y = lib(x); exec(y); }"
        specs = {"lib": ExternalSpec("lib", "v1 干净", "clean", version="v1")}
        alts = (ExternalSpec("lib", "v2 不可信", "tainted", version="v2"),)
        base = AnalysisConfig(external_specs=specs, spec_alternatives=alts)
        self.assertEqual(len(analyze_source(source, base).conflicts), 1)
        withdrawn_v1 = analyze_source(
            source,
            AnalysisConfig(
                external_specs=specs,
                spec_alternatives=alts,
                disabled_assumptions={"lib@v1"},
            ),
        )
        self.assertEqual(withdrawn_v1.conflicts, ())
        self.assertEqual(
            [s.assumptions for s in withdrawn_v1.scenarios if s.state == "risk"],
            [("lib@v2",)],
        )
        withdrawn_v2 = analyze_source(
            source,
            AnalysisConfig(
                external_specs=specs,
                spec_alternatives=alts,
                disabled_assumptions={"lib@v2"},
            ),
        )
        self.assertEqual(withdrawn_v2.conflicts, ())
        self.assertEqual(
            [s.state for s in withdrawn_v2.scenarios], ["no_risk"]
        )

    def test_multiple_independent_conflicts_resolved_separately(self):
        source = (
            "def main(){ x = read_input(); y = lib(x); z = net(x);"
            " exec(y); eval_sql(z); }"
        )
        specs = {
            "lib": ExternalSpec("lib", "lib v1 干净", "clean", version="v1"),
            "net": ExternalSpec("net", "net v1 干净", "clean", version="v1"),
        }
        alts = (
            ExternalSpec("lib", "lib v2 不可信", "tainted", version="v2"),
            ExternalSpec("net", "net v2 不可信", "tainted", version="v2"),
        )
        _, snapshot = snapshot_analysis(
            source, AnalysisConfig(external_specs=specs, spec_alternatives=alts)
        )
        self.assertEqual(len(snapshot.conflicts), 2)
        new_specs = {
            "lib": ExternalSpec("lib", "lib v2 不可信", "tainted", version="v2"),
            "net": specs["net"],
        }
        result, report, _ = revise_specs(snapshot, new_specs)
        self.assertEqual(len(report.resolved_conflicts), 1)
        self.assertIn("net:1:47#net@v1|net@v2", report.remaining_conflicts)
        self.assertEqual(len(result.conflicts), 1)
        self.assertEqual(report.conflict_driven_conclusions, ("exec:1:55",))
        self.assertEqual(report.path_driven_conclusions, ())
        self.assertEqual(report.reused_conclusions, ("eval_sql:1:64",))

    def test_path_change_attributed_separately_from_conflict(self):
        source = "def main(){ x = read_input(); y = lib(x); exec(y); }"
        specs = {"lib": ExternalSpec("lib", "v1 干净", "clean", version="v1")}
        alts = (ExternalSpec("lib", "v2 不可信", "tainted", version="v2"),)
        _, snapshot = snapshot_analysis(
            source, AnalysisConfig(external_specs=specs, spec_alternatives=alts)
        )
        new_specs = {
            "lib": ExternalSpec("lib", "v3 不可信", "tainted", version="v3")
        }
        _, report, _ = revise_specs(snapshot, new_specs, spec_alternatives=())
        self.assertIn("exec:1:43", report.path_driven_conclusions)

    def test_same_hypothesis_at_different_call_instances_not_conflict(self):
        source = (
            "def main(){ x = read_input(); a = lib(x); b = lib(x);"
            " exec(a + b); }"
        )
        config = AnalysisConfig(
            external_specs={
                "lib": ExternalSpec("lib", "v1 干净", "clean", version="v1")
            },
            spec_alternatives=(
                ExternalSpec("lib", "v2 不可信", "tainted", version="v2"),
            ),
        )
        result = analyze_source(source, config)
        self.assertEqual(len(result.conflicts), 2)
        self.assertEqual(
            {c.conflict_id for c in result.conflicts},
            {"lib:1:35#lib@v1|lib@v2", "lib:1:47#lib@v1|lib@v2"},
        )
        explanation = result.explanations[0]
        self.assertEqual(explanation.scenario_only_groups, ())
        self.assertEqual(explanation.compatible_groups, (("lib@v2",),))

    def test_unknown_and_recursion_stay_undecidable_with_candidates(self):
        source = (
            "def main(){ x = read_input(); y = lib(x); z = mystery(x);"
            " exec(y); eval_sql(z); }"
        )
        config = AnalysisConfig(
            external_specs={
                "lib": ExternalSpec("lib", "v1 干净", "clean", version="v1")
            },
            spec_alternatives=(
                ExternalSpec("lib", "v2 不可信", "tainted", version="v2"),
            ),
        )
        result = analyze_source(source, config)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        states = {s.conclusion_id: s.state for s in result.scenarios}
        self.assertEqual(states["eval_sql:1:68"], "undecidable")
        self.assertEqual(states["exec:1:59"], "risk")

    def test_confirmed_and_constant_paths_unaffected_by_conflicts(self):
        source = (
            "def main(){ x = read_input(); y = lib(x);"
            " exec(\"ls\"); exec(x); eval_sql(y); }"
        )
        config = AnalysisConfig(
            external_specs={
                "lib": ExternalSpec("lib", "v1 干净", "clean", version="v1")
            },
            spec_alternatives=(
                ExternalSpec("lib", "v2 不可信", "tainted", version="v2"),
            ),
        )
        result = analyze_source(source, config)
        self.assertIs(result.verdict, Verdict.UNSAFE)
        states = {e.conclusion_id: e.state for e in result.explanations}
        self.assertEqual(states["exec:1:43"], "CONFIRMED_SAFE")
        self.assertEqual(states["exec:1:55"], "CONFIRMED_RISK")
        self.assertEqual(states["eval_sql:1:64"], "CONDITIONAL_RISK")
        self.assertEqual(len(result.conflicts), 1)

    def test_snapshot_roundtrip_preserves_conflicts_and_scenarios(self):
        source = "def main(){ x = read_input(); y = lib(x); exec(y); }"
        config = AnalysisConfig(
            external_specs={
                "lib": ExternalSpec("lib", "v1 干净", "clean", version="v1")
            },
            spec_alternatives=(
                ExternalSpec("lib", "v2 不可信", "tainted", version="v2"),
            ),
        )
        _, snapshot = snapshot_analysis(source, config)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "snap.json"
            snapshot.save(path)
            loaded = type(snapshot).load(path)
        self.assertEqual(
            [c.conflict_id for c in loaded.conflicts],
            [c.conflict_id for c in snapshot.conflicts],
        )
        self.assertEqual(
            [(s.scenario_id, s.state, s.assumptions) for s in loaded.scenarios],
            [(s.scenario_id, s.state, s.assumptions) for s in snapshot.scenarios],
        )
        self.assertEqual(loaded.alternatives, snapshot.alternatives)
        _, report, new_snapshot = revise_specs(
            loaded,
            {"lib": ExternalSpec("lib", "v2 不可信", "tainted", version="v2")},
        )
        self.assertEqual(len(report.old_snapshot.conflicts), 1)
        self.assertEqual(len(new_snapshot.conflicts), 0)

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

    def test_unknown_constant_arg_return_is_uncertain(self):
        result = analyze_source('def main(){ exec(mystery("ls")); }')
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual([d.rule for d in result.diagnostics], ["TAINT-UNCERTAIN"])

    def test_external_spec_clean_makes_verdict_assumed_and_records_dependency(self):
        source = "def main(){ token = get_token(); exec(token); }"
        cfg = AnalysisConfig(
            external_specs={
                "get_token": ExternalSpec(
                    "get_token",
                    "框架保证返回已编码的常量令牌",
                    returns="clean",
                    version="v1",
                )
            }
        )
        result = analyze_source(source, cfg)
        self.assertIs(result.verdict, Verdict.ASSUMED)
        self.assertEqual(result.diagnostics, [])
        self.assertEqual(result.assumptions[0].assumption_id, "get_token@v1")
        self.assertTrue(
            any("get_token@v1" in n for n in result.notes)
        )

    def test_external_spec_tainted_reports_assumed_flow(self):
        source = "def main(){ exec(fetch_url()); }"
        cfg = AnalysisConfig(
            external_specs={
                "fetch_url": ExternalSpec(
                    "fetch_url", "读取网络响应", returns="tainted", version="v2"
                )
            }
        )
        result = analyze_source(source, cfg)
        self.assertIs(result.verdict, Verdict.ASSUMED)
        self.assertEqual(result.diagnostics[0].rule, "TAINT-ASSUMED")
        self.assertEqual(result.diagnostics[0].assumptions, ("fetch_url@v2",))

    def test_external_spec_propagate(self):
        safe_cfg = AnalysisConfig(
            external_specs={"echo": ExternalSpec("echo", "原样返回实参")}
        )
        self.assertIs(
            analyze_source('def main(){ exec(echo("ls")); }', safe_cfg).verdict,
            Verdict.ASSUMED,
        )
        unsafe = analyze_source(
            "def main(){ exec(echo(read_input())); }", safe_cfg
        )
        self.assertIs(unsafe.verdict, Verdict.ASSUMED)
        self.assertEqual(unsafe.diagnostics[0].rule, "TAINT-ASSUMED")

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
        # 两条路径都经过缺少说明的外部调用，均不能冒充已证实风险。
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual({d.rule for d in result.diagnostics}, {"TAINT-UNCERTAIN"})

    def test_unknown_external_does_not_taint_unrelated_constant_sink(self):
        source = 'def main(){ token = get_token(); exec("ls"); }'
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual(result.diagnostics, [])

    def test_unknown_tainted_arg_branch_join_is_uncertain(self):
        source = (
            "def main(){"
            " x = read_input();"
            " if (1) { v = mystery(x); } else { v = \"c\"; }"
            " exec(v);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual([d.rule for d in result.diagnostics], ["TAINT-UNCERTAIN"])
        kinds = [h.kind for h in result.diagnostics[0].paths[0].hops]
        self.assertEqual(
            kinds,
            ["source", "assign", "unknown", "assign", "join", "sink"],
        )

    def test_confirmed_and_unknown_branches_remain_separate_after_join(self):
        source = (
            "def main(){"
            " x = read_input();"
            " if (1) { v = x; } else { v = get_token(); }"
            " exec(v);"
            "}"
        )
        result = analyze_source(source)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertEqual(
            sorted(d.rule for d in result.diagnostics),
            ["TAINT-FLOW", "TAINT-UNCERTAIN"],
        )

    def test_external_spec_version_comparison_withdraws_only_matching_assumption(self):
        old = {
            "a": ExternalSpec("a", "旧说明 A", returns="clean", version="1"),
            "b": ExternalSpec("b", "旧说明 B", returns="tainted", version="7"),
        }
        new = {
            "a": ExternalSpec("a", "新说明 A", returns="tainted", version="2"),
        }
        changes = compare_external_specs(old, new)
        by_name = {change.name: change for change in changes}
        self.assertEqual(by_name["a"].status, "changed")
        self.assertEqual(
            by_name["a"].changed_fields,
            ("version", "returns", "description"),
        )
        self.assertEqual(by_name["b"].status, "withdrawn")
        self.assertEqual(by_name["a"].invalidated_assumptions, ("a@1",))
        self.assertEqual(by_name["b"].invalidated_assumptions, ("b@7",))

    def test_withdrawn_spec_matches_only_diagnostics_using_it(self):
        cfg = AnalysisConfig(
            external_specs={
                "fetch_a": ExternalSpec("fetch_a", "A", returns="tainted", version="1"),
                "fetch_b": ExternalSpec("fetch_b", "B", returns="tainted", version="9"),
            }
        )
        result = analyze_source(
            "def main(){ exec(fetch_a()); exec(fetch_b()); }", cfg
        )
        changes = compare_external_specs(
            cfg.external_specs,
            {"fetch_a": cfg.external_specs["fetch_a"]},
        )
        invalid = {aid for change in changes for aid in change.invalidated_assumptions}
        affected = [d for d in result.diagnostics if set(d.assumptions) & invalid]
        self.assertEqual([d.assumptions[0] for d in affected], ["fetch_b@9"])

    def test_safe_constant_path_has_independent_conclusion(self):
        result = analyze_source('def main(){ exec("ls"); }')
        explanation = result.explanations[0]
        self.assertEqual(explanation.state, "CONFIRMED_SAFE")
        self.assertEqual(explanation.path_explanations[0].kind, "safe")
        self.assertEqual(explanation.assumption_groups, ())

    def test_disabling_assumption_moves_conditional_risk_to_unknown(self):
        cfg = AnalysisConfig(
            external_specs={
                "fetch": ExternalSpec("fetch", "网络输入", returns="tainted", version="1")
            }
        )
        enabled = analyze_source("def main(){ exec(fetch()); }", cfg)
        self.assertEqual(enabled.explanations[0].state, "CONDITIONAL_RISK")
        disabled = analyze_source(
            "def main(){ exec(fetch()); }",
            AnalysisConfig(
                external_specs=cfg.external_specs,
                disabled_assumptions={"fetch@1"},
            ),
        )
        self.assertIs(disabled.verdict, Verdict.INCOMPLETE)
        self.assertEqual(disabled.explanations[0].state, "UNKNOWN_RISK")

    def test_minimal_assumptions_distinguish_common_from_alternative_paths(self):
        source = (
            "def main(){"
            " x = read_input();"
            " if (1) { v = encode(x); } else { v = relay(x); }"
            " exec(v);"
            "}"
        )
        cfg = AnalysisConfig(
            external_specs={
                "encode": ExternalSpec("encode", "编码但保留污点", version="1"),
                "relay": ExternalSpec("relay", "转发", version="2"),
            }
        )
        explanation = analyze_source(source, cfg).explanations[0]
        self.assertEqual(
            explanation.assumption_groups,
            (("encode@1",), ("relay@2",)),
        )
        self.assertEqual(explanation.common_assumptions, ())
        self.assertEqual(explanation.indispensable_assumptions, ())

    def test_shared_assumption_is_indispensable_across_alternatives(self):
        source = (
            "def main(){"
            " x = read_input();"
            " if (1) { v = safe_lib(x); } else { v = safe_lib(x); }"
            " exec(v);"
            "}"
        )
        cfg = AnalysisConfig(
            external_specs={
                "safe_lib": ExternalSpec("safe_lib", "库保持污点语义", version="9"),
                "encode": ExternalSpec("encode", "编码", version="1"),
                "relay": ExternalSpec("relay", "转发", version="2"),
            }
        )
        explanation = analyze_source(source, cfg).explanations[0]
        self.assertEqual(explanation.assumption_groups, (("safe_lib@9",),))
        self.assertEqual(explanation.common_assumptions, ("safe_lib@9",))
        self.assertEqual(
            explanation.indispensable_assumptions, ("safe_lib@9",)
        )

    def test_safe_branch_remains_independent_when_other_branch_is_unknown(self):
        source = (
            "def main(){"
            " if (1) { v = \"safe\"; } else { v = mystery(); }"
            " exec(v);"
            "}"
        )
        explanation = analyze_source(source).explanations[0]
        self.assertEqual(explanation.state, "UNKNOWN_RISK")
        kinds = {item.kind for item in explanation.path_explanations}
        self.assertEqual(kinds, {"risk", "safe"})

    def test_snapshot_revision_reuses_unrelated_conclusion(self):
        source = (
            "def main(){"
            " exec(fetch_a());"
            ' exec("ls");'
            "}"
        )
        cfg = AnalysisConfig(
            external_specs={
                "fetch_a": ExternalSpec("fetch_a", "A", returns="tainted", version="1")
            }
        )
        _, snapshot = snapshot_analysis(source, cfg)
        new_result, report, new_snapshot = revise_specs(
            snapshot,
            {
                "fetch_a": ExternalSpec(
                    "fetch_a", "A changed", returns="clean", version="2"
                )
            },
        )
        self.assertIn("exec:1:13", report.affected_conclusions)
        self.assertIn("exec:1:30", report.reused_conclusions)
        self.assertEqual(
            {item.conclusion_id for item in new_snapshot.explanations},
            {item.conclusion_id for item in snapshot.explanations},
        )
        self.assertIs(new_result.verdict, Verdict.ASSUMED)

        with TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "research.json"
            snapshot.save(snapshot_path)
            loaded = type(snapshot).load(snapshot_path)
            self.assertEqual(loaded.source, snapshot.source)
            self.assertEqual(
                tuple(item.conclusion_id for item in loaded.explanations),
                tuple(item.conclusion_id for item in snapshot.explanations),
            )


if __name__ == "__main__":
    unittest.main()
