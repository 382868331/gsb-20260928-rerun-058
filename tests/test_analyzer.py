import unittest
from dataclasses import replace
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
    study_scenarios,
    revise_study,
    NamedScenario,
)
from taintlab.analyzer import ExternalSpecScope
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


class ScopedExternalSpecTests(unittest.TestCase):
    SOURCE = (
        "def main(){"
        " x = read_input();"
        " a = lib(x); b = lib(x);"
        " exec(a); eval_sql(b);"
        "}"
    )

    def config(self):
        return AnalysisConfig(
            external_specs=(
                ExternalSpec(
                    "lib", "第一处使用旧版净化", "clean",
                    version="v1",
                    scope=ExternalSpecScope.call_site(1, 35),
                ),
                ExternalSpec(
                    "lib", "第二处使用新版转发", "propagate",
                    version="v2",
                    scope=ExternalSpecScope.call_site(1, 47),
                ),
            )
        )

    def test_same_library_can_use_different_versions_by_call_site(self):
        result = analyze_source(self.SOURCE, self.config())
        states = {e.conclusion_id: e.state for e in result.explanations}
        self.assertEqual(states["exec:1:55"], "CONDITIONALLY_SAFE")
        self.assertEqual(states["eval_sql:1:64"], "CONDITIONAL_RISK")
        diagnostic = next(d for d in result.diagnostics if d.loc.col == 64)
        self.assertEqual(diagnostic.assumptions, ("lib@v2[call::1:47]",))
        records = {r.assumption_id: r for r in result.assumptions}
        self.assertEqual(records["lib@v1[call::1:35]"].scope, "call::1:35")
        self.assertEqual(records["lib@v2[call::1:47]"].scope, "call::1:47")
        self.assertEqual(result.conflicts, ())

    def test_unknown_call_does_not_inherit_nearby_sanitization(self):
        source = (
            "def main(){"
            " x = read_input(); a = lib(x); b = lib(x);"
            " exec(a); eval_sql(b);"
            "}"
        )
        config = AnalysisConfig(
            external_specs=(
                ExternalSpec(
                    "lib", "只有第一处净化", "clean",
                    version="v1",
                    scope=ExternalSpecScope.call_site(1, 35),
                ),
            )
        )
        result = analyze_source(source, config)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        states = {e.conclusion_id: e.state for e in result.explanations}
        self.assertEqual(states["exec:1:55"], "CONDITIONALLY_SAFE")
        self.assertEqual(states["eval_sql:1:64"], "UNKNOWN_RISK")

    def test_file_scope_overrides_global_spec_for_entire_file(self):
        config = AnalysisConfig(
            external_specs=(
                ExternalSpec("lib", "全局净化", "clean", version="v1"),
                ExternalSpec(
                    "lib", "本文件转发", "propagate", version="v2",
                    scope=ExternalSpecScope.file(),
                ),
            )
        )
        result = analyze_source(self.SOURCE, config)
        self.assertIs(result.verdict, Verdict.ASSUMED)
        self.assertEqual(
            sorted({a for d in result.diagnostics for a in d.assumptions}),
            ["lib@v2[file:]"],
        )
        self.assertEqual(
            sorted(r.assumption_id for r in result.assumptions),
            ["lib@v2[file:]"],
        )

    def test_local_retraction_does_not_remove_other_call_site_basis(self):
        local_id = "lib@v1[call::1:35]"
        config = replace(self.config(), disabled_assumptions=frozenset({local_id}))
        result = analyze_source(self.SOURCE, config)
        states = {e.conclusion_id: e.state for e in result.explanations}
        self.assertEqual(states["exec:1:55"], "UNKNOWN_RISK")
        self.assertEqual(states["eval_sql:1:64"], "CONDITIONAL_RISK")
        self.assertEqual(
            [r.assumption_id for r in result.assumptions],
            ["lib@v2[call::1:47]"],
        )

    def test_scoped_conflict_is_checked_only_at_intersecting_call(self):
        config = AnalysisConfig(
            external_specs=(
                ExternalSpec(
                    "lib", "第一处旧版净化", "clean", "v1",
                    scope=ExternalSpecScope.call_site(1, 35),
                ),
            ),
            spec_alternatives=(
                ExternalSpec(
                    "lib", "第一处新版不可信", "tainted", "v2",
                    scope=ExternalSpecScope.call_site(1, 35),
                ),
                ExternalSpec(
                    "lib", "第二处旧版转发", "propagate", "v1",
                    scope=ExternalSpecScope.call_site(1, 47),
                ),
            ),
        )
        scenario = NamedScenario(
            "mixed", "不同位置采用各自版本",
            (
                "lib@v2[call::1:35]",
                "lib@v1[call::1:47]",
            ),
        )
        study = study_scenarios(self.SOURCE, (scenario,), config)
        evaluated = study.by_name("mixed")
        self.assertTrue(evaluated.feasible)
        self.assertEqual(evaluated.minimal_conflicts, ())
        self.assertEqual(
            {c.sink_id: c.state for c in evaluated.sink_conclusions},
            {
                "exec:1:55": "conditional_risk",
                "eval_sql:1:64": "conditional_risk",
            },
        )

    def test_compare_and_reload_preserve_local_and_global_basis(self):
        old_config = self.config()
        _, snapshot = snapshot_analysis(self.SOURCE, old_config)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scoped.json"
            snapshot.save(path)
            loaded = type(snapshot).load(path)

        self.assertEqual(loaded.specs, snapshot.specs)
        new_specs = (
            replace(snapshot.specs[0], description="第一处更新后的净化"),
            snapshot.specs[1],
        )
        changes = compare_external_specs(loaded.specs, new_specs)
        changed = next(c for c in changes if c.status == "changed")
        self.assertEqual(
            changed.invalidated_assumptions,
            ("lib@v1[call::1:35]",),
        )
        _, report, new_snapshot = revise_specs(loaded, new_specs)
        self.assertIn("exec:1:55", report.affected_conclusions)
        self.assertIn("eval_sql:1:64", report.reused_conclusions)
        self.assertEqual(new_snapshot.specs[1], snapshot.specs[1])

    def test_reload_compares_global_spec_with_local_override(self):
        global_config = AnalysisConfig(
            external_specs=(
                ExternalSpec("lib", "全局净化", "clean", version="v1"),
            )
        )
        _, snapshot = snapshot_analysis(self.SOURCE, global_config)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "global-to-local.json"
            snapshot.save(path)
            loaded = type(snapshot).load(path)

        local_override = (
            ExternalSpec(
                "lib", "第一处改为不可信", "tainted", "v2",
                scope=ExternalSpecScope.call_site(1, 35),
            ),
        )
        result, report, _ = revise_specs(loaded, local_override)
        states = {e.conclusion_id: e.state for e in result.explanations}
        self.assertEqual(states["exec:1:55"], "CONDITIONAL_RISK")
        self.assertEqual(states["eval_sql:1:64"], "UNKNOWN_RISK")
        self.assertEqual(
            sorted(report.affected_conclusions),
            ["eval_sql:1:64", "exec:1:55"],
        )


class NamedScenarioStudyTests(unittest.TestCase):
    """命名联合情景：共享外部返回、冲突清洗说明与局部撤销的构造案例。

    两个输出点 exec(u)/eval_sql(u) 共享同一次外部返回 relay(x)，
    另有一个完全没有说明的外部调用 mystery()，用于区分“未知外部返回”
    与“没有可行情景”两种状态。
    """

    SOURCE = (
        "def main(){"
        " x = read_input();"
        " u = relay(x);"
        " m = mystery();"
        " exec(u);"
        " eval_sql(u);"
        " exec(m);"
        "}"
    )

    def config(self, disabled=()):
        return AnalysisConfig(
            external_specs={
                "relay": ExternalSpec(
                    "relay", "旧版本：转发并保留污点",
                    returns="propagate", version="v1",
                )
            },
            spec_alternatives=(
                ExternalSpec(
                    "relay", "新版本：内部净化，返回干净值",
                    returns="clean", version="v2",
                ),
            ),
            disabled_assumptions=frozenset(disabled),
        )

    def scenarios(self):
        return (
            NamedScenario(
                "old-relay",
                "沿用转发语义 v1",
                ("relay@v1",),
            ),
            NamedScenario(
                "new-relay",
                "采用净化语义 v2",
                ("relay@v2",),
            ),
            NamedScenario(
                "both-relay",
                "同时采用两版互斥说明（构造的不可行情景）",
                ("relay@v1", "relay@v2"),
            ),
        )

    def test_shared_return_risk_is_scoped_to_scenario_and_version(self):
        study = study_scenarios(self.SOURCE, self.scenarios(), self.config())

        old = study.by_name("old-relay")
        new = study.by_name("new-relay")
        self.assertTrue(old.feasible and new.feasible)

        # 旧版本下两个共享同一返回值的输出点都是条件风险，路径必须注明
        # 情景名称与说明版本，结论不得扩展到其它备选。
        old_states = {c.sink_id: c.state for c in old.sink_conclusions}
        self.assertEqual(old_states["exec:1:60"], "conditional_risk")
        self.assertEqual(old_states["eval_sql:1:69"], "conditional_risk")
        for sink_id in ("exec:1:60", "eval_sql:1:69"):
            conclusion = next(
                c for c in old.sink_conclusions if c.sink_id == sink_id
            )
            self.assertTrue(conclusion.risk_explanations)
            for item in conclusion.risk_explanations:
                self.assertEqual(item.scenario, "old-relay")
                self.assertEqual(item.assumptions, ("relay@v1",))

        # 新版本（清洗）下同样两个输出点无风险；该无风险结论只属于
        # new-relay 情景，不会扩展到旧版本。
        new_states = {c.sink_id: c.state for c in new.sink_conclusions}
        self.assertEqual(new_states["exec:1:60"], "no_risk")
        self.assertEqual(new_states["eval_sql:1:69"], "no_risk")

    def test_contradictory_scenario_has_minimal_conflict_and_others_survive(self):
        study = study_scenarios(self.SOURCE, self.scenarios(), self.config())
        both = study.by_name("both-relay")

        # 不可行情景给出最小冲突依据（relay 那一次调用上的 v1|v2 互斥）。
        self.assertFalse(both.feasible)
        self.assertEqual(len(both.minimal_conflicts), 1)
        conflict = both.minimal_conflicts[0]
        self.assertEqual(conflict.name, "relay")
        self.assertEqual(set(conflict.assumptions), {"relay@v1", "relay@v2"})
        # 不可行情景不产生 sink 结论；其它情景仍然保留、可行。
        self.assertEqual(both.sink_conclusions, ())
        self.assertEqual(
            {item.scenario.name for item in study.results if item.feasible},
            {"old-relay", "new-relay"},
        )

    def test_no_feasible_scenario_is_incomplete_not_safe(self):
        # 唯一的联合情景自相矛盾：没有任何可行备选时研究总判 INCOMPLETE，
        # 与“存在未知外部返回”区分，也绝不能归成 SAFE。
        only_contradictory = (
            NamedScenario(
                "both-relay", "两版同时采用",
                ("relay@v1", "relay@v2"),
            ),
        )
        study = study_scenarios(
            self.SOURCE, only_contradictory, self.config()
        )
        self.assertEqual(study.verdict, "INCOMPLETE")
        self.assertFalse(study.by_name("both-relay").feasible)

    def test_unknown_external_return_is_undecidable_even_when_relay_clean(self):
        # mystery() 没有任何说明：未知外部返回与“无可行情景”是不同状态，
        # 即使 relay 取清洗版本，exec(m) 仍无法判定，不能归成安全。
        study = study_scenarios(self.SOURCE, self.scenarios(), self.config())
        new = study.by_name("new-relay")
        mystery = next(
            c for c in new.sink_conclusions if c.sink_id == "exec:1:82"
        )
        self.assertEqual(mystery.state, "undecidable")
        self.assertIs(new.verdict, "INCOMPLETE")

        # 旧版本既有条件风险又有未知项：风险与未知都不被对方掩盖。
        old = study.by_name("old-relay")
        old_states = {c.sink_id: c.state for c in old.sink_conclusions}
        self.assertEqual(old_states["exec:1:60"], "conditional_risk")
        self.assertEqual(old_states["exec:1:82"], "undecidable")
        # 存在未知项时情景总判为 INCOMPLETE，而非 ASSUMED/SAFE。
        self.assertEqual(old.verdict, "INCOMPLETE")

    def test_partial_retraction_resolves_only_one_of_independent_conflicts(self):
        # 两个独立调用点各自存在一对冲突；撤销一条说明只解除涉及它的
        # 那一组冲突，另一组保留，情景由不可行转为部分可行。
        source = (
            "def main(){"
            " x = read_input();"
            " a = relay(x); b = relay(x);"
            " exec(a); eval_sql(b);"
            "}"
        )
        scenarios = (
            NamedScenario("both", "两版同时采用", ("relay@v1", "relay@v2")),
        )
        study = study_scenarios(source, scenarios, self.config())
        self.assertFalse(study.by_name("both").feasible)
        self.assertEqual(
            len(study.by_name("both").minimal_conflicts), 2
        )

        # 局部撤销 v1：两个调用点上的 v1|v2 冲突都涉及 v1，故全部解除。
        retracted = study_scenarios(
            source,
            scenarios,
            self.config(disabled={"relay@v1"}),
        )
        result = retracted.by_name("both")
        self.assertTrue(result.feasible)
        self.assertEqual(result.minimal_conflicts, ())

    def test_retracting_one_spec_leaves_independent_conflict_intact(self):
        # 一个情景内包含两组相互独立的矛盾（lib 与 net 各一对）；
        # 只撤销 lib@v1 时 lib 的冲突消失，net 的冲突仍在，情景仍不可行。
        source = (
            "def main(){"
            " x = read_input(); y = lib(x); z = net(x);"
            " exec(y); eval_sql(z);"
            "}"
        )
        config = AnalysisConfig(
            external_specs={
                "lib": ExternalSpec("lib", "lib 干净", "clean", version="v1"),
                "net": ExternalSpec("net", "net 干净", "clean", version="v1"),
            },
            spec_alternatives=(
                ExternalSpec("lib", "lib 不可信", "tainted", version="v2"),
                ExternalSpec("net", "net 不可信", "tainted", version="v2"),
            ),
        )
        scenario = NamedScenario(
            "all", "同时采用四个版本",
            ("lib@v1", "lib@v2", "net@v1", "net@v2"),
        )
        study = study_scenarios(source, (scenario,), config)
        before = study.by_name("all")
        self.assertFalse(before.feasible)
        self.assertEqual(
            sorted(c.name for c in before.minimal_conflicts), ["lib", "net"]
        )

        # 局部撤销 lib@v1：该说明不再参与，lib 冲突被解除，net 冲突保留。
        disabled_config = AnalysisConfig(
            external_specs=config.external_specs,
            spec_alternatives=config.spec_alternatives,
            disabled_assumptions={"lib@v1"},
        )
        remaining_scenario = NamedScenario(
            "all-minus-lib-v1",
            "撤销 lib@v1 后剩余说明",
            ("lib@v2", "net@v1", "net@v2"),
        )
        after = study_scenarios(
            source, (remaining_scenario,), disabled_config
        ).by_name("all-minus-lib-v1")
        self.assertFalse(after.feasible)
        self.assertEqual(
            [c.name for c in after.minimal_conflicts], ["net"]
        )
        self.assertEqual(
            set(after.minimal_conflicts[0].assumptions),
            {"net@v1", "net@v2"},
        )

    def test_revise_study_keeps_old_query_basis_and_reprojects_new(self):
        study = study_scenarios(self.SOURCE, self.scenarios(), self.config())
        # 旧查询保持原依据：旧情景中 relay@v1 是条件风险。
        self.assertEqual(
            study.by_name("old-relay").sink_conclusions[0].state,
            "conditional_risk",
        )

        # 派生比较研究：把 relay 修订为新的净化版本 v3，候选不再含冲突。
        new_specs = {
            "relay": ExternalSpec(
                "relay", "修订版：净化", returns="clean", version="v3"
            )
        }
        new_scenarios = (
            NamedScenario("revised-relay", "修订后的净化情景", ("relay@v3",)),
        )
        _, revised = revise_study(
            study,
            new_specs=new_specs,
            scenarios=new_scenarios,
            spec_alternatives=(),
        )
        revised_result = revised.by_name("revised-relay")
        self.assertTrue(revised_result.feasible)
        revised_states = {
            c.sink_id: c.state for c in revised_result.sink_conclusions
        }
        self.assertEqual(revised_states["exec:1:60"], "no_risk")
        self.assertEqual(revised_states["eval_sql:1:69"], "no_risk")
        # 未知返回 mystery() 不随说明修订被补成安全。
        self.assertEqual(revised_states["exec:1:82"], "undecidable")
        # 旧研究对象未被修改，仍可单独回看原依据。
        self.assertEqual(
            study.by_name("old-relay").sink_conclusions[0].state,
            "conditional_risk",
        )
        self.assertIn("relay@v1", study.by_name("both-relay").scenario.assumptions)

    def test_study_json_roundtrip_preserves_scenario_basis(self):
        study = study_scenarios(self.SOURCE, self.scenarios(), self.config())
        with TemporaryDirectory() as directory:
            path = Path(directory) / "study.json"
            study.save(path)
            loaded = type(study).load(path)
            self.assertEqual(
                [s.name for s in loaded.scenarios],
                [s.name for s in study.scenarios],
            )
            old = loaded.by_name("old-relay")
            conclusion = next(
                c for c in old.sink_conclusions if c.sink_id == "exec:1:60"
            )
            self.assertEqual(conclusion.state, "conditional_risk")
            self.assertEqual(
                conclusion.risk_explanations[0].scenario, "old-relay"
            )
            self.assertEqual(
                conclusion.risk_explanations[0].assumptions, ("relay@v1",)
            )
            both = loaded.by_name("both-relay")
            self.assertFalse(both.feasible)
            self.assertEqual(len(both.minimal_conflicts), 1)


if __name__ == "__main__":
    unittest.main()
