"""互斥行为假设与情景分析的回归测试。"""

import unittest

from taintlab import (
    AnalysisConfig,
    BehaviorHypothesis,
    Verdict,
    analyze_source,
    revise_specs,
    snapshot_analysis,
)


def hyp(name, returns, site=None, hid=None):
    return BehaviorHypothesis(
        name, returns, description=f"{name} 的假设", site=site, hypothesis_id=hid
    )


SHARED_CALL = "def main(){ x = read_input(); y = fetch(x); exec(y); }"


class ConflictDetectionTests(unittest.TestCase):
    def test_shared_call_conflict_recorded_with_constraints(self):
        result = analyze_source(
            SHARED_CALL,
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "tainted", hid="h_tainted"),
                )
            ),
        )
        self.assertEqual(len(result.conflicts), 1)
        conflict = result.conflicts[0]
        self.assertEqual(conflict.call, "fetch")
        self.assertEqual(set(conflict.hypotheses), {"h_clean", "h_tainted"})
        # 最小依据可追到具体调用位置与两条互斥约束。
        self.assertEqual((conflict.loc.line, conflict.loc.col), (1, 35))
        self.assertTrue(any("returns=clean" in c for c in conflict.constraints))
        self.assertTrue(any("returns=tainted" in c for c in conflict.constraints))

    def test_scenarios_split_feasible_risk_and_no_risk(self):
        result = analyze_source(
            SHARED_CALL,
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "tainted", hid="h_tainted"),
                )
            ),
        )
        scenarios = {s.scenario_id: s for s in result.scenarios}
        self.assertEqual(scenarios["ALL"].state, "CONTRADICTORY")
        self.assertEqual(len(scenarios["ALL"].conflicts), 1)
        by_hyp = {
            s.hypotheses: s.state
            for s in result.scenarios
            if s.scenario_id != "ALL"
        }
        self.assertEqual(by_hyp[("h_clean",)], "NO_RISK_FOUND")
        self.assertEqual(by_hyp[("h_tainted",)], "FEASIBLE_RISK")

    def test_conflict_without_remaining_paths_is_not_safe(self):
        # 冲突存在、但没有可行风险路径时，不得给出空洞的安全结论。
        source = "def main(){ y = fetch(\"c\"); exec(\"ls\"); }"
        result = analyze_source(
            source,
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "tainted", hid="h_tainted"),
                )
            ),
        )
        self.assertIsNot(result.verdict, Verdict.SAFE)
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertTrue(any("互斥" in note for note in result.notes))

    def test_confirmed_risk_survives_conflicts(self):
        source = (
            "def main(){ x = read_input(); y = fetch(x); exec(x); exec(y); }"
        )
        result = analyze_source(
            source,
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "tainted", hid="h_tainted"),
                )
            ),
        )
        # 无需外部假设的已证实路径不受冲突影响。
        self.assertIs(result.verdict, Verdict.UNSAFE)
        confirmed = [d for d in result.diagnostics if d.rule == "TAINT-FLOW"]
        self.assertEqual(len(confirmed), 1)

    def test_retracting_one_hypothesis_clears_its_conflict(self):
        hypotheses = (
            hyp("fetch", "clean", hid="h_clean"),
            hyp("fetch", "tainted", hid="h_tainted"),
        )
        result = analyze_source(
            SHARED_CALL,
            AnalysisConfig(
                hypotheses=hypotheses,
                disabled_assumptions={"h_clean"},
            ),
        )
        self.assertEqual(list(result.conflicts), [])
        self.assertIs(result.verdict, Verdict.ASSUMED)
        scenario_states = {s.state for s in result.scenarios}
        self.assertIn("FEASIBLE_RISK", scenario_states)
        self.assertNotIn("CONTRADICTORY", scenario_states)

    def test_multiple_independent_conflicts_coexist(self):
        source = (
            "def main(){ x = read_input();"
            " a = f(x); b = g(x);"
            " exec(a); exec(b); }"
        )
        hypotheses = (
            hyp("f", "clean", hid="f_clean"),
            hyp("f", "tainted", hid="f_tainted"),
            hyp("g", "clean", hid="g_clean"),
            hyp("g", "tainted", hid="g_tainted"),
        )
        result = analyze_source(source, AnalysisConfig(hypotheses=hypotheses))
        self.assertEqual(len(result.conflicts), 2)
        # 撤回 f_tainted 只解决 f 上的冲突，g 上的冲突仍在。
        partial = analyze_source(
            source,
            AnalysisConfig(
                hypotheses=hypotheses,
                disabled_assumptions={"f_tainted"},
            ),
        )
        self.assertEqual(len(partial.conflicts), 1)
        self.assertEqual(partial.conflicts[0].call, "g")
        self.assertIsNot(partial.verdict, Verdict.SAFE)

    def test_similar_hypotheses_on_different_instances_not_conflated(self):
        source = (
            "def main(){ a = lib(\"1\"); b = lib(\"2\");"
            " exec(a); exec(b); }"
        )
        # 限定到不同调用实例的相反假设：各自成立，不构成冲突。
        result = analyze_source(
            source,
            AnalysisConfig(
                hypotheses=(
                    hyp("lib", "clean", site="1:17", hid="h_a"),
                    hyp("lib", "tainted", site="1:31", hid="h_b"),
                )
            ),
        )
        self.assertEqual(list(result.conflicts), [])
        # 不加 site 限定时，同一函数的两个调用实例各自产生独立冲突。
        result2 = analyze_source(
            source,
            AnalysisConfig(
                hypotheses=(
                    hyp("lib", "clean", hid="h_clean"),
                    hyp("lib", "tainted", hid="h_tainted"),
                )
            ),
        )
        self.assertEqual(len(result2.conflicts), 2)
        locs = {(c.loc.line, c.loc.col) for c in result2.conflicts}
        self.assertEqual(locs, {(1, 17), (1, 31)})

    def test_propagate_conflicts_only_when_args_tainted(self):
        tainted = analyze_source(
            SHARED_CALL,
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "propagate", hid="h_prop"),
                )
            ),
        )
        self.assertEqual(len(tainted.conflicts), 1)
        clean_args = analyze_source(
            "def main(){ y = fetch(\"c\"); exec(y); }",
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "propagate", hid="h_prop"),
                )
            ),
        )
        self.assertEqual(list(clean_args.conflicts), [])

    def test_recursion_and_unknown_not_resolved_by_hypotheses(self):
        source = (
            "def loop(n){"
            " if (n == 0) { return n; } else { return loop(n - 1); }"
            "}"
            "def main(){ v = loop(read_input()); y = fetch(v); exec(y); }"
        )
        result = analyze_source(
            source,
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "propagate", hid="h_prop"),
                )
            ),
        )
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        # 递归截断的未知事实不靠假设补默认结果消除。
        undecidable = [
            s
            for s in result.scenarios
            if any(c.state == "UNDECIDABLE" for c in s.conclusions)
        ]
        self.assertTrue(undecidable)

    def test_unknown_external_without_hypothesis_stays_unknown(self):
        source = "def main(){ x = read_input(); y = mystery(x); exec(y); }"
        result = analyze_source(
            source,
            AnalysisConfig(hypotheses=(hyp("other", "clean", hid="h1"),)),
        )
        self.assertIs(result.verdict, Verdict.INCOMPLETE)
        self.assertTrue(any(d.rule == "TAINT-UNCERTAIN" for d in result.diagnostics))


class ScenarioExplanationTests(unittest.TestCase):
    def test_scenario_paths_distinguish_feasible_and_blocked(self):
        result = analyze_source(
            SHARED_CALL,
            AnalysisConfig(
                hypotheses=(
                    hyp("fetch", "clean", hid="h_clean"),
                    hyp("fetch", "tainted", hid="h_tainted"),
                )
            ),
        )
        scenario = next(
            s for s in result.scenarios if s.hypotheses == ("h_clean",)
        )
        conclusion = scenario.conclusions[0]
        # 该情景下 tainted 路径被阻断，安全路径可行。
        self.assertTrue(
            any(p.kind == "safe" for p in conclusion.feasible_paths)
        )
        self.assertTrue(
            any(
                p.kind == "risk" and p.assumptions == ("h_tainted",)
                for p in conclusion.blocked_paths
            )
        )

    def test_constant_safe_paths_kept_without_assumptions(self):
        result = analyze_source(
            "def main(){ exec(\"ls\"); }",
            AnalysisConfig(hypotheses=(hyp("fetch", "clean", hid="h1"),)),
        )
        self.assertIs(result.verdict, Verdict.SAFE)
        explanation = result.explanations[0]
        self.assertEqual(explanation.state, "CONFIRMED_SAFE")
        for scenario in result.scenarios:
            self.assertEqual(scenario.conclusions[0].state, "NO_RISK_FOUND")


class RevisionTests(unittest.TestCase):
    HYPOTHESES = (
        hyp("fetch", "clean", hid="h_clean"),
        hyp("fetch", "tainted", hid="h_tainted"),
    )

    def test_revision_reports_conflict_resolution(self):
        _, snapshot = snapshot_analysis(
            SHARED_CALL, AnalysisConfig(hypotheses=self.HYPOTHESES)
        )
        self.assertEqual(snapshot.scenarios[0].state, "CONTRADICTORY")
        result, report, new_snapshot = revise_specs(
            snapshot, hypotheses=(hyp("fetch", "tainted", hid="h_tainted"),)
        )
        # 旧情景保留可回看。
        self.assertEqual(
            report.old_snapshot.scenarios[0].state, "CONTRADICTORY"
        )
        self.assertEqual(len(report.resolved_conflicts), 1)
        self.assertEqual(report.new_conflicts, ())
        self.assertIs(result.verdict, Verdict.ASSUMED)
        change = next(
            c for c in report.risk_changes if c.conclusion_id == "exec:1:45"
        )
        self.assertIn("conflict_resolved", change.causes)
        self.assertNotIn("path_changed", change.causes)
        self.assertEqual(new_snapshot.scenarios[0].state, "FEASIBLE_RISK")

    def test_revision_distinguishes_path_change_from_conflict(self):
        source = (
            "def main(){ x = read_input();"
            " y = fetch(x); z = other(x);"
            " exec(y); exec(z); }"
        )
        from taintlab import ExternalSpec

        _, snapshot = snapshot_analysis(
            source,
            AnalysisConfig(
                hypotheses=self.HYPOTHESES,
                external_specs={"other": ExternalSpec("other", "说明", "clean")},
            ),
        )
        result, report, _ = revise_specs(
            snapshot,
            new_specs={"other": ExternalSpec("other", "说明", "tainted")},
            hypotheses=(hyp("fetch", "tainted", hid="h_tainted"),),
        )
        by_id = {c.conclusion_id: c for c in report.risk_changes}
        # fetch 上的变化来自冲突解除。
        self.assertIn("conflict_resolved", by_id["exec:1:59"].causes)
        # other 上的变化来自说明修订（程序路径/依据变化），而非冲突。
        other_change = by_id["exec:1:68"]
        self.assertNotIn("conflict_resolved", other_change.causes)
        self.assertIn("spec_changed", other_change.causes)

    def test_snapshot_roundtrip_preserves_conflicts_and_scenarios(self):
        import json
        from taintlab.analyzer import ResearchSnapshot

        _, snapshot = snapshot_analysis(
            SHARED_CALL, AnalysisConfig(hypotheses=self.HYPOTHESES)
        )
        restored = ResearchSnapshot.from_dict(json.loads(snapshot.to_json()))
        self.assertEqual(
            [c.conflict_id for c in restored.conflicts],
            [c.conflict_id for c in snapshot.conflicts],
        )
        self.assertEqual(
            [(s.scenario_id, s.state) for s in restored.scenarios],
            [(s.scenario_id, s.state) for s in snapshot.scenarios],
        )
        self.assertEqual(
            [h.hid for h in restored.hypotheses], ["h_clean", "h_tainted"]
        )


if __name__ == "__main__":
    unittest.main()

