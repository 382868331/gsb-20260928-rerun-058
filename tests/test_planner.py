import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from taintlab import (
    ExternalSpec,
    Verdict,
    analyze_source,
    compare_coverage_strategies,
    format_plan_text,
    plan_coverage,
    revise_plan,
)
from taintlab.analyzer import ExternalSpecScope
from taintlab.planner import CoveragePlan


BASIC_SOURCE = (
    "def main(){"
    " x = read_input();"
    " y = fetch(x);"
    " exec(y);"
    "}"
)


class CoveragePlanningTests(unittest.TestCase):
    def test_plan_covers_unknown_target_with_available_version(self):
        plan = plan_coverage(
            BASIC_SOURCE,
            available_specs=[
                ExternalSpec("fetch", "fetch v1 返回干净值", "clean", version="v1"),
            ],
        )
        self.assertTrue(plan.feasible)
        self.assertEqual(plan.chosen_assumptions, ("fetch@v1",))
        states = {t.sink_id: t.state for t in plan.target_coverages}
        self.assertEqual(set(states.values()), {"covered"})
        self.assertEqual(plan.unknown_positions, ())
        # 条件安全不能提升为无条件安全：采用方案后仍判 ASSUMED
        self.assertEqual(plan.verdict, "ASSUMED")
        adopted = analyze_source(BASIC_SOURCE, plan.adopt_config())
        self.assertIs(adopted.verdict, Verdict.ASSUMED)

    def test_uncoverable_positions_stay_unknown(self):
        source = (
            "def main(){"
            " x = read_input();"
            " y = fetch(x);"
            " z = other(x);"
            " exec(y);"
            " exec(z);"
            "}"
        )
        plan = plan_coverage(
            source,
            available_specs=[
                ExternalSpec("fetch", "干净返回", "clean", version="v1"),
            ],
        )
        states = sorted(t.state for t in plan.target_coverages)
        self.assertEqual(states, ["covered", "unknown"])
        unknown_names = {p.name for p in plan.unknown_positions}
        self.assertEqual(unknown_names, {"other"})
        self.assertEqual(plan.verdict, "INCOMPLETE")

    def test_file_and_call_site_scopes_shown_per_call_site(self):
        source = (
            "def main(){\n"
            " a = read_input();\n"
            " x = lib(a);\n"
            " exec(x);\n"
            " y = lib(a);\n"
            " exec(y);\n"
            "}"
        )
        file_spec = ExternalSpec(
            "lib", "文件级：返回干净值", "clean", version="v1",
            scope=ExternalSpecScope.file(),
        )
        local_spec = ExternalSpec(
            "lib", "局部：该调用返回不可信值", "tainted", version="v2",
            scope=ExternalSpecScope.call_site(5, 6),
        )
        plan = plan_coverage(source, existing_specs=[file_spec, local_spec])
        by_loc = {str(a.loc): a for a in plan.applicability}
        first, second = by_loc["3:6"], by_loc["5:6"]
        self.assertEqual((first.assumption_id, first.scope), ("lib@v1[file:]", "file:"))
        self.assertEqual(
            (second.assumption_id, second.scope),
            ("lib@v2[call::5:6]", "call::5:6"),
        )
        # 局部风险说明不被文件级安全结论覆盖：第二个 sink 仍按
        # 局部说明判为条件风险，整体结论依赖说明（ASSUMED）
        self.assertEqual(plan.verdict, "ASSUMED")
        by_sink = {t.sink_id: t for t in plan.target_coverages}
        self.assertEqual(
            by_sink["exec:6:2"].required_assumptions, ("lib@v2[call::5:6]",)
        )
        self.assertTrue(plan.feasible)

    def test_file_scope_does_not_extend_to_other_file(self):
        other_file = ExternalSpec(
            "fetch", "其它文件的说明", "clean", version="v1",
            scope=ExternalSpecScope.file("other.tl"),
        )
        plan = plan_coverage(BASIC_SOURCE, existing_specs=[other_file])
        self.assertEqual(
            [a.status for a in plan.applicability], ["unknown"]
        )
        self.assertEqual(plan.target_coverages[0].state, "unknown")

    def test_disjoint_versions_can_be_adopted_together(self):
        source = (
            "def main(){\n"
            " a = read_input();\n"
            " x = lib(a);\n"
            " exec(x);\n"
            " y = lib(a);\n"
            " exec(y);\n"
            "}"
        )
        specs = [
            ExternalSpec(
                "lib", "v1 仅第一处", "clean", version="v1",
                scope=ExternalSpecScope.call_site(3, 6),
            ),
            ExternalSpec(
                "lib", "v2 仅第二处", "clean", version="v2",
                scope=ExternalSpecScope.call_site(5, 6),
            ),
        ]
        plan = plan_coverage(source, available_specs=specs)
        self.assertTrue(plan.feasible)
        self.assertEqual(
            set(plan.chosen_assumptions),
            {"lib@v1[call::3:6]", "lib@v2[call::5:6]"},
        )
        self.assertEqual(
            {t.state for t in plan.target_coverages}, {"covered"}
        )

    def test_mutually_exclusive_same_site_specs_block_feasibility(self):
        existing = [
            ExternalSpec("fetch", "v1 干净", "clean", version="v1"),
            ExternalSpec("fetch", "v2 不可信", "tainted", version="v2"),
        ]
        plan = plan_coverage(BASIC_SOURCE, existing_specs=existing)
        self.assertFalse(plan.feasible)
        self.assertEqual(plan.verdict, "INFEASIBLE")
        self.assertEqual(len(plan.blocking_conflicts), 1)
        self.assertEqual(
            set(plan.blocking_conflicts[0].assumptions),
            {"fetch@v1", "fetch@v2"},
        )

    def test_strategy_comparison_minimal_vs_preserve(self):
        # 现有说明互相矛盾（同一调用上干净 vs 不可信），方案被锁死；
        # 新说明 v3 与 v2 互斥、与 v1 相容。
        existing = [
            ExternalSpec("fetch", "v1 干净", "clean", version="v1"),
            ExternalSpec("fetch", "v2 不可信", "tainted", version="v2"),
        ]
        available = [ExternalSpec("fetch", "v3 干净", "clean", version="v3")]
        comparison = compare_coverage_strategies(
            BASIC_SOURCE, available_specs=available, existing_specs=existing,
        )
        # 最少新增：采用 v3 并撤销与之互斥的现有 v2，方案恢复可行
        minimal = comparison.minimal
        self.assertTrue(minimal.feasible)
        self.assertEqual(minimal.chosen_assumptions, ("fetch@v1", "fetch@v3"))
        self.assertEqual(minimal.dropped_existing, ("fetch@v2",))
        self.assertEqual(
            {t.state for t in minimal.target_coverages}, {"covered"}
        )
        # 尽量保留：新增不得驱逐现有说明，矛盾保留、方案不可行
        preserve = comparison.preserve
        self.assertFalse(preserve.feasible)
        self.assertEqual(preserve.verdict, "INFEASIBLE")
        self.assertEqual(
            set(preserve.kept_existing), {"fetch@v1", "fetch@v2"}
        )
        self.assertEqual(preserve.dropped_existing, ())

    def test_revise_plan_recomputes_only_affected_targets(self):
        source = (
            "def main(){"
            " a = read_input();"
            " x = fetch(a);"
            " exec(x);"
            " y = other(a);"
            " exec(y);"
            "}"
        )
        plan = plan_coverage(
            source,
            available_specs=[
                ExternalSpec("fetch", "干净", "clean", version="v1"),
                ExternalSpec("other", "干净", "clean", version="v1"),
            ],
        )
        self.assertEqual(
            {t.state for t in plan.target_coverages}, {"covered"}
        )
        new_plan, report = revise_plan(plan, disabled_assumptions={"fetch@v1"})
        self.assertEqual(report.revoked, ("fetch@v1",))
        self.assertEqual(len(report.affected_targets), 1)
        self.assertEqual(len(report.reused_targets), 1)
        affected_id = report.affected_targets[0]
        reused_id = report.reused_targets[0]
        new_by_id = {t.sink_id: t for t in new_plan.target_coverages}
        old_by_id = {t.sink_id: t for t in plan.target_coverages}
        self.assertEqual(new_by_id[affected_id].state, "unknown")
        # 未受影响目标复用旧对象，不重算
        self.assertIs(new_by_id[reused_id], old_by_id[reused_id])
        self.assertEqual(new_by_id[reused_id].state, "covered")

    def test_save_load_preserves_unknown_positions_and_versions(self):
        source = (
            "def main(){"
            " a = read_input();"
            " x = fetch(a);"
            " exec(x);"
            " y = other(a);"
            " exec(y);"
            "}"
        )
        plan = plan_coverage(
            source,
            available_specs=[
                ExternalSpec("fetch", "干净", "clean", version="v1"),
            ],
        )
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            plan.save(path)
            loaded = CoveragePlan.load(path)
        self.assertEqual(loaded.chosen_assumptions, plan.chosen_assumptions)
        self.assertEqual(
            [p.name for p in loaded.unknown_positions], ["other"]
        )
        self.assertEqual(loaded.target_coverages, plan.target_coverages)
        self.assertEqual(loaded.applicability, plan.applicability)
        self.assertEqual(loaded.verdict, plan.verdict)

    def test_format_plan_text_mentions_scopes_and_unknown(self):
        plan = plan_coverage(BASIC_SOURCE)
        text = format_plan_text(plan)
        self.assertIn("未知行为", text)
        self.assertIn("fetch()", text)


if __name__ == "__main__":
    unittest.main()
