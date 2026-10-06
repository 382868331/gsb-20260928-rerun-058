import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from taintlab import (
    AnalysisConfig,
    ExternalSpec,
    Verdict,
    adopt_coverage_plan,
    analyze_source,
    format_coverage_text,
    plan_coverage,
    revise_coverage,
)
from taintlab.analyzer import ExternalSpecScope
from taintlab.coverage import CoveragePlanStudy


def sink_ids(source):
    return [item.conclusion_id for item in analyze_source(source).explanations]


class CoveragePlanningTests(unittest.TestCase):
    def test_min_new_and_max_keep_strategies_differ_on_existing_specs(self):
        # 现有说明 relay@v1 与 noisy@v1；目标只依赖 relay。
        # min_new 为压缩总规模丢弃 noisy@v1，max_keep 尽量保留现有说明。
        source = (
            "def main(){"
            " x = read_input();"
            " a = relay(x);"
            " b = noisy(1);"
            " exec(a);"
            "}"
        )
        (target,) = sink_ids(source)
        existing = (
            ExternalSpec("relay", "净化", returns="clean", version="v1"),
            ExternalSpec("noisy", "净化", returns="clean", version="v1"),
        )
        study = plan_coverage(
            source, [target], [], config=AnalysisConfig(external_specs=existing)
        )
        min_new = study.by_strategy("min_new")
        max_keep = study.by_strategy("max_keep")
        self.assertIsNotNone(min_new)
        self.assertIsNotNone(max_keep)
        self.assertEqual(min_new.assumption_ids, ("relay@v1",))
        self.assertEqual(max_keep.assumption_ids, ("noisy@v1", "relay@v1"))
        self.assertEqual(min_new.added_assumptions, ())
        self.assertEqual(
            max_keep.kept_assumptions, ("noisy@v1", "relay@v1")
        )
        self.assertTrue(min_new.targets[0].covered)
        self.assertTrue(max_keep.targets[0].covered)

    def test_conflicting_specs_at_same_call_block_feasible_plan(self):
        source = "def main(){ x = read_input(); y = relay(x); exec(y); }"
        (target,) = sink_ids(source)
        available = (
            ExternalSpec("relay", "净化", returns="clean", version="v1"),
            ExternalSpec("relay", "读环境", returns="tainted", version="v2"),
        )
        study = plan_coverage(source, [target], available)
        # 同一调用实例上互斥的两条说明不能共同出现在可行方案中。
        self.assertIn(("relay@v1", "relay@v2"), study.blocked_combinations)
        for plan in study.plans:
            self.assertTrue(plan.feasible)
            self.assertEqual(len(plan.specs), 1)
            self.assertEqual(plan.conflicts, ())

    def test_disjoint_versions_of_same_library_can_be_coadopted(self):
        source = (
            "def main(){\n"
            " x = read_input();\n"
            " a = relay(x);\n"
            " b = relay(x);\n"
            " exec(a);\n"
            " exec(b);\n"
            "}"
        )
        targets = sink_ids(source)
        result = analyze_source(source)
        relay_locs = sorted({
            (hop.loc.line, hop.loc.col)
            for exp in result.explanations
            for path in exp.path_explanations
            for hop in path.path.hops
            if hop.kind == "unknown" and "relay" in hop.text
        })
        self.assertEqual(len(relay_locs), 2)
        (line1, col1), (line2, col2) = sorted(relay_locs)
        available = (
            ExternalSpec(
                "relay", "v1 净化", returns="clean", version="v1",
                scope=ExternalSpecScope.call_site(line1, col1),
            ),
            ExternalSpec(
                "relay", "v2 净化", returns="clean", version="v2",
                scope=ExternalSpecScope.call_site(line2, col2),
            ),
        )
        study = plan_coverage(source, targets, available)
        plan = study.by_strategy("min_new")
        self.assertIsNotNone(plan)
        self.assertEqual(
            set(plan.assumption_ids),
            {
                f"relay@v1[call::{line1}:{col1}]",
                f"relay@v2[call::{line2}:{col2}]",
            },
        )
        # 逐调用点展示实际适用关系：每个调用点适用自己位置的版本。
        applies = {
            (site.loc.line, site.loc.col): site.assumption_id
            for site in plan.call_sites
        }
        self.assertEqual(applies[(line1, col1)], f"relay@v1[call::{line1}:{col1}]")
        self.assertEqual(applies[(line2, col2)], f"relay@v2[call::{line2}:{col2}]")
        self.assertEqual(plan.unknown_sites, ())

    def test_file_scope_does_not_override_local_call_site_spec(self):
        source = (
            "def main(){\n"
            " x = read_input();\n"
            " a = relay(x);\n"
            " b = relay(x);\n"
            " exec(a);\n"
            " exec(b);\n"
            "}"
        )
        targets = sink_ids(source)
        result = analyze_source(source)
        relay_locs = sorted(
            {
                (hop.loc.line, hop.loc.col)
                for exp in result.explanations
                for path in exp.path_explanations
                for hop in path.path.hops
                if hop.kind == "unknown" and "relay" in hop.text
            }
        )
        (line1, col1), (line2, col2) = relay_locs
        available = (
            ExternalSpec(
                "relay", "文件级净化", returns="clean", version="v1",
                scope=ExternalSpecScope.file(),
            ),
            ExternalSpec(
                "relay", "局部风险", returns="tainted", version="v2",
                scope=ExternalSpecScope.call_site(line1, col1),
            ),
        )
        study = plan_coverage(source, targets, available)
        plan = study.by_strategy("min_new")
        self.assertIsNotNone(plan)
        applies = {
            (site.loc.line, site.loc.col): site.assumption_id
            for site in plan.call_sites
        }
        # 局部调用点适用窄作用域说明，文件级结论不覆盖已明确的局部风险。
        self.assertEqual(applies[(line1, col1)], f"relay@v2[call::{line1}:{col1}]")
        self.assertEqual(applies[(line2, col2)], "relay@v1[file:]")
        states = {item.target: item.state for item in plan.targets}
        self.assertIn("CONDITIONAL_RISK", states.values())
        self.assertIn("CONDITIONALLY_SAFE", states.values())

    def test_unknown_calls_are_listed_and_uncoverable_target_blocks_plan(self):
        source = (
            "def main(){\n"
            " x = read_input();\n"
            " a = relay(x);\n"
            " b = mystery(x);\n"
            " exec(a);\n"
            " exec(b);\n"
            "}"
        )
        targets = sink_ids(source)
        available = (
            ExternalSpec("relay", "净化", returns="clean", version="v1"),
        )
        # mystery 没有说明：包含其 sink 的目标无法被覆盖，不产生方案。
        study = plan_coverage(source, targets, available)
        self.assertEqual(study.plans, ())
        # 只把可覆盖的 sink 作为目标时方案成立，未知调用仍被明确列出。
        study = plan_coverage(source, targets[:1], available)
        plan = study.by_strategy("min_new")
        self.assertIsNotNone(plan)
        self.assertEqual(plan.assumption_ids, ("relay@v1",))
        self.assertEqual(len(plan.unknown_sites), 1)
        self.assertEqual(plan.unknown_sites[0].name, "mystery")
        self.assertEqual(plan.unknown_sites[0].status, "unknown")

    def test_revise_coverage_recomputes_only_affected_targets(self):
        source = (
            "def main(){\n"
            " x = read_input();\n"
            " a = relay(x);\n"
            " b = guard(x);\n"
            " exec(a);\n"
            " exec(b);\n"
            "}"
        )
        targets = sink_ids(source)
        available = (
            ExternalSpec("relay", "净化", returns="clean", version="v1"),
            ExternalSpec("guard", "净化", returns="clean", version="v1"),
        )
        study = plan_coverage(source, targets, available)
        plan = study.by_strategy("min_new")
        self.assertEqual(plan.assumption_ids, ("guard@v1", "relay@v1"))
        revision = revise_coverage(study, ("relay@v1",))
        item = next(r for r in revision.revisions if r.strategy == "min_new")
        self.assertEqual(item.affected_conclusions, (targets[0],))
        self.assertEqual(item.reused_conclusions, (targets[1],))
        # 未受影响的输出位置沿用旧结论对象，只重算受影响的输出。
        old_by_target = {t.target: t for t in plan.targets}
        new_by_target = {t.target: t for t in item.plan.targets}
        self.assertIs(
            new_by_target[targets[1]], old_by_target[targets[1]]
        )
        self.assertIsNot(
            new_by_target[targets[0]], old_by_target[targets[0]]
        )
        # 撤销后该位置回到未知，不再被覆盖。
        self.assertFalse(new_by_target[targets[0]].covered)
        self.assertEqual(new_by_target[targets[0]].state, "UNKNOWN_RISK")

    def test_save_load_preserves_unknown_sites_and_versions(self):
        source = (
            "def main(){\n"
            " x = read_input();\n"
            " a = relay(x);\n"
            " b = mystery(x);\n"
            " exec(a);\n"
            "}"
        )
        (target,) = sink_ids(source)
        available = (
            ExternalSpec("relay", "净化", returns="clean", version="v1"),
        )
        study = plan_coverage(source, [target], available)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "coverage.json"
            study.save(path)
            loaded = CoveragePlanStudy.load(path)
        plan = loaded.by_strategy("min_new")
        self.assertIsNotNone(plan)
        self.assertEqual(plan.assumption_ids, ("relay@v1",))
        self.assertEqual(plan.specs[0].version, "v1")
        self.assertEqual(len(plan.unknown_sites), 1)
        self.assertEqual(plan.unknown_sites[0].name, "mystery")
        self.assertEqual(loaded.targets, (target,))

    def test_adopt_plan_does_not_promote_conditional_safety(self):
        source = "def main(){ x = read_input(); y = relay(x); exec(y); }"
        (target,) = sink_ids(source)
        available = (
            ExternalSpec("relay", "净化", returns="clean", version="v1"),
        )
        study = plan_coverage(source, [target], available)
        plan = study.by_strategy("min_new")
        self.assertEqual(plan.targets[0].state, "CONDITIONALLY_SAFE")
        result = adopt_coverage_plan(plan, source)
        # 采用方案后结论依赖外部说明，不能是无条件安全。
        self.assertIsNot(result.verdict, Verdict.SAFE)
        self.assertIs(result.verdict, Verdict.ASSUMED)

    def test_format_coverage_text_lists_sites_and_blocked(self):
        source = "def main(){ x = read_input(); y = relay(x); exec(y); }"
        (target,) = sink_ids(source)
        available = (
            ExternalSpec("relay", "净化", returns="clean", version="v1"),
            ExternalSpec("relay", "读环境", returns="tainted", version="v2"),
        )
        study = plan_coverage(source, [target], available)
        text = format_coverage_text(study)
        self.assertIn("relay@v1", text)
        self.assertIn("被阻止的互斥组合", text)


if __name__ == "__main__":
    unittest.main()
