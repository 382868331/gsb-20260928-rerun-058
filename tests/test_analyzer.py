from __future__ import annotations

import unittest

from taintl.api import analyze_source
from taintl.callgraph import build_call_graph
from taintl.parser import parse_source


class AnalyzerTest(unittest.TestCase):
    def test_direct_untrusted_flow_is_reported(self):
        result = analyze_source("""
fn main() {
  let x = read_input();
  danger(x);
}
""")
        self.assertTrue(result.complete)
        self.assertFalse(result.safe)
        self.assertEqual([item.rule for item in result.diagnostics], ["tainted-sink"])
        self.assertEqual(result.diagnostics[0].path[0].line, 3)
        self.assertEqual(result.diagnostics[0].path[0].kind, "source")

    def test_explicit_sanitization_is_safe(self):
        result = analyze_source("""
fn main() {
  let x = read_input();
  let y = sanitize(x);
  danger(y);
}
""")
        self.assertTrue(result.complete)
        self.assertTrue(result.safe)
        self.assertEqual(result.diagnostics, [])

    def test_sanitized_value_does_not_merge_back_into_original(self):
        result = analyze_source("""
fn main() {
  let raw = read_input();
  let safe = sanitize(raw);
  if (true) {
    safe = safe;
  } else {
    safe = raw;
  }
  danger(safe);
}
""")
        rules = [item.rule for item in result.diagnostics]
        self.assertIn("tainted-sink", rules)

    def test_cross_function_parameter_and_return_path(self):
        result = analyze_source("""
fn forward(value) {
  return value;
}
fn main() {
  let x = forward(read_input());
  danger(x);
}
""")
        self.assertFalse(result.safe)
        diagnostic = next(item for item in result.diagnostics if item.rule == "tainted-sink")
        self.assertEqual([node.kind for node in diagnostic.path], ["source", "call", "return-to-call", "sink"])
        self.assertIn(("main", "forward"), [(edge[0], edge[1]) for edge in result.call_edges])

    def test_branch_merge_tracks_both_possibilities(self):
        sanitized_branch = analyze_source("""
fn main() {
  let x = sanitize(read_input());
  if (true) {
    x = sanitize(x);
  } else {
    x = sanitize(x);
  }
  danger(x);
}
""")
        self.assertTrue(sanitized_branch.safe)

        tainted_branch = analyze_source("""
fn main() {
  let x = sanitize(read_input());
  if (true) {
    x = "literal";
  } else {
    x = read_input();
  }
  danger(x);
}
""")
        self.assertFalse(tainted_branch.safe)

    def test_recursion_limit_is_not_reported_as_safe(self):
        result = analyze_source("""
fn loop(value) {
  return loop(value);
}
fn main() {
  danger(loop(read_input()));
}
""", max_depth=2)
        self.assertFalse(result.complete)
        self.assertFalse(result.safe)
        self.assertIn("analysis-limit", [item.rule for item in result.diagnostics])
        self.assertTrue(any(item.rule == "unknown-sink" for item in result.diagnostics))

    def test_unresolved_call_is_conservatively_unknown(self):
        result = analyze_source("""
fn main() {
  danger(missing(read_input()));
}
""")
        self.assertFalse(result.complete)
        self.assertIn("unresolved-call", [item.rule for item in result.diagnostics])
        self.assertIn("unknown-sink", [item.rule for item in result.diagnostics])

    def test_expression_call_to_non_returning_function_is_incomplete(self):
        result = analyze_source("""
fn process(value) {
  danger(value);
}
fn main() {
  danger(process(read_input()));
}
""")
        self.assertFalse(result.complete)
        self.assertIn("missing-return", [item.rule for item in result.diagnostics])

    def test_static_call_graph_does_not_require_execution(self):
        program = parse_source("""
fn helper(value) { return sanitize(value); }
fn main() { danger(helper(read_input())); }
""")
        edges = {(edge.caller, edge.callee): edge for edge in build_call_graph(program)}
        self.assertIn(("helper", "sanitize"), edges)
        self.assertTrue(edges[("helper", "sanitize")].builtin)


if __name__ == "__main__":
    unittest.main()
