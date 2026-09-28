# TaintL

TaintL is a text-only static taint-analysis foundation for a small teaching language. It parses source text into syntax objects, builds call relationships, tracks untrusted values to dangerous calls, and reports source-level propagation paths. Analyzed programs are never imported or executed.

## Language surface

```taintl
fn helper(value) {
  return sanitize(value);
}

fn main() {
  let input = read_input();
  danger(helper(input));
}
```

Built-in names are:

- `read_input` and `source`: untrusted sources.
- `sanitize` and `clean`: explicit sanitizers. A sanitized tag is distinct from the original tainted tag.
- `danger` and `sink`: dangerous operations.

Supported constructs include functions, parameters, `let`, assignment, `return`, `if`/`else`, booleans, strings, integers, calls, and common binary/unary operators.

## Analysis guarantees

- Function arguments and returned values are tracked across user-defined calls.
- Both branches are analyzed and their possible values are joined after branch convergence.
- A sanitized value is represented separately; assigning or joining it back with the original retains the original tainted tag.
- Every taint finding contains line/column steps from source to sink.
- Recursive and bounded analyses have explicit depth and global call-step limits.
- Hitting a limit, an unresolved callee, or missing `main` marks the result incomplete. Incomplete results are never reported as safe; conservatively unknown data reaching a sink is reported.

## Use

```bash
PYTHONPATH=src python -m taintl.cli examples/positive.taintl
PYTHONPATH=src python -m taintl.cli --json examples/negative.taintl
python -m unittest discover -s tests -v
```

The positive example reports a flow and exits with status `1`; the sanitized negative example exits `0`; an incomplete analysis exits `3`.
