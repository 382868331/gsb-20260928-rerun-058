from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from taintl.cli import main


class CliTest(unittest.TestCase):
    def test_incomplete_analysis_has_distinct_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "program.taintl"
            path.write_text(
                "fn loop(value) { return loop(value); }\n"
                "fn main() { danger(loop(read_input())); }\n"
            )
            self.assertEqual(main([str(path), "--max-depth", "1"]), 3)


if __name__ == "__main__":
    unittest.main()
