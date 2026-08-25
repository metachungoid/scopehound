from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.benchmark import run_benchmark
from scopehound.workspace import Workspace


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_reports_effectiveness_metrics_and_zero_denominators(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixtures = root / "fixtures"
            fixtures.mkdir()
            (fixtures / "benchmark.json").write_text(json.dumps({"version": 1, "fixtures": [
                {"name": "known", "link_status": "built", "coverage_delta": 4, "cpu_seconds": 60, "replay": "success", "unique_fingerprints": 1, "findings": 1, "duplicates": 0, "false_positives": 0},
                {"name": "compile-failure", "link_status": "failed", "coverage_delta": 0, "cpu_seconds": 0, "replay": "not_attempted", "unique_fingerprints": 0, "findings": 0, "duplicates": 1, "false_positives": 1},
            ]}), encoding="utf-8")

            result = run_benchmark(fixtures, Workspace(root / "state"), execute=False)

        self.assertEqual(result.version, 1)
        self.assertEqual(result.fixtures, 2)
        self.assertAlmostEqual(result.link_success_rate, 0.5)
        self.assertEqual(result.coverage_delta, 2.0)
        self.assertAlmostEqual(result.unique_fingerprints_per_cpu_hour, 60.0)
        self.assertEqual(result.replay_success_rate, 1.0)
        self.assertAlmostEqual(result.duplicate_rate, 0.5)
        self.assertAlmostEqual(result.false_positive_rate, 1.0)

    def test_missing_optional_tools_are_explicit_skips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixtures = Path(temp_dir) / "fixtures"
            fixtures.mkdir()
            (fixtures / "benchmark.json").write_text(json.dumps({"version": 1, "fixtures": []}), encoding="utf-8")

            result = run_benchmark(fixtures, Workspace(Path(temp_dir) / "state"), execute=False)

        self.assertIn("llvm-cov", result.skipped_tools)


if __name__ == "__main__":
    unittest.main()
