from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.controls import compare_controls, run_control_matrix
from scopehound.targetpacks import cjson_target_pack
from scopehound.workspace import Workspace


class ControlTests(unittest.TestCase):
    def test_compare_controls_distinguishes_fixed_and_current(self) -> None:
        result = compare_controls([
            {"label": "v1.7.17", "role": "positive", "expected": "heap-buffer-overflow", "fingerprints": ["parse_string"]},
            {"label": "v1.7.18", "role": "fixed", "expected": "no-crash", "fingerprints": []},
            {"label": "current", "role": "current", "expected": "exploratory", "fingerprints": []},
        ])

        self.assertEqual(result["positive_status"], "positive_reproduced")
        self.assertEqual(result["fixed_status"], "fixed_not_reproduced")
        self.assertEqual(result["current_status"], "current_not_observed")

    def test_dry_run_control_matrix_records_all_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_control_matrix(
                cjson_target_pack(), Workspace(Path(temp_dir)), engine="standalone",
                backend="native", duration_seconds=1, execute=False,
            )

        self.assertEqual(len(result["controls"]), 3)
        self.assertTrue(all(item["status"] == "planned" for item in result["controls"]))
        self.assertEqual(result["comparison"]["current_status"], "current_not_observed")


if __name__ == "__main__":
    unittest.main()
