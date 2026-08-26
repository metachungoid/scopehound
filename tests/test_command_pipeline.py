from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scopehound.cli import main
from tests.fixtures import valid_manifest_data


class CommandPipelineTests(unittest.TestCase):
    def _run(self, *argv: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_discovery_approval_planning_and_optimizer_commands(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "catalog"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = root / "catalog.json"
            code, _, error = self._run(
                "discover-targets", "--root", str(fixture), "--output", str(catalog),
                "--checked-at", "2026-08-26", "--json",
            )
            self.assertEqual((code, error), (0, ""))
            candidate = json.loads(catalog.read_text(encoding="utf-8"))["candidates"][0]
            approval = root / "approval.json"
            code, _, error = self._run(
                "approve-target", "--catalog", str(catalog), "--candidate-id", candidate["candidate_id"],
                "--revision", "v1.2.3", "--reviewer", "tester", "--approved-at", "2026-08-26",
                "--expires-at", "2026-09-26", "--output", str(approval), "--json",
            )
            self.assertEqual((code, error), (0, ""))
            data = valid_manifest_data()
            data["target"]["name"] = candidate["project"]  # type: ignore[index]
            data["target"]["repository"] = candidate["repository"]  # type: ignore[index]
            data["authorization"]["policy_url"] = candidate["policy_urls"][0]  # type: ignore[index]
            data["authorization"]["policy_digest"] = candidate["policy_digest"]  # type: ignore[index]
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            arms = root / "arms.json"
            code, _, error = self._run(
                "plan-experiments", "--manifest", str(manifest), "--approval", str(approval),
                "--output", str(arms), "--json",
            )
            self.assertEqual((code, error), (0, ""))
            arms_payload = json.loads(arms.read_text(encoding="utf-8"))
            metrics = root / "metrics.json"
            metrics.write_text(json.dumps({item["arm_id"]: {"cpu_seconds": 60, "promotable_candidates": 0} for item in arms_payload["arms"]}), encoding="utf-8")
            selected = root / "selected.json"
            code, _, error = self._run(
                "optimize-campaign", "--manifest", str(manifest), "--approval", str(approval),
                "--arms", str(arms), "--metrics", str(metrics), "--round", "1",
                "--output", str(selected), "--json",
            )
            self.assertEqual((code, error), (0, ""))
            self.assertIn("active_arm_ids", json.loads(selected.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
