from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scopehound.cli import main

from tests.fixtures import valid_manifest_data


class CampaignCliTests(unittest.TestCase):
    def test_engines_json_lists_explicit_availability(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["engines", "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual({item["name"] for item in payload["engines"]}, {"standalone", "libfuzzer"})

    def test_campaign_dry_run_writes_state_without_running_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = root / "target.json"
            manifest_path.write_text(json.dumps(valid_manifest_data()), encoding="utf-8")
            workspace = root / "state"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main([
                    "campaign", "--manifest", str(manifest_path), "--workspace", str(workspace),
                    "--engine", "standalone", "--backend", "native", "--duration", "1", "--json",
                ])

            state_path = workspace / "targets" / "example-parser" / "campaign.json"
            state_exists = state_path.is_file()

        self.assertEqual(code, 0)
        self.assertTrue(state_exists)
        self.assertFalse(json.loads(stdout.getvalue())["executed"])

    def test_controls_requires_authorized_manifest_for_execution(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main([
                "controls", "--target-pack", "cjson", "--workspace", ".scopehound",
                "--engine", "standalone", "--backend", "native", "--duration", "1", "--execute",
            ])

        self.assertNotEqual(code, 0)
        self.assertIn("authorization_required", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
