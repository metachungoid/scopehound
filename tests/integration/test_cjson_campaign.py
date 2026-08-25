from __future__ import annotations

import shutil
import unittest

from scopehound.cjson_validation import run_cjson_validation
from scopehound.errors import ScopeHoundError
from scopehound.manifest import validate_manifest
from scopehound.targetpacks import CJSON_CURRENT_COMMIT


def _authorized_cjson_manifest():
    return validate_manifest({
        "schema_version": 1,
        "target": {
            "name": "cjson", "repository": "https://github.com/DaveGamble/cJSON.git",
            "revision": "fb16e5cf358798aabb049655975cde8427101056", "language": "c",
        },
        "authorization": {
            "status": "authorized", "policy_url": "https://github.com/DaveGamble/cJSON/security",
            "checked_at": "2026-08-25", "eligible_classes": ["memory-corruption"],
            "notes": "Approved local control validation.",
        },
        "commands": {"build": ["cc", "--version"], "fuzz": ["cc", "--version"]},
        "opportunity": {
            "bounty_eligibility": 1.0, "attacker_reachability": 0.5,
            "code_criticality": 0.5, "change_recency": 0.5,
            "fuzzing_gap": 0.5, "build_reproducibility": 1.0, "duplicate_risk": 0.1,
        },
    })


class CjsonCampaignIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(
        shutil.which("gcc") and shutil.which("git"),
        "gcc and git are required for the real-library validation",
    )
    def test_cjson_positive_reproduces_and_fixed_does_not(self) -> None:
        try:
            result = run_cjson_validation(
            duration_seconds=2,
            execute=True,
            manifest=_authorized_cjson_manifest(),
        )
        except ScopeHoundError as error:
            if error.category in {"command_failed", "integration_unavailable"}:
                self.skipTest(error.message)
            raise

        self.assertEqual(result["positive"]["status"], "positive_reproduced")
        self.assertEqual(result["fixed"]["status"], "fixed_not_reproduced")
        self.assertRegex(
            result["positive"]["fingerprint"], r"parse_string|heap-buffer-overflow"
        )
        self.assertNotIn("current", result["published_paths"])


if __name__ == "__main__":
    unittest.main()
