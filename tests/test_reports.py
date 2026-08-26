from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.findings import parse_sanitizer_output
from scopehound.manifest import validate_manifest
from scopehound.reproduction import ReproductionResult
from scopehound.reports import render_report_profile
from scopehound.triage import inspect_artifact
from tests.fixtures import valid_manifest_data


LOG = "ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"


class ReportProfileTests(unittest.TestCase):
    def test_profiles_are_channel_shaped_and_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "crash"
            artifact.write_bytes(b"crash")
            manifest = validate_manifest(valid_manifest_data())
            finding = parse_sanitizer_output(LOG, artifact)[0]
            reproduction = ReproductionResult(
                artifact=artifact.name, expected_fingerprint=finding.fingerprint,
                observed_fingerprints=(finding.fingerprint,), status="reproduced",
                command=("./fuzzer", "crash"), returncode=1, stdout=LOG, stderr="",
                matching_attempts=2,
            )
            for profile in ("neutral", "private-email", "platform-form"):
                report = render_report_profile(
                    manifest, inspect_artifact(artifact), artifact.name, finding,
                    reproduction, profile=profile,
                )
                self.assertIn("human_review_required: true", report)
                self.assertIn("evidence draft", report.casefold())
                self.assertNotRegex(report.casefold(), r"zero-day|confirmed vulnerability|guaranteed bounty")
                if profile == "private-email":
                    self.assertIn("Subject:", report)
                if profile == "platform-form":
                    self.assertIn("Impact summary", report)

    def test_unknown_profile_is_rejected(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "crash"
            artifact.write_bytes(b"x")
            with self.assertRaises(ValueError):
                render_report_profile(manifest, inspect_artifact(artifact), artifact.name, profile="other")


if __name__ == "__main__":
    unittest.main()
