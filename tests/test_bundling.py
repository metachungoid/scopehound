from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.bundling import create_bundle
from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output, write_findings
from scopehound.manifest import validate_manifest
from scopehound.reproduction import ReproductionResult, write_reproduction
from scopehound.triage import TriageResult, cluster_findings, triage_artifacts, write_triage

from tests.fixtures import valid_manifest_data


class BundlingTests(unittest.TestCase):
    def test_creates_review_bundle_with_manifest_evidence_and_report(self) -> None:
        log = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in parse /src/parser.c:12:4\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = root / "target.json"
            manifest_path.write_text(json.dumps(valid_manifest_data()), encoding="utf-8")
            manifest = validate_manifest(valid_manifest_data())
            artifacts = root / "artifacts"
            artifacts.mkdir()
            artifact = artifacts / "crash-001"
            artifact.write_bytes(b"boom")
            findings_path = root / "findings.json"
            findings = parse_sanitizer_output(log, artifact)
            write_findings(findings, findings_path)
            triage_result = triage_artifacts(artifacts)
            triage_path = root / "triage.json"
            write_triage(
                TriageResult(triage_result.unique, triage_result.duplicates, cluster_findings(findings)),
                triage_path,
            )
            reproduction_path = root / "reproduction.json"
            write_reproduction(
                ReproductionResult(
                    artifact="crash-001", expected_fingerprint=findings[0].fingerprint,
                    observed_fingerprints=(findings[0].fingerprint,), status="reproduced",
                    command=("./build/parser_fuzzer", str(artifact)), returncode=1,
                    stdout=log, stderr="",
                ),
                reproduction_path,
            )
            output = root / "bundle"

            summary = create_bundle(
                manifest_path,
                manifest,
                artifact,
                output,
                findings_path,
                triage_path,
                reproduction_path,
            )
            inventory = json.loads((output / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(summary.artifact_sha256, inventory["artifact"]["sha256"])
            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "crash-001").exists())
            self.assertTrue((output / "findings.json").exists())
            self.assertTrue((output / "triage.json").exists())
            self.assertTrue((output / "reproduction.json").exists())
            self.assertTrue((output / "report.md").exists())
            self.assertIn("human_review_required: true", (output / "report.md").read_text(encoding="utf-8"))
            self.assertIn("report.md", inventory["files"])


    def test_refuses_to_overwrite_existing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_data = valid_manifest_data()
            manifest_path = root / "target.json"
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
            manifest = validate_manifest(manifest_data)
            artifact = root / "crash-001"
            artifact.write_bytes(b"boom")
            output = root / "bundle"
            output.mkdir()
            (output / "keep.txt").write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(ScopeHoundError, "already exists"):
                create_bundle(manifest_path, manifest, artifact, output)

    def test_includes_minimization_record_and_child_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_data = valid_manifest_data()
            manifest_path = root / "target.json"
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
            manifest = validate_manifest(manifest_data)
            artifact = root / "crash"
            artifact.write_bytes(b"parent")
            child = root / "crash.minimized"
            child.write_bytes(b"child")
            minimization = root / "minimize.json"
            minimization.write_text(json.dumps({"child": str(child), "parent_sha256": "parent"}), encoding="utf-8")
            output = root / "bundle"

            create_bundle(manifest_path, manifest, artifact, output, minimization_path=minimization)

            self.assertTrue((output / "minimization.json").exists())
            self.assertTrue((output / "minimized-crash.minimized").exists())

    def test_includes_campaign_and_controls_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_data = valid_manifest_data()
            manifest_path = root / "target.json"
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
            manifest = validate_manifest(manifest_data)
            artifact = root / "crash"
            artifact.write_bytes(b"parent")
            campaign = root / "campaign.json"
            campaign.write_text(json.dumps({"campaign_id": "abc", "engine": "standalone"}), encoding="utf-8")
            controls = root / "controls.json"
            controls.write_text(json.dumps({"comparison": {"current_status": "current_not_observed"}}), encoding="utf-8")
            output = root / "bundle"

            create_bundle(
                manifest_path, manifest, artifact, output,
                campaign_path=campaign, controls_path=controls,
            )

            self.assertTrue((output / "campaign.json").exists())
            self.assertTrue((output / "controls.json").exists())
            inventory = json.loads((output / "bundle.json").read_text(encoding="utf-8"))
            self.assertIn("campaign", inventory)
            self.assertIn("controls", inventory)


if __name__ == "__main__":
    unittest.main()
