from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output, write_findings
from scopehound.issue import promote_issue
from scopehound.known_issues import compare_known_issues, write_comparisons
from scopehound.manifest import validate_manifest
from scopehound.reproduction import ReproductionResult, write_reproduction

from tests.fixtures import valid_manifest_data


LOG = (
    "ERROR: AddressSanitizer: heap-buffer-overflow\n"
    "    #0 0x1 in parse /src/parser.c:12:4\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"
)


class IssueTests(unittest.TestCase):
    def _inputs(self, root: Path):
        data = valid_manifest_data()
        data["target"]["revision"] = "0123456789abcdef"  # type: ignore[index]
        manifest = validate_manifest(data)
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        artifact = root / "crash-001"
        artifact.write_bytes(b"controlled-positive")
        findings = parse_sanitizer_output(LOG, artifact)
        findings_path = root / "findings.json"
        write_findings(findings, findings_path)
        reproduction_path = root / "reproduction.json"
        write_reproduction(
            ReproductionResult(
                artifact=artifact.name,
                expected_fingerprint=findings[0].fingerprint,
                observed_fingerprints=(findings[0].fingerprint,),
                status="reproduced",
                command=("./fuzzer", str(artifact)),
                returncode=1,
                stdout=LOG,
                stderr="",
                attempts=(
                    {"status": "reproduced", "matches": True, "observed_fingerprints": [findings[0].fingerprint]},
                    {"status": "reproduced", "matches": True, "observed_fingerprints": [findings[0].fingerprint]},
                ),
                matching_attempts=2,
            ),
            reproduction_path,
        )
        comparison_path = root / "comparison.json"
        write_comparisons(
            compare_known_issues(findings, (), current_revision=manifest.target.revision),
            comparison_path,
        )
        return manifest, manifest_path, artifact, findings_path, reproduction_path, comparison_path

    def test_promotes_two_matching_replays_to_immutable_review_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inputs = self._inputs(root)
            package = root / "issue"

            result = promote_issue(
                inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5], package
            )

            payload = json.loads((package / "issue.json").read_text(encoding="utf-8"))
            report = (package / "report.md").read_text(encoding="utf-8")

        self.assertEqual(result.status, "promoted")
        self.assertEqual(payload["candidate_status"], "new_candidate")
        self.assertEqual(payload["novelty"], "unverified")
        self.assertEqual(payload["replay"]["matching_attempts"], 2)
        self.assertIn("Potential memory-safety finding", report)
        self.assertIn("human_review_required: true", report)

    def test_one_replay_and_known_fingerprint_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest, manifest_path, artifact, findings_path, reproduction_path, comparison_path = self._inputs(root)
            one_replay = ReproductionResult(
                artifact=artifact.name,
                expected_fingerprint="different",
                observed_fingerprints=(),
                status="not_reproduced",
                command=("./fuzzer", str(artifact)),
                returncode=0,
                stdout="",
                stderr="",
                attempts=({"status": "reproduced", "matches": True},),
                matching_attempts=1,
            )
            one_path = root / "one.json"
            write_reproduction(one_replay, one_path)
            with self.assertRaises(ScopeHoundError) as raised:
                promote_issue(manifest, manifest_path, artifact, findings_path, one_path, comparison_path, root / "blocked")

            known_path = root / "known.json"
            known_path.write_text(json.dumps([{"fingerprint": json.loads(findings_path.read_text())[0]["fingerprint"]}]), encoding="utf-8")
            known_comparison = root / "known-comparison.json"
            write_comparisons(
                compare_known_issues(
                    (parse_sanitizer_output(LOG, artifact)[0],),
                    # load through the public parser in the implementation path
                    __import__("scopehound.known_issues", fromlist=["load_known_issues"]).load_known_issues(known_path),
                    current_revision=manifest.target.revision,
                ),
                known_comparison,
            )
            with self.assertRaises(ScopeHoundError) as known_raised:
                promote_issue(manifest, manifest_path, artifact, findings_path, reproduction_path, known_comparison, root / "known")

        self.assertEqual(raised.exception.category, "issue_blocked")
        self.assertEqual(known_raised.exception.category, "issue_blocked")

    def test_package_output_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            inputs = self._inputs(root)
            package = root / "issue"
            package.mkdir()

            with self.assertRaises(ScopeHoundError) as raised:
                promote_issue(inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5], package)

        self.assertEqual(raised.exception.category, "output_exists")


if __name__ == "__main__":
    unittest.main()
