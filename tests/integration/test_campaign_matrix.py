from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scopehound.findings import parse_sanitizer_output, write_findings
from scopehound.issue import promote_issue
from scopehound.known_issues import compare_known_issues, write_comparisons
from scopehound.manifest import validate_manifest
from scopehound.matrix import run_matrix
from scopehound.reproduction import record_replay_attempt, reproduce_finding, write_reproduction
from scopehound.workspace import Workspace


@unittest.skipUnless(shutil.which("cc") or shutil.which("gcc"), "a C compiler is required")
class CampaignMatrixIntegrationTests(unittest.TestCase):
    def test_controlled_c_positive_reaches_new_candidate_package(self) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        assert compiler is not None
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = Path(__file__).parents[2] / "tests" / "fixtures" / "controlled_bug.c"
            binary = root / "controlled-fuzzer"
            manifest_data = {
                "schema_version": 1,
                "target": {
                    "name": "controlled-c-positive",
                    "repository": str(root),
                    "revision": "controlled-revision-1",
                    "language": "c",
                },
                "authorization": {
                    "status": "authorized",
                    "policy_url": "https://example.invalid/local-controlled-test",
                    "checked_at": "2026-08-26",
                    "eligible_classes": ["memory-corruption"],
                    "notes": "Intentional local positive control only.",
                },
                "commands": {
                    "build": [compiler, "-g", "-O0", "-fsanitize=address", str(source), "-o", str(binary)],
                    "fuzz": [str(binary)],
                    "reproduce": [str(binary), "{artifact}"],
                },
                "environment": {"ASAN_OPTIONS": "abort_on_error=1:symbolize=0"},
                "opportunity": {
                    "bounty_eligibility": 1.0,
                    "attacker_reachability": 0.5,
                    "code_criticality": 0.5,
                    "change_recency": 0.5,
                    "fuzzing_gap": 1.0,
                    "build_reproducibility": 1.0,
                    "duplicate_risk": 0.0,
                },
                "campaign": {
                    "max_workers": 1,
                    "engines": ["standalone"],
                    "build_variants": [{"name": "asan"}],
                    "wall_clock_seconds": 30,
                    "cpu_seconds": 30,
                },
                "economics": {"expected_reward": 1000, "reward_confidence": 0.1},
            }
            manifest = validate_manifest(manifest_data)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
            workspace = Workspace(root / "workspace")

            state = run_matrix(manifest, workspace, duration_seconds=2, execute=True)

            self.assertEqual(state.jobs[0].status, "completed")
            self.assertGreaterEqual(state.jobs[0].candidate_count, 1)
            artifact = workspace.artifacts_dir(manifest.target.name) / "controlled-crash"
            artifact.write_bytes(b"controlled-positive")
            completed = subprocess.run(
                [str(binary), str(artifact)],
                cwd=workspace.repo_dir(manifest.target.name),
                env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:symbolize=0"},
                capture_output=True,
                text=True,
                check=False,
            )
            log = completed.stdout + "\n" + completed.stderr
            findings = parse_sanitizer_output(log, artifact)
            self.assertTrue(findings)
            findings_path = root / "findings.json"
            write_findings(findings, findings_path)
            first = reproduce_finding(manifest, workspace, artifact, findings[0].fingerprint, execute=True)
            second = reproduce_finding(manifest, workspace, artifact, findings[0].fingerprint, execute=True)
            reproduction_path = root / "reproduction.json"
            write_reproduction(record_replay_attempt(first, second), reproduction_path)
            comparison_path = root / "comparison.json"
            write_comparisons(
                compare_known_issues(findings, (), current_revision=manifest.target.revision),
                comparison_path,
            )
            package = promote_issue(
                manifest, manifest_path, artifact, findings_path, reproduction_path,
                comparison_path, root / "issue",
            )

            payload = json.loads(package.issue_json.read_text(encoding="utf-8"))

        self.assertEqual(payload["candidate_status"], "new_candidate")
        self.assertEqual(payload["novelty"], "unverified")
        self.assertEqual(payload["replay"]["matching_attempts"], 2)


if __name__ == "__main__":
    unittest.main()
