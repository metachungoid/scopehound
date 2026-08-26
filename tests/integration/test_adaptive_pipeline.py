from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.approval import create_approval
from scopehound.catalog import discover_local_metadata
from scopehound.confirmation import CrossBuildConfirmation
from scopehound.experiments import expand_experiment_arms
from scopehound.findings import parse_sanitizer_output
from scopehound.known_issues import DuplicateEvidence, IssueComparison
from scopehound.manifest import validate_manifest
from scopehound.optimizer import ArmMetrics, select_next_round
from scopehound.reports import render_report_profile
from scopehound.reproduction import ReproductionResult
from scopehound.triage import inspect_artifact
from scopehound.verification import verify_candidate
from tests.fixtures import valid_manifest_data


LOG = "ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"


class AdaptivePipelineIntegrationTests(unittest.TestCase):
    def test_approved_local_candidate_flows_to_gated_client_draft(self) -> None:
        fixture = Path(__file__).parents[1] / "fixtures" / "catalog"
        candidate = discover_local_metadata(fixture, checked_at="2026-08-26")[0]
        data = valid_manifest_data()
        data["target"].update({"name": candidate.project, "repository": candidate.repository})  # type: ignore[index]
        data["authorization"].update({  # type: ignore[index]
            "policy_url": candidate.policy_urls[0], "policy_digest": candidate.policy_digest,
            "status": "authorized", "eligible_classes": ["memory-corruption"],
        })
        manifest = validate_manifest(data)
        approval = create_approval(
            candidate, revision=manifest.target.revision, reviewer="integration",
            approved_at="2026-08-26", expires_at="2026-09-26",
            eligible_classes=("memory-corruption",), testing_mode="sandboxed-local",
        )
        arms = expand_experiment_arms(manifest, approval)
        metrics = {
            arm.arm_id: ArmMetrics(cpu_seconds=3600, promotable_candidates=1 if index == 0 else 0)
            for index, arm in enumerate(arms)
        }
        selected = select_next_round(arms, metrics, manifest.campaign.optimizer, round_index=1)
        self.assertLessEqual(len(selected), len(arms))

        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "crash"
            artifact.write_bytes(b"controlled")
            finding = parse_sanitizer_output(LOG, artifact)[0]
            reproduction = ReproductionResult(
                artifact=artifact.name, expected_fingerprint=finding.fingerprint,
                observed_fingerprints=(finding.fingerprint,), status="reproduced",
                command=("./fuzzer", artifact.name), returncode=1, stdout=LOG, stderr="",
                matching_attempts=2, attempts=({"matches": True}, {"matches": True}),
            )
            verification = verify_candidate(
                manifest, artifact, finding, reproduction,
                IssueComparison(finding.fingerprint, "new_candidate", None, None, None, finding.root_cause),
                CrossBuildConfirmation("confirmed_across_builds", ("asan", "ubsan"), finding.root_cause, {}),
                duplicate_evidence=(
                    DuplicateEvidence("public", "no_match", "2026-08-26"),
                    DuplicateEvidence("private", "no_match", "2026-08-26"),
                ), root_cause_review=True, reachability_review=True,
                latest_revision_check=True, scope_recheck=True, approval=approval,
            )
            self.assertTrue(verification.promotable)
            report = render_report_profile(
                manifest, inspect_artifact(artifact), artifact.name, finding, reproduction,
                profile="private-email", verification=verification,
            )
        self.assertIn("Subject:", report)
        self.assertIn("human_review_required: true", report)
        self.assertNotIn("zero-day", report.casefold())


if __name__ == "__main__":
    unittest.main()
