from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.confirmation import CrossBuildConfirmation
from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output
from scopehound.known_issues import DuplicateEvidence, IssueComparison
from scopehound.manifest import validate_manifest
from scopehound.reproduction import ReproductionResult
from scopehound.verification import verify_candidate
from tests.fixtures import valid_manifest_data


LOG = "ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in parse /src/parser.c:12:4\nSUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"


class VerificationTests(unittest.TestCase):
    def _inputs(self):
        data = valid_manifest_data()
        manifest = validate_manifest(data)
        with tempfile.NamedTemporaryFile(prefix="artifact-", delete=False) as handle:
            handle.write(b"crash")
            artifact = Path(handle.name)
        finding = parse_sanitizer_output(LOG, artifact)[0]
        reproduction = ReproductionResult(
            artifact=artifact.name, expected_fingerprint=finding.fingerprint,
            observed_fingerprints=(finding.fingerprint,), status="reproduced",
            command=("fuzzer", artifact.name), returncode=1, stdout=LOG, stderr="",
            matching_attempts=2, attempts=({"matches": True}, {"matches": True}),
        )
        comparison = IssueComparison(finding.fingerprint, "new_candidate", None, None, None, finding.root_cause)
        confirmation = CrossBuildConfirmation("confirmed_across_builds", ("asan", "ubsan"), finding.root_cause, {})
        return manifest, artifact, finding, reproduction, comparison, confirmation

    def test_all_verification_gates_produce_promotable_result(self) -> None:
        inputs = self._inputs()
        result = verify_candidate(
            *inputs,
            duplicate_evidence=(
                DuplicateEvidence("public", "no_match", "2026-08-26", "fingerprint"),
                DuplicateEvidence("private", "no_match", "2026-08-26", "root cause"),
            ),
            root_cause_review=True, reachability_review=True,
            latest_revision_check=True, scope_recheck=True,
        )
        self.assertTrue(result.promotable)
        self.assertTrue(all(result.gates.values()))

    def test_missing_duplicate_or_human_review_blocks_without_claiming_global_novelty(self) -> None:
        inputs = self._inputs()
        result = verify_candidate(
            *inputs, duplicate_evidence=(DuplicateEvidence("public", "no_match", "2026-08-26"),),
            root_cause_review=False, reachability_review=True,
            latest_revision_check=True, scope_recheck=True,
        )
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("duplicate" in reason for reason in result.reasons))
        self.assertFalse(result.promotable)

    def test_duplicate_match_is_blocked(self) -> None:
        inputs = self._inputs()
        result = verify_candidate(
            *inputs,
            duplicate_evidence=(
                DuplicateEvidence("public", "match", "2026-08-26"),
                DuplicateEvidence("private", "no_match", "2026-08-26"),
            ),
            root_cause_review=True, reachability_review=True,
            latest_revision_check=True, scope_recheck=True,
        )
        self.assertFalse(result.gates["duplicate_search"])


if __name__ == "__main__":
    unittest.main()
