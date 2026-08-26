from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from scopehound.approval import (
    ApprovalRecord,
    create_approval,
    load_approval,
    require_current_approval,
    write_approval,
)
from scopehound.catalog import CatalogCandidate
from scopehound.errors import ScopeHoundError
from scopehound.manifest import validate_manifest
from tests.fixtures import valid_manifest_data


def candidate() -> CatalogCandidate:
    return CatalogCandidate(
        candidate_id="candidate-1", project="example-parser",
        repository="https://example.invalid/project.git",
        policy_urls=("https://example.invalid/security-policy",),
        disclosure_channels=("email",), eligible_classes=("memory-corruption",),
        policy_digest="a" * 64, source_names=("curated",), source_confidence=1.0,
        discovered_at="2026-08-26", checked_at="2026-08-26",
    )


class ApprovalTests(unittest.TestCase):
    def test_create_and_round_trip_is_stable(self) -> None:
        record = create_approval(
            candidate(), revision="abc123", reviewer="researcher",
            approved_at="2026-08-26", expires_at="2026-09-26",
            eligible_classes=("memory-corruption",), testing_mode="sandboxed-local",
        )
        self.assertEqual(record.candidate_id, "candidate-1")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            write_approval(record, path)
            self.assertEqual(load_approval(path), record)

    def test_current_approval_permits_matching_manifest(self) -> None:
        data = valid_manifest_data()
        data["authorization"]["policy_digest"] = "a" * 64  # type: ignore[index]
        manifest = validate_manifest(data)
        record = create_approval(
            candidate(), revision="v1.2.3", reviewer="researcher",
            approved_at="2026-08-26", expires_at="2026-09-26",
            eligible_classes=("memory-corruption",), testing_mode="sandboxed-local",
        )
        require_current_approval(manifest, record, required_class="memory-corruption", now=date(2026, 8, 27))

    def test_stale_policy_revision_and_expiry_are_rejected(self) -> None:
        data = valid_manifest_data()
        data["authorization"]["policy_digest"] = "a" * 64  # type: ignore[index]
        manifest = validate_manifest(data)
        record = create_approval(
            candidate(), revision="v1.2.3", reviewer="researcher",
            approved_at="2026-08-26", expires_at="2026-09-26",
            eligible_classes=("memory-corruption",), testing_mode="sandboxed-local",
        )
        for mutate in (
            lambda: validate_manifest({**data, "target": {**data["target"], "revision": "v1.2.4"}}),  # type: ignore[index]
            lambda: manifest,
        ):
            candidate_manifest = mutate()
            with self.assertRaises(ScopeHoundError) as raised:
                require_current_approval(candidate_manifest, record, required_class="memory-corruption", now=date(2026, 9, 27))
            self.assertEqual(raised.exception.category, "approval_stale")

    def test_invalid_mode_and_missing_class_are_rejected(self) -> None:
        with self.assertRaises(ScopeHoundError):
            create_approval(
                candidate(), revision="v1.2.3", reviewer="researcher",
                approved_at="2026-08-26", expires_at="2026-09-26",
                eligible_classes=("memory-corruption",), testing_mode="remote-probing",
            )
        data = valid_manifest_data()
        data["authorization"]["policy_digest"] = "a" * 64  # type: ignore[index]
        record = create_approval(
            candidate(), revision="v1.2.3", reviewer="researcher",
            approved_at="2026-08-26", expires_at="2026-09-26",
            eligible_classes=("web",), testing_mode="sandboxed-local",
        )
        with self.assertRaises(ScopeHoundError):
            require_current_approval(validate_manifest(data), record, required_class="memory-corruption", now=date(2026, 8, 27))


if __name__ == "__main__":
    unittest.main()
