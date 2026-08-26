from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.catalog import (
    CatalogCandidate,
    discover_local_metadata,
    load_catalog,
    merge_candidates,
    write_catalog,
)
from scopehound.errors import ScopeHoundError


class CatalogTests(unittest.TestCase):
    def test_local_metadata_is_read_only_and_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security.txt").write_text(
                "Contact: mailto:security@example.test\n"
                "Policy: https://example.test/security\n"
                "Canonical: https://example.test/.well-known/security.txt\n",
                encoding="utf-8",
            )
            (root / "SECURITY.md").write_text(
                "# Security policy\n\n"
                "Report vulnerabilities at https://example.test/security\n",
                encoding="utf-8",
            )
            candidates = discover_local_metadata(root, checked_at="2026-08-26")

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate.status, "scope_unverified")
        self.assertIn("mailto:security@example.test", candidate.disclosure_channels)
        self.assertEqual(candidate.policy_urls, ("https://example.test/security",))
        self.assertEqual(len(candidate.policy_digest), 64)
        self.assertEqual(candidate.checked_at, "2026-08-26")

    def test_merge_deduplicates_repository_and_preserves_sources(self) -> None:
        first = CatalogCandidate(
            candidate_id="a", project="demo", repository="https://github.com/acme/demo.git",
            policy_urls=("https://acme.test/security",), disclosure_channels=("email",),
            eligible_classes=("memory-corruption",), policy_digest="a" * 64,
            source_names=("local",), source_confidence=0.7, discovered_at="2026-08-26",
            checked_at="2026-08-26",
        )
        second = CatalogCandidate(
            candidate_id="b", project="demo", repository="https://github.com/acme/demo",
            policy_urls=("https://acme.test/security",), disclosure_channels=("web-form",),
            eligible_classes=("memory-corruption", "dos"), policy_digest="a" * 64,
            source_names=("curated",), source_confidence=0.9, discovered_at="2026-08-26",
            checked_at="2026-08-26",
        )
        merged = merge_candidates((first, second))
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].source_names, ("curated", "local"))
        self.assertEqual(merged[0].disclosure_channels, ("email", "web-form"))
        self.assertEqual(merged[0].eligible_classes, ("dos", "memory-corruption"))
        self.assertEqual(merged[0].source_confidence, 0.9)

    def test_catalog_round_trip_and_malformed_record(self) -> None:
        candidate = CatalogCandidate(
            candidate_id="candidate-1", project="demo", repository="/tmp/demo",
            policy_urls=("https://example.test/security",), disclosure_channels=("email",),
            eligible_classes=("memory-corruption",), policy_digest="b" * 64,
            source_names=("local",), source_confidence=0.5, discovered_at="2026-08-26",
            checked_at="2026-08-26",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            write_catalog((candidate,), path)
            self.assertEqual(load_catalog(path), (candidate,))
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["candidates"][0].pop("policy_digest")
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ScopeHoundError) as raised:
                load_catalog(path)
        self.assertEqual(raised.exception.category, "catalog_invalid")


if __name__ == "__main__":
    unittest.main()
