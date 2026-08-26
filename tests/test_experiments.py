from __future__ import annotations

import unittest

from scopehound.approval import create_approval
from scopehound.catalog import CatalogCandidate
from scopehound.errors import ScopeHoundError
from scopehound.experiments import expand_experiment_arms
from scopehound.manifest import validate_manifest
from tests.fixtures import valid_manifest_data


class ExperimentTests(unittest.TestCase):
    def _manifest(self):
        data = valid_manifest_data()
        data["authorization"]["policy_digest"] = "a" * 64  # type: ignore[index]
        data["campaign"] = {
            "engines": ["standalone", "libfuzzer"],
            "build_variants": [{"name": "asan"}, {"name": "ubsan"}],
            "oracles": [{"name": "roundtrip", "kind": "roundtrip", "command": ["true"]}],
            "optimizer": {"exploration_fraction": 0.25, "halving_factor": 2},
        }
        data["corpus"] = {"seed_dir": "seeds"}
        return validate_manifest(data)

    def _approval(self):
        return create_approval(
            CatalogCandidate(
                candidate_id="candidate-1", project="example-parser",
                repository="https://example.invalid/project.git",
                policy_urls=("https://example.invalid/security-policy",), disclosure_channels=("email",),
                eligible_classes=("memory-corruption",), policy_digest="a" * 64,
                source_names=("curated",), source_confidence=1.0,
                checked_at="2026-08-26", discovered_at="2026-08-26",
            ),
            revision="v1.2.3", reviewer="r", approved_at="2026-08-26", expires_at="2026-09-26",
            eligible_classes=("memory-corruption",), testing_mode="sandboxed-local",
        )

    def test_expansion_is_cross_product_with_stable_digests(self) -> None:
        manifest = self._manifest()
        arms = expand_experiment_arms(manifest, self._approval())
        self.assertEqual(len(arms), 8)
        self.assertEqual(arms, expand_experiment_arms(manifest, self._approval()))
        self.assertEqual({arm.digest for arm in arms}.__len__(), len(arms))
        self.assertEqual(arms[0].objective, "promotable_candidates_per_cpu_hour")

    def test_missing_approval_is_rejected(self) -> None:
        with self.assertRaises(ScopeHoundError) as raised:
            expand_experiment_arms(self._manifest(), None)
        self.assertEqual(raised.exception.category, "approval_required")

    def test_optimizer_configuration_is_validated(self) -> None:
        for optimizer in ({"exploration_fraction": 1.1}, {"halving_factor": 1}, {"candidate_weight": -1}):
            data = valid_manifest_data()
            data["campaign"] = {"optimizer": optimizer}  # type: ignore[index]
            with self.assertRaises(ScopeHoundError):
                validate_manifest(data)


if __name__ == "__main__":
    unittest.main()
