from __future__ import annotations

import unittest

from scopehound.manifest import Opportunity
from scopehound.scoring import score_opportunity


class ScoringTests(unittest.TestCase):
    def test_score_uses_geometric_mean_and_duplicate_penalty(self) -> None:
        opportunity = Opportunity(
            bounty_eligibility=1.0,
            attacker_reachability=0.8,
            code_criticality=0.7,
            change_recency=0.6,
            fuzzing_gap=0.9,
            build_reproducibility=0.8,
            duplicate_risk=0.4,
        )

        result = score_opportunity(opportunity)

        self.assertAlmostEqual(result.score, 55.256, places=3)
        self.assertEqual(result.factors["duplicate_risk"], 0.4)

    def test_zero_prerequisite_produces_zero_score(self) -> None:
        opportunity = Opportunity(0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0)

        result = score_opportunity(opportunity)

        self.assertEqual(result.score, 0.0)


if __name__ == "__main__":
    unittest.main()
