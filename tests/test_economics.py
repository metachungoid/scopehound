from __future__ import annotations

import unittest

from scopehound.economics import CampaignMetrics, estimate_yield


class EconomicsTests(unittest.TestCase):
    def test_estimate_is_deterministic_and_explains_inputs(self) -> None:
        result = estimate_yield(
            CampaignMetrics(
                cpu_seconds=1800,
                candidate_count=4,
                replay_attempts=4,
                matching_replays=3,
                duplicate_count=1,
                opportunity_score=80.0,
                expected_reward=5000.0,
                reward_confidence=0.5,
                cpu_hour_cost=0.25,
            )
        )

        self.assertEqual(result.candidate_rate_per_cpu_hour, 8.0)
        self.assertEqual(result.replay_success_rate, 0.75)
        self.assertEqual(result.duplicate_rate, 0.25)
        self.assertGreater(result.expected_value_per_cpu_hour, 0.0)
        self.assertIn("not a bounty prediction", result.disclaimer)

    def test_missing_reward_and_zero_cpu_are_safe(self) -> None:
        result = estimate_yield(
            CampaignMetrics(
                cpu_seconds=0,
                candidate_count=-2,
                replay_attempts=0,
                matching_replays=2,
                duplicate_count=3,
                opportunity_score=120.0,
                expected_reward=None,
                reward_confidence=2.0,
                cpu_hour_cost=-1.0,
            )
        )

        self.assertEqual(result.candidate_rate_per_cpu_hour, 0.0)
        self.assertEqual(result.replay_success_rate, 0.0)
        self.assertEqual(result.expected_value_per_cpu_hour, 0.0)
        self.assertGreaterEqual(result.cpu_cost_per_cpu_hour, 0.0)


if __name__ == "__main__":
    unittest.main()
