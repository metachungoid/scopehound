from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.experiments import ExperimentArm
from scopehound.manifest import OptimizerConfig
from scopehound.optimizer import (
    ArmMetrics,
    OptimizerState,
    calculate_reward,
    load_optimizer_state,
    record_round,
    select_next_round,
    write_optimizer_state,
)


def arm(name: str) -> ExperimentArm:
    return ExperimentArm(name, "demo", "default", "asan", "standalone", "generated", "none", "m" * 64, "v1")


class OptimizerTests(unittest.TestCase):
    def test_candidate_signal_dominates_proxy_signals(self) -> None:
        config = OptimizerConfig(exploration_fraction=0.0, candidate_weight=0.7, duplicate_weight=0.15, replay_weight=0.1, coverage_weight=0.05)
        candidate = calculate_reward(ArmMetrics(cpu_seconds=3600, promotable_candidates=1), config)
        proxy = calculate_reward(ArmMetrics(cpu_seconds=3600, coverage_delta=1.0, matching_replays=1, replay_attempts=1), config)
        self.assertGreater(candidate, proxy)

    def test_successive_halving_drops_low_yield_and_is_deterministic(self) -> None:
        arms = tuple(arm(name) for name in ("a", "b", "c", "d"))
        metrics = {
            "a": ArmMetrics(cpu_seconds=3600, promotable_candidates=3),
            "b": ArmMetrics(cpu_seconds=3600, promotable_candidates=2),
            "c": ArmMetrics(cpu_seconds=3600, promotable_candidates=0),
            "d": ArmMetrics(cpu_seconds=3600, promotable_candidates=0),
        }
        config = OptimizerConfig(exploration_fraction=0.0, halving_factor=2)
        selected = select_next_round(arms, metrics, config, round_index=1)
        self.assertEqual(tuple(item.arm_id for item in selected), ("a", "b"))
        self.assertEqual(selected, select_next_round(arms, metrics, config, round_index=1))

    def test_exploration_keeps_an_unproven_arm(self) -> None:
        arms = tuple(arm(name) for name in ("a", "b", "c", "d"))
        metrics = {name: ArmMetrics(cpu_seconds=3600, promotable_candidates=1 if name == "a" else 0) for name in ("a", "b", "c", "d")}
        config = OptimizerConfig(exploration_fraction=0.5, halving_factor=2)
        selected = select_next_round(arms, metrics, config, round_index=1)
        self.assertIn("a", {item.arm_id for item in selected})
        self.assertTrue({item.arm_id for item in selected} & {"b", "c", "d"})

    def test_state_round_trip_is_atomic_json(self) -> None:
        state = OptimizerState(campaign_digest="c" * 64, round_index=1, active_arm_ids=("a",), history=())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "optimizer.json"
            write_optimizer_state(state, path)
            self.assertEqual(load_optimizer_state(path), state)
            updated = record_round(state, (arm("a"),), {"a": ArmMetrics(cpu_seconds=60, promotable_candidates=1)})
            self.assertEqual(updated.round_index, 2)


if __name__ == "__main__":
    unittest.main()
