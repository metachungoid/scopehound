from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class CampaignMetrics:
    """Observed campaign measurements plus researcher-entered economics.

    Reward fields are optional metadata. They never establish authorization,
    severity, or a likely payout.
    """

    cpu_seconds: float
    candidate_count: int
    replay_attempts: int
    matching_replays: int
    duplicate_count: int
    opportunity_score: float
    expected_reward: float | None = None
    reward_confidence: float = 0.0
    cpu_hour_cost: float = 0.0


@dataclass(frozen=True)
class YieldEstimate:
    cpu_seconds: float
    candidate_count: int
    candidate_rate_per_cpu_hour: float
    replay_success_rate: float
    duplicate_rate: float
    opportunity_factor: float
    expected_reward: float | None
    reward_confidence: float
    cpu_cost_per_cpu_hour: float
    expected_value_per_cpu_hour: float
    disclaimer: str = (
        "This is an operational prioritization estimate, not a bounty "
        "prediction or guarantee of profit."
    )


def estimate_yield(metrics: CampaignMetrics) -> YieldEstimate:
    cpu_seconds = max(0.0, float(metrics.cpu_seconds))
    candidate_count = max(0, int(metrics.candidate_count))
    replay_attempts = max(0, int(metrics.replay_attempts))
    matching_replays = max(0, int(metrics.matching_replays))
    duplicate_count = max(0, int(metrics.duplicate_count))
    opportunity_factor = _clamp(float(metrics.opportunity_score) / 100.0, 0.0, 1.0)
    reward_confidence = _clamp(float(metrics.reward_confidence), 0.0, 1.0)
    expected_reward = (
        max(0.0, float(metrics.expected_reward))
        if metrics.expected_reward is not None
        else None
    )
    hours = cpu_seconds / 3600.0
    candidate_rate = candidate_count / hours if hours else 0.0
    replay_rate = (
        _clamp(matching_replays / replay_attempts, 0.0, 1.0)
        if replay_attempts
        else 0.0
    )
    duplicate_rate = _clamp(
        duplicate_count / max(candidate_count, 1), 0.0, 1.0
    )
    cpu_cost = max(0.0, float(metrics.cpu_hour_cost))
    expected_value = 0.0
    if expected_reward is not None:
        expected_value = (
            expected_reward
            * reward_confidence
            * opportunity_factor
            * replay_rate
            * (1.0 - duplicate_rate)
            * candidate_rate
        )
    return YieldEstimate(
        cpu_seconds=cpu_seconds,
        candidate_count=candidate_count,
        candidate_rate_per_cpu_hour=round(candidate_rate, 6),
        replay_success_rate=round(replay_rate, 6),
        duplicate_rate=round(duplicate_rate, 6),
        opportunity_factor=round(opportunity_factor, 6),
        expected_reward=expected_reward,
        reward_confidence=round(reward_confidence, 6),
        cpu_cost_per_cpu_hour=round(cpu_cost, 6),
        expected_value_per_cpu_hour=round(max(0.0, expected_value - cpu_cost), 6),
    )


def write_yield_estimate(result: YieldEstimate, output: Path) -> None:
    payload = asdict(result)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write yield estimate {output}: {error}") from error


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return min(maximum, max(minimum, value))
