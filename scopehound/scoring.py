from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping

from scopehound.manifest import Opportunity


@dataclass(frozen=True)
class ScoreResult:
    score: float
    factors: Mapping[str, float]


def score_opportunity(opportunity: Opportunity) -> ScoreResult:
    factors = {
        "bounty_eligibility": opportunity.bounty_eligibility,
        "attacker_reachability": opportunity.attacker_reachability,
        "code_criticality": opportunity.code_criticality,
        "change_recency": opportunity.change_recency,
        "fuzzing_gap": opportunity.fuzzing_gap,
        "build_reproducibility": opportunity.build_reproducibility,
        "duplicate_risk": opportunity.duplicate_risk,
    }
    prerequisites = tuple(factors[name] for name in tuple(factors)[:6])
    geometric_mean = math.prod(prerequisites) ** (1.0 / len(prerequisites))
    penalty = 1.0 - 0.75 * opportunity.duplicate_risk
    return ScoreResult(score=100.0 * geometric_mean * penalty, factors=factors)
