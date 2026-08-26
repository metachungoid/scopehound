from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

from scopehound.errors import ScopeHoundError
from scopehound.experiments import ExperimentArm
from scopehound.manifest import OptimizerConfig


@dataclass(frozen=True)
class ArmMetrics:
    cpu_seconds: float
    promotable_candidates: int = 0
    candidate_count: int = 0
    duplicate_count: int = 0
    matching_replays: int = 0
    replay_attempts: int = 0
    coverage_delta: float = 0.0


@dataclass(frozen=True)
class ArmObservation:
    arm_id: str
    round_index: int
    metrics: ArmMetrics
    reward: float


@dataclass(frozen=True)
class OptimizerState:
    campaign_digest: str
    round_index: int
    active_arm_ids: tuple[str, ...]
    history: tuple[ArmObservation, ...] = ()


def calculate_reward(metrics: ArmMetrics, config: OptimizerConfig) -> float:
    """Return a bounded deterministic reward whose dominant signal is new candidates/CPU-hour."""
    if metrics.cpu_seconds < 0 or metrics.promotable_candidates < 0:
        raise ScopeHoundError("optimizer_invalid", "metrics cannot be negative")
    cpu_hours = max(metrics.cpu_seconds / 3600.0, 1 / 3600.0)
    candidate_rate = min(1.0, metrics.promotable_candidates / cpu_hours)
    duplicate_quality = 1.0 - min(1.0, metrics.duplicate_count / max(1, metrics.candidate_count))
    replay_quality = min(1.0, metrics.matching_replays / max(1, metrics.replay_attempts))
    coverage = min(1.0, max(0.0, metrics.coverage_delta))
    return round(
        config.candidate_weight * candidate_rate
        + config.duplicate_weight * duplicate_quality
        + config.replay_weight * replay_quality
        + config.coverage_weight * coverage,
        8,
    )


def select_next_round(
    arms: Sequence[ExperimentArm],
    observations: Mapping[str, ArmMetrics],
    config: OptimizerConfig,
    *,
    round_index: int,
) -> tuple[ExperimentArm, ...]:
    if not arms:
        return ()
    if round_index <= 0 or not observations:
        return tuple(sorted(arms, key=lambda item: item.arm_id))
    keep = max(1, math.ceil(len(arms) / config.halving_factor))
    ranked = sorted(
        arms,
        key=lambda item: (-calculate_reward(observations.get(item.arm_id, ArmMetrics(0.0)), config), item.arm_id),
    )
    explore = min(keep - 1 if keep > 1 else 0, math.ceil(keep * config.exploration_fraction))
    exploit_count = keep - explore
    selected = ranked[:exploit_count]
    selected_ids = {item.arm_id for item in selected}
    exploratory = sorted((item for item in arms if item.arm_id not in selected_ids), key=lambda item: item.arm_id)[:explore]
    return tuple(sorted((*selected, *exploratory), key=lambda item: item.arm_id))


def record_round(
    state: OptimizerState,
    arms: Sequence[ExperimentArm],
    observations: Mapping[str, ArmMetrics],
) -> OptimizerState:
    current = {arm.arm_id: arm for arm in arms}
    history = list(state.history)
    for arm_id in sorted(observations):
        if arm_id not in current:
            raise ScopeHoundError("optimizer_invalid", f"unknown arm observation: {arm_id}")
        history.append(ArmObservation(arm_id, state.round_index, observations[arm_id], 0.0))
    return OptimizerState(
        campaign_digest=state.campaign_digest,
        round_index=state.round_index + 1,
        active_arm_ids=tuple(sorted(current)),
        history=tuple(history),
    )


def write_optimizer_state(state: OptimizerState, path: Path) -> None:
    payload = {
        "schema_version": 1,
        "campaign_digest": state.campaign_digest,
        "round_index": state.round_index,
        "active_arm_ids": list(state.active_arm_ids),
        "history": [
            {"arm_id": item.arm_id, "round_index": item.round_index, "metrics": asdict(item.metrics), "reward": item.reward}
            for item in state.history
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ScopeHoundError("optimizer_write_failed", f"cannot write optimizer state: {error}") from error


def load_optimizer_state(path: Path) -> OptimizerState:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise ScopeHoundError("optimizer_invalid", "optimizer schema_version must be 1")
        history = tuple(
            ArmObservation(
                arm_id=str(item["arm_id"]), round_index=int(item["round_index"]),
                metrics=ArmMetrics(**item["metrics"]), reward=float(item.get("reward", 0.0)),
            )
            for item in payload.get("history", [])
        )
        return OptimizerState(
            campaign_digest=str(payload["campaign_digest"]), round_index=int(payload["round_index"]),
            active_arm_ids=tuple(str(item) for item in payload.get("active_arm_ids", [])), history=history,
        )
    except ScopeHoundError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("optimizer_invalid", f"cannot read optimizer state: {error}") from error
