from __future__ import annotations

import json
from pathlib import Path

from scopehound.approval import load_approval
from scopehound.errors import ScopeHoundError
from scopehound.experiments import ExperimentArm
from scopehound.manifest import load_manifest
from scopehound.optimizer import ArmMetrics, select_next_round
from scopehound.policy import require_approved


def optimize(
    manifest_path: Path,
    approval_path: Path,
    arms_path: Path,
    metrics_path: Path,
    output: Path,
    *,
    round_index: int,
) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    approval = load_approval(approval_path)
    require_approved(manifest, approval)
    try:
        arms_payload = json.loads(arms_path.read_text(encoding="utf-8"))
        metrics_payload = json.loads(metrics_path.read_text(encoding="utf-8"))
        arms = tuple(ExperimentArm(**{key: item[key] for key in ExperimentArm.__dataclass_fields__}) for item in arms_payload["arms"])
        metrics = {str(key): ArmMetrics(**value) for key, value in metrics_payload.items()}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read optimizer inputs: {error}") from error
    selected = select_next_round(arms, metrics, manifest.campaign.optimizer, round_index=round_index)
    payload = {
        "schema_version": 1,
        "round_index": round_index,
        "active_arm_ids": [arm.arm_id for arm in selected],
        "arms": [{**arm.__dict__, "digest": arm.digest} for arm in selected],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"round_index": round_index, "selected": len(selected), "output": str(output)}
