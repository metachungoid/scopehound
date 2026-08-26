from __future__ import annotations

import json
from pathlib import Path

from scopehound.approval import load_approval
from scopehound.experiments import expand_experiment_arms
from scopehound.manifest import load_manifest


def plan(manifest_path: Path, approval_path: Path, output: Path) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    arms = expand_experiment_arms(manifest, load_approval(approval_path))
    payload = {
        "schema_version": 1,
        "target": manifest.target.name,
        "arms": [{**arm.__dict__, "digest": arm.digest} for arm in arms],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"count": len(arms), "target": manifest.target.name, "output": str(output)}
