from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from scopehound.errors import ScopeHoundError
from scopehound.targetpacks import ControlRevision
from scopehound.workspace import Workspace


def compare_controls(records: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    result: dict[str, object] = {}
    for record in records:
        role = record.get("role")
        fingerprints = record.get("fingerprints", [])
        if not isinstance(fingerprints, list):
            fingerprints = []
        status = _status_for_role(str(role), bool(fingerprints), str(record.get("status", "")))
        result[f"{role}_status"] = status
    for role in ("positive", "fixed", "current"):
        result.setdefault(f"{role}_status", "inconclusive")
    return result


def run_control_matrix(
    pack: Mapping[str, object],
    workspace: Workspace,
    *,
    engine: str,
    backend: str,
    duration_seconds: int,
    execute: bool,
    runner: Callable[[ControlRevision], Mapping[str, object]] | None = None,
) -> Mapping[str, object]:
    controls = pack.get("controls")
    if not isinstance(controls, tuple):
        raise ScopeHoundError("input_invalid", "target pack controls must be a tuple")
    if execute and runner is None:
        raise ScopeHoundError("controls_executor_missing", "control execution requires a local runner")
    records: list[Mapping[str, object]] = []
    for control in controls:
        if not isinstance(control, ControlRevision):
            raise ScopeHoundError("input_invalid", "target pack control has an invalid type")
        if execute:
            observed = dict(runner(control))  # type: ignore[misc]
            record = {
                "label": control.label, "requested_revision": control.requested_revision,
                "commit": control.commit, "expected": control.expected, "role": control.role,
                "engine": engine, "backend": backend, "duration_seconds": duration_seconds,
                **observed,
            }
        else:
            record = {
                "label": control.label, "requested_revision": control.requested_revision,
                "commit": control.commit, "expected": control.expected, "role": control.role,
                "engine": engine, "backend": backend, "duration_seconds": duration_seconds,
                "status": "planned", "fingerprints": [],
            }
        records.append(record)
    comparison = compare_controls(records)
    target = str(pack.get("name", "target"))
    controls_dir = workspace.controls_dir(target)
    controls_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        _write_json(record, controls_dir / f"{record['role']}.json")
    result = {"target": target, "controls": records, "comparison": comparison, "published_paths": []}
    _write_json(result, controls_dir / "comparison.json")
    return result


def _status_for_role(role: str, has_fingerprint: bool, status: str) -> str:
    if status in {"planned", "inconclusive", "unavailable"}:
        return "inconclusive" if status != "planned" else (
            "current_not_observed" if role == "current" else "inconclusive"
        )
    if role == "positive":
        return "positive_reproduced" if has_fingerprint else "positive_not_reproduced"
    if role == "fixed":
        return "fixed_reproduced" if has_fingerprint else "fixed_not_reproduced"
    if role == "current":
        return "current_observed" if has_fingerprint else "current_not_observed"
    return "inconclusive"


def _write_json(payload: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(json.dumps(_json_value(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write control record {path}: {error}") from error


def _json_value(value: object) -> object:
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value
