from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.manifest import CommandGroup, Manifest
from scopehound.policy import require_authorized
from scopehound.runner import command_plans, run_plan
from scopehound.workspace import Workspace


_STAGES = ("prepare", "build", "harness_build", "run", "controls")
_PREREQUISITE = {
    "build": "prepare",
    "harness_build": "build",
    "run": "harness_build",
    "controls": "run",
}


@dataclass(frozen=True)
class StageRecord:
    stage: str
    status: str
    input_digest: str
    attempts: int
    commands: tuple[Mapping[str, object], ...]
    error: str | None = None


@dataclass(frozen=True)
class CampaignState:
    campaign_id: str
    target: str
    manifest_digest: str
    revision: str
    engine: str
    backend: str
    created_at: str
    updated_at: str
    stages: tuple[StageRecord, ...] = ()


def create_campaign(
    manifest: Manifest,
    workspace: Workspace,
    *,
    engine: str,
    backend: str,
) -> CampaignState:
    require_authorized(manifest)
    target = manifest.target.name
    target_dir = workspace.target_dir(target)
    target_dir.mkdir(parents=True, exist_ok=True)
    for directory in (
        workspace.repo_dir(target), workspace.build_dir(target), workspace.generated_dir(target),
        workspace.binaries_dir(target), workspace.corpus_dir(target), workspace.artifacts_dir(target),
        workspace.coverage_dir(target), workspace.provenance_dir(target), workspace.reports_dir(target),
        workspace.controls_dir(target), workspace.logs_dir(target),
    ):
        directory.mkdir(parents=True, exist_ok=True)
    now = _utc_now()
    state = CampaignState(
        campaign_id=uuid.uuid4().hex[:16],
        target=target,
        manifest_digest=manifest_digest(manifest),
        revision=manifest.target.revision,
        engine=engine,
        backend=backend,
        created_at=now,
        updated_at=now,
    )
    _write_state(state, workspace.campaign_file(target))
    return state


def load_campaign(path: Path) -> CampaignState:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read campaign state: {error}") from error
    if not isinstance(payload, dict):
        raise ScopeHoundError("input_invalid", "campaign state must be an object")
    try:
        stages = tuple(_stage_from_payload(item) for item in payload.get("stages", []))
        return CampaignState(
            campaign_id=_required_string(payload, "campaign_id"),
            target=_required_string(payload, "target"),
            manifest_digest=_required_string(payload, "manifest_digest"),
            revision=_required_string(payload, "revision"),
            engine=_required_string(payload, "engine"),
            backend=_required_string(payload, "backend"),
            created_at=_required_string(payload, "created_at"),
            updated_at=_required_string(payload, "updated_at"),
            stages=stages,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("input_invalid", f"invalid campaign state: {error}") from error


def run_stage(
    state: CampaignState,
    manifest: Manifest,
    workspace: Workspace,
    stage: str,
    group: CommandGroup,
    *,
    execute: bool,
    force: bool = False,
) -> CampaignState:
    require_authorized(manifest)
    if stage not in _STAGES:
        raise ScopeHoundError("campaign_invalid", f"unknown campaign stage: {stage}")
    if state.target != manifest.target.name or state.manifest_digest != manifest_digest(manifest):
        raise ScopeHoundError("campaign_stale", "campaign state does not match the manifest")
    input_digest = _stage_digest(manifest, stage, group)
    existing = [record for record in state.stages if record.stage == stage]
    latest = existing[-1] if existing else None
    if latest is not None and latest.input_digest != input_digest and not force:
        raise ScopeHoundError("campaign_stale", f"{stage} inputs changed; use force for a new attempt")
    if latest is not None and latest.input_digest == input_digest and not force:
        if latest.status in {"planned", "completed"}:
            return state
        raise ScopeHoundError("campaign_blocked", f"{stage} failed; use force for a new attempt")
    _require_prerequisite(state, stage)
    plans = command_plans(
        manifest, workspace, group, stage=stage,
        timeout_seconds=_stage_timeout(stage), mutates=True,
    )
    command_records: list[Mapping[str, object]] = []
    status = "planned"
    error: str | None = None
    if execute:
        status = "completed"
        for plan in plans:
            try:
                result = run_plan(plan, execute=True, allow_failure=True, backend=state.backend)
                command_status = "completed" if result.returncode == 0 else "failed"
                if result.returncode != 0:
                    status = "failed"
                    error = f"command exited {result.returncode}"
                command_records.append(_command_record(result, command_status))
            except ScopeHoundError as raised:
                status = "failed"
                error = raised.message
                command_records.append({"argv": list(plan.argv), "status": "failed", "error": raised.message})
                break
    else:
        for plan in plans:
            command_records.append({
                "argv": list(plan.argv), "status": "planned", "returncode": None,
                "backend": state.backend, "policy": {},
            })
    attempt = max((record.attempts for record in existing), default=0) + 1
    updated = CampaignState(
        campaign_id=state.campaign_id,
        target=state.target,
        manifest_digest=state.manifest_digest,
        revision=state.revision,
        engine=state.engine,
        backend=state.backend,
        created_at=state.created_at,
        updated_at=_utc_now(),
        stages=state.stages + (StageRecord(stage, status, input_digest, attempt, tuple(command_records), error),),
    )
    _write_state(updated, workspace.campaign_file(manifest.target.name))
    return updated


def manifest_digest(manifest: Manifest) -> str:
    payload = {
        "schema_version": manifest.schema_version,
        "target": asdict(manifest.target),
        "authorization": asdict(manifest.authorization),
        "commands": {
            "prepare": _group_payload(manifest.commands.prepare_steps),
            "build": _group_payload(manifest.commands.build_steps),
            "fuzz": _group_payload(manifest.commands.fuzz_steps),
            "reproduce": _group_payload(manifest.commands.reproduce_steps),
            "harness_build": _group_payload(manifest.commands.harness_build_steps),
        },
        "environment": dict(manifest.environment),
        "corpus": asdict(manifest.corpus),
        "opportunity": asdict(manifest.opportunity),
        "campaign": {
            "max_workers": manifest.campaign.max_workers,
            "max_retries": manifest.campaign.max_retries,
            "share_corpus": manifest.campaign.share_corpus,
            "wall_clock_seconds": manifest.campaign.wall_clock_seconds,
            "cpu_seconds": manifest.campaign.cpu_seconds,
            "process_limit": manifest.campaign.process_limit,
            "engines": list(manifest.campaign.engines),
            "changed_functions": list(manifest.campaign.changed_functions),
            "build_variants": [
                {
                    "name": variant.name,
                    "build": _group_payload(variant.build_steps),
                    "fuzz": _group_payload(variant.fuzz_steps),
                    "environment": dict(variant.environment),
                    "changed_functions": list(variant.changed_functions),
                }
                for variant in manifest.campaign.build_variants
            ],
            "oracles": [
                {"name": oracle.name, "kind": oracle.kind, "command": list(oracle.command)}
                for oracle in manifest.campaign.oracles
            ],
        },
        "economics": {
            "expected_reward": manifest.economics.expected_reward,
            "reward_confidence": manifest.economics.reward_confidence,
            "cpu_hour_cost": manifest.economics.cpu_hour_cost,
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_prerequisite(state: CampaignState, stage: str) -> None:
    prerequisite = _PREREQUISITE.get(stage)
    if prerequisite is None:
        return
    records = [record for record in state.stages if record.stage == prerequisite]
    if not records:
        if stage == "build":
            return
        raise ScopeHoundError("campaign_blocked", f"{stage} requires a completed {prerequisite} stage")
    if records[-1].status not in {"planned", "completed"}:
        raise ScopeHoundError("campaign_blocked", f"{stage} requires a completed {prerequisite} stage")


def _stage_digest(manifest: Manifest, stage: str, group: CommandGroup) -> str:
    payload = {"manifest": manifest_digest(manifest), "stage": stage, "commands": _group_payload(group)}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _group_payload(group: CommandGroup) -> list[list[str]]:
    return [list(command) for command in group]


def _stage_timeout(stage: str) -> float:
    return 600.0 if stage in {"prepare", "build", "harness_build"} else 120.0


def _command_record(result: object, status: str) -> Mapping[str, object]:
    return {
        "argv": list(result.argv), "status": status, "returncode": result.returncode,
        "stdout": result.stdout, "stderr": result.stderr, "backend": result.backend,
        "policy": dict(result.policy),
    }


def _stage_from_payload(payload: object) -> StageRecord:
    if not isinstance(payload, dict):
        raise TypeError("stage must be an object")
    commands = payload.get("commands", [])
    if not isinstance(commands, list):
        raise TypeError("stage commands must be an array")
    return StageRecord(
        stage=str(payload["stage"]), status=str(payload["status"]),
        input_digest=str(payload["input_digest"]), attempts=int(payload["attempts"]),
        commands=tuple(dict(item) for item in commands if isinstance(item, dict)),
        error=payload.get("error"),
    )


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise TypeError(f"{key} must be a non-empty string")
    return value


def _write_state(state: CampaignState, path: Path) -> None:
    payload = {
        "campaign_id": state.campaign_id, "target": state.target,
        "manifest_digest": state.manifest_digest, "revision": state.revision,
        "engine": state.engine, "backend": state.backend,
        "created_at": state.created_at, "updated_at": state.updated_at,
        "stages": [
            {
                "stage": record.stage, "status": record.status,
                "input_digest": record.input_digest, "attempts": record.attempts,
                "commands": [dict(command) for command in record.commands],
                "error": record.error,
            }
            for record in state.stages
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write campaign state {path}: {error}") from error


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
