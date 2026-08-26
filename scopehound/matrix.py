from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from scopehound.campaign import manifest_digest
from scopehound.approval import ApprovalRecord
from scopehound.economics import CampaignMetrics, YieldEstimate, estimate_yield
from scopehound.engines import list_engine_adapters
from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output
from scopehound.manifest import BuildVariant, Manifest
from scopehound.policy import require_approved, require_authorized
from scopehound.resource import classify_resource_output
from scopehound.runner import command_plans, run_plan
from scopehound.scoring import score_opportunity
from scopehound.workspace import Workspace


@dataclass(frozen=True)
class MatrixJob:
    job_id: str
    target: str
    variant: str
    engine: str
    digest: str
    status: str = "queued"
    attempts: int = 0
    wall_seconds: float = 0.0
    cpu_seconds: float = 0.0
    candidate_count: int = 0
    duplicate_count: int = 0
    replay_attempts: int = 0
    matching_replays: int = 0
    resource_kind: str | None = None
    commands: tuple[Mapping[str, object], ...] = ()
    error: str | None = None
    skipped_reason: str | None = None


@dataclass(frozen=True)
class MatrixState:
    target: str
    manifest_digest: str
    max_workers: int
    created_at: str
    updated_at: str
    jobs: tuple[MatrixJob, ...]
    expected_yield: YieldEstimate


def expand_matrix(manifest: Manifest, *, duration_seconds: int) -> tuple[MatrixJob, ...]:
    if not 1 <= duration_seconds <= 86_400:
        raise ScopeHoundError("duration_invalid", "matrix duration must be between 1 and 86400 seconds")
    variants = manifest.campaign.build_variants or (BuildVariant("default"),)
    digest = manifest_digest(manifest)
    jobs: list[MatrixJob] = []
    for variant in variants:
        for engine in manifest.campaign.engines:
            source = f"{manifest.target.name}|{variant.name}|{engine}|{digest}|{duration_seconds}"
            job_id = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
            job_digest = hashlib.sha256(
                f"{digest}|{variant.name}|{engine}".encode("utf-8")
            ).hexdigest()
            jobs.append(
                MatrixJob(
                    job_id=job_id,
                    target=manifest.target.name,
                    variant=variant.name,
                    engine=engine,
                    digest=job_digest,
                )
            )
    return tuple(jobs)


def run_matrix(
    manifest: Manifest,
    workspace: Workspace,
    *,
    duration_seconds: int,
    execute: bool = False,
    backend: str = "native",
    retry: bool = False,
    approval: ApprovalRecord | None = None,
) -> MatrixState:
    if approval is None:
        require_authorized(manifest)
    else:
        require_approved(manifest, approval)
    planned = expand_matrix(manifest, duration_seconds=duration_seconds)
    state_path = workspace.matrix_file(manifest.target.name)
    if state_path.exists() and not retry:
        existing = _load_state(state_path)
        if existing.manifest_digest != manifest_digest(manifest):
            raise ScopeHoundError("campaign_stale", "matrix state does not match the manifest")
        return existing
    previous: dict[str, MatrixJob] = {}
    if state_path.exists():
        existing = _load_state(state_path)
        if existing.manifest_digest != manifest_digest(manifest):
            raise ScopeHoundError("campaign_stale", "matrix state does not match the manifest")
        previous = {job.job_id: job for job in existing.jobs}
    adapters = {item.name: item for item in list_engine_adapters()}
    jobs = [
        replace(job, attempts=previous.get(job.job_id, MatrixJob("", "", "", "", "")).attempts)
        for job in planned
    ]
    if retry:
        jobs = [
            replace(job, attempts=job.attempts + 1)
            if job.attempts < manifest.campaign.max_retries + 1
            else replace(job, status="skipped", skipped_reason="retry budget exhausted")
            for job in jobs
        ]
    else:
        jobs = [replace(job, attempts=max(1, job.attempts)) for job in jobs]
    started_at = _utc_now()
    if execute:
        with ThreadPoolExecutor(max_workers=manifest.campaign.max_workers) as executor:
            futures = {
                executor.submit(
                    _run_job,
                    manifest,
                    workspace,
                    job,
                    duration_seconds,
                    execute,
                    backend,
                    adapters,
                ): index
                for index, job in enumerate(jobs)
            }
            for future in as_completed(futures):
                jobs[futures[future]] = future.result()
    else:
        jobs = [_plan_job(job, adapters) for job in jobs]
    estimate = _aggregate_yield(manifest, jobs)
    state = MatrixState(
        target=manifest.target.name,
        manifest_digest=manifest_digest(manifest),
        max_workers=manifest.campaign.max_workers,
        created_at=_load_created_at(state_path) or started_at,
        updated_at=_utc_now(),
        jobs=tuple(sorted(jobs, key=lambda item: item.job_id)),
        expected_yield=estimate,
    )
    _write_state(state, state_path)
    return state


def _run_job(
    manifest: Manifest,
    workspace: Workspace,
    job: MatrixJob,
    duration_seconds: int,
    execute: bool,
    backend: str,
    adapters: Mapping[str, object],
) -> MatrixJob:
    adapter = adapters.get(job.engine)
    if adapter is None or not getattr(adapter, "available", False):
        reason = getattr(adapter, "reason", "engine adapter is unavailable")
        return replace(job, status="skipped", skipped_reason=reason)
    if job.engine not in {"standalone", "libfuzzer"}:
        return replace(
            job,
            status="skipped",
            skipped_reason="adapter is available but execution integration is not enabled",
        )
    variant = next(
        (item for item in manifest.campaign.build_variants if item.name == job.variant),
        BuildVariant("default"),
    )
    build_group = variant.build_steps or manifest.commands.build_steps
    fuzz_group = variant.fuzz_steps or manifest.commands.fuzz_steps
    command_groups = (build_group, fuzz_group)
    records: list[Mapping[str, object]] = []
    outputs: list[str] = []
    started = time.monotonic()
    status = "completed"
    error: str | None = None
    if execute:
        for stage, group in zip(("build", "fuzz"), command_groups):
            for plan in command_plans(
                manifest,
                workspace,
                group,
                stage=stage,
                timeout_seconds=duration_seconds if stage == "fuzz" else min(duration_seconds, 600),
                mutates=True,
            ):
                if variant.environment:
                    plan = replace(
                        plan,
                        environment={**dict(plan.environment), **dict(variant.environment)},
                    )
                try:
                    result = run_plan(plan, execute=True, allow_failure=True, backend=backend)
                except ScopeHoundError as raised:
                    status = "timed_out" if raised.category == "timeout" else "failed"
                    error = raised.message
                    records.append({"stage": stage, "status": status, "error": error})
                    break
                output = result.stdout + "\n" + result.stderr
                outputs.append(output)
                command_status = "completed" if result.returncode == 0 else "failed"
                records.append({
                    "stage": stage,
                    "argv": list(result.argv),
                    "status": command_status,
                    "returncode": result.returncode,
                })
                if result.returncode != 0 and not parse_sanitizer_output(output):
                    status = "failed"
                    error = f"{stage} command exited {result.returncode}"
                    break
            if status in {"failed", "timed_out"}:
                break
    else:
        records = [
            {"stage": stage, "status": "planned", "argv": list(plan.argv)}
            for stage, group in zip(command_groups, command_groups)
            for plan in command_plans(
                manifest,
                workspace,
                group,
                stage="plan",
                timeout_seconds=duration_seconds,
                mutates=True,
            )
        ]
        status = "planned"
    combined = "\n".join(outputs)
    findings = parse_sanitizer_output(combined) if combined else ()
    resource = classify_resource_output(combined)
    elapsed = round(time.monotonic() - started, 3)
    return replace(
        job,
        status=status,
        wall_seconds=elapsed,
        cpu_seconds=elapsed,
        candidate_count=len(findings),
        resource_kind=resource.kind if resource else None,
        commands=tuple(records),
        error=error,
    )


def _plan_job(job: MatrixJob, adapters: Mapping[str, object]) -> MatrixJob:
    adapter = adapters.get(job.engine)
    if adapter is None or not getattr(adapter, "available", False):
        return replace(job, status="skipped", skipped_reason=getattr(adapter, "reason", "engine adapter is unavailable"))
    if job.engine not in {"standalone", "libfuzzer"}:
        return replace(job, status="skipped", skipped_reason="adapter is available but execution integration is not enabled")
    return replace(job, status="planned")


def _aggregate_yield(manifest: Manifest, jobs: list[MatrixJob]) -> YieldEstimate:
    score = score_opportunity(manifest.opportunity).score
    return estimate_yield(
        CampaignMetrics(
            cpu_seconds=sum(job.cpu_seconds for job in jobs),
            candidate_count=sum(job.candidate_count for job in jobs),
            replay_attempts=sum(job.replay_attempts for job in jobs),
            matching_replays=sum(job.matching_replays for job in jobs),
            duplicate_count=sum(job.duplicate_count for job in jobs),
            opportunity_score=score,
            expected_reward=manifest.economics.expected_reward,
            reward_confidence=manifest.economics.reward_confidence,
            cpu_hour_cost=manifest.economics.cpu_hour_cost,
        )
    )


def _load_state(path: Path) -> MatrixState:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        jobs = tuple(_job_from_payload(item) for item in payload.get("jobs", []))
        yield_payload = payload.get("expected_yield", {})
        estimate = YieldEstimate(**yield_payload)
        return MatrixState(
            target=str(payload["target"]),
            manifest_digest=str(payload["manifest_digest"]),
            max_workers=int(payload["max_workers"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            jobs=jobs,
            expected_yield=estimate,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read matrix state {path}: {error}") from error


def _job_from_payload(payload: object) -> MatrixJob:
    if not isinstance(payload, dict):
        raise TypeError("matrix job must be an object")
    return MatrixJob(
        job_id=str(payload["job_id"]), target=str(payload["target"]), variant=str(payload["variant"]),
        engine=str(payload["engine"]), digest=str(payload["digest"]), status=str(payload.get("status", "queued")),
        attempts=int(payload.get("attempts", 0)), wall_seconds=float(payload.get("wall_seconds", 0.0)),
        cpu_seconds=float(payload.get("cpu_seconds", 0.0)), candidate_count=int(payload.get("candidate_count", 0)),
        duplicate_count=int(payload.get("duplicate_count", 0)), replay_attempts=int(payload.get("replay_attempts", 0)),
        matching_replays=int(payload.get("matching_replays", 0)), resource_kind=payload.get("resource_kind"),
        commands=tuple(dict(item) for item in payload.get("commands", []) if isinstance(item, dict)),
        error=payload.get("error"), skipped_reason=payload.get("skipped_reason"),
    )


def _write_state(state: MatrixState, path: Path) -> None:
    payload = {
        "target": state.target,
        "manifest_digest": state.manifest_digest,
        "max_workers": state.max_workers,
        "created_at": state.created_at,
        "updated_at": state.updated_at,
        "jobs": [
            {
                **{key: value for key, value in asdict(job).items() if key != "commands"},
                "commands": [dict(item) for item in job.commands],
            }
            for job in state.jobs
        ],
        "expected_yield": asdict(state.expected_yield),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write matrix state {path}: {error}") from error


def _load_created_at(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload.get("created_at") if isinstance(payload, dict) else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
