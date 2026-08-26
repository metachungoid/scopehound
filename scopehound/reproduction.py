from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output
from scopehound.manifest import Manifest
from scopehound.policy import require_authorized
from scopehound.provenance import create_provenance
from scopehound.runner import CommandPlan, run_plan
from scopehound.workspace import Workspace


@dataclass(frozen=True)
class ReproductionResult:
    artifact: str
    expected_fingerprint: str
    observed_fingerprints: tuple[str, ...]
    status: str
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    provenance: Mapping[str, object] | None = None
    attempts: tuple[Mapping[str, object], ...] = ()
    matching_attempts: int = 0


def load_reproduction(path: Path) -> ReproductionResult:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("reproduction record must be an object")
        result = ReproductionResult(
            artifact=_required_string(payload, "artifact"),
            expected_fingerprint=_required_string(payload, "expected_fingerprint"),
            observed_fingerprints=tuple(
                _required_string_value(item, "observed_fingerprints item")
                for item in _required_list(payload, "observed_fingerprints")
            ),
            status=_required_string(payload, "status"),
            command=tuple(
                _required_string_value(item, "command item")
                for item in _required_list(payload, "command")
            ),
            returncode=_optional_int(payload.get("returncode")),
            stdout=_required_string(payload, "stdout"),
            stderr=_required_string(payload, "stderr"),
            provenance=payload.get("provenance"),
            attempts=tuple(_attempt_payload(item) for item in payload.get("attempts", []))
            if isinstance(payload.get("attempts", []), list)
            else (),
            matching_attempts=_optional_nonnegative_int(payload.get("matching_attempts")),
        )
        if not result.attempts:
            result = ReproductionResult(
                **{
                    **result.__dict__,
                    "attempts": (_attempt_record(result),),
                    "matching_attempts": 1 if result.status == "reproduced" else 0,
                }
            )
        elif result.matching_attempts == 0:
            result = ReproductionResult(
                **{
                    **result.__dict__,
                    "matching_attempts": sum(
                        1 for item in result.attempts if bool(item.get("matches"))
                    ),
                }
            )
        return result
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read reproduction {path}: {error}") from error


def reproduce_finding(
    manifest: Manifest,
    workspace: Workspace,
    artifact: Path,
    expected_fingerprint: str,
    execute: bool = False,
    timeout_seconds: int = 120,
    backend: str = "native",
) -> ReproductionResult:
    require_authorized(manifest)
    command = manifest.commands.reproduce
    if command is None:
        raise ScopeHoundError(
            "reproduction_unconfigured",
            "manifest commands.reproduce must be configured before replay",
        )
    if not 1 <= timeout_seconds <= 3_600:
        raise ScopeHoundError(
            "duration_invalid", "reproduction timeout must be between 1 and 3600 seconds"
        )

    artifact_path = _artifact_path(workspace, manifest.target.name, artifact)
    repository = workspace.repo_dir(manifest.target.name)
    if execute and not repository.is_dir():
        raise ScopeHoundError("workspace_missing", f"target checkout is missing: {repository}")
    argv = tuple(argument.replace("{artifact}", str(artifact_path)) for argument in command)
    environment = dict(manifest.environment)
    environment["SCOPEHOUND_ARTIFACTS_DIR"] = str(workspace.artifacts_dir(manifest.target.name))
    environment["SCOPEHOUND_REPRO_ARTIFACT"] = str(artifact_path)
    plan = CommandPlan(
        argv=argv,
        cwd=repository,
        environment=MappingProxyType(environment),
        timeout_seconds=timeout_seconds,
        mutates=True,
        create_directories=(workspace.logs_dir(manifest.target.name),),
    )
    result = run_plan(plan, execute=execute, allow_failure=True, backend=backend)
    findings = parse_sanitizer_output(
        result.stdout + "\n" + result.stderr, artifact_path
    ) if execute else ()
    observed = tuple(finding.fingerprint for finding in findings)
    if not execute:
        status = "planned"
    elif expected_fingerprint in observed:
        status = "reproduced"
    elif observed:
        status = "different_finding"
    else:
        status = "not_reproduced"
    provenance = create_provenance(
        manifest, result, environment=manifest.environment, backend=backend,
        backend_policy=result.policy,
        timeout_seconds=timeout_seconds,
    )
    provenance_payload = {
        "target": provenance.target, "repository": provenance.repository,
        "revision": provenance.revision, "manifest_digest": provenance.manifest_digest,
        "argv": list(provenance.argv), "environment": dict(provenance.environment),
        "host_platform": provenance.host_platform, "toolchain": dict(provenance.toolchain),
        "sanitizer_runtime": provenance.sanitizer_runtime,
        "source_sha256": provenance.source_sha256, "binary_sha256": provenance.binary_sha256,
        "corpus_sha256": provenance.corpus_sha256, "dictionary_sha256": provenance.dictionary_sha256,
        "started_at": provenance.started_at, "ended_at": provenance.ended_at,
        "timeout_seconds": provenance.timeout_seconds, "backend": provenance.backend,
        "backend_policy": dict(provenance.backend_policy),
        "executed": provenance.executed,
    }
    return ReproductionResult(
        artifact=artifact_path.name,
        expected_fingerprint=expected_fingerprint,
        observed_fingerprints=observed,
        status=status,
        command=argv,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        provenance=provenance_payload,
        attempts=(_attempt_record_payload(
            status=status,
            observed=observed,
            command=argv,
            returncode=result.returncode,
            provenance=provenance_payload,
        ),),
        matching_attempts=1 if status == "reproduced" else 0,
    )


def record_replay_attempt(
    existing: ReproductionResult, attempt: ReproductionResult
) -> ReproductionResult:
    """Merge a second bounded replay without discarding the first evidence."""

    if existing.artifact != attempt.artifact:
        raise ScopeHoundError("input_invalid", "replay artifacts do not match")
    if existing.expected_fingerprint != attempt.expected_fingerprint:
        raise ScopeHoundError("input_invalid", "replay fingerprints do not match")
    first_attempts = existing.attempts or (_attempt_record(existing),)
    second_attempts = attempt.attempts or (_attempt_record(attempt),)
    attempts = first_attempts + second_attempts
    observed: list[str] = []
    for item in attempts:
        for fingerprint in item.get("observed_fingerprints", ()):
            if isinstance(fingerprint, str) and fingerprint not in observed:
                observed.append(fingerprint)
    matching = sum(1 for item in attempts if bool(item.get("matches")))
    status = (
        "reproduced"
        if matching
        else "different_finding"
        if observed
        else "not_reproduced"
    )
    return ReproductionResult(
        artifact=existing.artifact,
        expected_fingerprint=existing.expected_fingerprint,
        observed_fingerprints=tuple(observed),
        status=status,
        command=existing.command,
        returncode=attempt.returncode,
        stdout="\n".join(item for item in (existing.stdout, attempt.stdout) if item),
        stderr="\n".join(item for item in (existing.stderr, attempt.stderr) if item),
        provenance=attempt.provenance or existing.provenance,
        attempts=attempts,
        matching_attempts=matching,
    )


def write_reproduction(result: ReproductionResult, output: Path) -> None:
    payload = asdict(result)
    payload["command"] = list(result.command)
    payload["observed_fingerprints"] = list(result.observed_fingerprints)
    payload["attempts"] = [dict(item) for item in result.attempts]
    if result.provenance:
        payload["provenance"] = dict(result.provenance)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write reproduction output: {error}") from error


def _artifact_path(workspace: Workspace, target_name: str, artifact: Path) -> Path:
    artifacts_root = workspace.artifacts_dir(target_name)
    resolved = artifact.expanduser().resolve()
    try:
        resolved.relative_to(artifacts_root)
    except ValueError as error:
        raise ScopeHoundError(
            "unsafe_path", "reproduction artifact must remain inside target artifacts"
        ) from error
    if not resolved.is_file():
        raise ScopeHoundError("input_invalid", f"reproduction artifact is missing: {resolved}")
    return resolved


def _required_string(payload: dict[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    return value


def _required_list(payload: dict[str, object], field: str) -> list[object]:
    value = payload.get(field)
    if not isinstance(value, list):
        raise TypeError(f"{field} must be an array")
    return value


def _required_string_value(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    return value


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("returncode must be an integer or null")
    return value


def _optional_nonnegative_int(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError("matching_attempts must be a non-negative integer")
    return value


def _attempt_payload(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise TypeError("attempt must be an object")
    observed = value.get("observed_fingerprints", [])
    if not isinstance(observed, list) or not all(isinstance(item, str) for item in observed):
        raise TypeError("attempt observed_fingerprints must be an array of strings")
    return {
        "status": str(value.get("status", "")),
        "observed_fingerprints": tuple(observed),
        "command": tuple(item for item in value.get("command", []) if isinstance(item, str)),
        "returncode": value.get("returncode"),
        "matches": bool(value.get("matches", False)),
        "provenance": value.get("provenance"),
    }


def _attempt_record(result: ReproductionResult) -> Mapping[str, object]:
    return _attempt_record_payload(
        status=result.status,
        observed=result.observed_fingerprints,
        command=result.command,
        returncode=result.returncode,
        provenance=result.provenance,
    )


def _attempt_record_payload(
    *,
    status: str,
    observed: tuple[str, ...],
    command: tuple[str, ...],
    returncode: int | None,
    provenance: Mapping[str, object] | None,
) -> Mapping[str, object]:
    return {
        "status": status,
        "observed_fingerprints": tuple(observed),
        "command": tuple(command),
        "returncode": returncode,
        "matches": status == "reproduced",
        "provenance": dict(provenance) if provenance else None,
    }
