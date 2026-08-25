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


def load_reproduction(path: Path) -> ReproductionResult:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("reproduction record must be an object")
        return ReproductionResult(
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
        )
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
    )


def write_reproduction(result: ReproductionResult, output: Path) -> None:
    payload = asdict(result)
    payload["command"] = list(result.command)
    payload["observed_fingerprints"] = list(result.observed_fingerprints)
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
