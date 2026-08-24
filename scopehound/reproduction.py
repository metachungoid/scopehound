from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType

from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output
from scopehound.manifest import Manifest
from scopehound.policy import require_authorized
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


def reproduce_finding(
    manifest: Manifest,
    workspace: Workspace,
    artifact: Path,
    expected_fingerprint: str,
    execute: bool = False,
    timeout_seconds: int = 120,
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
    result = run_plan(plan, execute=execute, allow_failure=True)
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
    return ReproductionResult(
        artifact=artifact_path.name,
        expected_fingerprint=expected_fingerprint,
        observed_fingerprints=observed,
        status=status,
        command=argv,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def write_reproduction(result: ReproductionResult, output: Path) -> None:
    payload = asdict(result)
    payload["command"] = list(result.command)
    payload["observed_fingerprints"] = list(result.observed_fingerprints)
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
