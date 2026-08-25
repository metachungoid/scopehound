from __future__ import annotations

import hashlib
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
class MinimizedArtifact:
    parent: str
    child: str
    parent_sha256: str
    child_sha256: str | None
    expected_fingerprint: str
    status: str
    attempts: int
    command: tuple[str, ...]


def minimize_artifact(
    manifest: Manifest,
    workspace: Workspace,
    artifact: Path,
    expected_fingerprint: str,
    *,
    execute: bool = False,
    timeout_seconds: int = 120,
) -> MinimizedArtifact:
    require_authorized(manifest)
    if not 1 <= timeout_seconds <= 3_600:
        raise ScopeHoundError("duration_invalid", "minimization timeout must be between 1 and 3600 seconds")
    if manifest.commands.reproduce is None:
        raise ScopeHoundError("reproduction_unconfigured", "commands.reproduce is required for minimization")
    parent = _artifact_path(workspace, manifest.target.name, artifact)
    parent_bytes = parent.read_bytes()
    parent_sha = _digest(parent_bytes)
    child = parent.with_name(parent.name + ".minimized")
    if child.exists() and child.resolve() != parent.resolve():
        raise ScopeHoundError("output_exists", f"minimized artifact already exists: {child}")
    if not execute:
        result = MinimizedArtifact(str(parent), str(child), parent_sha, None, expected_fingerprint, "planned", 0, ())
        _write_result(result, workspace.provenance_dir(manifest.target.name) / f"minimize-{parent.name}.json")
        return result
    repository = workspace.repo_dir(manifest.target.name)
    if not repository.is_dir():
        raise ScopeHoundError("workspace_missing", f"target checkout is missing: {repository}")
    current = parent_bytes
    attempts = 0
    last_command: tuple[str, ...] = ()
    chunk = max(1, len(current) // 2)
    while chunk >= 1 and len(current) > 1:
        changed = False
        for start in range(0, len(current), chunk):
            trial = current[:start] + current[start + chunk:]
            if not trial or trial == current:
                continue
            child.write_bytes(trial)
            command = tuple(argument.replace("{artifact}", str(child)) for argument in manifest.commands.reproduce)
            last_command = command
            plan = CommandPlan(
                argv=command, cwd=repository, environment=MappingProxyType(dict(manifest.environment)),
                timeout_seconds=timeout_seconds, mutates=True,
                create_directories=(workspace.logs_dir(manifest.target.name),),
            )
            observed = run_plan(plan, execute=True, allow_failure=True)
            attempts += 1
            findings = parse_sanitizer_output(observed.stdout + "\n" + observed.stderr, child)
            if expected_fingerprint in {finding.fingerprint for finding in findings}:
                current = trial
                changed = True
                break
        if not changed:
            chunk //= 2
    child.write_bytes(current)
    child_sha = _digest(current)
    result = MinimizedArtifact(
        str(parent), str(child), parent_sha, child_sha, expected_fingerprint,
        "minimized" if len(current) < len(parent_bytes) else "unchanged", attempts, last_command,
    )
    _write_result(result, workspace.provenance_dir(manifest.target.name) / f"minimize-{parent.name}.json")
    return result


def _artifact_path(workspace: Workspace, target_name: str, artifact: Path) -> Path:
    root = workspace.artifacts_dir(target_name)
    resolved = artifact.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ScopeHoundError("unsafe_path", "artifact must remain inside target artifacts") from error
    if not resolved.is_file():
        raise ScopeHoundError("input_invalid", f"artifact is missing: {resolved}")
    return resolved


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_result(result: MinimizedArtifact, output: Path) -> None:
    payload = asdict(result)
    payload["command"] = list(result.command)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write minimization record {output}: {error}") from error


def write_minimized(result: MinimizedArtifact, output: Path) -> None:
    _write_result(result, output)
