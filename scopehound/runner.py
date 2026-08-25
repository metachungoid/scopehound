from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.manifest import Manifest
from scopehound.policy import require_authorized
from scopehound.sandbox import wrap_plan
from scopehound.workspace import Workspace


@dataclass(frozen=True)
class CommandPlan:
    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    timeout_seconds: float
    mutates: bool
    create_directories: tuple[Path, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    executed: bool
    backend: str = "native"
    policy: Mapping[str, object] = field(default_factory=dict)


def prepare_plans(
    manifest: Manifest,
    workspace: Workspace,
    allow_local_repository: bool = False,
) -> tuple[CommandPlan, CommandPlan]:
    require_authorized(manifest)
    repository = manifest.target.repository
    if _is_local_repository(repository) and not allow_local_repository:
        raise ScopeHoundError(
            "local_repository_not_allowed",
            "local repositories require --allow-local-repository",
        )
    target_dir = workspace.target_dir(manifest.target.name)
    repo_dir = workspace.repo_dir(manifest.target.name)
    if repo_dir.exists():
        raise ScopeHoundError(
            "workspace_exists", f"target checkout already exists: {repo_dir}"
        )
    environment = MappingProxyType(dict(manifest.environment))
    clone = CommandPlan(
        argv=("git", "clone", "--no-checkout", repository, str(repo_dir)),
        cwd=target_dir,
        environment=environment,
        timeout_seconds=600,
        mutates=True,
        create_directories=(target_dir,),
    )
    checkout = CommandPlan(
        argv=("git", "checkout", "--detach", manifest.target.revision),
        cwd=repo_dir,
        environment=environment,
        timeout_seconds=300,
        mutates=True,
    )
    return clone, checkout


def build_plan(manifest: Manifest, workspace: Workspace) -> CommandPlan:
    require_authorized(manifest)
    return CommandPlan(
        argv=manifest.commands.build,
        cwd=workspace.repo_dir(manifest.target.name),
        environment=MappingProxyType(dict(manifest.environment)),
        timeout_seconds=1800,
        mutates=True,
        create_directories=(workspace.logs_dir(manifest.target.name),),
    )


def fuzz_plan(
    manifest: Manifest, workspace: Workspace, duration_seconds: int
) -> CommandPlan:
    require_authorized(manifest)
    if not 1 <= duration_seconds <= 86_400:
        raise ScopeHoundError(
            "duration_invalid", "fuzz duration must be between 1 and 86400 seconds"
        )
    artifacts_dir = workspace.artifacts_dir(manifest.target.name)
    environment = dict(manifest.environment)
    environment["SCOPEHOUND_ARTIFACTS_DIR"] = str(artifacts_dir)
    return CommandPlan(
        argv=manifest.commands.fuzz,
        cwd=workspace.repo_dir(manifest.target.name),
        environment=MappingProxyType(environment),
        timeout_seconds=duration_seconds + 10,
        mutates=True,
        create_directories=(artifacts_dir, workspace.logs_dir(manifest.target.name)),
    )


def run_plan(
    plan: CommandPlan,
    execute: bool = False,
    allow_failure: bool = False,
    *,
    backend: str = "native",
) -> CommandResult:
    wrapped = wrap_plan(plan, backend)
    policy = {
        "name": wrapped.policy.name,
        "network": wrapped.policy.network,
        "read_only_repo": wrapped.policy.read_only_repo,
        "cpu_seconds": wrapped.policy.cpu_seconds,
        "memory_mb": wrapped.policy.memory_mb,
        "process_limit": wrapped.policy.process_limit,
    }
    if not execute:
        return CommandResult(wrapped.argv, None, "", "", False, backend, policy)

    for directory in plan.create_directories:
        directory.mkdir(parents=True, exist_ok=True)
    plan.cwd.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(plan.environment)
    try:
        completed = subprocess.run(
            wrapped.argv,
            cwd=plan.cwd,
            env=environment,
            shell=False,
            capture_output=True,
            text=True,
            timeout=plan.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ScopeHoundError(
            "timeout",
            f"command exceeded {plan.timeout_seconds:g} seconds: {plan.argv[0]}",
        ) from error
    except OSError as error:
        raise ScopeHoundError(
            "command_failed", f"could not start {plan.argv[0]}: {error}"
        ) from error

    result = CommandResult(
        argv=wrapped.argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        executed=True,
        backend=backend,
        policy=policy,
    )
    if completed.returncode != 0 and not allow_failure:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise ScopeHoundError(
            "command_failed",
            f"command exited {completed.returncode}: {detail[:1000]}",
        )
    return result


def _is_local_repository(repository: str) -> bool:
    return repository.startswith("file://") or Path(repository).is_absolute()
