from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from scopehound.errors import ScopeHoundError

if TYPE_CHECKING:
    from scopehound.runner import CommandPlan


@dataclass(frozen=True)
class BackendPolicy:
    name: str
    network: str
    read_only_repo: bool
    cpu_seconds: int
    memory_mb: int
    process_limit: int


@dataclass(frozen=True)
class WrappedPlan:
    argv: tuple[str, ...]
    policy: BackendPolicy


_POLICIES = {
    "native": BackendPolicy("native", "host", False, 0, 0, 0),
    "bubblewrap": BackendPolicy("bubblewrap", "none", True, 600, 4096, 128),
    "docker": BackendPolicy("docker", "none", True, 600, 4096, 128),
}


def backend_policy(name: str) -> BackendPolicy:
    try:
        return _POLICIES[name]
    except KeyError as error:
        raise ScopeHoundError("sandbox_invalid", f"unknown execution backend: {name}") from error


def backend_available(name: str) -> bool:
    backend_policy(name)
    return name == "native" or shutil.which("bwrap" if name == "bubblewrap" else "docker") is not None


def wrap_plan(plan: "CommandPlan", name: str = "native", *, check_available: bool = True) -> WrappedPlan:
    policy = backend_policy(name)
    if check_available and not backend_available(name):
        tool = "bwrap" if name == "bubblewrap" else "docker"
        raise ScopeHoundError("sandbox_unavailable", f"execution backend {name} requires {tool}")
    if name == "native":
        return WrappedPlan(tuple(plan.argv), policy)
    root = plan.cwd.parent.resolve()
    repo = plan.cwd.resolve()
    if name == "bubblewrap":
        argv = (
            "bwrap", "--die-with-parent", "--new-session", "--unshare-net",
            "--unshare-pid", "--unshare-uts", "--unshare-ipc", "--unshare-user",
            "--uid", "65534", "--gid", "65534", "--bind", str(root), str(root),
            "--ro-bind", str(repo), str(repo), "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/tmp", "--chdir", str(plan.cwd), "--", *plan.argv,
        )
        return WrappedPlan(tuple(argv), policy)
    image = os.environ.get("SCOPEHOUND_DOCKER_IMAGE", "scopehound-toolchain:latest")
    argv = (
        "docker", "run", "--rm", "--network", "none", "--read-only", "--user", "65534:65534",
        "--cpus", "1", "--memory", f"{policy.memory_mb}m", "--pids-limit", str(policy.process_limit),
        "--cap-drop", "ALL", "-v", f"{root}:{root}:rw", "-v", f"{repo}:{repo}:ro",
        "-w", str(plan.cwd), image, *plan.argv,
    )
    return WrappedPlan(tuple(argv), policy)
