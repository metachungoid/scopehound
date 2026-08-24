from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from scopehound.errors import ScopeHoundError
from scopehound.manifest import Manifest
from scopehound.policy import require_authorized
from scopehound.runner import CommandPlan, run_plan
from scopehound.workspace import Workspace


@dataclass(frozen=True)
class HarnessValidation:
    generated_file: str
    command: tuple[str, ...]
    status: str
    returncode: int | None
    stdout: str
    stderr: str


def validate_harnesses(
    manifest: Manifest,
    workspace: Workspace,
    harnesses_dir: Path,
    compiler: str,
    execute: bool = False,
) -> tuple[HarnessValidation, ...]:
    """Syntax-check generated harnesses without linking or executing them."""
    require_authorized(manifest)
    target_dir = workspace.target_dir(manifest.target.name)
    harness_root = _contained(target_dir, harnesses_dir, "harness directory")
    repository = workspace.repo_dir(manifest.target.name)
    if execute and not repository.is_dir():
        raise ScopeHoundError(
            "workspace_missing", f"target checkout is missing: {repository}"
        )

    generated_files = _load_generated_files(harness_root)
    plans = tuple(
        _validation_plan(
            manifest,
            repository,
            harness_root / generated_file,
            compiler,
        )
        for generated_file in generated_files
    )
    validations: list[HarnessValidation] = []
    for generated_file, plan in zip(generated_files, plans):
        result = run_plan(plan, execute=execute, allow_failure=True)
        if not execute:
            status = "planned"
        elif result.returncode == 0:
            status = "syntax_valid"
        else:
            status = "syntax_invalid"
        validations.append(
            HarnessValidation(
                generated_file=generated_file,
                command=plan.argv,
                status=status,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        )
    return tuple(validations)


def write_validation(results: tuple[HarnessValidation, ...], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = []
    for result in results:
        item = asdict(result)
        item["command"] = list(result.command)
        payload.append(item)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write validation output: {error}") from error


def _validation_plan(
    manifest: Manifest,
    repository: Path,
    generated_file: Path,
    compiler: str,
) -> CommandPlan:
    return CommandPlan(
        argv=(compiler, "-std=c++17", "-fsyntax-only", "-I", str(repository), str(generated_file)),
        cwd=repository,
        environment=MappingProxyType(dict(manifest.environment)),
        timeout_seconds=120,
        mutates=False,
    )


def _load_generated_files(harnesses_dir: Path) -> tuple[str, ...]:
    metadata_path = harnesses_dir / "harnesses.json"
    try:
        raw: Any = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError(
            "input_invalid", f"cannot read harness metadata: {error}"
        ) from error
    if not isinstance(raw, list):
        raise ScopeHoundError("input_invalid", "harness metadata must be an array")

    names: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("generated_file"), str):
            raise ScopeHoundError(
                "input_invalid", f"harness metadata item {index} lacks generated_file"
            )
        name = item["generated_file"]
        candidate = Path(name)
        if (
            not name
            or candidate.name != name
            or candidate.suffix.lower() not in {".cc", ".cpp", ".cxx"}
        ):
            raise ScopeHoundError("unsafe_path", f"invalid generated harness path: {name}")
        _contained(harnesses_dir, harnesses_dir / name, "generated harness")
        if not (harnesses_dir / name).is_file():
            raise ScopeHoundError(
                "input_invalid", f"generated harness is missing: {harnesses_dir / name}"
            )
        names.append(name)
    return tuple(names)


def _contained(base: Path, candidate: Path, label: str) -> Path:
    resolved_base = base.resolve()
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_base)
    except ValueError as error:
        raise ScopeHoundError(
            "unsafe_path", f"{label} must remain inside the target workspace"
        ) from error
    return resolved_candidate
