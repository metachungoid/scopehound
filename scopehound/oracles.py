from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.runner import CommandPlan, run_plan


@dataclass(frozen=True)
class OracleResult:
    kind: str
    status: str
    input_sha256: str
    left_command: tuple[str, ...]
    right_command: tuple[str, ...]
    left_output: str
    right_output: str
    duration_seconds: float
    details: Mapping[str, object]


def compare_outputs(
    kind: str, input_data: bytes, left_output: str, right_output: str
) -> OracleResult:
    if kind not in {"differential", "metamorphic", "roundtrip"}:
        raise ScopeHoundError("oracle_invalid", f"unsupported oracle kind: {kind}")
    status = "match" if left_output == right_output else "disagreement"
    return OracleResult(
        kind=kind,
        status=status,
        input_sha256=hashlib.sha256(input_data).hexdigest(),
        left_command=(),
        right_command=(),
        left_output=left_output,
        right_output=right_output,
        duration_seconds=0.0,
        details={
            "oracle_disagreement_is_not_memory_finding": status == "disagreement",
        },
    )


def run_oracle(
    kind: str,
    left_command: tuple[str, ...],
    right_command: tuple[str, ...],
    artifact: Path,
    cwd: Path,
    *,
    execute: bool,
    timeout_seconds: int,
    backend: str = "native",
) -> OracleResult:
    if not 1 <= timeout_seconds <= 3_600:
        raise ScopeHoundError("duration_invalid", "oracle timeout must be between 1 and 3600 seconds")
    if not artifact.is_file() or artifact.is_symlink():
        raise ScopeHoundError("input_invalid", f"oracle artifact is missing: {artifact}")
    rendered_left = _render(left_command, artifact)
    rendered_right = _render(right_command, artifact)
    input_data = artifact.read_bytes()
    if not execute:
        return OracleResult(
            kind=kind,
            status="planned",
            input_sha256=hashlib.sha256(input_data).hexdigest(),
            left_command=rendered_left,
            right_command=rendered_right,
            left_output="",
            right_output="",
            duration_seconds=0.0,
            details={"oracle_disagreement_is_not_memory_finding": True},
        )
    started = time.monotonic()
    try:
        left = run_plan(
            CommandPlan(rendered_left, cwd, {}, timeout_seconds, False),
            execute=True,
            allow_failure=True,
            backend=backend,
        )
        right = run_plan(
            CommandPlan(rendered_right, cwd, {}, timeout_seconds, False),
            execute=True,
            allow_failure=True,
            backend=backend,
        )
    except ScopeHoundError as error:
        status = "timeout" if error.category == "timeout" else "error"
        return OracleResult(
            kind=kind,
            status=status,
            input_sha256=hashlib.sha256(input_data).hexdigest(),
            left_command=rendered_left,
            right_command=rendered_right,
            left_output="",
            right_output="",
            duration_seconds=round(time.monotonic() - started, 3),
            details={"error": error.message, "oracle_disagreement_is_not_memory_finding": True},
        )
    result = compare_outputs(kind, input_data, left.stdout + left.stderr, right.stdout + right.stderr)
    return OracleResult(
        kind=result.kind,
        status=result.status if left.returncode == right.returncode else "error",
        input_sha256=result.input_sha256,
        left_command=rendered_left,
        right_command=rendered_right,
        left_output=result.left_output,
        right_output=result.right_output,
        duration_seconds=round(time.monotonic() - started, 3),
        details={
            **dict(result.details),
            "left_returncode": left.returncode,
            "right_returncode": right.returncode,
        },
    )


def _render(command: tuple[str, ...], artifact: Path) -> tuple[str, ...]:
    return tuple(argument.replace("{artifact}", str(artifact)) for argument in command)


def write_oracle(result: OracleResult, output: Path) -> None:
    payload = asdict(result)
    payload["left_command"] = list(result.left_command)
    payload["right_command"] = list(result.right_command)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write oracle output {output}: {error}") from error
