from __future__ import annotations

import hashlib
import random
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.runner import CommandPlan, run_plan


@dataclass(frozen=True)
class EngineInfo:
    name: str
    available: bool
    executable: str | None
    reason: str


@dataclass(frozen=True)
class EngineRun:
    engine: str
    status: str
    command: tuple[str, ...]
    duration_seconds: float
    input_count: int
    corpus_before: int
    corpus_after: int
    artifacts: tuple[str, ...]
    mutations: tuple[Mapping[str, object], ...]
    stdout: str
    stderr: str
    toolchain: Mapping[str, str]
    skipped_reason: str | None = None


def list_engines() -> tuple[EngineInfo, ...]:
    gcc = shutil.which("gcc")
    clang = shutil.which("clang")
    return (
        EngineInfo(
            "standalone", gcc is not None, gcc,
            "available" if gcc else "gcc is not installed",
        ),
        EngineInfo(
            "libfuzzer", clang is not None, clang,
            "available" if clang else "clang/libFuzzer is not installed",
        ),
    )


def deterministic_mutations(
    seed: bytes,
    *,
    max_input_size: int,
    count: int,
    seed_value: int,
) -> tuple[bytes, ...]:
    if max_input_size < 1:
        raise ScopeHoundError("input_invalid", "max_input_size must be positive")
    if count < 0:
        raise ScopeHoundError("input_invalid", "mutation count cannot be negative")
    original = seed[:max_input_size]
    randomizer = random.Random(seed_value)
    mutations: list[bytes] = []
    for _ in range(count):
        value = bytearray(original)
        operation = randomizer.randrange(4)
        if operation == 0:
            index = randomizer.randrange(len(value) or 1)
            if value:
                value[index] = randomizer.randrange(256)
            else:
                value.append(randomizer.randrange(256))
        elif operation == 1 and len(value) < max_input_size:
            index = randomizer.randrange(len(value) + 1)
            value.insert(index, randomizer.randrange(256))
        elif operation == 2 and value:
            del value[randomizer.randrange(len(value))]
        else:
            length = randomizer.randrange(len(value) + 1) if value else 0
            value = value[:length]
        mutations.append(bytes(value[:max_input_size]))
    return tuple(mutations)


def run_standalone(
    binary: Path,
    corpus: Path,
    artifacts: Path,
    *,
    duration_seconds: int,
    max_input_size: int,
    seed_value: int,
    execute: bool,
    backend: str,
) -> EngineRun:
    _validate_duration(duration_seconds)
    if not binary.is_absolute():
        binary = binary.resolve()
    seed_files = tuple(path for path in sorted(corpus.rglob("*")) if path.is_file()) if corpus.exists() else ()
    seeds = [(path.name, path.read_bytes()[:max_input_size]) for path in seed_files]
    if not seeds:
        seeds = [("empty", b"")]
    cases: list[tuple[str, bytes, str | None, int | None]] = []
    for name, seed in seeds:
        parent = hashlib.sha256(seed).hexdigest()
        cases.append((name, seed, None, None))
        for index, mutation in enumerate(
            deterministic_mutations(seed, max_input_size=max_input_size, count=4, seed_value=seed_value)
        ):
            cases.append((f"{name}-mutation-{index}", mutation, parent, seed_value))
    if not execute:
        command = (str(binary), "<artifact>")
        return EngineRun(
            engine="standalone", status="planned", command=command, duration_seconds=0.0,
            input_count=len(cases), corpus_before=len(seeds), corpus_after=len(seeds),
            artifacts=(), mutations=tuple(_mutation_record(name, data, parent, value) for name, data, parent, value in cases),
            stdout="", stderr="", toolchain=_toolchain_versions(),
        )

    artifacts.mkdir(parents=True, exist_ok=True)
    inputs_dir = artifacts / "inputs"
    logs_dir = artifacts / "logs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    outputs: list[str] = []
    evidence: list[str] = []
    mutation_records: list[Mapping[str, object]] = []
    status = "completed"
    all_stdout: list[str] = []
    all_stderr: list[str] = []
    representative: tuple[str, ...] = (str(binary), "<artifact>")
    for name, data, parent, mutation_seed in cases:
        if time.monotonic() - started >= duration_seconds:
            status = "timeout"
            break
        digest = hashlib.sha256(data).hexdigest()
        input_path = inputs_dir / f"{digest}.bin"
        input_path.write_bytes(data)
        plan = CommandPlan(
            argv=(str(binary), str(input_path)), cwd=binary.parent, environment={},
            timeout_seconds=max(0.1, duration_seconds - (time.monotonic() - started)), mutates=False,
        )
        try:
            result = run_plan(plan, execute=True, allow_failure=True, backend=backend)
            output = result.stdout + "\n" + result.stderr
            all_stdout.append(result.stdout)
            all_stderr.append(result.stderr)
            log_path = logs_dir / f"{digest}.log"
            log_path.write_text(output, encoding="utf-8")
            outputs.append(str(log_path))
            sanitizer = _has_sanitizer_output(output)
            if sanitizer:
                status = "finding"
                evidence.append(str(input_path))
            elif result.returncode not in (0, None) and status != "finding":
                status = "failed"
            mutation_records.append(_mutation_record(name, data, parent, mutation_seed, sanitizer=sanitizer))
            representative = result.argv
        except ScopeHoundError as raised:
            status = "failed"
            all_stderr.append(raised.message)
            mutation_records.append(_mutation_record(name, data, parent, mutation_seed, error=raised.message))
            break
    return EngineRun(
        engine="standalone", status=status, command=representative,
        duration_seconds=round(time.monotonic() - started, 3), input_count=len(mutation_records),
        corpus_before=len(seeds), corpus_after=len(seeds), artifacts=tuple(evidence),
        mutations=tuple(mutation_records), stdout="\n".join(all_stdout), stderr="\n".join(all_stderr),
        toolchain=_toolchain_versions(),
    )


def run_libfuzzer(
    binary: Path,
    corpus: Path,
    artifacts: Path,
    *,
    duration_seconds: int,
    dictionary: Path | None,
    execute: bool,
    backend: str,
) -> EngineRun:
    _validate_duration(duration_seconds)
    info = next(item for item in list_engines() if item.name == "libfuzzer")
    if not info.available:
        raise ScopeHoundError("engine_unavailable", info.reason)
    artifacts.mkdir(parents=True, exist_ok=True) if execute else None
    argv = [str(binary), str(corpus), f"-max_total_time={duration_seconds}", f"-artifact_prefix={artifacts}/"]
    if dictionary is not None:
        argv.append(f"-dict={dictionary}")
    plan = CommandPlan(
        argv=tuple(argv), cwd=binary.parent, environment={}, timeout_seconds=duration_seconds + 10,
        mutates=True, create_directories=(corpus, artifacts),
    )
    result = run_plan(plan, execute=execute, allow_failure=True, backend=backend)
    output = result.stdout + "\n" + result.stderr
    status = "planned" if not execute else ("finding" if _has_sanitizer_output(output) else ("completed" if result.returncode == 0 else "failed"))
    return EngineRun(
        engine="libfuzzer", status=status, command=tuple(argv), duration_seconds=float(duration_seconds),
        input_count=0, corpus_before=0, corpus_after=0, artifacts=tuple(str(p) for p in artifacts.glob("*")) if execute else (),
        mutations=(), stdout=result.stdout, stderr=result.stderr, toolchain=_toolchain_versions(),
    )


def _mutation_record(
    name: str,
    data: bytes,
    parent: str | None,
    mutation_seed: int | None,
    *,
    sanitizer: bool = False,
    error: str | None = None,
) -> Mapping[str, object]:
    return {
        "name": name, "input_sha256": hashlib.sha256(data).hexdigest(),
        "parent_sha256": parent, "mutation_seed": mutation_seed,
        "sanitizer": sanitizer, "error": error,
    }


def _has_sanitizer_output(output: str) -> bool:
    return any(token in output for token in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:"))


def _toolchain_versions() -> Mapping[str, str]:
    values: dict[str, str] = {}
    for name in ("gcc", "clang"):
        executable = shutil.which(name)
        if executable is None:
            continue
        try:
            result = subprocess.run((executable, "--version"), capture_output=True, text=True, shell=False, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        first_line = (result.stdout or result.stderr).splitlines()
        if first_line:
            values[name] = first_line[0][:200]
    return values


def _validate_duration(duration_seconds: int) -> None:
    if not 1 <= duration_seconds <= 86_400:
        raise ScopeHoundError("duration_invalid", "engine duration must be between 1 and 86400 seconds")
