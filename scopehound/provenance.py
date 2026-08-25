from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.manifest import Manifest
from scopehound.runner import CommandResult


@dataclass(frozen=True)
class ProvenanceRecord:
    target: str
    repository: str
    revision: str
    manifest_digest: str
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    host_platform: str
    toolchain: Mapping[str, str]
    sanitizer_runtime: str | None
    source_sha256: str | None
    binary_sha256: str | None
    corpus_sha256: str | None
    dictionary_sha256: str | None
    started_at: str
    ended_at: str
    timeout_seconds: float
    backend: str
    backend_policy: Mapping[str, object]
    executed: bool


def create_provenance(
    manifest: Manifest,
    result: CommandResult,
    *,
    backend: str = "native",
    timeout_seconds: float = 0.0,
    environment: Mapping[str, str] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    source_sha256: str | None = None,
    binary_sha256: str | None = None,
    corpus_sha256: str | None = None,
    dictionary_sha256: str | None = None,
    sanitizer_runtime: str | None = None,
    backend_policy: Mapping[str, object] | None = None,
) -> ProvenanceRecord:
    now = _utc_now()
    values = dict(environment or {})
    selected_environment = {
        key: values[key]
        for key in sorted(values)
        if key in {"CC", "CXX", "CFLAGS", "CXXFLAGS", "ASAN_OPTIONS", "UBSAN_OPTIONS"}
    }
    toolchain = {
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    for key in ("CC", "CXX"):
        if key in values:
            toolchain[key] = values[key]
    return ProvenanceRecord(
        target=manifest.target.name,
        repository=manifest.target.repository,
        revision=manifest.target.revision,
        manifest_digest=manifest_digest(manifest),
        argv=result.argv,
        environment=MappingProxyType(selected_environment),
        host_platform=platform.platform(),
        toolchain=MappingProxyType(toolchain),
        sanitizer_runtime=sanitizer_runtime,
        source_sha256=source_sha256,
        binary_sha256=binary_sha256,
        corpus_sha256=corpus_sha256,
        dictionary_sha256=dictionary_sha256,
        started_at=start_time or now,
        ended_at=end_time or now,
        timeout_seconds=float(timeout_seconds),
        backend=backend,
        backend_policy=MappingProxyType(dict(backend_policy or {})),
        executed=result.executed,
    )


def manifest_digest(manifest: Manifest) -> str:
    payload = {
        "schema_version": manifest.schema_version,
        "target": asdict(manifest.target),
        "authorization": asdict(manifest.authorization),
        "commands": {
            "build": list(manifest.commands.build), "fuzz": list(manifest.commands.fuzz),
            "reproduce": list(manifest.commands.reproduce) if manifest.commands.reproduce else None,
            "harness_build": list(manifest.commands.harness_build) if manifest.commands.harness_build else None,
        },
        "environment": dict(manifest.environment),
        "corpus": asdict(manifest.corpus),
        "opportunity": asdict(manifest.opportunity),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def normalize_stack(frames: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for frame in frames:
        match = re.search(r"(?P<prefix>.*?\bat\s+)(?P<path>/[^: ]+)(?P<suffix>:\d+(?::\d+)?)$", frame)
        if match:
            normalized.append(f"{match.group('prefix')}{Path(match.group('path')).name}{match.group('suffix')}")
        else:
            normalized.append(frame.strip())
    return tuple(normalized)


def symbolize_stack(
    frames: tuple[str, ...] | list[str], symbolizer: str, cwd: Path, *, execute: bool = False
) -> tuple[str, ...]:
    original = tuple(frames)
    if not execute:
        return original
    try:
        completed = subprocess.run(
            (symbolizer,), cwd=cwd, input="\n".join(original) + "\n", text=True,
            capture_output=True, shell=False, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScopeHoundError("symbolizer_failed", f"could not run {symbolizer}: {error}") from error
    output = tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())
    return output or original


def write_provenance(record: ProvenanceRecord, output: Path) -> None:
    payload = {
        "target": record.target, "repository": record.repository, "revision": record.revision,
        "manifest_digest": record.manifest_digest, "argv": list(record.argv),
        "environment": dict(record.environment), "host_platform": record.host_platform,
        "toolchain": dict(record.toolchain), "sanitizer_runtime": record.sanitizer_runtime,
        "source_sha256": record.source_sha256, "binary_sha256": record.binary_sha256,
        "corpus_sha256": record.corpus_sha256, "dictionary_sha256": record.dictionary_sha256,
        "started_at": record.started_at, "ended_at": record.ended_at,
        "timeout_seconds": record.timeout_seconds, "backend": record.backend,
        "backend_policy": dict(record.backend_policy), "executed": record.executed,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write provenance {output}: {error}") from error


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
