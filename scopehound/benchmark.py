from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from scopehound.errors import ScopeHoundError
from scopehound.workspace import Workspace


@dataclass(frozen=True)
class BenchmarkResult:
    version: int
    fixtures: int
    link_success_rate: float
    coverage_delta: float
    unique_fingerprints_per_cpu_hour: float
    replay_success_rate: float
    duplicate_rate: float
    false_positive_rate: float
    skipped_tools: tuple[str, ...]


def run_benchmark(fixtures_dir: Path, workspace: Workspace, *, execute: bool = False) -> BenchmarkResult:
    root = fixtures_dir.expanduser().resolve()
    if not root.is_dir():
        raise ScopeHoundError("input_invalid", f"benchmark fixtures directory is missing: {root}")
    metadata_path = root / "benchmark.json"
    try:
        payload: Any = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read benchmark metadata: {error}") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("fixtures"), list):
        raise ScopeHoundError("input_invalid", "benchmark metadata must contain a fixtures array")
    version = payload.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ScopeHoundError("input_invalid", "benchmark version must be a positive integer")
    entries = [item for item in payload["fixtures"] if isinstance(item, dict)]
    total = len(entries)
    built = sum(item.get("link_status") == "built" for item in entries)
    coverage = sum(_number(item.get("coverage_delta", 0.0)) for item in entries)
    cpu_seconds = sum(_number(item.get("cpu_seconds", 0.0)) for item in entries)
    unique = sum(_number(item.get("unique_fingerprints", 0.0)) for item in entries)
    replay_attempts = sum(item.get("replay", "not_attempted") != "not_attempted" for item in entries)
    replay_successes = sum(item.get("replay") == "success" for item in entries)
    duplicates = sum(_number(item.get("duplicates", 0.0)) for item in entries)
    findings = sum(_number(item.get("findings", 0.0)) for item in entries)
    false_positives = sum(_number(item.get("false_positives", 0.0)) for item in entries)
    skipped: list[str] = []
    if shutil.which("llvm-cov") is None:
        skipped.append("llvm-cov")
    if shutil.which("llvm-symbolizer") is None:
        skipped.append("llvm-symbolizer")
    result = BenchmarkResult(
        version=version,
        fixtures=total,
        link_success_rate=built / total if total else 0.0,
        coverage_delta=coverage / total if total else 0.0,
        unique_fingerprints_per_cpu_hour=unique * 3600.0 / cpu_seconds if cpu_seconds else 0.0,
        replay_success_rate=replay_successes / replay_attempts if replay_attempts else 0.0,
        duplicate_rate=duplicates / total if total else 0.0,
        false_positive_rate=false_positives / findings if findings else 0.0,
        skipped_tools=tuple(sorted(skipped)),
    )
    output = workspace.root / "benchmark.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(_serialize(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write benchmark result: {error}") from error
    return result


def write_benchmark_markdown(result: BenchmarkResult, output: Path) -> None:
    text = f"""# ScopeHound benchmark

- Fixture version: `{result.version}`
- Fixtures: `{result.fixtures}`
- Link success rate: `{result.link_success_rate:.3f}`
- Mean coverage delta: `{result.coverage_delta:.3f}`
- Unique fingerprints per CPU-hour: `{result.unique_fingerprints_per_cpu_hour:.3f}`
- Replay success rate: `{result.replay_success_rate:.3f}`
- Duplicate rate: `{result.duplicate_rate:.3f}`
- False-positive rate: `{result.false_positive_rate:.3f}`
- Skipped tools: `{', '.join(result.skipped_tools) if result.skipped_tools else 'none'}`
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write benchmark report: {error}") from error


def _serialize(result: BenchmarkResult) -> dict[str, object]:
    payload = asdict(result)
    payload["skipped_tools"] = list(result.skipped_tools)
    return payload


def _number(value: object) -> float:
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0
