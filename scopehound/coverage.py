from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from scopehound.errors import ScopeHoundError
from scopehound.manifest import Manifest
from scopehound.policy import require_authorized
from scopehound.workspace import Workspace


@dataclass(frozen=True)
class CorpusStats:
    count: int
    bytes: int
    digest: str | None


@dataclass(frozen=True)
class CoverageArtifact:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class CoverageRecord:
    candidate_id: str
    before: CorpusStats
    after: CorpusStats
    engine_stats: Mapping[str, float | int]
    coverage_artifacts: tuple[CoverageArtifact, ...]
    function_delta: int | None
    edge_delta: int | None
    cpu_seconds: float
    finding_count: int


def load_coverage(path: Path) -> CoverageRecord:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("coverage record must be an object")
        before = payload["before"]
        after = payload["after"]
        artifacts = payload.get("coverage_artifacts", [])
        if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(artifacts, list):
            raise TypeError("coverage record sections have invalid types")
        return CoverageRecord(
            candidate_id=str(payload["candidate_id"]),
            before=CorpusStats(int(before["count"]), int(before["bytes"]), before.get("digest")),
            after=CorpusStats(int(after["count"]), int(after["bytes"]), after.get("digest")),
            engine_stats=dict(payload.get("engine_stats", {})),
            coverage_artifacts=tuple(
                CoverageArtifact(str(item["path"]), str(item["sha256"]), int(item["size"]))
                for item in artifacts
            ),
            function_delta=payload.get("function_delta"), edge_delta=payload.get("edge_delta"),
            cpu_seconds=float(payload.get("cpu_seconds", 0.0)),
            finding_count=int(payload.get("finding_count", 0)),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read coverage record {path}: {error}") from error


_STAT = re.compile(
    r"^\s*(?:stat::|#\s*)?(?P<key>[A-Za-z][A-Za-z0-9_. -]*?)\s*:\s*(?P<value>[0-9]+(?:\.[0-9]+)?)\s*$"
)


def summarize_engine_output(text: str) -> dict[str, float | int]:
    stats: dict[str, float | int] = {}
    for line in text.splitlines():
        match = _STAT.match(line)
        if not match:
            continue
        key = re.sub(r"[^a-z0-9]+", "_", match.group("key").strip().lower()).strip("_")
        if not key:
            continue
        raw = match.group("value")
        stats[key] = float(raw) if "." in raw else int(raw)
    return dict(sorted(stats.items()))


def collect_coverage(
    manifest: Manifest,
    workspace: Workspace,
    candidate_id: str,
    *,
    before_dir: Path | None = None,
    after_dir: Path | None = None,
    engine_output: str = "",
    coverage_paths: tuple[Path, ...] = (),
    llvm_before: Path | None = None,
    llvm_after: Path | None = None,
    cpu_seconds: float = 0.0,
    finding_count: int = 0,
) -> CoverageRecord:
    require_authorized(manifest)
    if cpu_seconds < 0 or finding_count < 0:
        raise ScopeHoundError("input_invalid", "cpu_seconds and finding_count must be non-negative")
    target_dir = workspace.target_dir(manifest.target.name)
    before = corpus_stats(before_dir, target_dir) if before_dir else CorpusStats(0, 0, None)
    after = corpus_stats(after_dir, target_dir) if after_dir else CorpusStats(0, 0, None)
    artifacts = tuple(_coverage_artifact(path, target_dir) for path in coverage_paths)
    function_delta, edge_delta = _llvm_delta(llvm_before, llvm_after)
    record = CoverageRecord(
        candidate_id=candidate_id,
        before=before,
        after=after,
        engine_stats=summarize_engine_output(engine_output),
        coverage_artifacts=artifacts,
        function_delta=function_delta,
        edge_delta=edge_delta,
        cpu_seconds=float(cpu_seconds),
        finding_count=finding_count,
    )
    _write_record(record, workspace.coverage_dir(manifest.target.name) / f"{candidate_id}.json")
    return record


def corpus_stats(directory: Path, target_dir: Path) -> CorpusStats:
    root = _contained(target_dir, directory, "corpus directory")
    if not root.exists():
        return CorpusStats(0, 0, None)
    if not root.is_dir():
        raise ScopeHoundError("input_invalid", f"corpus path is not a directory: {root}")
    files = [path for path in sorted(root.rglob("*")) if path.is_file()]
    digest = hashlib.sha256()
    total = 0
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        file_digest, size = _hash_file(path)
        digest.update(relative + b"\0" + file_digest.encode("ascii") + b"\0")
        total += size
    return CorpusStats(len(files), total, digest.hexdigest() if files else None)


def _coverage_artifact(path: Path, target_dir: Path) -> CoverageArtifact:
    resolved = _contained(target_dir, path, "coverage artifact")
    if not resolved.is_file():
        raise ScopeHoundError("input_invalid", f"coverage artifact is missing: {resolved}")
    digest, size = _hash_file(resolved)
    return CoverageArtifact(str(resolved), digest, size)


def _llvm_delta(before: Path | None, after: Path | None) -> tuple[int | None, int | None]:
    if before is None or after is None:
        return None, None
    before_data = _load_json(before)
    after_data = _load_json(after)
    before_functions, before_edges = _llvm_metrics(before_data)
    after_functions, after_edges = _llvm_metrics(after_data)
    return len(after_functions - before_functions), len(after_edges) - len(before_edges)


def _llvm_metrics(payload: object) -> tuple[set[str], list[str]]:
    if not isinstance(payload, dict):
        raise ScopeHoundError("input_invalid", "LLVM coverage export must be an object")
    entries = payload.get("data", [])
    if not isinstance(entries, list):
        raise ScopeHoundError("input_invalid", "LLVM coverage export data must be an array")
    functions: set[str] = set()
    edges: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw_functions = entry.get("functions", [])
        if isinstance(raw_functions, list):
            for function in raw_functions:
                if isinstance(function, dict) and isinstance(function.get("name"), str) and function.get("count", 0):
                    functions.add(function["name"])
        raw_edges = entry.get("edges", entry.get("segments", []))
        if isinstance(raw_edges, list):
            edges.extend(json.dumps(edge, sort_keys=True) for edge in raw_edges)
    return functions, edges


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read coverage export {path}: {error}") from error


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65_536), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise ScopeHoundError("input_invalid", f"cannot read coverage file {path}: {error}") from error
    return digest.hexdigest(), size


def _contained(base: Path, candidate: Path, label: str) -> Path:
    resolved_base = base.resolve()
    resolved_candidate = candidate.expanduser().resolve()
    try:
        resolved_candidate.relative_to(resolved_base)
    except ValueError as error:
        raise ScopeHoundError("unsafe_path", f"{label} must remain inside the target workspace") from error
    return resolved_candidate


def _write_record(record: CoverageRecord, output: Path) -> None:
    item = asdict(record)
    item["engine_stats"] = dict(record.engine_stats)
    item["coverage_artifacts"] = [asdict(artifact) for artifact in record.coverage_artifacts]
    item["before"] = asdict(record.before)
    item["after"] = asdict(record.after)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(item, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write coverage record {output}: {error}") from error
