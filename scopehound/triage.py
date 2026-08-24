from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.findings import Finding


@dataclass(frozen=True)
class ArtifactRecord:
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class TriageResult:
    unique: tuple[ArtifactRecord, ...]
    duplicates: Mapping[str, tuple[str, ...]]
    finding_groups: tuple["FindingGroup", ...] = ()


@dataclass(frozen=True)
class FindingGroup:
    fingerprint: str
    sanitizer: str
    kind: str
    location: str
    function: str
    artifacts: tuple[str, ...]


def inspect_artifact(path: Path) -> ArtifactRecord:
    if path.is_symlink() or not path.is_file():
        raise ScopeHoundError(
            "artifacts_invalid", f"artifact is not a regular file: {path}"
        )
    sha256, size = _hash_file(path)
    return ArtifactRecord(path, sha256, size)


def triage_artifacts(directory: Path) -> TriageResult:
    if not directory.is_dir():
        raise ScopeHoundError(
            "artifacts_invalid", f"artifact directory does not exist: {directory}"
        )

    groups: dict[tuple[str, int], list[Path]] = {}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            continue
        record = inspect_artifact(path)
        groups.setdefault((record.sha256, record.size), []).append(path)

    canonical_records: list[ArtifactRecord] = []
    duplicates: dict[str, tuple[str, ...]] = {}
    for (sha256, size), paths in groups.items():
        ordered = sorted(paths, key=lambda item: item.name)
        canonical = ordered[0]
        canonical_records.append(ArtifactRecord(canonical, sha256, size))
        if len(ordered) > 1:
            duplicates[canonical.name] = tuple(path.name for path in ordered[1:])

    canonical_records.sort(key=lambda item: item.path.name)
    return TriageResult(tuple(canonical_records), duplicates)


def cluster_findings(findings: tuple[Finding, ...]) -> tuple[FindingGroup, ...]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.fingerprint, []).append(finding)
    result: list[FindingGroup] = []
    for fingerprint, members in grouped.items():
        ordered = sorted(members, key=lambda item: (item.artifact or "", item.location, item.function))
        representative = ordered[0]
        artifacts = tuple(sorted({item.artifact for item in members if item.artifact}))
        result.append(
            FindingGroup(
                fingerprint=fingerprint,
                sanitizer=representative.sanitizer,
                kind=representative.kind,
                location=representative.location,
                function=representative.function,
                artifacts=artifacts,
            )
        )
    return tuple(sorted(result, key=lambda item: item.fingerprint))


def write_triage(result: TriageResult, output: Path) -> None:
    payload = {
        "duplicates": {
            key: list(result.duplicates[key]) for key in sorted(result.duplicates)
        },
        "unique": [
            {
                "path": record.path.name,
                "sha256": record.sha256,
                "size": record.size,
            }
            for record in result.unique
        ],
        "finding_groups": [
            {
                "artifacts": list(group.artifacts),
                "fingerprint": group.fingerprint,
                "function": group.function,
                "kind": group.kind,
                "location": group.location,
                "sanitizer": group.sanitizer,
            }
            for group in result.finding_groups
        ],
    }
    _atomic_write(output, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as artifact:
            while chunk := artifact.read(65_536):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise ScopeHoundError(
            "artifacts_invalid", f"cannot read artifact {path.name}: {error}"
        ) from error
    return digest.hexdigest(), size


def _atomic_write(output: Path, content: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError(
            "output_failed", f"cannot write {output}: {error}"
        ) from error
