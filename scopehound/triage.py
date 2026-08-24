from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class ArtifactRecord:
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class TriageResult:
    unique: tuple[ArtifactRecord, ...]
    duplicates: Mapping[str, tuple[str, ...]]


def triage_artifacts(directory: Path) -> TriageResult:
    if not directory.is_dir():
        raise ScopeHoundError(
            "artifacts_invalid", f"artifact directory does not exist: {directory}"
        )

    groups: dict[tuple[str, int], list[Path]] = {}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            continue
        sha256, size = _hash_file(path)
        groups.setdefault((sha256, size), []).append(path)

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
