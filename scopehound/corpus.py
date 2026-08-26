from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class CorpusEntry:
    path: str
    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class SeedRecord:
    path: str
    input_sha256: str
    size: int
    parent: str | None = None
    oracle: str | None = None


def inventory_corpus(root: Path, *, max_input_size: int) -> tuple[CorpusEntry, ...]:
    if max_input_size < 1:
        raise ScopeHoundError("input_invalid", "max_input_size must be positive")
    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        raise ScopeHoundError("input_invalid", f"corpus directory is missing: {resolved}")
    records: list[CorpusEntry] = []
    for path in sorted((item for item in resolved.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
        if path.is_symlink():
            continue
        data = path.read_bytes()[:max_input_size]
        relative = path.relative_to(resolved).as_posix()
        records.append(
            CorpusEntry(
                path=relative,
                name=path.name,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
            )
        )
    return tuple(records)


def structure_aware_seeds(
    root: Path,
    *,
    max_input_size: int,
    parent: str | None = None,
    oracle: str | None = None,
) -> tuple[SeedRecord, ...]:
    return tuple(
        SeedRecord(item.path, item.sha256, item.size, parent, oracle)
        for item in inventory_corpus(root, max_input_size=max_input_size)
    )
