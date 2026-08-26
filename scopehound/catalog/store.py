from __future__ import annotations

import json
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Iterable

from scopehound.catalog.model import CatalogCandidate, canonical_repository
from scopehound.errors import ScopeHoundError


_SCHEMA_VERSION = 1


def merge_candidates(candidates: Iterable[CatalogCandidate]) -> tuple[CatalogCandidate, ...]:
    merged: dict[tuple[str, tuple[str, ...]], CatalogCandidate] = {}
    for candidate in candidates:
        key = (canonical_repository(candidate.repository), tuple(sorted(candidate.policy_urls)))
        existing = merged.get(key)
        if existing is None:
            merged[key] = replace(candidate, repository=canonical_repository(candidate.repository))
            continue
        merged[key] = replace(
            existing,
            candidate_id=min(existing.candidate_id, candidate.candidate_id),
            policy_urls=tuple(sorted(set(existing.policy_urls) | set(candidate.policy_urls))),
            disclosure_channels=tuple(sorted(set(existing.disclosure_channels) | set(candidate.disclosure_channels))),
            eligible_classes=tuple(sorted(set(existing.eligible_classes) | set(candidate.eligible_classes))),
            source_names=tuple(sorted(set(existing.source_names) | set(candidate.source_names))),
            source_confidence=max(existing.source_confidence, candidate.source_confidence),
            checked_at=max(existing.checked_at, candidate.checked_at),
        )
    return tuple(sorted(merged.values(), key=lambda item: (item.project, item.repository, item.candidate_id)))


def write_catalog(candidates: tuple[CatalogCandidate, ...], output: Path) -> None:
    records = merge_candidates(candidates)
    payload = {"schema_version": _SCHEMA_VERSION, "candidates": [item.to_dict() for item in records]}
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ScopeHoundError("catalog_write_failed", f"cannot write catalog: {error}") from error


def load_catalog(path: Path) -> tuple[CatalogCandidate, ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("catalog_invalid", f"cannot read catalog: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        raise ScopeHoundError("catalog_invalid", "catalog schema_version must be 1")
    records = payload.get("candidates")
    if not isinstance(records, list):
        raise ScopeHoundError("catalog_invalid", "catalog candidates must be an array")
    try:
        candidates = [CatalogCandidate.from_dict(record) for record in records]
    except (TypeError, ScopeHoundError) as error:
        if isinstance(error, ScopeHoundError):
            raise
        raise ScopeHoundError("catalog_invalid", "catalog record must be an object") from error
    return merge_candidates(candidates)
