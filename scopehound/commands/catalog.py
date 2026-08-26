from __future__ import annotations

from datetime import date
from pathlib import Path

from scopehound.approval import create_approval, write_approval
from scopehound.catalog import discover_local_metadata, load_catalog, write_catalog


def discover(root: Path, output: Path, *, checked_at: str | None = None) -> dict[str, object]:
    candidates = discover_local_metadata(root, checked_at=checked_at or date.today().isoformat())
    write_catalog(candidates, output)
    return {"count": len(candidates), "output": str(output), "candidates": [item.to_dict() for item in candidates]}


def approve(
    catalog: Path,
    candidate_id: str,
    output: Path,
    *,
    revision: str,
    reviewer: str,
    approved_at: str,
    expires_at: str,
    testing_mode: str,
    notes: str = "",
) -> dict[str, object]:
    candidates = load_catalog(catalog)
    matches = tuple(item for item in candidates if item.candidate_id == candidate_id)
    if len(matches) != 1:
        from scopehound.errors import ScopeHoundError
        raise ScopeHoundError("catalog_invalid", f"candidate id is not unique: {candidate_id}")
    record = create_approval(
        matches[0], revision=revision, reviewer=reviewer, approved_at=approved_at,
        expires_at=expires_at, eligible_classes=matches[0].eligible_classes,
        testing_mode=testing_mode, notes=notes,
    )
    write_approval(record, output)
    return {"candidate_id": record.candidate_id, "revision": record.revision, "output": str(output)}
