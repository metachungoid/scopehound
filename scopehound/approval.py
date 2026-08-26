from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Mapping

from scopehound.catalog import CatalogCandidate
from scopehound.catalog.model import canonical_repository
from scopehound.errors import ScopeHoundError
from scopehound.manifest import Manifest


_SCHEMA_VERSION = 1
_TESTING_MODES = {"read-only", "sandboxed-local"}


@dataclass(frozen=True)
class ApprovalRecord:
    candidate_id: str
    project: str
    repository: str
    revision: str
    reviewer: str
    approved_at: str
    checked_at: str
    expires_at: str
    policy_url: str
    policy_digest: str
    eligible_classes: tuple[str, ...]
    testing_mode: str
    notes: str = ""
    schema_version: int = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["eligible_classes"] = list(self.eligible_classes)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ApprovalRecord":
        if payload.get("schema_version") != _SCHEMA_VERSION:
            raise ScopeHoundError("approval_invalid", "approval schema_version must be 1")
        required = (
            "candidate_id", "project", "repository", "revision", "reviewer", "approved_at",
            "checked_at", "expires_at", "policy_url", "policy_digest", "eligible_classes", "testing_mode",
        )
        if any(field not in payload for field in required):
            raise ScopeHoundError("approval_invalid", "approval record is missing required fields")
        try:
            record = cls(
                candidate_id=_string(payload["candidate_id"], "candidate_id"),
                project=_string(payload["project"], "project"),
                repository=canonical_repository(_string(payload["repository"], "repository")),
                revision=_string(payload["revision"], "revision"),
                reviewer=_string(payload["reviewer"], "reviewer"),
                approved_at=_date_string(payload["approved_at"], "approved_at"),
                checked_at=_date_string(payload["checked_at"], "checked_at"),
                expires_at=_date_string(payload["expires_at"], "expires_at"),
                policy_url=_string(payload["policy_url"], "policy_url"),
                policy_digest=_digest(payload["policy_digest"], "policy_digest"),
                eligible_classes=_string_tuple(payload["eligible_classes"], "eligible_classes"),
                testing_mode=_string(payload["testing_mode"], "testing_mode"),
                notes=_optional_string(payload.get("notes", ""), "notes"),
                schema_version=1,
            )
        except (TypeError, ValueError) as error:
            raise ScopeHoundError("approval_invalid", f"invalid approval record: {error}") from error
        if record.testing_mode not in _TESTING_MODES:
            raise ScopeHoundError("approval_invalid", f"unsupported testing mode: {record.testing_mode}")
        if date.fromisoformat(record.expires_at) < date.fromisoformat(record.approved_at):
            raise ScopeHoundError("approval_invalid", "expires_at cannot precede approved_at")
        return record


def create_approval(
    candidate: CatalogCandidate,
    *,
    revision: str,
    reviewer: str,
    approved_at: str,
    expires_at: str,
    eligible_classes: tuple[str, ...],
    testing_mode: str,
    notes: str = "",
) -> ApprovalRecord:
    approved = _date_string(approved_at, "approved_at")
    expires = _date_string(expires_at, "expires_at")
    if date.fromisoformat(expires) < date.fromisoformat(approved):
        raise ScopeHoundError("approval_invalid", "expires_at cannot precede approved_at")
    if testing_mode not in _TESTING_MODES:
        raise ScopeHoundError("approval_invalid", f"unsupported testing mode: {testing_mode}")
    classes = tuple(sorted(set(eligible_classes)))
    if not classes:
        raise ScopeHoundError("approval_invalid", "eligible_classes cannot be empty")
    return ApprovalRecord(
        candidate_id=candidate.candidate_id,
        project=candidate.project,
        repository=canonical_repository(candidate.repository),
        revision=_string(revision, "revision"),
        reviewer=_string(reviewer, "reviewer"),
        approved_at=approved,
        checked_at=candidate.checked_at or approved,
        expires_at=expires,
        policy_url=candidate.policy_urls[0],
        policy_digest=candidate.policy_digest,
        eligible_classes=classes,
        testing_mode=testing_mode,
        notes=notes,
    )


def require_current_approval(
    manifest: Manifest,
    approval: ApprovalRecord,
    *,
    required_class: str,
    now: date,
) -> None:
    if canonical_repository(manifest.target.repository) != canonical_repository(approval.repository):
        raise ScopeHoundError("approval_stale", "approval repository does not match manifest target")
    if manifest.target.revision != approval.revision:
        raise ScopeHoundError("approval_stale", "approval revision does not match manifest target")
    if manifest.authorization.policy_url != approval.policy_url:
        raise ScopeHoundError("approval_stale", "approval policy URL does not match manifest authorization")
    if manifest.authorization.policy_digest != approval.policy_digest:
        raise ScopeHoundError("approval_stale", "approval policy digest does not match manifest authorization")
    if now > date.fromisoformat(approval.expires_at):
        raise ScopeHoundError("approval_stale", "approval has expired")
    if required_class not in approval.eligible_classes or required_class not in manifest.authorization.eligible_classes:
        raise ScopeHoundError("approval_stale", f"approval does not permit class: {required_class}")
    if approval.testing_mode != "sandboxed-local":
        raise ScopeHoundError("approval_stale", "execution requires sandboxed-local approval")


def write_approval(record: ApprovalRecord, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record.to_dict(), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ScopeHoundError("approval_write_failed", f"cannot write approval: {error}") from error


def load_approval(path: Path) -> ApprovalRecord:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("approval_invalid", f"cannot read approval: {error}") from error
    if not isinstance(payload, dict):
        raise ScopeHoundError("approval_invalid", "approval must be an object")
    return ApprovalRecord.from_dict(payload)


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScopeHoundError("approval_invalid", f"{field} must be a non-empty string")
    return value


def _optional_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ScopeHoundError("approval_invalid", f"{field} must be a string")
    return value


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ScopeHoundError("approval_invalid", f"{field} must be a non-empty string array")
    return tuple(sorted(set(value)))


def _date_string(value: object, field: str) -> str:
    text = _string(value, field)
    try:
        date.fromisoformat(text)
    except ValueError as error:
        raise ScopeHoundError("approval_invalid", f"{field} must be an ISO date") from error
    return text


def _digest(value: object, field: str) -> str:
    text = _string(value, field)
    if len(text) != 64:
        raise ScopeHoundError("approval_invalid", f"{field} must be a SHA-256 hex digest")
    try:
        int(text, 16)
    except ValueError as error:
        raise ScopeHoundError("approval_invalid", f"{field} must be hexadecimal") from error
    return text
