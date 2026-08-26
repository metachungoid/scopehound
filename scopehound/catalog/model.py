from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class CatalogCandidate:
    candidate_id: str
    project: str
    repository: str
    policy_urls: tuple[str, ...]
    disclosure_channels: tuple[str, ...]
    eligible_classes: tuple[str, ...]
    policy_digest: str
    source_names: tuple[str, ...]
    source_confidence: float
    status: str = "scope_unverified"
    discovered_at: str = ""
    checked_at: str = ""

    def __post_init__(self) -> None:
        if not self.candidate_id or not self.project or not self.repository:
            raise ScopeHoundError("catalog_invalid", "candidate identity fields are required")
        if not self.policy_digest or len(self.policy_digest) != 64:
            raise ScopeHoundError("catalog_invalid", "policy_digest must be a SHA-256 hex digest")
        try:
            int(self.policy_digest, 16)
        except ValueError as error:
            raise ScopeHoundError("catalog_invalid", "policy_digest must be hexadecimal") from error
        if not 0.0 <= float(self.source_confidence) <= 1.0:
            raise ScopeHoundError("catalog_invalid", "source_confidence must be between 0 and 1")
        if self.status not in {"scope_unverified", "scope_verified", "rejected"}:
            raise ScopeHoundError("catalog_invalid", "unsupported catalog status")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "CatalogCandidate":
        required = (
            "candidate_id", "project", "repository", "policy_urls", "disclosure_channels",
            "eligible_classes", "policy_digest", "source_names", "source_confidence",
        )
        missing = [name for name in required if name not in payload]
        if missing:
            raise ScopeHoundError("catalog_invalid", f"missing catalog fields: {', '.join(missing)}")
        try:
            return cls(
                candidate_id=_string(payload["candidate_id"], "candidate_id"),
                project=_string(payload["project"], "project"),
                repository=canonical_repository(_string(payload["repository"], "repository")),
                policy_urls=_string_tuple(payload["policy_urls"], "policy_urls"),
                disclosure_channels=_string_tuple(payload["disclosure_channels"], "disclosure_channels"),
                eligible_classes=_string_tuple(payload["eligible_classes"], "eligible_classes"),
                policy_digest=_string(payload["policy_digest"], "policy_digest"),
                source_names=_string_tuple(payload["source_names"], "source_names"),
                source_confidence=float(payload["source_confidence"]),
                status=_string(payload.get("status", "scope_unverified"), "status"),
                discovered_at=_string(payload.get("discovered_at", ""), "discovered_at"),
                checked_at=_string(payload.get("checked_at", ""), "checked_at"),
            )
        except (TypeError, ValueError) as error:
            raise ScopeHoundError("catalog_invalid", f"invalid catalog record: {error}") from error


def canonical_repository(repository: str) -> str:
    value = repository.strip()
    if value.startswith("git@") and ":" in value:
        host, path = value[4:].split(":", 1)
        value = f"ssh://{host}/{path}"
    if "://" in value:
        parsed = urlsplit(value)
        path = parsed.path.rstrip("/")
        if path.endswith(".git"):
            path = path[:-4]
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))
    return value.rstrip("/")


def candidate_id(repository: str, policy_digest: str) -> str:
    return hashlib.sha256(f"{canonical_repository(repository)}\0{policy_digest}".encode()).hexdigest()[:20]


def policy_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScopeHoundError("catalog_invalid", f"{field} must be a non-empty string")
    return value


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value or not all(isinstance(item, str) and item for item in value):
        raise ScopeHoundError("catalog_invalid", f"{field} must be a non-empty string array")
    return tuple(value)
