from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from scopehound.catalog.model import CatalogCandidate, candidate_id, canonical_repository, policy_digest
from scopehound.errors import ScopeHoundError


class DiscoveryProvider(Protocol):
    def discover(self, source: str) -> tuple[CatalogCandidate, ...]: ...


_URL = re.compile(r"https?://[^\s)>\]`]+")
_MAIL = re.compile(r"mailto:[^\s)>\]`]+", re.IGNORECASE)
_MAX_METADATA_BYTES = 256 * 1024


def discover_local_metadata(root: Path, *, checked_at: str = "") -> tuple[CatalogCandidate, ...]:
    """Read local policy metadata only; never imports or executes repository code."""
    if not root.is_dir():
        raise ScopeHoundError("catalog_invalid", f"metadata root is not a directory: {root}")
    files = tuple(
        path for path in
        (root / "security.txt", root / ".well-known" / "security.txt", root / "SECURITY.md")
        if path.is_file()
    )
    if not files:
        raise ScopeHoundError("catalog_invalid", "no security policy metadata found")
    contents: list[bytes] = []
    policy_urls: set[str] = set()
    channels: set[str] = set()
    for path in files:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ScopeHoundError("catalog_provider_failed", f"cannot read {path.name}: {error}") from error
        if len(raw) > _MAX_METADATA_BYTES:
            raise ScopeHoundError("catalog_invalid", f"metadata file is too large: {path.name}")
        contents.append(raw)
        text = raw.decode("utf-8", errors="replace")
        for url in _URL.findall(text):
            normalized = url.rstrip(".,;)")
            if path.name != "security.txt" and "security" not in normalized.casefold():
                continue
            if path.name == "security.txt" and not any(
                line.casefold().startswith("policy:") and normalized in line for line in text.splitlines()
            ):
                continue
            if normalized:
                policy_urls.add(normalized)
        channels.update(match.rstrip(".,;)") for match in _MAIL.findall(text))
    if not policy_urls:
        raise ScopeHoundError("catalog_invalid", "metadata does not declare a policy URL")
    combined = b"\n".join(contents)
    repository = canonical_repository(str(root.resolve()))
    digest = policy_digest(combined)
    candidate = CatalogCandidate(
        candidate_id=candidate_id(repository, digest),
        project=root.name or "local-project",
        repository=repository,
        policy_urls=tuple(sorted(policy_urls)),
        disclosure_channels=tuple(sorted(channels or {"policy-url"})),
        eligible_classes=("memory-corruption",),
        policy_digest=digest,
        source_names=("local-metadata",),
        source_confidence=0.5,
        status="scope_unverified",
        discovered_at=checked_at,
        checked_at=checked_at,
    )
    return (candidate,)
