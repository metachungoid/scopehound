from __future__ import annotations

from scopehound.errors import ScopeHoundError
from scopehound.manifest import Manifest


def require_authorized(manifest: Manifest) -> None:
    authorization = manifest.authorization
    if authorization.status != "authorized":
        raise ScopeHoundError(
            "authorization_required",
            "target authorization status must be 'authorized' before execution",
        )
    if not authorization.policy_url:
        raise ScopeHoundError(
            "authorization_required", "a verified scope-policy URL is required"
        )
    if "memory-corruption" not in authorization.eligible_classes:
        raise ScopeHoundError(
            "authorization_required",
            "memory-corruption must be explicitly listed as an eligible class",
        )
