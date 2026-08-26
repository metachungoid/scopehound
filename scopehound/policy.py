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


def require_approved(manifest: Manifest, approval: object, *, required_class: str = "memory-corruption") -> None:
    """Require legacy manifest authorization plus a current immutable approval record."""
    from datetime import date

    from scopehound.approval import ApprovalRecord, require_current_approval

    require_authorized(manifest)
    if not isinstance(approval, ApprovalRecord):
        raise ScopeHoundError("approval_required", "a valid approval record is required before execution")
    require_current_approval(manifest, approval, required_class=required_class, now=date.today())
