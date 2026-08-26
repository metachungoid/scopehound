from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Mapping, Sequence

from scopehound.approval import ApprovalRecord
from scopehound.confirmation import CrossBuildConfirmation
from scopehound.errors import ScopeHoundError
from scopehound.findings import Finding
from scopehound.known_issues import DuplicateEvidence, IssueComparison
from scopehound.manifest import Manifest
from scopehound.policy import require_approved, require_authorized
from scopehound.reproduction import ReproductionResult


@dataclass(frozen=True)
class VerificationResult:
    status: str
    gates: Mapping[str, bool]
    reasons: tuple[str, ...]
    duplicate_evidence: tuple[DuplicateEvidence, ...]

    @property
    def promotable(self) -> bool:
        return self.status == "promotable"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "gates": dict(self.gates),
            "reasons": list(self.reasons),
            "duplicate_evidence": [asdict(item) for item in self.duplicate_evidence],
        }


def verify_candidate(
    manifest: Manifest,
    artifact: Path,
    finding: Finding,
    reproduction: ReproductionResult,
    comparison: IssueComparison,
    confirmation: CrossBuildConfirmation | None,
    *,
    duplicate_evidence: Sequence[DuplicateEvidence],
    root_cause_review: bool,
    reachability_review: bool,
    latest_revision_check: bool,
    scope_recheck: bool,
    approval: ApprovalRecord | None = None,
) -> VerificationResult:
    if approval is None:
        require_authorized(manifest)
    else:
        require_approved(manifest, approval)
    evidence = tuple(duplicate_evidence)
    gates: dict[str, bool] = {
        "artifact": artifact.is_file() and not artifact.is_symlink(),
        "sanitizer": finding.sanitizer in {"AddressSanitizer", "UndefinedBehaviorSanitizer", "MemorySanitizer"},
        "reproduction": reproduction.status == "reproduced" and reproduction.matching_attempts >= 2,
        "comparison": comparison.label == "new_candidate" and comparison.fingerprint == finding.fingerprint,
        "root_cause": bool(finding.root_cause) and root_cause_review,
        "reachability": reachability_review,
        "cross_build": confirmation is not None and confirmation.status == "confirmed_across_builds",
        "duplicate_search": {item.source for item in evidence} >= {"public", "private"}
        and all(item.status == "no_match" for item in evidence),
        "latest_revision": latest_revision_check,
        "scope_recheck": scope_recheck,
    }
    reasons = tuple(
        _reason(name, value) for name, value in gates.items() if not value
    )
    return VerificationResult("promotable" if not reasons else "blocked", gates, reasons, evidence)


def _reason(name: str, passed: bool) -> str:
    if passed:
        return ""
    return {
        "artifact": "artifact is not a regular file",
        "sanitizer": "finding is not a supported memory-safety sanitizer signal",
        "reproduction": "two matching replay attempts are required",
        "comparison": "known-issue comparison is not a matching new candidate",
        "root_cause": "reviewed normalized root cause is required",
        "reachability": "attacker-controlled reachability review is required",
        "cross_build": "matching cross-build confirmation is required",
        "duplicate_search": "public and private duplicate searches must each produce no-match evidence",
        "latest_revision": "latest eligible revision has not been checked",
        "scope_recheck": "scope and disclosure channel have not been rechecked",
    }[name]
