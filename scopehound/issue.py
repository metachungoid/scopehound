from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

from scopehound.confirmation import CrossBuildConfirmation
from scopehound.approval import ApprovalRecord
from scopehound.errors import ScopeHoundError
from scopehound.findings import Finding, load_findings
from scopehound.known_issues import IssueComparison
from scopehound.manifest import Manifest
from scopehound.policy import require_approved, require_authorized
from scopehound.reporting import render_report, write_report
from scopehound.reproduction import ReproductionResult, load_reproduction
from scopehound.triage import inspect_artifact
from scopehound.verification import VerificationResult


@dataclass(frozen=True)
class GateDecision:
    status: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class IssuePackage:
    status: str
    output: Path
    issue_json: Path
    report: Path
    decision: GateDecision


def promote_issue(
    manifest: Manifest,
    manifest_path: Path,
    artifact: Path,
    findings_path: Path,
    reproduction_path: Path,
    comparison_path: Path,
    output_dir: Path,
    *,
    triage_path: Path | None = None,
    minimization_path: Path | None = None,
    coverage_path: Path | None = None,
    campaign_path: Path | None = None,
    controls_path: Path | None = None,
    confirmation_path: Path | None = None,
    economics_path: Path | None = None,
    approval: ApprovalRecord | None = None,
    verification: VerificationResult | None = None,
) -> IssuePackage:
    if approval is None:
        require_authorized(manifest)
    else:
        require_approved(manifest, approval)
    if output_dir.exists():
        raise ScopeHoundError("output_exists", f"issue package already exists: {output_dir}")
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ScopeHoundError("input_invalid", f"manifest file is missing: {manifest_path}")
    artifact_record = inspect_artifact(artifact)
    findings = load_findings(findings_path)
    finding = _select_finding(findings, artifact_record.path.name)
    reproduction = load_reproduction(reproduction_path)
    comparisons = _load_comparisons(comparison_path)
    comparison = _select_comparison(comparisons, finding.fingerprint)
    confirmation = _load_confirmation(confirmation_path) if confirmation_path else None
    decision = evaluate_gate(
        manifest,
        artifact_record.path,
        finding,
        reproduction,
        comparison,
        confirmation,
    )
    if verification is not None and not verification.promotable:
        raise ScopeHoundError("issue_blocked", "; ".join(verification.reasons))
    if decision.status != "promoted":
        raise ScopeHoundError("issue_blocked", "; ".join(decision.reasons))

    output_dir.mkdir(parents=True, exist_ok=False)
    copied: list[str] = []
    copied.append(_copy_input(manifest_path, output_dir / "manifest.json"))
    copied.append(_copy_input(findings_path, output_dir / "findings.json"))
    copied.append(_copy_input(reproduction_path, output_dir / "reproduction.json"))
    copied.append(_copy_input(comparison_path, output_dir / "comparison.json"))
    copied.append(_copy_input(artifact_record.path, output_dir / artifact_record.path.name))
    for label, path in (
        ("triage.json", triage_path),
        ("minimization.json", minimization_path),
        ("coverage.json", coverage_path),
        ("campaign.json", campaign_path),
        ("controls.json", controls_path),
        ("confirmation.json", confirmation_path),
    ):
        if path is not None:
            copied.append(_copy_input(path, output_dir / label))
    economics = _load_mapping(economics_path) if economics_path else asdict(manifest.economics)
    issue_payload = {
        "schema_version": 1,
        "candidate_status": "new_candidate",
        "novelty": "unverified",
        "target": manifest.target.name,
        "repository": manifest.target.repository,
        "revision": manifest.target.revision,
        "finding": _finding_payload(finding),
        "comparison": asdict(comparison),
        "replay": {
            "status": reproduction.status,
            "attempts": len(reproduction.attempts) or 1,
            "matching_attempts": reproduction.matching_attempts,
            "command": list(reproduction.command),
        },
        "artifact": {
            "name": artifact_record.path.name,
            "sha256": artifact_record.sha256,
            "size": artifact_record.size,
        },
        "provenance": dict(reproduction.provenance or {}),
        "economics": economics,
        "evidence_files": sorted(copied),
        "missing_review": [
            "source root-cause review",
            "attacker-controlled reachability",
            "public and private duplicate search",
            "latest eligible revision check",
            "scope and disclosure-channel recheck",
            "human severity assessment",
        ],
        "gate": {"status": decision.status, "reasons": list(decision.reasons)},
    }
    if verification is not None:
        issue_payload["verification"] = verification.to_dict()
    issue_json = output_dir / "issue.json"
    _atomic_json(issue_json, issue_payload)
    report = render_report(
        manifest,
        artifact_record,
        artifact_record.path.name,
        finding,
        reproduction,
        campaign=_load_mapping(campaign_path) if campaign_path else None,
        controls=_load_mapping(controls_path) if controls_path else None,
    )
    report += (
        "\n## Candidate economics\n\n"
        "This estimate is for campaign prioritization only, not a bounty "
        "prediction or guarantee of profit.\n\n"
        f"- Researcher-entered economics: `{json.dumps(economics, sort_keys=True)}`\n"
        "- Novelty state: `unverified`\n"
    )
    report_path = output_dir / "report.md"
    write_report(report, report_path)
    return IssuePackage("promoted", output_dir, issue_json, report_path, decision)


def evaluate_gate(
    manifest: Manifest,
    artifact: Path,
    finding: Finding,
    reproduction: ReproductionResult,
    comparison: IssueComparison,
    confirmation: CrossBuildConfirmation | None = None,
) -> GateDecision:
    reasons: list[str] = []
    if not artifact.is_file() or artifact.is_symlink():
        reasons.append("artifact is not a regular file")
    if finding.artifact and finding.artifact != artifact.name:
        reasons.append("finding artifact does not match supplied artifact")
    if reproduction.artifact != artifact.name:
        reasons.append("reproduction artifact does not match supplied artifact")
    if reproduction.status != "reproduced":
        reasons.append(f"reproduction status is {reproduction.status}, not reproduced")
    if reproduction.matching_attempts < 2:
        reasons.append("at least two matching replay attempts are required")
    if comparison.label != "new_candidate":
        reasons.append(f"known-issue comparison is {comparison.label}")
    if comparison.fingerprint != finding.fingerprint:
        reasons.append("known-issue comparison fingerprint does not match finding")
    if not finding.root_cause:
        reasons.append("finding has no normalized root-cause signature")
    if confirmation is not None and confirmation.status != "confirmed_across_builds":
        reasons.append("cross-build confirmation did not match")
    if finding.sanitizer not in {"AddressSanitizer", "UndefinedBehaviorSanitizer", "MemorySanitizer"}:
        reasons.append("finding is not a supported memory-safety sanitizer signal")
    return GateDecision("promoted" if not reasons else "blocked", tuple(reasons))


def _select_finding(findings: tuple[Finding, ...], artifact: str) -> Finding:
    matches = tuple(item for item in findings if item.artifact == artifact)
    if len(matches) == 1:
        return matches[0]
    if len(findings) == 1:
        return findings[0]
    raise ScopeHoundError("input_invalid", f"no unique finding matches artifact: {artifact}")


def _select_comparison(comparisons: tuple[IssueComparison, ...], fingerprint: str) -> IssueComparison:
    matches = tuple(item for item in comparisons if item.fingerprint == fingerprint)
    if len(matches) != 1:
        raise ScopeHoundError("input_invalid", f"no unique comparison matches fingerprint: {fingerprint}")
    return matches[0]


def _load_comparisons(path: Path) -> tuple[IssueComparison, ...]:
    payload = _load_json(path)
    if not isinstance(payload, list):
        raise ScopeHoundError("input_invalid", "known-issue comparison must be an array")
    try:
        return tuple(
            IssueComparison(
                fingerprint=str(item["fingerprint"]),
                label=str(item["label"]),
                issue_summary=item.get("issue_summary"),
                fixed_revision=item.get("fixed_revision"),
                matched_by=item.get("matched_by"),
                root_cause=item.get("root_cause"),
            )
            for item in payload
            if isinstance(item, dict)
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("input_invalid", f"invalid known-issue comparison: {error}") from error


def _load_confirmation(path: Path) -> CrossBuildConfirmation:
    payload = _load_mapping(path)
    variants = payload.get("variants", [])
    return CrossBuildConfirmation(
        status=str(payload.get("status", "")),
        variants=tuple(item for item in variants if isinstance(item, str)),
        root_cause=payload.get("root_cause") if isinstance(payload.get("root_cause"), str) else None,
        details=payload.get("details", {}) if isinstance(payload.get("details", {}), dict) else {},
    )


def _finding_payload(finding: Finding) -> dict[str, object]:
    payload = asdict(finding)
    payload["stack"] = list(finding.stack)
    payload["normalized_stack"] = list(finding.normalized_stack)
    payload["provenance"] = dict(finding.provenance) if finding.provenance else None
    return payload


def _copy_input(source: Path, destination: Path) -> str:
    if not source.is_file() or source.is_symlink():
        raise ScopeHoundError("input_invalid", f"evidence file is missing: {source}")
    try:
        shutil.copy2(source, destination)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot copy evidence {source}: {error}") from error
    return destination.name


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read JSON {path}: {error}") from error


def _load_mapping(path: Path | None) -> dict[str, object]:
    if path is None:
        return {}
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ScopeHoundError("input_invalid", f"JSON record must be an object: {path}")
    return payload


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write issue JSON {path}: {error}") from error
