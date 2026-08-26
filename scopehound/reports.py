from __future__ import annotations

from pathlib import Path
from typing import Mapping

from scopehound.coverage import CoverageRecord
from scopehound.findings import Finding
from scopehound.manifest import Manifest
from scopehound.reporting import render_report
from scopehound.reproduction import ReproductionResult
from scopehound.triage import ArtifactRecord
from scopehound.verification import VerificationResult


REPORT_PROFILES = ("neutral", "private-email", "platform-form")
_FORBIDDEN = ("zero-day", "confirmed vulnerability", "guaranteed bounty")


def render_report_profile(
    manifest: Manifest,
    artifact: ArtifactRecord,
    relative_artifact_path: str,
    finding: Finding | None = None,
    reproduction: ReproductionResult | None = None,
    *,
    profile: str = "neutral",
    coverage: CoverageRecord | None = None,
    campaign: Mapping[str, object] | None = None,
    controls: Mapping[str, object] | None = None,
    verification: VerificationResult | None = None,
) -> str:
    if profile not in REPORT_PROFILES:
        raise ValueError(f"unknown report profile: {profile}")
    base = render_report(
        manifest, artifact, relative_artifact_path, finding, reproduction,
        coverage, campaign, controls,
    )
    if profile == "private-email":
        channel = (
            "## Private email handoff\n\n"
            "Subject: Evidence draft — potential memory-safety issue in "
            f"{manifest.target.name}\n\n"
            "To: use the security contact named by the current policy\n\n"
            "Please review the evidence and send only through the designated private channel.\n\n"
        )
    elif profile == "platform-form":
        channel = (
            "## Platform submission fields\n\n"
            f"- Title: Potential memory-safety issue in {manifest.target.name}\n"
            "- Impact summary: complete after human severity review\n"
            "- Reproduction: see the bounded steps and attached artifact below\n"
            "- Disclosure status: draft; human submission required\n\n"
        )
    else:
        channel = "## Neutral disclosure handoff\n\nReview this evidence draft and select the current private disclosure channel.\n\n"
    if verification is not None:
        channel += "## Verification gate summary\n\n"
        channel += "\n".join(f"- {name}: {'pass' if passed else 'blocked'}" for name, passed in verification.gates.items())
        channel += "\n\n"
    text = channel + base
    lowered = text.casefold()
    if any(term in lowered for term in _FORBIDDEN):
        raise ValueError("report profile contains an unsupported certainty or payout claim")
    return text
