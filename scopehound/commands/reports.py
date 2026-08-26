from __future__ import annotations

from pathlib import Path

from scopehound.findings import load_findings
from scopehound.manifest import load_manifest
from scopehound.reproduction import load_reproduction
from scopehound.reports import render_report_profile
from scopehound.triage import inspect_artifact
from scopehound.reporting import write_report


def draft(
    manifest_path: Path,
    artifact_path: Path,
    output: Path,
    *,
    profile: str,
    findings_path: Path | None = None,
    reproduction_path: Path | None = None,
) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    artifact = inspect_artifact(artifact_path)
    finding = None
    if findings_path:
        findings = load_findings(findings_path)
        matches = tuple(item for item in findings if item.artifact == artifact.path.name)
        finding = matches[0] if matches else (findings[0] if len(findings) == 1 else None)
    reproduction = load_reproduction(reproduction_path) if reproduction_path else None
    if reproduction is not None and reproduction.artifact != artifact.path.name:
        from scopehound.errors import ScopeHoundError
        raise ScopeHoundError("input_invalid", "reproduction artifact does not match requested artifact")
    report = render_report_profile(manifest, artifact, artifact.path.name, finding, reproduction, profile=profile)
    write_report(report, output)
    return {"profile": profile, "output": str(output), "artifact_sha256": artifact.sha256}
