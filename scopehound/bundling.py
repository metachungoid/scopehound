from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scopehound.errors import ScopeHoundError
from scopehound.findings import Finding, load_findings
from scopehound.manifest import Manifest
from scopehound.policy import require_authorized
from scopehound.reporting import render_report, write_report
from scopehound.reproduction import ReproductionResult, load_reproduction
from scopehound.triage import inspect_artifact


@dataclass(frozen=True)
class BundleSummary:
    output: Path
    files: tuple[str, ...]
    artifact_sha256: str


def create_bundle(
    manifest_path: Path,
    manifest: Manifest,
    artifact: Path,
    output: Path,
    findings_path: Path | None = None,
    triage_path: Path | None = None,
    reproduction_path: Path | None = None,
    minimization_path: Path | None = None,
    coverage_path: Path | None = None,
    campaign_path: Path | None = None,
    controls_path: Path | None = None,
) -> BundleSummary:
    """Create a local, human-reviewable evidence bundle without transmitting it."""
    require_authorized(manifest)
    if output.is_symlink():
        raise ScopeHoundError("unsafe_path", f"bundle output cannot be a symlink: {output}")
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise ScopeHoundError("output_exists", f"bundle output already exists: {output}")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.mkdir()

    artifact_record = inspect_artifact(artifact)
    findings = _load_optional_findings(findings_path)
    finding = _select_finding(findings, artifact_record.path.name)
    reproduction = _load_optional_reproduction(reproduction_path, artifact_record.path.name)
    campaign_record = _load_optional_mapping(campaign_path)
    controls_record = _load_optional_mapping(controls_path)

    files: list[str] = ["bundle.json"]
    _copy_input(manifest_path, output / "manifest.json")
    files.append("manifest.json")
    _copy_input(artifact_record.path, output / artifact_record.path.name)
    files.append(artifact_record.path.name)
    if findings_path:
        _copy_input(findings_path, output / "findings.json")
        files.append("findings.json")
    if triage_path:
        _copy_input(triage_path, output / "triage.json")
        files.append("triage.json")
    if reproduction_path:
        _copy_input(reproduction_path, output / "reproduction.json")
        files.append("reproduction.json")
    if coverage_path:
        _copy_input(coverage_path, output / "coverage.json")
        files.append("coverage.json")
    if minimization_path:
        _copy_input(minimization_path, output / "minimization.json")
        files.append("minimization.json")
        child = _minimized_child(minimization_path)
        _copy_input(child, output / f"minimized-{child.name}")
        files.append(f"minimized-{child.name}")
    if campaign_path:
        _copy_input(campaign_path, output / "campaign.json")
        files.append("campaign.json")
    if controls_path:
        _copy_input(controls_path, output / "controls.json")
        files.append("controls.json")

    report_path = output / "report.md"
    write_report(
        render_report(
            manifest,
            artifact_record,
            artifact_record.path.name,
            finding,
            reproduction,
            campaign=campaign_record,
            controls=controls_record,
        ),
        report_path,
    )
    files.append("report.md")
    files.sort()
    inventory = {
        "artifact": {
            "filename": artifact_record.path.name,
            "sha256": artifact_record.sha256,
            "size": artifact_record.size,
        },
        "files": files,
        "human_review_required": True,
        "schema_version": 1,
        "target": {
            "name": manifest.target.name,
            "repository": manifest.target.repository,
            "revision": manifest.target.revision,
        },
    }
    if campaign_record:
        inventory["campaign"] = campaign_record
    if controls_record:
        inventory["controls"] = controls_record
    _atomic_write(output / "bundle.json", json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    return BundleSummary(output, tuple(sorted(files)), artifact_record.sha256)


def _load_optional_findings(path: Path | None) -> tuple[Finding, ...]:
    return load_findings(path) if path else ()


def _load_optional_reproduction(path: Path | None, artifact_name: str) -> ReproductionResult | None:
    if path is None:
        return None
    reproduction = load_reproduction(path)
    if reproduction.artifact != artifact_name:
        raise ScopeHoundError(
            "input_invalid",
            f"reproduction artifact does not match requested artifact: {reproduction.artifact}",
        )
    return reproduction


def _load_optional_mapping(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read JSON record {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ScopeHoundError("input_invalid", f"JSON record must be an object: {path}")
    return payload


def _select_finding(findings: tuple[Finding, ...], artifact_name: str) -> Finding | None:
    matching = [item for item in findings if item.artifact == artifact_name]
    return matching[0] if matching else (findings[0] if len(findings) == 1 else None)


def _copy_input(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ScopeHoundError("input_invalid", f"bundle input is not a regular file: {source}")
    try:
        shutil.copyfile(source, destination)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot copy {source}: {error}") from error


def _minimized_child(record_path: Path) -> Path:
    try:
        payload: Any = json.loads(record_path.read_text(encoding="utf-8"))
        child = payload["child"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read minimization child: {error}") from error
    if not isinstance(child, str):
        raise ScopeHoundError("input_invalid", "minimization child must be a path string")
    path = Path(child).expanduser().resolve()
    if path.is_symlink() or not path.is_file():
        raise ScopeHoundError("input_invalid", f"minimization child is not a regular file: {path}")
    return path


def _atomic_write(output: Path, content: str) -> None:
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write {output}: {error}") from error
