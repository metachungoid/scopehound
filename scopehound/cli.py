from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Sequence

from scopehound.errors import ScopeHoundError
from scopehound.findings import load_findings, parse_sanitizer_output, write_findings
from scopehound.manifest import Manifest, load_manifest
from scopehound.reporting import render_report, write_report
from scopehound.runner import (
    CommandPlan,
    CommandResult,
    build_plan,
    fuzz_plan,
    prepare_plans,
    run_plan,
)
from scopehound.scoring import score_opportunity
from scopehound.triage import inspect_artifact, triage_artifacts, write_triage
from scopehound.workspace import Workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopehound",
        description="Scope-aware local memory-safety research assistant",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a target manifest")
    _manifest_argument(validate)
    _json_argument(validate)

    score = subparsers.add_parser("score", help="explain a target opportunity score")
    _manifest_argument(score)
    _json_argument(score)

    prepare = subparsers.add_parser("prepare", help="plan or clone a pinned repository")
    _manifest_argument(prepare)
    _workspace_argument(prepare)
    prepare.add_argument("--allow-local-repository", action="store_true")
    _execute_argument(prepare)
    _json_argument(prepare)

    build = subparsers.add_parser("build", help="plan or run the target build command")
    _manifest_argument(build)
    _workspace_argument(build)
    _execute_argument(build)
    _json_argument(build)

    fuzz = subparsers.add_parser("fuzz", help="plan or run a bounded local fuzz command")
    _manifest_argument(fuzz)
    _workspace_argument(fuzz)
    fuzz.add_argument("--duration", required=True, type=int, metavar="SECONDS")
    _execute_argument(fuzz)
    _json_argument(fuzz)

    findings = subparsers.add_parser("findings", help="extract structured sanitizer findings from a log")
    findings.add_argument("--log", required=True, type=Path)
    findings.add_argument("--artifact", type=Path)
    findings.add_argument("--output", required=True, type=Path)
    _json_argument(findings)

    triage = subparsers.add_parser("triage", help="deduplicate local crash artifacts")
    triage.add_argument("--artifacts", required=True, type=Path)
    triage.add_argument("--output", required=True, type=Path)
    _json_argument(triage)

    report = subparsers.add_parser("report", help="write a human-review disclosure draft")
    _manifest_argument(report)
    report.add_argument("--artifact", required=True, type=Path)
    report.add_argument("--findings", type=Path)
    report.add_argument("--output", required=True, type=Path)
    _json_argument(report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except ScopeHoundError as error:
        payload = {"ok": False, "error": error.category, "message": error.message}
        if getattr(args, "json", False):
            print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        else:
            print(f"{error.category}: {error.message}", file=sys.stderr)
        return 1 if error.category in {"command_failed", "timeout"} else 2


def entrypoint() -> None:
    raise SystemExit(main())


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "validate":
        manifest = load_manifest(args.manifest)
        _success(args, {"target": manifest.target.name}, f"valid: {manifest.target.name}")
        return 0

    if args.command == "score":
        manifest = load_manifest(args.manifest)
        result = score_opportunity(manifest.opportunity)
        payload = {"target": manifest.target.name, "score": result.score, "factors": dict(result.factors)}
        lines = [f"score: {result.score:.3f}"]
        lines.extend(f"{name}: {value:.3f}" for name, value in result.factors.items())
        _success(args, payload, "\n".join(lines))
        return 0

    if args.command == "prepare":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        plans = prepare_plans(manifest, workspace, args.allow_local_repository)
        results = _run_many(plans, args.execute)
        if args.execute:
            _write_logs(workspace, manifest, "prepare", results)
        _plans_success(args, plans, results)
        return 0

    if args.command == "build":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        plan = build_plan(manifest, workspace)
        result = run_plan(plan, args.execute)
        if args.execute:
            _write_logs(workspace, manifest, "build", (result,))
        _plans_success(args, (plan,), (result,))
        return 0

    if args.command == "fuzz":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        plan = fuzz_plan(manifest, workspace, args.duration)
        result = run_plan(plan, args.execute, allow_failure=True)
        if args.execute:
            _write_logs(workspace, manifest, "fuzz", (result,))
            findings = parse_sanitizer_output(result.stdout + "\n" + result.stderr)
            write_findings(findings, workspace.findings_file(manifest.target.name))
            if result.returncode and not findings:
                raise ScopeHoundError("command_failed", f"fuzz command exited {result.returncode} without a sanitizer finding")
        _plans_success(args, (plan,), (result,))
        return 0

    if args.command == "findings":
        try:
            log = args.log.read_text(encoding="utf-8")
        except OSError as error:
            raise ScopeHoundError("input_invalid", f"cannot read log {args.log}: {error}") from error
        findings = parse_sanitizer_output(log, args.artifact)
        write_findings(findings, args.output)
        _success(args, {"count": len(findings), "output": str(args.output)}, f"found {len(findings)} sanitizer findings -> {args.output}")
        return 0

    if args.command == "triage":
        result = triage_artifacts(args.artifacts)
        write_triage(result, args.output)
        payload = {"unique": len(result.unique), "duplicate_groups": len(result.duplicates), "output": str(args.output)}
        _success(args, payload, f"triaged {len(result.unique)} unique artifacts -> {args.output}")
        return 0

    if args.command == "report":
        manifest = load_manifest(args.manifest)
        artifact = inspect_artifact(args.artifact)
        finding = None
        if args.findings:
            parsed = load_findings(args.findings)
            finding = parsed[0] if parsed else None
        report = render_report(manifest, artifact, artifact.path.name, finding)
        write_report(report, args.output)
        _success(args, {"output": str(args.output), "sha256": artifact.sha256}, f"report draft: {args.output}")
        return 0

    raise ScopeHoundError("command_invalid", f"unknown command: {args.command}")


def _run_many(plans: Sequence[CommandPlan], execute: bool) -> tuple[CommandResult, ...]:
    return tuple(run_plan(plan, execute) for plan in plans)


def _write_logs(
    workspace: Workspace,
    manifest: Manifest,
    label: str,
    results: Sequence[CommandResult],
) -> None:
    logs = workspace.logs_dir(manifest.target.name)
    logs.mkdir(parents=True, exist_ok=True)
    for index, result in enumerate(results, start=1):
        suffix = f"-{index}" if len(results) > 1 else ""
        output = logs / f"{label}{suffix}.log"
        content = (
            f"argv: {json.dumps(list(result.argv))}\n"
            f"returncode: {result.returncode}\n"
            "\n[stdout]\n"
            f"{result.stdout}"
            "\n[stderr]\n"
            f"{result.stderr}"
        )
        output.write_text(content, encoding="utf-8")


def _plans_success(
    args: argparse.Namespace,
    plans: Sequence[CommandPlan],
    results: Sequence[CommandResult],
) -> None:
    payload = {
        "executed": bool(args.execute),
        "plans": [
            {"argv": list(plan.argv), "cwd": str(plan.cwd), "timeout_seconds": plan.timeout_seconds}
            for plan in plans
        ],
    }
    if args.execute:
        text = "executed successfully"
    else:
        rendered = "\n".join(
            f"  cwd={plan.cwd} {shlex.join(plan.argv)}" for plan in plans
        )
        text = f"DRY RUN (use --execute to run)\n{rendered}"
    _success(args, payload, text)


def _success(args: argparse.Namespace, payload: dict[str, object], text: str) -> None:
    if getattr(args, "json", False):
        print(json.dumps({"ok": True, **payload}, sort_keys=True))
    else:
        print(text)


def _manifest_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", required=True, type=Path)


def _workspace_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", type=Path, default=Path(".scopehound"))


def _execute_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--execute", action="store_true", help="perform the planned local action")


def _json_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
