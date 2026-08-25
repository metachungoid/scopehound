from __future__ import annotations

import argparse
import json
import shlex
import sys
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from scopehound.bundling import create_bundle
from scopehound.analyze import import_fuzz_introspector, parse_ast_json, rank_candidates
from scopehound.benchmark import run_benchmark, write_benchmark_markdown
from scopehound.campaign import create_campaign, load_campaign, run_stage
from scopehound.candidates import build_harnesses, run_harness
from scopehound.controls import run_control_matrix
from scopehound.cjson_validation import run_cjson_validation
from scopehound.coverage import collect_coverage, load_coverage
from scopehound.engines import list_engines
from scopehound.known_issues import compare_known_issues, load_known_issues, write_comparisons
from scopehound.errors import ScopeHoundError
from scopehound.findings import load_findings, parse_sanitizer_output, write_findings
from scopehound.discovery import discover_harnesses, write_harnesses
from scopehound.harness import HarnessCandidate, generate_harnesses, write_harnesses as write_generated_harnesses
from scopehound.manifest import Manifest, load_manifest
from scopehound.minimize import minimize_artifact, write_minimized
from scopehound.provenance import create_provenance, normalize_stack
from scopehound.reporting import render_report, write_report
from scopehound.reproduction import load_reproduction, reproduce_finding, write_reproduction
from scopehound.runner import (
    CommandPlan,
    CommandResult,
    build_plan,
    fuzz_plan,
    prepare_plans,
    run_plan,
)
from scopehound.scoring import score_opportunity
from scopehound.triage import (
    TriageResult,
    cluster_findings,
    inspect_artifact,
    triage_artifacts,
    write_triage,
)
from scopehound.targetpacks import CJSON_CURRENT_COMMIT, cjson_target_pack
from scopehound.validation import validate_harnesses, write_validation
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
    _backend_argument(build)
    _execute_argument(build)
    _json_argument(build)

    fuzz = subparsers.add_parser("fuzz", help="plan or run a bounded local fuzz command")
    _manifest_argument(fuzz)
    _workspace_argument(fuzz)
    _backend_argument(fuzz)
    fuzz.add_argument("--duration", required=True, type=int, metavar="SECONDS")
    _execute_argument(fuzz)
    _json_argument(fuzz)

    discover = subparsers.add_parser("discover", help="find existing C/C++ fuzz harnesses")
    discover.add_argument("--repo", required=True, type=Path)
    discover.add_argument("--output", required=True, type=Path)
    _json_argument(discover)

    generated = subparsers.add_parser("generate-harnesses", help="generate candidate libFuzzer harnesses")
    generated.add_argument("--repo", required=True, type=Path)
    generated.add_argument("--output-dir", required=True, type=Path)
    _json_argument(generated)

    validation = subparsers.add_parser(
        "validate-harnesses", help="syntax-check generated libFuzzer harnesses"
    )
    _manifest_argument(validation)
    _workspace_argument(validation)
    validation.add_argument("--harnesses-dir", required=True, type=Path)
    validation.add_argument("--output", required=True, type=Path)
    validation.add_argument("--compiler", default="c++")
    _backend_argument(validation)
    _execute_argument(validation)
    _json_argument(validation)

    candidate_build = subparsers.add_parser(
        "build-harnesses", help="compile generated harness candidates"
    )
    _manifest_argument(candidate_build)
    _workspace_argument(candidate_build)
    candidate_build.add_argument("--harnesses-dir", required=True, type=Path)
    candidate_build.add_argument("--compiler", help="recorded compiler override for future toolchains")
    _backend_argument(candidate_build)
    _execute_argument(candidate_build)
    _json_argument(candidate_build)

    candidate_run = subparsers.add_parser(
        "run-harness", help="run one built generated harness for a bounded duration"
    )
    _manifest_argument(candidate_run)
    _workspace_argument(candidate_run)
    candidate_run.add_argument("--candidate", required=True)
    candidate_run.add_argument("--duration", required=True, type=int, metavar="SECONDS")
    _backend_argument(candidate_run)
    _execute_argument(candidate_run)
    _json_argument(candidate_run)

    coverage = subparsers.add_parser(
        "coverage", help="record corpus and local coverage feedback"
    )
    _manifest_argument(coverage)
    _workspace_argument(coverage)
    coverage.add_argument("--candidate", required=True)
    coverage.add_argument("--before", type=Path)
    coverage.add_argument("--after", type=Path)
    coverage.add_argument("--engine-log", type=Path)
    coverage.add_argument("--coverage-artifact", action="append", type=Path, default=[])
    coverage.add_argument("--llvm-before", type=Path)
    coverage.add_argument("--llvm-after", type=Path)
    coverage.add_argument("--cpu-seconds", type=float, default=0.0)
    coverage.add_argument("--finding-count", type=int, default=0)
    _json_argument(coverage)

    analyze = subparsers.add_parser(
        "analyze", help="rank generated candidates using local AST and reachability metadata"
    )
    _manifest_argument(analyze)
    analyze.add_argument("--repo", required=True, type=Path)
    analyze.add_argument("--harnesses", type=Path)
    analyze.add_argument("--ast", type=Path)
    analyze.add_argument("--introspector", type=Path)
    analyze.add_argument("--output", required=True, type=Path)
    _json_argument(analyze)

    minimize = subparsers.add_parser("minimize", help="minimize a local crash artifact with replay checks")
    _manifest_argument(minimize)
    _workspace_argument(minimize)
    minimize.add_argument("--artifact", required=True, type=Path)
    minimize.add_argument("--expected-fingerprint", required=True)
    minimize.add_argument("--output", required=True, type=Path)
    minimize.add_argument("--timeout", type=int, default=120)
    _backend_argument(minimize)
    _execute_argument(minimize)
    _json_argument(minimize)

    known = subparsers.add_parser("known-issues", help="compare findings with local known-issue data")
    _manifest_argument(known)
    known.add_argument("--findings", required=True, type=Path)
    known.add_argument("--issues", required=True, type=Path)
    known.add_argument("--output", required=True, type=Path)
    _json_argument(known)

    benchmark = subparsers.add_parser("benchmark", help="measure local benchmark fixture effectiveness")
    benchmark.add_argument("--fixtures-dir", required=True, type=Path)
    _workspace_argument(benchmark)
    benchmark.add_argument("--output", required=True, type=Path)
    benchmark.add_argument("--markdown", type=Path)
    _execute_argument(benchmark)
    _json_argument(benchmark)

    engines = subparsers.add_parser("engines", help="list local fuzz engines and availability")
    _json_argument(engines)

    campaign = subparsers.add_parser("campaign", help="run or resume a staged local campaign")
    _manifest_argument(campaign)
    _workspace_argument(campaign)
    campaign.add_argument("--engine", choices=("standalone", "libfuzzer"), default="standalone")
    _backend_argument(campaign)
    campaign.add_argument("--duration", required=True, type=int, metavar="SECONDS")
    campaign.add_argument("--force-stage", choices=("prepare", "build", "harness_build", "run", "controls"))
    _execute_argument(campaign)
    _json_argument(campaign)

    controls = subparsers.add_parser("controls", help="run or plan a target control matrix")
    controls.add_argument("--target-pack", choices=("cjson",), required=True)
    controls.add_argument("--manifest", type=Path)
    _workspace_argument(controls)
    controls.add_argument("--current-revision", default=CJSON_CURRENT_COMMIT)
    controls.add_argument("--engine", choices=("standalone", "libfuzzer"), default="standalone")
    _backend_argument(controls)
    controls.add_argument("--duration", required=True, type=int, metavar="SECONDS")
    _execute_argument(controls)
    _json_argument(controls)

    reproduce = subparsers.add_parser(
        "reproduce", help="replay an artifact and compare its sanitizer fingerprint"
    )
    _manifest_argument(reproduce)
    _workspace_argument(reproduce)
    reproduce.add_argument("--artifact", required=True, type=Path)
    reproduce.add_argument("--findings", required=True, type=Path)
    reproduce.add_argument("--output", required=True, type=Path)
    reproduce.add_argument("--timeout", type=int, default=120, metavar="SECONDS")
    _backend_argument(reproduce)
    _execute_argument(reproduce)
    _json_argument(reproduce)

    findings = subparsers.add_parser("findings", help="extract structured sanitizer findings from a log")
    findings.add_argument("--log", required=True, type=Path)
    findings.add_argument("--artifact", type=Path)
    findings.add_argument("--output", required=True, type=Path)
    _json_argument(findings)

    triage = subparsers.add_parser("triage", help="deduplicate local crash artifacts")
    triage.add_argument("--artifacts", required=True, type=Path)
    triage.add_argument("--findings", type=Path)
    triage.add_argument("--output", required=True, type=Path)
    _json_argument(triage)

    report = subparsers.add_parser("report", help="write a human-review disclosure draft")
    _manifest_argument(report)
    report.add_argument("--artifact", required=True, type=Path)
    report.add_argument("--findings", type=Path)
    report.add_argument("--reproduction", type=Path)
    report.add_argument("--coverage", type=Path)
    report.add_argument("--campaign", type=Path)
    report.add_argument("--controls", type=Path)
    report.add_argument("--output", required=True, type=Path)
    _json_argument(report)

    bundle = subparsers.add_parser(
        "bundle", help="package a local finding for human review"
    )
    _manifest_argument(bundle)
    bundle.add_argument("--artifact", required=True, type=Path)
    bundle.add_argument("--output-dir", required=True, type=Path)
    bundle.add_argument("--findings", type=Path)
    bundle.add_argument("--triage", type=Path)
    bundle.add_argument("--reproduction", type=Path)
    bundle.add_argument("--minimization", type=Path)
    bundle.add_argument("--coverage", type=Path)
    bundle.add_argument("--campaign", type=Path)
    bundle.add_argument("--controls", type=Path)
    _json_argument(bundle)

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
    if args.command == "engines":
        engines = [
            {"name": item.name, "available": item.available, "executable": item.executable, "reason": item.reason}
            for item in list_engines()
        ]
        _success(args, {"engines": engines}, "\n".join(
            f"{item['name']}: {'available' if item['available'] else 'unavailable'} ({item['reason']})"
            for item in engines
        ))
        return 0

    if args.command == "campaign":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        engine_info = next(item for item in list_engines() if item.name == args.engine)
        if not engine_info.available:
            raise ScopeHoundError("engine_unavailable", engine_info.reason)
        campaign_path = workspace.campaign_file(manifest.target.name)
        state = load_campaign(campaign_path) if campaign_path.exists() else create_campaign(
            manifest, workspace, engine=args.engine, backend=args.backend
        )
        stages = (
            ("prepare", manifest.commands.prepare_steps),
            ("build", manifest.commands.build_steps),
            ("harness_build", manifest.commands.harness_build_steps),
        )
        for stage, group in stages:
            if group:
                state = run_stage(
                    state, manifest, workspace, stage, group,
                    execute=args.execute, force=args.force_stage == stage,
                )
        if manifest.commands.harness_build_steps and manifest.commands.fuzz_steps:
            state = run_stage(
                state, manifest, workspace, "run", manifest.commands.fuzz_steps,
                execute=args.execute, force=args.force_stage == "run",
            )
        payload = {
            "campaign_id": state.campaign_id, "target": state.target,
            "executed": bool(args.execute), "engine": state.engine, "backend": state.backend,
            "stages": [{"stage": item.stage, "status": item.status, "attempts": item.attempts} for item in state.stages],
            "output": str(campaign_path),
        }
        _success(args, payload, f"campaign {state.campaign_id}: {len(state.stages)} stages -> {campaign_path}")
        return 0

    if args.command == "controls":
        if args.execute and args.manifest is None:
            raise ScopeHoundError("authorization_required", "--manifest is required for control execution")
        manifest = None
        if args.manifest is not None:
            manifest = load_manifest(args.manifest)
            if args.execute and manifest.authorization.status != "authorized":
                raise ScopeHoundError("authorization_required", "control execution requires an authorized manifest")
        pack = cjson_target_pack(args.current_revision)
        if args.execute:
            result = run_cjson_validation(
                workspace=args.workspace,
                current_revision=args.current_revision,
                duration_seconds=args.duration,
                execute=True,
                manifest=manifest,
            )
            output = Workspace(args.workspace).controls_dir("cjson") / "comparison.json"
            _success(args, {"target": "cjson", "comparison": result["comparison"], "output": str(output)}, f"control matrix cjson -> {output}")
            return 0
        result = run_control_matrix(
            pack, Workspace(args.workspace), engine=args.engine, backend=args.backend,
            duration_seconds=args.duration, execute=args.execute,
        )
        _success(
            args,
            {"target": result["target"], "comparison": result["comparison"], "output": str(Workspace(args.workspace).controls_dir(str(result["target"])) / "comparison.json")},
            f"control matrix {result['target']} -> {Workspace(args.workspace).controls_dir(str(result['target'])) / 'comparison.json'}",
        )
        return 0

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
        result = run_plan(plan, args.execute, backend=args.backend)
        if args.execute:
            _write_logs(workspace, manifest, "build", (result,))
        _plans_success(args, (plan,), (result,))
        return 0

    if args.command == "fuzz":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        plan = fuzz_plan(manifest, workspace, args.duration)
        result = run_plan(plan, args.execute, allow_failure=True, backend=args.backend)
        if args.execute:
            _write_logs(workspace, manifest, "fuzz", (result,))
            findings = parse_sanitizer_output(result.stdout + "\n" + result.stderr)
            provenance = create_provenance(
                manifest, result, backend=args.backend, backend_policy=result.policy,
                timeout_seconds=args.duration + 10, environment=manifest.environment,
            )
            provenance_payload = {
                "target": provenance.target, "repository": provenance.repository,
                "revision": provenance.revision, "manifest_digest": provenance.manifest_digest,
                "argv": list(provenance.argv), "environment": dict(provenance.environment),
                "host_platform": provenance.host_platform, "toolchain": dict(provenance.toolchain),
                "sanitizer_runtime": provenance.sanitizer_runtime,
                "source_sha256": provenance.source_sha256, "binary_sha256": provenance.binary_sha256,
                "corpus_sha256": provenance.corpus_sha256, "dictionary_sha256": provenance.dictionary_sha256,
                "started_at": provenance.started_at, "ended_at": provenance.ended_at,
                "timeout_seconds": provenance.timeout_seconds, "backend": provenance.backend,
                "backend_policy": dict(provenance.backend_policy), "executed": provenance.executed,
            }
            findings = tuple(
                replace(item, normalized_stack=normalize_stack(item.stack), provenance=provenance_payload)
                for item in findings
            )
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

    if args.command == "discover":
        candidates = discover_harnesses(args.repo)
        write_harnesses(candidates, args.output)
        _success(args, {"count": len(candidates), "output": str(args.output)}, f"discovered {len(candidates)} harness candidates -> {args.output}")
        return 0

    if args.command == "generate-harnesses":
        candidates = generate_harnesses(args.repo)
        write_generated_harnesses(candidates, args.output_dir)
        _success(args, {"count": len(candidates), "output": str(args.output_dir)}, f"generated {len(candidates)} harness candidates -> {args.output_dir}")
        return 0

    if args.command == "validate-harnesses":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        output = _target_path(workspace, manifest.target.name, args.output)
        results = validate_harnesses(
            manifest,
            workspace,
            args.harnesses_dir,
            args.compiler,
            execute=args.execute,
            backend=args.backend,
        )
        write_validation(results, output)
        invalid = sum(result.status == "syntax_invalid" for result in results)
        if invalid:
            raise ScopeHoundError(
                "command_failed",
                f"{invalid} generated harnesses failed syntax validation; see {output}",
            )
        _success(
            args,
            {
                "count": len(results),
                "output": str(output),
                "statuses": {
                    status: sum(item.status == status for item in results)
                    for status in sorted({item.status for item in results})
                },
            },
            f"validated {len(results)} generated harnesses -> {output}",
        )
        return 0

    if args.command == "build-harnesses":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        results = build_harnesses(
            manifest, workspace, args.harnesses_dir, execute=args.execute, backend=args.backend
        )
        statuses = {status: sum(item.status == status for item in results) for status in sorted({item.status for item in results})}
        output = workspace.generated_dir(manifest.target.name) / "harness-build.json"
        if any(item.status == "build_failed" for item in results):
            raise ScopeHoundError("command_failed", f"one or more generated harnesses failed to build; see {output}")
        _success(
            args,
            {"count": len(results), "statuses": statuses, "output": str(output)},
            f"processed {len(results)} generated harnesses -> {output}",
        )
        return 0

    if args.command == "run-harness":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        result = run_harness(
            manifest, workspace, args.candidate, args.duration, execute=args.execute, backend=args.backend
        )
        if args.execute and result.findings:
            findings_path = workspace.findings_file(manifest.target.name)
            existing = load_findings(findings_path) if findings_path.exists() else ()
            merged = {item.fingerprint: item for item in (*existing, *result.findings)}
            write_findings(tuple(merged[key] for key in sorted(merged)), findings_path)
        if args.execute and result.status == "failed":
            raise ScopeHoundError("command_failed", f"harness exited {result.returncode} without a sanitizer finding")
        output = workspace.provenance_dir(manifest.target.name) / f"harness-{result.candidate_id}.json"
        _success(
            args,
            {"candidate": result.candidate_id, "status": result.status, "findings": len(result.findings), "output": str(output)},
            f"harness {result.candidate_id}: {result.status} -> {output}",
        )
        return 0

    if args.command == "coverage":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        engine_output = ""
        if args.engine_log:
            try:
                engine_output = args.engine_log.read_text(encoding="utf-8")
            except OSError as error:
                raise ScopeHoundError("input_invalid", f"cannot read engine log: {error}") from error
        record = collect_coverage(
            manifest, workspace, args.candidate, before_dir=args.before, after_dir=args.after,
            engine_output=engine_output, coverage_paths=tuple(args.coverage_artifact),
            llvm_before=args.llvm_before, llvm_after=args.llvm_after,
            cpu_seconds=args.cpu_seconds, finding_count=args.finding_count,
        )
        output = workspace.coverage_dir(manifest.target.name) / f"{args.candidate}.json"
        _success(
            args,
            {"candidate": record.candidate_id, "output": str(output), "function_delta": record.function_delta, "edge_delta": record.edge_delta},
            f"coverage record: {output}",
        )
        return 0

    if args.command == "analyze":
        manifest = load_manifest(args.manifest)
        candidates = _load_analysis_candidates(args.harnesses) if args.harnesses else _generated_candidates(args.repo)
        ast_functions = parse_ast_json(args.ast) if args.ast else ()
        introspector = import_fuzz_introspector(args.introspector) if args.introspector else None
        reachability = dict(introspector.reachability) if introspector else {}
        covered = dict(introspector.covered) if introspector else {}
        ranked = rank_candidates(
            candidates, authorized=manifest.authorization.status == "authorized",
            reachability=reachability, covered=covered,
        )
        payload = {
            "target": manifest.target.name,
            "ast_functions": [
                {"name": item.name, "qualified_name": item.qualified_name, "file": item.file, "line": item.line, "parameters": list(item.parameters), "namespace": item.namespace}
                for item in ast_functions
            ],
            "introspector": {"source": introspector.source, "reachability": reachability, "covered": covered} if introspector else None,
            "ranked": [
                {"path": item.path, "function": item.function, "score": item.score, "authorization": item.authorization, "buildability": item.buildability, "reachability": item.reachability, "coverage_gap": item.coverage_gap, "input_suitability": item.input_suitability, "duplicate_risk": item.duplicate_risk}
                for item in ranked
            ],
        }
        _write_json_output(payload, args.output)
        _success(args, {"count": len(ranked), "output": str(args.output)}, f"ranked {len(ranked)} candidates -> {args.output}")
        return 0

    if args.command == "minimize":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        result = minimize_artifact(
            manifest, workspace, args.artifact, args.expected_fingerprint,
            execute=args.execute, timeout_seconds=args.timeout, backend=args.backend,
        )
        write_minimized(result, args.output)
        _success(
            args,
            {"status": result.status, "child": result.child, "parent_sha256": result.parent_sha256, "child_sha256": result.child_sha256, "output": str(args.output)},
            f"minimization {result.status}: {result.child} -> {args.output}",
        )
        return 0

    if args.command == "known-issues":
        manifest = load_manifest(args.manifest)
        findings = load_findings(args.findings)
        issues = load_known_issues(args.issues)
        comparisons = compare_known_issues(findings, issues, current_revision=manifest.target.revision)
        write_comparisons(comparisons, args.output)
        _success(
            args,
            {"count": len(comparisons), "labels": {label: sum(item.label == label for item in comparisons) for label in sorted({item.label for item in comparisons})}, "output": str(args.output)},
            f"compared {len(comparisons)} findings -> {args.output}",
        )
        return 0

    if args.command == "benchmark":
        workspace = Workspace(args.workspace)
        result = run_benchmark(args.fixtures_dir, workspace, execute=args.execute)
        payload = {
            "version": result.version, "fixtures": result.fixtures,
            "link_success_rate": result.link_success_rate, "coverage_delta": result.coverage_delta,
            "unique_fingerprints_per_cpu_hour": result.unique_fingerprints_per_cpu_hour,
            "replay_success_rate": result.replay_success_rate, "duplicate_rate": result.duplicate_rate,
            "false_positive_rate": result.false_positive_rate, "skipped_tools": list(result.skipped_tools),
        }
        _write_json_output(payload, args.output)
        if args.markdown:
            write_benchmark_markdown(result, args.markdown)
        _success(args, {"fixtures": result.fixtures, "output": str(args.output), "markdown": str(args.markdown) if args.markdown else None}, f"benchmark: {args.output}")
        return 0

    if args.command == "reproduce":
        manifest = load_manifest(args.manifest)
        workspace = Workspace(args.workspace)
        findings_path = _target_path(workspace, manifest.target.name, args.findings)
        output = _target_path(workspace, manifest.target.name, args.output)
        artifact = args.artifact.expanduser().resolve()
        parsed = load_findings(findings_path)
        matching = [item for item in parsed if item.artifact == artifact.name]
        baseline = matching[0] if matching else (parsed[0] if len(parsed) == 1 else None)
        if baseline is None:
            raise ScopeHoundError(
                "input_invalid", f"no unique baseline finding matches artifact: {artifact.name}"
            )
        result = reproduce_finding(
            manifest,
            workspace,
            artifact,
            baseline.fingerprint,
            execute=args.execute,
            timeout_seconds=args.timeout,
            backend=args.backend,
        )
        write_reproduction(result, output)
        if result.status == "reproduced":
            updated = tuple(
                replace(item, reproducibility="reproduced")
                if item.fingerprint == baseline.fingerprint
                else item
                for item in parsed
            )
            write_findings(updated, findings_path)
        if result.status in {"different_finding", "not_reproduced"}:
            raise ScopeHoundError(
                "command_failed", f"reproduction status: {result.status}; see {output}"
            )
        _success(
            args,
            {"artifact": result.artifact, "output": str(output), "status": result.status},
            f"reproduction status: {result.status} -> {output}",
        )
        return 0

    if args.command == "triage":
        result = triage_artifacts(args.artifacts)
        if args.findings:
            findings = load_findings(args.findings)
            result = TriageResult(
                result.unique, result.duplicates, cluster_findings(findings)
            )
        write_triage(result, args.output)
        payload = {
            "unique": len(result.unique),
            "duplicate_groups": len(result.duplicates),
            "finding_groups": len(result.finding_groups),
            "output": str(args.output),
        }
        _success(
            args,
            payload,
            f"triaged {len(result.unique)} unique artifacts and "
            f"{len(result.finding_groups)} finding groups -> {args.output}",
        )
        return 0

    if args.command == "report":
        manifest = load_manifest(args.manifest)
        artifact = inspect_artifact(args.artifact)
        finding = None
        if args.findings:
            parsed = load_findings(args.findings)
            matching = [item for item in parsed if item.artifact == artifact.path.name]
            finding = matching[0] if matching else (parsed[0] if len(parsed) == 1 else None)
        reproduction = None
        if args.reproduction:
            reproduction = load_reproduction(args.reproduction)
            if reproduction.artifact != artifact.path.name:
                raise ScopeHoundError(
                    "input_invalid",
                    f"reproduction artifact does not match requested artifact: {reproduction.artifact}",
                )
        report = render_report(manifest, artifact, artifact.path.name, finding, reproduction)
        if args.coverage:
            report = render_report(
                manifest, artifact, artifact.path.name, finding, reproduction,
                load_coverage(args.coverage),
            )
        campaign_record = _load_json_mapping(args.campaign) if args.campaign else None
        controls_record = _load_json_mapping(args.controls) if args.controls else None
        if campaign_record or controls_record:
            report = render_report(
                manifest, artifact, artifact.path.name, finding, reproduction,
                load_coverage(args.coverage) if args.coverage else None,
                campaign_record, controls_record,
            )
        write_report(report, args.output)
        _success(args, {"output": str(args.output), "sha256": artifact.sha256}, f"report draft: {args.output}")
        return 0

    if args.command == "bundle":
        manifest = load_manifest(args.manifest)
        summary = create_bundle(
            args.manifest,
            manifest,
            args.artifact,
            args.output_dir,
            args.findings,
            args.triage,
            args.reproduction,
            args.minimization,
            args.coverage,
            args.campaign,
            args.controls,
        )
        _success(
            args,
            {
                "artifact_sha256": summary.artifact_sha256,
                "files": list(summary.files),
                "output": str(summary.output),
            },
            f"review bundle: {summary.output}",
        )
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
            f"backend: {result.backend}\n"
            f"policy: {json.dumps(dict(result.policy), sort_keys=True)}\n"
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
            {
                "argv": list(plan.argv), "cwd": str(plan.cwd),
                "timeout_seconds": plan.timeout_seconds,
                "backend": result.backend, "policy": dict(result.policy),
            }
            for plan, result in zip(plans, results)
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


def _backend_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend", choices=("native", "bubblewrap", "docker"), default="native",
        help="execution backend; unavailable sandboxes fail without fallback",
    )


def _target_path(workspace: Workspace, target_name: str, requested: Path) -> Path:
    target = workspace.target_dir(target_name)
    resolved = requested.expanduser().resolve()
    try:
        resolved.relative_to(target)
    except ValueError as error:
        raise ScopeHoundError(
            "unsafe_path", "output must remain inside the target workspace"
        ) from error
    return resolved


def _generated_candidates(repo: Path) -> tuple[HarnessCandidate, ...]:
    return generate_harnesses(repo)


def _load_analysis_candidates(path: Path) -> tuple[HarnessCandidate, ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read harness candidates: {error}") from error
    if not isinstance(payload, list):
        raise ScopeHoundError("input_invalid", "harness candidates must be an array")
    candidates: list[HarnessCandidate] = []
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("generated_file"), str):
            raise ScopeHoundError("input_invalid", "harness candidate lacks generated_file")
        path_value = item.get("path", item["generated_file"])
        candidates.append(
            HarnessCandidate(
                path=Path(str(path_value)), function=str(item.get("function", Path(item["generated_file"]).stem)),
                parameters=str(item.get("parameters", "")), confidence=str(item.get("confidence", "low")),
                status=str(item.get("status", "needs_build_validation")), source="",
            )
        )
    return tuple(candidates)


def _write_json_output(payload: object, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write output {output}: {error}") from error


def _load_json_mapping(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read JSON record {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ScopeHoundError("input_invalid", f"JSON record must be an object: {path}")
    return payload
