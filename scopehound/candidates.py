from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from scopehound.errors import ScopeHoundError
from scopehound.findings import Finding, parse_sanitizer_output
from scopehound.manifest import Manifest
from scopehound.policy import require_authorized
from scopehound.runner import CommandPlan, CommandResult, run_plan
from scopehound.workspace import Workspace


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: str
    generated_file: str
    source_path: str
    function: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class CandidateBuild:
    candidate_id: str
    generated_file: str
    source: str
    binary: str
    command: tuple[str, ...]
    status: str
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class HarnessRun:
    candidate_id: str
    binary: str
    corpus_dir: str
    artifact_dir: str
    command: tuple[str, ...]
    status: str
    returncode: int | None
    stdout: str
    stderr: str
    findings: tuple[Finding, ...]


def load_candidates(harnesses_dir: Path, target_dir: Path) -> tuple[CandidateRecord, ...]:
    root = _contained(target_dir, harnesses_dir, "harness directory")
    metadata_path = root / "harnesses.json"
    try:
        payload: Any = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read harness metadata: {error}") from error
    if not isinstance(payload, list):
        raise ScopeHoundError("input_invalid", "harness metadata must be an array")
    records: list[CandidateRecord] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ScopeHoundError("input_invalid", f"harness metadata item {index} must be an object")
        generated = item.get("generated_file")
        if not isinstance(generated, str) or Path(generated).name != generated:
            raise ScopeHoundError("unsafe_path", f"invalid generated harness path: {generated!r}")
        generated_path = _contained(root, root / generated, "generated harness")
        if not generated_path.is_file():
            raise ScopeHoundError("input_invalid", f"generated harness is missing: {generated_path}")
        source_value = item.get("path", generated)
        if not isinstance(source_value, str):
            raise ScopeHoundError("input_invalid", f"harness metadata item {index} path must be a string")
        function = item.get("function", Path(generated).stem)
        if not isinstance(function, str) or not function:
            raise ScopeHoundError("input_invalid", f"harness metadata item {index} function must be a string")
        candidate_id = hashlib.sha256(
            f"{generated}\0{source_value}\0{function}".encode("utf-8")
        ).hexdigest()[:16]
        records.append(
            CandidateRecord(
                candidate_id=candidate_id,
                generated_file=generated,
                source_path=source_value,
                function=function,
                metadata=dict(item),
            )
        )
    return tuple(sorted(records, key=lambda record: (record.function, record.generated_file, record.candidate_id)))


def build_harnesses(
    manifest: Manifest,
    workspace: Workspace,
    harnesses_dir: Path,
    *,
    execute: bool = False,
    backend: str = "native",
) -> tuple[CandidateBuild, ...]:
    require_authorized(manifest)
    target_dir = workspace.target_dir(manifest.target.name)
    repository = workspace.repo_dir(manifest.target.name)
    if execute and not repository.is_dir():
        raise ScopeHoundError("workspace_missing", f"target checkout is missing: {repository}")
    candidates = load_candidates(harnesses_dir, target_dir)
    results: list[CandidateBuild] = []
    for candidate in candidates:
        source = _contained(target_dir, Path(harnesses_dir).resolve() / candidate.generated_file, "generated source")
        binary = _contained(workspace.binaries_dir(manifest.target.name), workspace.binaries_dir(manifest.target.name) / f"{candidate.candidate_id}.bin", "candidate binary")
        if manifest.commands.harness_build is None:
            results.append(
                CandidateBuild(
                    candidate_id=candidate.candidate_id,
                    generated_file=candidate.generated_file,
                    source=str(source),
                    binary=str(binary),
                    command=(),
                    status="unconfigured",
                    returncode=None,
                    stdout="",
                    stderr="commands.harness_build is not configured",
                )
            )
            continue
        argv = _substitute(
            manifest.commands.harness_build,
            repo=repository,
            source=source,
            binary=binary,
            corpus=workspace.corpus_dir(manifest.target.name),
            dictionary=_dictionary_path(manifest, repository),
            artifact=workspace.artifacts_dir(manifest.target.name),
            duration=0,
        )
        plan = CommandPlan(
            argv=argv,
            cwd=repository,
            environment=MappingProxyType(dict(manifest.environment)),
            timeout_seconds=600,
            mutates=True,
            create_directories=(workspace.binaries_dir(manifest.target.name), workspace.logs_dir(manifest.target.name)),
        )
        result = run_plan(plan, execute=execute, allow_failure=True, backend=backend)
        status = "planned" if not execute else ("built" if result.returncode == 0 else "build_failed")
        results.append(
            CandidateBuild(
                candidate_id=candidate.candidate_id,
                generated_file=candidate.generated_file,
                source=str(source),
                binary=str(binary),
                command=argv,
                status=status,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        )
    _write_builds(results, workspace.generated_dir(manifest.target.name) / "harness-build.json")
    return tuple(results)


def run_harness(
    manifest: Manifest,
    workspace: Workspace,
    candidate_id: str,
    duration_seconds: int,
    *,
    execute: bool = False,
    backend: str = "native",
) -> HarnessRun:
    require_authorized(manifest)
    if not 1 <= duration_seconds <= 86_400:
        raise ScopeHoundError("duration_invalid", "harness duration must be between 1 and 86400 seconds")
    builds = _load_builds(workspace.generated_dir(manifest.target.name) / "harness-build.json")
    build = next((item for item in builds if item.candidate_id == candidate_id), None)
    if build is None or build.status != "built":
        raise ScopeHoundError("candidate_not_built", f"candidate is not marked built: {candidate_id}")
    binary = Path(build.binary).resolve()
    _contained(workspace.binaries_dir(manifest.target.name), binary, "candidate binary")
    repository = workspace.repo_dir(manifest.target.name)
    corpus_dir = _contained(workspace.corpus_dir(manifest.target.name), workspace.corpus_dir(manifest.target.name) / candidate_id, "candidate corpus")
    artifact_dir = _contained(workspace.artifacts_dir(manifest.target.name), workspace.artifacts_dir(manifest.target.name) / candidate_id, "candidate artifacts")
    if manifest.commands.fuzz.count("{binary}") != 1:
        raise ScopeHoundError("manifest_invalid", "commands.fuzz must contain exactly one {binary} placeholder for run-harness")
    argv = _substitute(
        manifest.commands.fuzz,
        repo=repository,
        source=Path(build.source),
        binary=binary,
        corpus=corpus_dir,
        dictionary=_dictionary_path(manifest, repository),
        artifact=artifact_dir,
        duration=duration_seconds,
    )
    environment = dict(manifest.environment)
    environment["SCOPEHOUND_ARTIFACTS_DIR"] = str(artifact_dir)
    environment["SCOPEHOUND_CORPUS_DIR"] = str(corpus_dir)
    environment["SCOPEHOUND_CANDIDATE_ID"] = candidate_id
    plan = CommandPlan(
        argv=argv,
        cwd=repository,
        environment=MappingProxyType(environment),
        timeout_seconds=duration_seconds + 10,
        mutates=True,
        create_directories=(corpus_dir, artifact_dir, workspace.logs_dir(manifest.target.name)),
    )
    result = run_plan(plan, execute=execute, allow_failure=True, backend=backend)
    findings = parse_sanitizer_output(result.stdout + "\n" + result.stderr) if execute else ()
    status = "planned" if not execute else ("finding" if findings else ("completed" if result.returncode == 0 else "failed"))
    record = HarnessRun(
        candidate_id=candidate_id,
        binary=str(binary),
        corpus_dir=str(corpus_dir),
        artifact_dir=str(artifact_dir),
        command=argv,
        status=status,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        findings=findings,
    )
    _write_run(record, workspace.provenance_dir(manifest.target.name) / f"harness-{candidate_id}.json")
    return record


def _dictionary_path(manifest: Manifest, repository: Path) -> Path:
    if manifest.corpus.dictionary is None:
        return Path("")
    return _contained(repository, repository / manifest.corpus.dictionary, "corpus dictionary")


def _substitute(command: tuple[str, ...], **values: Path | int) -> tuple[str, ...]:
    rendered: list[str] = []
    for argument in command:
        value = argument
        for name, replacement in values.items():
            value = value.replace("{" + name + "}", str(replacement))
        if "{" in value or "}" in value:
            raise ScopeHoundError("manifest_invalid", f"unresolved command placeholder: {argument}")
        rendered.append(value)
    return tuple(rendered)


def _contained(base: Path, candidate: Path, label: str) -> Path:
    resolved_base = base.resolve()
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_base)
    except ValueError as error:
        raise ScopeHoundError("unsafe_path", f"{label} must remain inside the target workspace") from error
    return resolved_candidate


def _write_builds(results: list[CandidateBuild] | tuple[CandidateBuild, ...], output: Path) -> None:
    payload = []
    for result in results:
        item = asdict(result)
        item["command"] = list(result.command)
        payload.append(item)
    _write_json(payload, output)


def _load_builds(path: Path) -> tuple[CandidateBuild, ...]:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read candidate build record: {error}") from error
    if not isinstance(payload, list):
        raise ScopeHoundError("input_invalid", "candidate build record must be an array")
    try:
        return tuple(
            CandidateBuild(
                candidate_id=item["candidate_id"], generated_file=item["generated_file"],
                source=item["source"], binary=item["binary"], command=tuple(item["command"]),
                status=item["status"], returncode=item.get("returncode"),
                stdout=item.get("stdout", ""), stderr=item.get("stderr", ""),
            )
            for item in payload
        )
    except (KeyError, TypeError) as error:
        raise ScopeHoundError("input_invalid", f"invalid candidate build record: {error}") from error


def _write_run(result: HarnessRun, output: Path) -> None:
    item = asdict(result)
    item["command"] = list(result.command)
    item["findings"] = [
        {**asdict(finding), "stack": list(finding.stack)} for finding in result.findings
    ]
    _write_json(item, output)


def _write_json(payload: object, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write candidate record {output}: {error}") from error
