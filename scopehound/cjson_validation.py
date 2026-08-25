from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Mapping

from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output
from scopehound.manifest import Manifest
from scopehound.targetpacks import CJSON_CURRENT_COMMIT, ControlRevision, cjson_target_pack, resolve_revision


def run_cjson_validation(
    *,
    workspace: Path | None = None,
    current_revision: str = CJSON_CURRENT_COMMIT,
    duration_seconds: int = 5,
    execute: bool = False,
    manifest: Manifest | None = None,
) -> Mapping[str, object]:
    if not 1 <= duration_seconds <= 86_400:
        raise ScopeHoundError("duration_invalid", "validation duration must be between 1 and 86400 seconds")
    pack = cjson_target_pack(current_revision)
    if not execute:
        return {
            "target": "cjson", "executed": False,
            "controls": [
                {"label": item.label, "role": item.role, "requested_revision": item.requested_revision,
                 "status": "planned", "fingerprints": []}
                for item in pack["controls"]  # type: ignore[union-attr]
            ],
            "published_paths": [],
        }
    if manifest is None or manifest.authorization.status != "authorized":
        raise ScopeHoundError("authorization_required", "cJSON execution requires an authorized manifest")
    if shutil.which("git") is None or shutil.which("gcc") is None:
        raise ScopeHoundError("integration_unavailable", "git and gcc are required for cJSON validation")
    if workspace is None:
        with tempfile.TemporaryDirectory(prefix="scopehound-cjson-") as temp_dir:
            return _run_in_workspace(pack, Path(temp_dir) / "targets" / "cjson", duration_seconds)
    root = workspace.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return _run_in_workspace(pack, root / "targets" / "cjson", duration_seconds)


def _run_in_workspace(pack: Mapping[str, object], root: Path, duration_seconds: int) -> Mapping[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    repository = root / "repo"
    _run(("git", "clone", "--quiet", str(pack["repository"]), str(repository)), cwd=root, timeout=600)
    seed_path = root / "seed.bin"
    seed = bytes(pack["seed"])
    seed_path.write_bytes(seed)
    records: dict[str, Mapping[str, object]] = {}
    for control in pack["controls"]:  # type: ignore[union-attr]
        if not isinstance(control, ControlRevision):
            raise ScopeHoundError("input_invalid", "cJSON control has an invalid type")
        _checkout(repository, control.requested_revision)
        commit = resolve_revision(repository)
        records[control.role] = _run_control(
            repository, root / control.role, seed_path, control, commit, duration_seconds
        )
    comparison = {
        "positive_status": records["positive"]["status"],
        "fixed_status": records["fixed"]["status"],
        "current_status": records["current"]["status"],
    }
    result = {
        "target": "cjson", "executed": True,
        "positive": records["positive"], "fixed": records["fixed"], "current": records["current"],
        "comparison": comparison, "published_paths": [],
        "input_sha256": hashlib.sha256(seed).hexdigest(),
    }
    _write_json(result, root / "comparison.json")
    return result


def _run_control(
    repository: Path,
    output_dir: Path,
    seed_path: Path,
    control: ControlRevision,
    commit: str,
    duration_seconds: int,
) -> Mapping[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    build_dir = output_dir / "build"
    build_dir.mkdir()
    harness = build_dir / "cjson_harness.c"
    harness.write_text(str(cjson_target_pack()["harness"].source), encoding="utf-8")
    driver = Path(__file__).with_name("standalone_driver.c")
    binary = build_dir / "cjson-driver"
    compile_argv = (
        "gcc", "-g", "-O1", "-fsanitize=address,undefined", "-I", str(repository),
        str(repository / "cJSON.c"), str(harness), str(driver),
        "-fsanitize=address,undefined", "-o", str(binary),
    )
    compiled = _run(compile_argv, cwd=repository, timeout=120)
    if compiled.returncode != 0:
        raise ScopeHoundError("command_failed", f"cJSON {control.role} build failed: {compiled.stderr[-1000:]}")
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    command = (str(binary), str(seed_path))
    try:
        run = subprocess.run(
            command, cwd=repository, env=environment, capture_output=True, text=True,
            shell=False, timeout=duration_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScopeHoundError("command_failed", f"cJSON {control.role} execution failed: {error}") from error
    raw = run.stdout + "\n" + run.stderr
    log_path = output_dir / "run.log"
    log_path.write_text(raw, encoding="utf-8")
    findings = parse_sanitizer_output(raw, seed_path)
    if control.role == "positive":
        status = "positive_reproduced" if findings else "positive_not_reproduced"
    elif control.role == "fixed":
        status = "fixed_reproduced" if findings else "fixed_not_reproduced"
    else:
        status = "current_observed" if findings else "current_not_observed"
    fingerprint = ""
    if findings:
        fingerprint = f"{findings[0].kind} in {findings[0].function}"
    record = {
        "label": control.label, "role": control.role, "requested_revision": control.requested_revision,
        "commit": commit, "expected": control.expected, "status": status,
        "fingerprint": fingerprint, "fingerprints": [finding.fingerprint for finding in findings],
        "returncode": run.returncode, "command": list(command), "compile_command": list(compile_argv),
        "log": str(log_path), "input_sha256": hashlib.sha256(seed_path.read_bytes()).hexdigest(),
        "toolchain": _gcc_version(),
    }
    _write_json(record, output_dir / "record.json")
    return record


def _checkout(repository: Path, revision: str) -> None:
    _run(("git", "checkout", "--quiet", "--detach", revision), cwd=repository, timeout=120)


def _run(argv: tuple[str, ...], *, cwd: Path, timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv, cwd=cwd, capture_output=True, text=True, shell=False, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScopeHoundError("command_failed", f"could not run {argv[0]}: {error}") from error
    if result.returncode != 0 and argv[:2] in (("git", "clone"), ("git", "checkout")):
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise ScopeHoundError("command_failed", f"{argv[0]} failed: {detail[:1000]}")
    return result


def _gcc_version() -> str:
    try:
        result = subprocess.run(("gcc", "--version"), capture_output=True, text=True, shell=False, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    return (result.stdout or result.stderr).splitlines()[0][:200] if (result.stdout or result.stderr) else "unknown"


def _write_json(payload: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
