from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output
from scopehound.manifest import validate_manifest
from scopehound.reproduction import (
    load_reproduction,
    record_replay_attempt,
    reproduce_finding,
    write_reproduction,
)
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


ASAN_REPRO_LOG = (
    "ERROR: AddressSanitizer: heap-buffer-overflow\n"
    "    #0 0x1 in parse /src/parser.c:12:4\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"
)


class ReproductionTests(unittest.TestCase):
    def test_dry_run_requires_configured_command_and_substitutes_artifact(self) -> None:
        manifest = self._manifest([sys.executable, "-c", "print('planned')", "{artifact}"])
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            artifact = workspace.artifacts_dir(manifest.target.name) / "crash-001"
            artifact.parent.mkdir(parents=True)
            workspace.repo_dir(manifest.target.name).mkdir(parents=True)
            artifact.write_bytes(b"boom")

            result = reproduce_finding(manifest, workspace, artifact, "expected", execute=False)

        self.assertEqual(result.status, "planned")
        self.assertIsNone(result.returncode)
        self.assertEqual(result.expected_fingerprint, "expected")
        self.assertIn(str(artifact), result.command)

    def test_execute_marks_matching_sanitizer_fingerprint_reproduced(self) -> None:
        manifest = self._manifest([
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1]); print(" + repr(ASAN_REPRO_LOG) + "); raise SystemExit(1)",
            "{artifact}",
        ])
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            artifact = workspace.artifacts_dir(manifest.target.name) / "crash-001"
            artifact.parent.mkdir(parents=True)
            workspace.repo_dir(manifest.target.name).mkdir(parents=True)
            artifact.write_bytes(b"boom")
            expected = parse_sanitizer_output(ASAN_REPRO_LOG, artifact)[0].fingerprint

            result = reproduce_finding(manifest, workspace, artifact, expected, execute=True)
            output = Path(temp_dir) / "reproduction.json"
            write_reproduction(result, output)
            payload = json.loads(output.read_text(encoding="utf-8"))
            loaded = load_reproduction(output)

        self.assertEqual(result.status, "reproduced")
        self.assertEqual(result.returncode, 1)
        self.assertIn(expected, result.observed_fingerprints)
        self.assertEqual(payload["status"], "reproduced")
        self.assertEqual(loaded.status, "reproduced")
        self.assertEqual(loaded.matching_attempts, 1)
        self.assertEqual(len(loaded.attempts), 1)

    def test_two_matching_replays_are_accounted_without_losing_evidence(self) -> None:
        manifest = self._manifest([
            sys.executable,
            "-c",
            "print(" + repr(ASAN_REPRO_LOG) + "); raise SystemExit(1)",
            "{artifact}",
        ])
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            artifact = workspace.artifacts_dir(manifest.target.name) / "crash-001"
            artifact.parent.mkdir(parents=True)
            workspace.repo_dir(manifest.target.name).mkdir(parents=True)
            artifact.write_bytes(b"boom")
            expected = parse_sanitizer_output(ASAN_REPRO_LOG, artifact)[0].fingerprint
            first = reproduce_finding(manifest, workspace, artifact, expected, execute=True)
            second = reproduce_finding(manifest, workspace, artifact, expected, execute=True)

        merged = record_replay_attempt(first, second)

        self.assertEqual(merged.status, "reproduced")
        self.assertEqual(merged.matching_attempts, 2)
        self.assertEqual(len(merged.attempts), 2)

    def test_old_reproduction_record_loads_with_one_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "old.json"
            output.write_text(json.dumps({
                "artifact": "crash", "expected_fingerprint": "fp",
                "observed_fingerprints": ["fp"], "status": "reproduced",
                "command": ["./fuzzer", "crash"], "returncode": 1,
                "stdout": "asan", "stderr": "",
            }), encoding="utf-8")

            result = load_reproduction(output)

        self.assertEqual(result.matching_attempts, 1)
        self.assertEqual(len(result.attempts), 1)

    def test_execute_distinguishes_missing_reproduction(self) -> None:
        manifest = self._manifest([sys.executable, "-c", "print('no sanitizer')", "{artifact}"])
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            artifact = workspace.artifacts_dir(manifest.target.name) / "crash-001"
            artifact.parent.mkdir(parents=True)
            workspace.repo_dir(manifest.target.name).mkdir(parents=True)
            artifact.write_bytes(b"boom")

            result = reproduce_finding(manifest, workspace, artifact, "expected", execute=True)

        self.assertEqual(result.status, "not_reproduced")
        self.assertEqual(result.observed_fingerprints, ())

    def test_reproduction_artifact_must_be_inside_workspace_artifacts(self) -> None:
        manifest = self._manifest([sys.executable, "-c", "print('planned')", "{artifact}"])
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            outside = Path(temp_dir) / "outside"
            outside.write_bytes(b"boom")

            with self.assertRaises(ScopeHoundError) as raised:
                reproduce_finding(manifest, workspace, outside, "expected", execute=False)

        self.assertEqual(raised.exception.category, "unsafe_path")

    @staticmethod
    def _manifest(command: list[str]):
        data = valid_manifest_data()
        data["commands"]["reproduce"] = command  # type: ignore[index]
        return validate_manifest(data)


if __name__ == "__main__":
    unittest.main()
