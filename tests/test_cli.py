from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scopehound.cli import main

from tests.fixtures import valid_manifest_data


class CliTests(unittest.TestCase):
    def test_bundled_example_manifest_validates(self) -> None:
        example = Path(__file__).parents[1] / "examples" / "example-target.json"

        code, output, _ = self._run("validate", "--manifest", str(example))

        self.assertEqual(code, 0)
        self.assertIn("valid: example-parser", output)

    def test_help_lists_all_commands(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        for command in ("validate", "score", "prepare", "build", "fuzz", "discover", "generate-harnesses", "findings", "triage", "report"):
            self.assertIn(command, output.getvalue())

    def test_validate_supports_text_and_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = self._write_manifest(Path(temp_dir), valid_manifest_data())

            text_code, text_output, _ = self._run("validate", "--manifest", str(manifest_path))
            json_code, json_output, _ = self._run(
                "validate", "--manifest", str(manifest_path), "--json"
            )

        self.assertEqual(text_code, 0)
        self.assertIn("valid: example-parser", text_output)
        self.assertEqual(json_code, 0)
        self.assertEqual(json.loads(json_output)["target"], "example-parser")

    def test_score_explains_factors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = self._write_manifest(Path(temp_dir), valid_manifest_data())

            code, output, _ = self._run("score", "--manifest", str(manifest_path), "--json")

        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertAlmostEqual(payload["score"], 55.256, places=3)
        self.assertEqual(payload["factors"]["fuzzing_gap"], 0.9)

    def test_prepare_build_and_fuzz_are_dry_run_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = self._write_manifest(root, valid_manifest_data())
            workspace = root / "state"

            prepare_code, prepare_output, _ = self._run(
                "prepare", "--manifest", str(manifest_path), "--workspace", str(workspace)
            )
            build_code, build_output, _ = self._run(
                "build", "--manifest", str(manifest_path), "--workspace", str(workspace)
            )
            fuzz_code, fuzz_output, _ = self._run(
                "fuzz", "--manifest", str(manifest_path), "--workspace", str(workspace),
                "--duration", "30",
            )

            self.assertFalse(workspace.exists())

        self.assertEqual((prepare_code, build_code, fuzz_code), (0, 0, 0))
        self.assertIn("DRY RUN", prepare_output)
        self.assertIn("DRY RUN", build_output)
        self.assertIn("DRY RUN", fuzz_output)

    def test_execution_requires_authorized_manifest(self) -> None:
        data = valid_manifest_data()
        data["authorization"]["status"] = "permission-needed"  # type: ignore[index]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = self._write_manifest(root, data)

            code, _, error = self._run(
                "prepare", "--manifest", str(manifest_path), "--workspace", str(root / "state")
            )

        self.assertEqual(code, 2)
        self.assertIn("authorization_required", error)

    def test_invalid_duration_returns_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = self._write_manifest(root, valid_manifest_data())

            code, _, error = self._run(
                "fuzz", "--manifest", str(manifest_path), "--workspace", str(root / "state"),
                "--duration", "0",
            )

        self.assertEqual(code, 2)
        self.assertIn("duration_invalid", error)

    def test_triage_and_report_create_requested_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            artifact = artifacts / "crash-001"
            artifact.write_bytes(b"boom")
            manifest_path = self._write_manifest(root, valid_manifest_data())
            triage_output = root / "triage.json"
            report_output = root / "report.md"

            triage_code, _, _ = self._run(
                "triage", "--artifacts", str(artifacts), "--output", str(triage_output)
            )
            report_code, _, _ = self._run(
                "report", "--manifest", str(manifest_path), "--artifact", str(artifact),
                "--output", str(report_output),
            )

            self.assertEqual(triage_code, 0)
            self.assertEqual(report_code, 0)
            self.assertEqual(json.loads(triage_output.read_text())["unique"][0]["path"], "crash-001")
            self.assertIn("human_review_required: true", report_output.read_text())

    def test_findings_command_extracts_a_reproducible_issue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            log = root / "asan.log"
            output = root / "findings.json"
            log.write_text(
                "ERROR: AddressSanitizer: heap-use-after-free\\n"
                "    #0 0x1 in parse /src/parser.c:12:4\\n"
                "SUMMARY: AddressSanitizer: heap-use-after-free /src/parser.c:12:4 in parse\\n",
                encoding="utf-8",
            )

            code, _, _ = self._run(
                "findings", "--log", str(log), "--output", str(output),
                "--artifact", "crash-001",
            )

            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(payload[0]["kind"], "heap-use-after-free")
        self.assertEqual(payload[0]["artifact"], "crash-001")

    def test_discover_command_writes_harness_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "fuzz.cc").write_text("LLVMFuzzerTestOneInput", encoding="utf-8")
            output = root / "harnesses.json"

            code, _, _ = self._run("discover", "--repo", str(root), "--output", str(output))

            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(payload[0]["entrypoint"], "LLVMFuzzerTestOneInput")

    def test_generate_harnesses_command_writes_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "parser.h").write_text(
                "int parse_packet(const unsigned char *data, size_t size);", encoding="utf-8"
            )
            output = root / "generated"

            code, _, _ = self._run(
                "generate-harnesses", "--repo", str(root), "--output-dir", str(output)
            )
            self.assertEqual(code, 0)
            self.assertTrue((output / "parse_packet_fuzzer.cc").exists())

    @staticmethod
    def _write_manifest(root: Path, data: dict[str, object]) -> Path:
        path = root / "target.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    @staticmethod
    def _run(*args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
