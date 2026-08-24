from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.manifest import validate_manifest
from scopehound.validation import validate_harnesses, write_validation
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


class HarnessValidationTests(unittest.TestCase):
    def test_dry_run_records_a_compile_plan_without_running_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = validate_manifest(valid_manifest_data())
            workspace = Workspace(root / "state")
            harnesses = workspace.target_dir(manifest.target.name) / "generated"
            harnesses.mkdir(parents=True)
            (workspace.repo_dir(manifest.target.name)).mkdir(parents=True)
            (harnesses / "harnesses.json").write_text(
                json.dumps([{"generated_file": "parse_packet_fuzzer.cc"}]),
                encoding="utf-8",
            )
            (harnesses / "parse_packet_fuzzer.cc").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *, unsigned long) { return 0; }\n",
                encoding="utf-8",
            )

            results = validate_harnesses(manifest, workspace, harnesses, "c++", execute=False)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "planned")
        self.assertIsNone(results[0].returncode)
        self.assertEqual(results[0].command[0], "c++")

    @unittest.skipUnless(shutil.which("c++"), "a C++ compiler is required")
    def test_execute_records_syntax_valid_for_a_compilable_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = validate_manifest(valid_manifest_data())
            workspace = Workspace(root / "state")
            harnesses = workspace.target_dir(manifest.target.name) / "generated"
            harnesses.mkdir(parents=True)
            workspace.repo_dir(manifest.target.name).mkdir(parents=True)
            (harnesses / "harnesses.json").write_text(
                json.dumps([{"generated_file": "parse_packet_fuzzer.cc"}]),
                encoding="utf-8",
            )
            (harnesses / "parse_packet_fuzzer.cc").write_text(
                "#include <cstddef>\n"
                "#include <cstdint>\n"
                "extern \"C\" int parse_packet(const unsigned char *, std::size_t);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
                "  return parse_packet(data, size);\n"
                "}\n",
                encoding="utf-8",
            )
            results = validate_harnesses(manifest, workspace, harnesses, "c++", execute=True)
            output = root / "validation.json"
            write_validation(results, output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(results[0].status, "syntax_valid")
        self.assertEqual(results[0].returncode, 0)
        self.assertEqual(payload[0]["status"], "syntax_valid")
        self.assertEqual(payload[0]["generated_file"], "parse_packet_fuzzer.cc")

    @unittest.skipUnless(shutil.which("c++"), "a C++ compiler is required")
    def test_execute_records_syntax_invalid_without_executing_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = validate_manifest(valid_manifest_data())
            workspace = Workspace(root / "state")
            harnesses = workspace.target_dir(manifest.target.name) / "generated"
            harnesses.mkdir(parents=True)
            workspace.repo_dir(manifest.target.name).mkdir(parents=True)
            (harnesses / "harnesses.json").write_text(
                json.dumps([{"generated_file": "broken_fuzzer.cc"}]),
                encoding="utf-8",
            )
            (harnesses / "broken_fuzzer.cc").write_text("this is not C++;\n", encoding="utf-8")

            results = validate_harnesses(manifest, workspace, harnesses, "c++", execute=True)

        self.assertEqual(results[0].status, "syntax_invalid")
        self.assertNotEqual(results[0].returncode, 0)

    def test_rejects_harness_directory_outside_target_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = validate_manifest(valid_manifest_data())
            workspace = Workspace(root / "state")
            outside = root / "outside"
            outside.mkdir()

            with self.assertRaisesRegex(ScopeHoundError, "target workspace"):
                validate_harnesses(manifest, workspace, outside, "c++", execute=False)


if __name__ == "__main__":
    unittest.main()
