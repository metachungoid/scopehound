from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from scopehound.candidates import build_harnesses, run_harness
from scopehound.errors import ScopeHoundError
from scopehound.harness import generate_harnesses, write_harnesses
from scopehound.manifest import validate_manifest
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


class CandidateTests(unittest.TestCase):
    def test_build_harnesses_records_plans_and_built_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = Workspace(root / "state")
            target = workspace.target_dir("example-parser")
            repo = workspace.repo_dir("example-parser")
            repo.mkdir(parents=True)
            generated = target / "generated-candidates"
            generated.mkdir(parents=True)
            (generated / "harnesses.json").write_text(
                json.dumps([{"generated_file": "parse_packet_fuzzer.cc", "function": "parse_packet", "path": "parser.h"}]),
                encoding="utf-8",
            )
            (generated / "parse_packet_fuzzer.cc").write_text("// generated\n", encoding="utf-8")
            data = valid_manifest_data()
            data["commands"]["harness_build"] = [  # type: ignore[index]
                sys.executable, "-c",
                "from pathlib import Path; Path(r'{binary}').write_bytes(Path(r'{source}').read_bytes())",
            ]
            manifest = validate_manifest(data)

            planned = build_harnesses(manifest, workspace, generated, execute=False)
            self.assertEqual(planned[0].status, "planned")
            self.assertTrue(any(str(generated / "parse_packet_fuzzer.cc") in arg for arg in planned[0].command))

            built = build_harnesses(manifest, workspace, generated, execute=True)
            self.assertEqual(built[0].status, "built")
            self.assertTrue(Path(built[0].binary).is_file())

    def test_build_failure_is_not_a_security_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = Workspace(root / "state")
            target = workspace.target_dir("example-parser")
            workspace.repo_dir("example-parser").mkdir(parents=True)
            generated = target / "generated-candidates"
            generated.mkdir(parents=True)
            (generated / "harnesses.json").write_text(
                json.dumps([{"generated_file": "broken.cc", "function": "broken"}]),
                encoding="utf-8",
            )
            (generated / "broken.cc").write_text("broken", encoding="utf-8")
            data = valid_manifest_data()
            data["commands"]["harness_build"] = [sys.executable, "-c", "from pathlib import Path; Path(r'{source}'); raise SystemExit(7)", "{binary}"]  # type: ignore[index]
            manifest = validate_manifest(data)

            result = build_harnesses(manifest, workspace, generated, execute=True)[0]

            self.assertEqual(result.status, "build_failed")
            self.assertNotIn("finding", result.status)
            self.assertEqual(result.returncode, 7)

    def test_run_harness_requires_a_built_candidate_and_attaches_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = Workspace(root / "state")
            target = workspace.target_dir("example-parser")
            workspace.repo_dir("example-parser").mkdir(parents=True)
            generated = target / "generated-candidates"
            generated.mkdir(parents=True)
            (generated / "harnesses.json").write_text(
                json.dumps([{"generated_file": "parse.cc", "function": "parse"}]),
                encoding="utf-8",
            )
            (generated / "parse.cc").write_text("// generated\n", encoding="utf-8")
            data = valid_manifest_data()
            data["commands"]["harness_build"] = [  # type: ignore[index]
                sys.executable, "-c", "from pathlib import Path; Path(r'{source}'); Path(r'{binary}').write_text('ok')",
            ]
            data["commands"]["fuzz"] = [  # type: ignore[index]
                sys.executable, "-c",
                "from pathlib import Path; p=Path(r'{corpus}').parent / 'artifacts' / 'crash'; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'x'); print('ERROR: AddressSanitizer: heap-buffer-overflow'); print('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:1:1 in parse'); raise SystemExit(1)",
                "{binary}", "{corpus}", "{duration}",
            ]
            manifest = validate_manifest(data)
            build = build_harnesses(manifest, workspace, generated, execute=True)[0]
            run = run_harness(manifest, workspace, build.candidate_id, duration_seconds=1, execute=True)

            self.assertEqual(run.status, "finding")
            self.assertEqual(len(run.findings), 1)
            self.assertTrue(Path(run.artifact_dir).is_dir())

    def test_run_harness_refuses_non_built_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = Workspace(root / "state")
            target = workspace.target_dir("example-parser")
            workspace.repo_dir("example-parser").mkdir(parents=True)
            generated = target / "generated-candidates"
            generated.mkdir(parents=True)
            (generated / "harnesses.json").write_text(
                json.dumps([{"generated_file": "parse.cc", "function": "parse"}]),
                encoding="utf-8",
            )
            (generated / "parse.cc").write_text("// generated\n", encoding="utf-8")
            data = valid_manifest_data()
            data["commands"]["harness_build"] = [sys.executable, "-c", "from pathlib import Path; Path(r'{source}'); raise SystemExit(7)", "{binary}"]  # type: ignore[index]
            manifest = validate_manifest(data)
            build_harnesses(manifest, workspace, generated, execute=True)

            with self.assertRaises(ScopeHoundError) as raised:
                run_harness(manifest, workspace, "missing", duration_seconds=1, execute=False)

            self.assertEqual(raised.exception.category, "candidate_not_built")


if __name__ == "__main__":
    unittest.main()
