from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.findings import parse_sanitizer_output
from scopehound.triage import TriageResult, cluster_findings, triage_artifacts, write_triage


class TriageTests(unittest.TestCase):
    def test_byte_identical_artifacts_are_grouped_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = Path(temp_dir) / "artifacts"
            artifacts.mkdir()
            (artifacts / "z-crash").write_bytes(b"alpha")
            (artifacts / "a-crash").write_bytes(b"alpha")
            (artifacts / "b-crash").write_bytes(b"beta")

            result = triage_artifacts(artifacts)

        alpha_hash = hashlib.sha256(b"alpha").hexdigest()
        self.assertEqual(len(result.unique), 2)
        self.assertEqual(result.unique[0].path.name, "a-crash")
        self.assertEqual(result.unique[0].sha256, alpha_hash)
        self.assertEqual(result.unique[0].size, 5)
        self.assertEqual(result.duplicates["a-crash"], ("z-crash",))

    def test_triage_requires_an_artifact_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "artifact"
            file_path.write_bytes(b"crash")

            with self.assertRaises(ScopeHoundError) as raised:
                triage_artifacts(file_path)

        self.assertEqual(raised.exception.category, "artifacts_invalid")

    def test_triage_json_has_stable_order_and_is_replaced_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "second").write_bytes(b"beta")
            (artifacts / "first").write_bytes(b"alpha")
            output = root / "triage.json"

            write_triage(triage_artifacts(artifacts), output)
            first_render = output.read_text(encoding="utf-8")
            write_triage(triage_artifacts(artifacts), output)

            payload = json.loads(first_render)
            self.assertEqual(first_render, output.read_text(encoding="utf-8"))
            self.assertEqual([item["path"] for item in payload["unique"]], ["first", "second"])
            self.assertFalse((root / "triage.json.tmp").exists())

    def test_sanitizer_fingerprints_cluster_distinct_artifacts(self) -> None:
        log = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in parse /src/parser.c:12:4\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"
        )
        first = parse_sanitizer_output(log, Path("crash-001"))[0]
        second = parse_sanitizer_output(log, Path("crash-002"))[0]

        groups = cluster_findings((first, second))

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].fingerprint, first.fingerprint)
        self.assertEqual(groups[0].artifacts, ("crash-001", "crash-002"))

    def test_root_cause_clusters_line_variants(self) -> None:
        first_log = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"
        )
        second_log = first_log.replace(":12:4", ":99:2")
        first = parse_sanitizer_output(first_log, Path("crash-001"))[0]
        second = parse_sanitizer_output(second_log, Path("crash-002"))[0]

        groups = cluster_findings((first, second))

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].root_cause, first.root_cause)

    def test_triage_json_includes_finding_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "crash-001").write_bytes(b"alpha")
            log = (
                "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:12:4 in parse\n"
            )
            group = cluster_findings((parse_sanitizer_output(log, Path("crash-001"))[0],))[0]
            output = root / "triage.json"

            result = triage_artifacts(artifacts)
            write_triage(TriageResult(result.unique, result.duplicates, (group,)), output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["finding_groups"][0]["artifacts"], ["crash-001"])


if __name__ == "__main__":
    unittest.main()
