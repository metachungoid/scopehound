from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.triage import triage_artifacts, write_triage


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


if __name__ == "__main__":
    unittest.main()
