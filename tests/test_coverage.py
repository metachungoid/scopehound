from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.coverage import collect_coverage, summarize_engine_output
from scopehound.manifest import validate_manifest
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


class CoverageTests(unittest.TestCase):
    def test_summarizes_engine_stats_without_rejecting_noise(self) -> None:
        stats = summarize_engine_output(
            "stat::number_of_executed_units: 42\n"
            "stat::average_exec_per_sec: 12.5\n"
            "not a stat: ???\n"
        )

        self.assertEqual(stats["number_of_executed_units"], 42)
        self.assertEqual(stats["average_exec_per_sec"], 12.5)

    def test_records_corpus_digests_and_llvm_deltas(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = Workspace(root / "state")
            target = workspace.target_dir("example-parser")
            before = target / "before-corpus"
            after = target / "after-corpus"
            before.mkdir(parents=True)
            after.mkdir(parents=True)
            (before / "seed").write_bytes(b"a")
            (after / "seed").write_bytes(b"a")
            (after / "new").write_bytes(b"bc")
            llvm_before = root / "before.json"
            llvm_after = root / "after.json"
            llvm_before.write_text(json.dumps({"data": [{"functions": [{"name": "parse", "count": 1}], "segments": [[1, 1, 1, 0, 0]]}]}), encoding="utf-8")
            llvm_after.write_text(json.dumps({"data": [{"functions": [{"name": "parse", "count": 1}, {"name": "decode", "count": 1}], "segments": [[1, 1, 1, 1, 0], [2, 1, 1, 1, 0]]}]}), encoding="utf-8")
            coverage_artifact = target / "llvm.profdata"
            coverage_artifact.write_bytes(b"coverage")
            manifest = validate_manifest(valid_manifest_data())

            record = collect_coverage(
                manifest, workspace, "candidate", before_dir=before, after_dir=after,
                engine_output="stat::number_of_executed_units: 7\n",
                coverage_paths=(coverage_artifact,), llvm_before=llvm_before,
                llvm_after=llvm_after, cpu_seconds=2.5, finding_count=1,
            )

        self.assertEqual(record.before.count, 1)
        self.assertEqual(record.after.count, 2)
        self.assertEqual(record.after.bytes, 3)
        self.assertNotEqual(record.before.digest, record.after.digest)
        self.assertEqual(record.function_delta, 1)
        self.assertEqual(record.edge_delta, 1)
        self.assertEqual(record.engine_stats["number_of_executed_units"], 7)
        self.assertEqual(record.finding_count, 1)
        self.assertTrue(record.coverage_artifacts[0].sha256)


if __name__ == "__main__":
    unittest.main()
