from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.matrix import expand_matrix, run_matrix
from scopehound.manifest import validate_manifest
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


class MatrixTests(unittest.TestCase):
    def _manifest(self):
        data = valid_manifest_data()
        data["campaign"] = {  # type: ignore[index]
            "max_workers": 2,
            "max_retries": 1,
            "engines": ["standalone", "afl++"],
            "build_variants": [{"name": "asan"}, {"name": "ubsan"}],
        }
        return validate_manifest(data)

    def test_expands_stable_target_variant_engine_jobs(self) -> None:
        jobs = expand_matrix(self._manifest(), duration_seconds=1)

        self.assertEqual(len(jobs), 4)
        self.assertEqual(jobs[0].target, "example-parser")
        self.assertEqual(jobs[0].variant, "asan")
        self.assertEqual(jobs[0].job_id, expand_matrix(self._manifest(), duration_seconds=1)[0].job_id)
        self.assertEqual(jobs[0].status, "queued")

    def test_dry_run_records_unavailable_engine_and_resumes_by_digest(self) -> None:
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            first = run_matrix(manifest, workspace, duration_seconds=1, execute=False)
            second = run_matrix(manifest, workspace, duration_seconds=1, execute=False)

        self.assertEqual(len(first.jobs), 4)
        self.assertEqual(first.jobs, second.jobs)
        self.assertEqual(first.max_workers, 2)
        self.assertIn(first.jobs[0].status, {"planned", "skipped"})
        self.assertTrue(first.expected_yield.disclaimer)

    def test_retry_appends_attempt_for_failed_or_skipped_job(self) -> None:
        manifest = self._manifest()
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            first = run_matrix(manifest, workspace, duration_seconds=1, execute=False)
            retried = run_matrix(manifest, workspace, duration_seconds=1, execute=False, retry=True)

        self.assertEqual(len(first.jobs), len(retried.jobs))
        self.assertTrue(all(item.attempts >= 1 for item in retried.jobs))


if __name__ == "__main__":
    unittest.main()
