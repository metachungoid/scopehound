from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path

from scopehound.oracles import compare_outputs, run_oracle


class OracleTests(unittest.TestCase):
    def test_differential_and_roundtrip_statuses_are_explicit(self) -> None:
        matching = compare_outputs("differential", b"input", "same", "same")
        disagreement = compare_outputs("differential", b"input", "left", "right")
        roundtrip = compare_outputs("roundtrip", b"input", "encoded", "encoded")

        self.assertEqual(matching.status, "match")
        self.assertEqual(disagreement.status, "disagreement")
        self.assertEqual(roundtrip.status, "match")
        self.assertTrue(disagreement.input_sha256)
        self.assertNotIn("vulnerability", disagreement.status)

    def test_oracle_dry_run_is_bounded_and_does_not_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "input"
            artifact.write_bytes(b"input")
            result = run_oracle(
                "differential", ("printf", "left"), ("printf", "right"),
                artifact, Path(temp_dir), execute=False, timeout_seconds=1,
            )

        self.assertEqual(result.status, "planned")
        self.assertEqual(result.input_sha256, hashlib.sha256(b"input").hexdigest())


if __name__ == "__main__":
    unittest.main()
