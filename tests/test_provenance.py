from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.manifest import validate_manifest
from scopehound.provenance import create_provenance, normalize_stack, symbolize_stack
from scopehound.runner import CommandResult

from tests.fixtures import valid_manifest_data


class ProvenanceTests(unittest.TestCase):
    def test_provenance_contains_manifest_digest_runtime_and_command(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        result = CommandResult(("tool", "--flag"), 0, "out", "err", True)

        record = create_provenance(
            manifest, result, backend="native", timeout_seconds=10,
            start_time="2026-08-25T12:00:00Z", end_time="2026-08-25T12:00:01Z",
        )

        self.assertEqual(record.argv, ("tool", "--flag"))
        self.assertEqual(record.backend, "native")
        self.assertEqual(len(record.manifest_digest), 64)
        self.assertIn("python", record.toolchain)
        self.assertEqual(record.timeout_seconds, 10)

    def test_stack_normalization_preserves_raw_and_can_use_symbolizer(self) -> None:
        raw = ("foo at /tmp/build/parser.cc:10:2", "bar at /tmp/build/parser.cc:11:2")
        normalized = normalize_stack(raw)

        self.assertEqual(normalized, ("foo at parser.cc:10:2", "bar at parser.cc:11:2"))
        self.assertEqual(symbolize_stack(raw, "llvm-symbolizer", Path("."), execute=False), raw)


if __name__ == "__main__":
    unittest.main()
