from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scopehound.corpus import inventory_corpus, structure_aware_seeds


class CorpusTests(unittest.TestCase):
    def test_inventory_hashes_and_bounds_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            root.mkdir()
            (root / "b.seed").write_bytes(b"beta")
            (root / "a.seed").write_bytes(b"alpha")
            (root / "too-large").write_bytes(b"0123456789")

            records = inventory_corpus(root, max_input_size=5)

        self.assertEqual([item.name for item in records], ["a.seed", "b.seed", "too-large"])
        self.assertEqual(records[0].sha256, hashlib.sha256(b"alpha").hexdigest())
        self.assertEqual(records[2].size, 5)

    def test_structure_aware_seed_records_keep_lineage_and_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            root.mkdir()
            (root / "seed").write_bytes(b"{}");

            records = structure_aware_seeds(
                root, max_input_size=16, parent="parent-hash", oracle="roundtrip"
            )

        self.assertEqual(records[0].parent, "parent-hash")
        self.assertEqual(records[0].oracle, "roundtrip")
        self.assertEqual(records[0].input_sha256, hashlib.sha256(b"{}").hexdigest())


if __name__ == "__main__":
    unittest.main()
