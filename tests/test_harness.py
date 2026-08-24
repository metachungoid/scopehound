from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.harness import generate_harnesses, write_harnesses


SOURCE = """
#include <stddef.h>
int parse_packet(const unsigned char *data, size_t size);
int decode_message(const char *input, size_t length);
void initialize_parser(void);
"""


class HarnessTests(unittest.TestCase):
    def test_ranks_buffer_and_length_apis_as_high_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "parser.h"
            source.write_text(SOURCE, encoding="utf-8")

            candidates = generate_harnesses(root)

        self.assertGreaterEqual(len(candidates), 2)
        self.assertEqual(candidates[0].function, "parse_packet")
        self.assertEqual(candidates[0].confidence, "high")
        self.assertIn("LLVMFuzzerTestOneInput", candidates[0].source)
        self.assertIn("parse_packet(", candidates[0].source)
        self.assertIn("size", candidates[0].source)
        self.assertIn("reinterpret_cast<const unsigned char *>(data)", candidates[0].source)
        self.assertNotIn("decltype(", candidates[0].source)

    def test_excludes_void_lifecycle_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "parser.h").write_text(SOURCE, encoding="utf-8")

            candidates = generate_harnesses(root)

        self.assertNotIn("initialize_parser", {candidate.function for candidate in candidates})

    def test_writes_candidate_sources_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "parser.h").write_text(SOURCE, encoding="utf-8")
            output = root / "generated"

            candidates = generate_harnesses(root)
            write_harnesses(candidates, output)
            metadata = json.loads((output / "harnesses.json").read_text(encoding="utf-8"))
            self.assertTrue((output / "parse_packet_fuzzer.cc").exists())
            self.assertEqual(metadata[0]["status"], "needs_build_validation")


if __name__ == "__main__":
    unittest.main()
