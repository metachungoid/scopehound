from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.discovery import discover_harnesses, write_harnesses


class DiscoveryTests(unittest.TestCase):
    def test_discovers_libfuzzer_entrypoints_and_oss_fuzz_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "oss-fuzz").mkdir()
            (root / "src" / "parser_fuzzer.cc").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size) { return 0; }",
                encoding="utf-8",
            )
            (root / "oss-fuzz" / "target.c").write_text(
                "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }",
                encoding="utf-8",
            )

            candidates = discover_harnesses(root)

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].entrypoint, "LLVMFuzzerTestOneInput")
        self.assertIn("parser_fuzzer.cc", str(candidates[0].path))
        self.assertEqual(candidates[0].confidence, "high")

    def test_ignores_build_and_git_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for directory in ("build", ".git"):
                path = root / directory
                path.mkdir()
                (path / "ignored.c").write_text("LLVMFuzzerTestOneInput", encoding="utf-8")

            self.assertEqual(discover_harnesses(root), ())

    def test_writes_machine_readable_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "fuzz.c").write_text("LLVMFuzzerTestOneInput", encoding="utf-8")
            output = root / "harnesses.json"
            write_harnesses(discover_harnesses(root), output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload[0]["entrypoint"], "LLVMFuzzerTestOneInput")


if __name__ == "__main__":
    unittest.main()
