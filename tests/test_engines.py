from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scopehound.engines import (
    deterministic_mutations,
    list_engines,
    run_standalone,
)


class EngineTests(unittest.TestCase):
    def test_mutations_are_deterministic_and_size_bounded(self) -> None:
        first = deterministic_mutations(b"{}", max_input_size=8, count=4, seed_value=7)
        second = deterministic_mutations(b"{}", max_input_size=8, count=4, seed_value=7)

        self.assertEqual(first, second)
        self.assertTrue(all(len(item) <= 8 for item in first))

    def test_engine_listing_does_not_claim_missing_libfuzzer(self) -> None:
        names = {item.name: item for item in list_engines(include_optional=True)}

        self.assertIn("standalone", names)
        self.assertIn("libfuzzer", names)
        if shutil.which("clang") is None:
            self.assertFalse(names["libfuzzer"].available)
        for optional in ("afl++", "honggfuzz", "centipede"):
            self.assertIn(optional, names)
            self.assertIsInstance(names[optional].adapter, str)

    def test_standalone_dry_run_does_not_launch_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "does-not-exist"
            corpus = root / "corpus"
            artifacts = root / "artifacts"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"seed")

            result = run_standalone(
                binary,
                corpus,
                artifacts,
                duration_seconds=1,
                max_input_size=32,
                seed_value=1,
                execute=False,
                backend="native",
            )

        self.assertEqual(result.status, "planned")
        self.assertFalse(artifacts.exists())

    @unittest.skipUnless(shutil.which("gcc"), "gcc is required for standalone integration")
    def test_standalone_records_sanitizer_finding_and_parent_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "target.c"
            binary = root / "target"
            source.write_text(
                "#include <stdio.h>\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "int main(int argc, char **argv) {\n"
                "  FILE *f = fopen(argv[1], \"rb\"); unsigned char b[8] = {0};\n"
                "  size_t n = fread(b, 1, sizeof b, f); fclose(f);\n"
                "  if (n && b[0] == 'X') { char *p = malloc(1); p[1] = 7; }\n"
                "  return 0;\n}\n",
                encoding="utf-8",
            )
            compile_result = subprocess.run(
                ["gcc", "-g", "-fsanitize=address,undefined", str(source), "-o", str(binary)],
                capture_output=True,
                text=True,
                check=False,
            )
            if compile_result.returncode != 0:
                self.skipTest(f"GCC sanitizer build unavailable: {compile_result.stderr}")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"X")

            result = run_standalone(
                binary,
                corpus,
                root / "artifacts",
                duration_seconds=2,
                max_input_size=32,
                seed_value=3,
                execute=True,
                backend="native",
            )

            self.assertEqual(result.status, "finding")
            self.assertTrue(result.artifacts)
            self.assertTrue(any(item["parent_sha256"] for item in result.mutations))


if __name__ == "__main__":
    unittest.main()
