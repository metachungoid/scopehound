from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.findings import parse_sanitizer_output, write_findings


ASAN_LOG = """==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011
READ of size 4 at 0x602000000011 thread T0
    #0 0x7f00 in parse_packet /src/lib/parser.c:142:9
    #1 0x7f01 in LLVMFuzzerTestOneInput /src/lib/fuzz.cc:31:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/lib/parser.c:142:9 in parse_packet
"""


class FindingsTests(unittest.TestCase):
    def test_parses_asan_signal_location_stack_and_fingerprint(self) -> None:
        findings = parse_sanitizer_output(ASAN_LOG, Path("crash-001"))

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.sanitizer, "AddressSanitizer")
        self.assertEqual(finding.kind, "heap-buffer-overflow")
        self.assertEqual(finding.location, "/src/lib/parser.c:142:9")
        self.assertEqual(finding.function, "parse_packet")
        self.assertEqual(finding.artifact, "crash-001")
        self.assertTrue(finding.fingerprint)
        self.assertTrue(any("parse_packet" in frame for frame in finding.stack))

    def test_deduplicates_repeated_sanitizer_blocks(self) -> None:
        findings = parse_sanitizer_output(ASAN_LOG + "\n" + ASAN_LOG)

        self.assertEqual(len(findings), 1)

    def test_parses_ubsan_runtime_error(self) -> None:
        log = "src/value.c:88:12: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'"

        findings = parse_sanitizer_output(log)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].sanitizer, "UndefinedBehaviorSanitizer")
        self.assertEqual(findings[0].kind, "signed integer overflow")
        self.assertEqual(findings[0].location, "src/value.c:88:12")

    def test_infers_libfuzzer_artifact_name_from_sanitizer_output(self) -> None:
        log = "Test unit written to ./crash-042\n" + ASAN_LOG

        findings = parse_sanitizer_output(log)

        self.assertEqual(findings[0].artifact, "crash-042")

    def test_write_findings_is_machine_readable_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "findings.json"
            findings = parse_sanitizer_output(ASAN_LOG, Path("crash-001"))

            write_findings(findings, output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload[0]["kind"], "heap-buffer-overflow")
        self.assertIn("fingerprint", payload[0])
        self.assertIn("reproducibility", payload[0])


if __name__ == "__main__":
    unittest.main()
