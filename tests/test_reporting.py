from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scopehound.manifest import validate_manifest
from scopehound.findings import Finding
from scopehound.reporting import render_report, write_report
from scopehound.triage import ArtifactRecord

from tests.fixtures import valid_manifest_data


class ReportingTests(unittest.TestCase):
    def test_report_contains_scope_reproduction_and_human_review_gates(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        artifact = ArtifactRecord(
            path=Path("crash-001"),
            sha256=hashlib.sha256(b"boom").hexdigest(),
            size=4,
        )
        finding = Finding(
            sanitizer="AddressSanitizer", kind="heap-buffer-overflow",
            summary="heap-buffer-overflow", location="/src/lib/parser.c:142:9",
            function="parse_packet", stack=("parse_packet at /src/lib/parser.c:142:9",),
            fingerprint="abc123", artifact="crash-001", raw_output="sanitizer output",
            reproducibility="reproduced",
        )

        report = render_report(manifest, artifact, "artifacts/crash-001", finding)

        required_fragments = (
            "human_review_required: true",
            "https://example.invalid/project.git",
            "v1.2.3",
            "https://example.invalid/security-policy",
            "2026-08-24",
            '["cmake", "--build", "build"]',
            '["./build/parser_fuzzer"]',
            "Reproduction command: `not configured`",
            artifact.sha256,
            "- [ ] Confirm attacker-controlled reachability",
            "- [ ] Search for duplicate reports and root causes",
            "- [ ] Reproduce against the latest eligible revision",
            "AddressSanitizer", "heap-buffer-overflow", "/src/lib/parser.c:142:9",
            "parse_packet", "abc123", "reproduced", "sanitizer output",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, report)

    def test_write_report_replaces_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.md"
            output.write_text("old", encoding="utf-8")

            write_report("new report\n", output)

            self.assertEqual(output.read_text(encoding="utf-8"), "new report\n")
            self.assertFalse((Path(temp_dir) / "report.md.tmp").exists())


if __name__ == "__main__":
    unittest.main()
