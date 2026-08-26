from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from scopehound.findings import Finding
from scopehound.known_issues import compare_known_issues, load_known_issues


class KnownIssuesTests(unittest.TestCase):
    def test_json_known_issue_labels_duplicate_and_regression(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "issues.json"
            path.write_text(
                '[{"fingerprint": "dup", "fixed_revision": "v2", "summary": "known"}]',
                encoding="utf-8",
            )
            issues = load_known_issues(path)
            finding = Finding("AddressSanitizer", "heap", "heap", "a.c:1:1", "parse", (), "dup", "crash", "raw")

            results = compare_known_issues((finding,), issues, current_revision="v1")

        self.assertEqual(results[0].label, "possible_regression")
        self.assertEqual(results[0].issue_summary, "known")

    def test_aliases_and_root_cause_are_duplicate_signals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "issues.json"
            path.write_text(
                '[{"fingerprint": "other", "aliases": ["alias-root"], "summary": "known"}]',
                encoding="utf-8",
            )
            issues = load_known_issues(path)
            finding = Finding(
                "AddressSanitizer", "heap", "heap", "a.c:1:1", "parse", (),
                "new-fingerprint", "crash", "raw", root_cause="alias-root",
            )

            result = compare_known_issues((finding,), issues, current_revision="v1")[0]

        self.assertEqual(result.label, "possible_duplicate")
        self.assertEqual(result.matched_by, "alias")

    def test_csv_unknown_issue_is_new_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "issues.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=("fingerprint", "summary"))
                writer.writeheader()
                writer.writerow({"fingerprint": "other", "summary": "other"})

            issue = load_known_issues(path)
            finding = Finding("UndefinedBehaviorSanitizer", "integer", "integer", "a.c:1:1", "parse", (), "new", "crash", "raw")
            result = compare_known_issues((finding,), issue, current_revision="v1")[0]

        self.assertEqual(result.label, "new_candidate")


if __name__ == "__main__":
    unittest.main()
