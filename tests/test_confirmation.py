from __future__ import annotations

import unittest

from scopehound.confirmation import compare_builds


class ConfirmationTests(unittest.TestCase):
    def test_matching_root_cause_across_build_variants_confirms_evidence(self) -> None:
        result = compare_builds(
            {"variant": "asan", "status": "reproduced", "root_cause": "root-1", "toolchain": {"cc": "clang"}},
            {"variant": "ubsan", "status": "reproduced", "root_cause": "root-1", "toolchain": {"cc": "gcc"}},
        )

        self.assertEqual(result.status, "confirmed_across_builds")
        self.assertEqual(result.root_cause, "root-1")
        self.assertEqual(result.variants, ("asan", "ubsan"))

    def test_different_root_causes_are_not_confirmed(self) -> None:
        result = compare_builds(
            {"variant": "asan", "status": "reproduced", "root_cause": "root-1"},
            {"variant": "ubsan", "status": "reproduced", "root_cause": "root-2"},
        )

        self.assertEqual(result.status, "mismatch")


if __name__ == "__main__":
    unittest.main()
