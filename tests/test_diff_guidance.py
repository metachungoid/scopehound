from __future__ import annotations

import unittest

from scopehound.diff_guidance import rank_changed_functions


class DiffGuidanceTests(unittest.TestCase):
    def test_changed_hints_and_coverage_gaps_are_explainable(self) -> None:
        ranked = rank_changed_functions(
            ("parse", "helper", "covered"),
            changed_functions=("parse",),
            covered_functions=("helper",),
        )

        self.assertEqual(ranked[0].name, "parse")
        self.assertGreater(ranked[0].score, ranked[1].score)
        self.assertTrue(ranked[0].changed_hint)
        self.assertTrue(ranked[0].explanation)

    def test_diffs_do_not_claim_vulnerabilities(self) -> None:
        ranked = rank_changed_functions(("parse",), changed_functions=("parse",), covered_functions=())

        self.assertFalse(ranked[0].vulnerability_claim)


if __name__ == "__main__":
    unittest.main()
