from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.analyze import import_fuzz_introspector, parse_ast_json, rank_candidates
from scopehound.harness import HarnessCandidate


class AnalyzeTests(unittest.TestCase):
    def test_parses_functions_and_parameters_from_clang_ast_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ast.json"
            path.write_text(json.dumps({
                "kind": "TranslationUnitDecl", "inner": [{
                    "kind": "NamespaceDecl", "name": "parser", "inner": [{
                        "kind": "FunctionDecl", "name": "parse", "qualifiedName": "parser::parse",
                        "loc": {"file": "parser.h", "line": 12},
                        "type": {"qualType": "int (const unsigned char *, unsigned long)"},
                        "inner": [{"kind": "ParmVarDecl", "type": {"qualType": "const unsigned char *"}}, {"kind": "ParmVarDecl", "type": {"qualType": "unsigned long"}}],
                    }],
                }],
            }), encoding="utf-8")

            functions = parse_ast_json(path)

        self.assertEqual(functions[0].qualified_name, "parser::parse")
        self.assertEqual(functions[0].file, "parser.h")
        self.assertEqual(functions[0].line, 12)
        self.assertEqual(functions[0].parameters, ("const unsigned char *", "unsigned long"))

    def test_imports_local_fuzz_introspector_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "introspector.json"
            path.write_text(json.dumps({"functions": [
                {"functionName": "parse", "reachability": 0.9, "coverage": 0.2, "covered": False},
                {"name": "decode", "reachability": 0.4, "covered": True},
            ]}), encoding="utf-8")

            metadata = import_fuzz_introspector(path)

        self.assertEqual(metadata.source, str(path.resolve()))
        self.assertAlmostEqual(metadata.reachability["parse"], 0.9)
        self.assertFalse(metadata.covered["parse"])
        self.assertTrue(metadata.covered["decode"])

    def test_ranking_prefers_authorized_buildable_uncovered_candidates(self) -> None:
        candidates = (
            HarnessCandidate(Path("a.h"), "parse", "const char *p, size_t n", "high", "needs_build_validation", ""),
            HarnessCandidate(Path("b.h"), "decode", "const char *p, size_t n", "high", "built", ""),
        )
        ranked = rank_candidates(candidates, authorized=True, reachability={"parse": 0.9, "decode": 0.2}, covered={"parse": False, "decode": True})

        self.assertEqual(ranked[0].function, "parse")
        self.assertGreater(ranked[0].score, ranked[1].score)
        self.assertEqual(ranked[0].coverage_gap, 1.0)


if __name__ == "__main__":
    unittest.main()
