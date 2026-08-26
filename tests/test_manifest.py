from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.manifest import load_manifest, validate_manifest

from tests.fixtures import valid_manifest_data


class ManifestTests(unittest.TestCase):
    def test_valid_manifest_is_normalized(self) -> None:
        manifest = validate_manifest(valid_manifest_data())

        self.assertEqual(manifest.target.name, "example-parser")
        self.assertEqual(manifest.target.language, "c")
        self.assertEqual(manifest.commands.build, ("cmake", "--build", "build"))
        self.assertIsNone(manifest.commands.reproduce)
        self.assertEqual(manifest.authorization.eligible_classes, ("memory-corruption",))
        self.assertEqual(dict(manifest.environment), {
            "CC": "clang",
            "CFLAGS": "-O1 -g -fsanitize=address,undefined",
        })
        self.assertIsNone(manifest.commands.harness_build)
        self.assertEqual(manifest.corpus.max_input_size, 1_048_576)
        self.assertEqual(manifest.corpus.coverage_mode, "none")
        self.assertEqual(manifest.campaign.max_workers, 1)
        self.assertEqual(manifest.campaign.engines, ("standalone",))
        self.assertIsNone(manifest.economics.expected_reward)

    def test_accepts_campaign_variants_oracles_and_economics(self) -> None:
        data = valid_manifest_data()
        data["campaign"] = {  # type: ignore[index]
            "max_workers": 2,
            "max_retries": 1,
            "share_corpus": True,
            "wall_clock_seconds": 120,
            "cpu_seconds": 90,
            "process_limit": 2,
            "engines": ["standalone", "libfuzzer"],
            "changed_functions": ["parse_document"],
            "build_variants": [
                {
                    "name": "asan",
                    "environment": {"ASAN_OPTIONS": "abort_on_error=1"},
                    "changed_functions": ["parse_document"],
                }
            ],
            "oracles": [
                {
                    "name": "roundtrip",
                    "kind": "metamorphic",
                    "command": ["./oracle", "{artifact}"],
                }
            ],
        }
        data["economics"] = {  # type: ignore[index]
            "expected_reward": 5000,
            "reward_confidence": 0.5,
            "cpu_hour_cost": 0.25,
        }

        manifest = validate_manifest(data)

        self.assertEqual(manifest.campaign.max_workers, 2)
        self.assertEqual(manifest.campaign.engines, ("standalone", "libfuzzer"))
        self.assertEqual(manifest.campaign.build_variants[0].name, "asan")
        self.assertEqual(manifest.campaign.oracles[0].command, ("./oracle", "{artifact}"))
        self.assertEqual(manifest.economics.expected_reward, 5000.0)

    def test_rejects_unsafe_campaign_configuration(self) -> None:
        invalid_campaigns = (
            {"max_workers": 0},
            {"engines": ["unknown"]},
            {"build_variants": [{"name": "../escape"}]},
            {"oracles": [{"name": "x", "kind": "unknown", "command": ["true"]}]},
            {"oracles": [{"name": "x", "kind": "differential", "command": "true"}]},
        )
        for campaign in invalid_campaigns:
            with self.subTest(campaign=campaign):
                data = valid_manifest_data()
                data["campaign"] = campaign  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def test_rejects_invalid_economics(self) -> None:
        for economics in (
            {"expected_reward": -1},
            {"reward_confidence": 1.1},
            {"cpu_hour_cost": -0.1},
        ):
            with self.subTest(economics=economics):
                data = valid_manifest_data()
                data["economics"] = economics  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def test_accepts_harness_build_placeholders_and_corpus_config(self) -> None:
        data = valid_manifest_data()
        data["commands"]["harness_build"] = [  # type: ignore[index]
            "clang++", "{source}", "-o", "{binary}", "-I", "{repo}"
        ]
        data["corpus"] = {  # type: ignore[index]
            "seed_dir": "seeds", "dictionary": "parser.dict",
            "max_input_size": 4096, "coverage_mode": "llvm"
        }

        manifest = validate_manifest(data)

        self.assertEqual(manifest.commands.harness_build[1], "{source}")
        self.assertEqual(manifest.corpus.seed_dir, "seeds")
        self.assertEqual(manifest.corpus.dictionary, "parser.dict")
        self.assertEqual(manifest.corpus.max_input_size, 4096)
        self.assertEqual(manifest.corpus.coverage_mode, "llvm")

    def test_accepts_grouped_build_steps_and_preserves_flat_compatibility(self) -> None:
        data = valid_manifest_data()
        data["commands"]["build"] = [  # type: ignore[index]
            ["cc", "-c", "a.c"], ["cc", "a.o", "-o", "a"]
        ]
        data["commands"]["prepare"] = [["cc", "--version"]]  # type: ignore[index]

        manifest = validate_manifest(data)

        self.assertEqual(manifest.commands.build, ("cc", "-c", "a.c"))
        self.assertEqual(manifest.commands.build_steps, (
            ("cc", "-c", "a.c"), ("cc", "a.o", "-o", "a"),
        ))
        self.assertEqual(manifest.commands.prepare_steps, (("cc", "--version"),))

    def test_rejects_grouped_command_with_unknown_placeholder(self) -> None:
        data = valid_manifest_data()
        data["commands"]["prepare"] = [["git", "-C", "{repo}", "{shell}"]]  # type: ignore[index]

        self._assert_manifest_invalid(data)

    def test_rejects_unknown_or_missing_harness_placeholders(self) -> None:
        for command in (
            ["clang++", "{source}", "-o", "{binary}", "{unknown}"],
            ["clang++", "{source}", "-o", "output"],
            ["clang++", "{source}", "{source}", "-o", "{binary}"],
        ):
            with self.subTest(command=command):
                data = valid_manifest_data()
                data["commands"]["harness_build"] = command  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def test_rejects_invalid_corpus_configuration(self) -> None:
        for corpus in (
            {"max_input_size": 0},
            {"max_input_size": 4096, "coverage_mode": "remote"},
            {"max_input_size": 4096, "seed_dir": "/absolute"},
        ):
            with self.subTest(corpus=corpus):
                data = valid_manifest_data()
                data["corpus"] = corpus  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def test_load_manifest_reads_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "target.json"
            path.write_text(json.dumps(valid_manifest_data()), encoding="utf-8")

            manifest = load_manifest(path)

        self.assertEqual(manifest.target.revision, "v1.2.3")

    def test_invalid_json_has_stable_error_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "target.json"
            path.write_text("{broken", encoding="utf-8")

            with self.assertRaises(ScopeHoundError) as raised:
                load_manifest(path)

        self.assertEqual(raised.exception.category, "manifest_invalid")

    def test_rejects_invalid_slugs(self) -> None:
        for slug in ("UPPER", "../escape", "two words", "-leading"):
            with self.subTest(slug=slug):
                data = valid_manifest_data()
                data["target"]["name"] = slug  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def test_rejects_moving_or_empty_revision(self) -> None:
        for revision in ("", "main", "master", "HEAD"):
            with self.subTest(revision=revision):
                data = valid_manifest_data()
                data["target"]["revision"] = revision  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def test_rejects_shell_string_commands(self) -> None:
        data = valid_manifest_data()
        data["commands"]["build"] = "cmake --build build"  # type: ignore[index]

        self._assert_manifest_invalid(data)

    def test_accepts_reproduction_command_with_artifact_placeholder(self) -> None:
        data = valid_manifest_data()
        data["commands"]["reproduce"] = ["./build/parser_fuzzer", "{artifact}"]  # type: ignore[index]

        manifest = validate_manifest(data)

        self.assertEqual(manifest.commands.reproduce, ("./build/parser_fuzzer", "{artifact}"))

    def test_rejects_reproduction_command_without_exact_artifact_placeholder(self) -> None:
        for command in (
            ["./build/parser_fuzzer"],
            ["./build/parser_fuzzer", "{artifact}", "{artifact}"],
        ):
            with self.subTest(command=command):
                data = valid_manifest_data()
                data["commands"]["reproduce"] = command  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def test_rejects_invalid_language_date_and_factor(self) -> None:
        mutations = [
            ("target", "language", "python"),
            ("authorization", "checked_at", "yesterday"),
            ("opportunity", "fuzzing_gap", 1.1),
            ("opportunity", "duplicate_risk", -0.1),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                data = valid_manifest_data()
                data[section][key] = value  # type: ignore[index]
                self._assert_manifest_invalid(data)

    def _assert_manifest_invalid(self, data: object) -> None:
        with self.assertRaises(ScopeHoundError) as raised:
            validate_manifest(data)
        self.assertEqual(raised.exception.category, "manifest_invalid")


if __name__ == "__main__":
    unittest.main()
