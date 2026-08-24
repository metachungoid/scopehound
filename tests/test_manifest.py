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
