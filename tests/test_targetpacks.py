from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.targetpacks import cjson_target_pack, resolve_revision


class TargetPackTests(unittest.TestCase):
    def test_cjson_recipe_requires_cleanup_and_public_seed(self) -> None:
        pack = cjson_target_pack()
        recipe = pack["harness"]

        self.assertEqual(recipe.cleanup, "cJSON_Delete(json)")
        self.assertEqual(pack["seed"], b'{"1":1,')
        self.assertEqual(
            {item.role for item in pack["controls"]}, {"positive", "fixed", "current"}
        )
        self.assertIn("https://github.com/DaveGamble/cJSON/issues/800", pack["public_references"])

    def test_resolve_revision_requires_detached_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            (repo / ".git").mkdir()

            with self.assertRaises(Exception):
                resolve_revision(repo)


if __name__ == "__main__":
    unittest.main()
