from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scopehound.cli import main

from tests.fixtures import valid_manifest_data


class EndToEndTests(unittest.TestCase):
    def test_authorized_local_repository_reaches_report_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            (source / "parser.c").write_text(
                "#include <stddef.h>\nint parse(const unsigned char *p, size_t n) { return n ? p[0] : 0; }\n",
                encoding="utf-8",
            )
            self._git(source, "init")
            self._git(source, "config", "user.name", "ScopeHound Test")
            self._git(source, "config", "user.email", "scopehound@example.invalid")
            self._git(source, "add", "parser.c")
            self._git(source, "commit", "-m", "fixture")
            revision = self._git(source, "rev-parse", "HEAD").strip()

            data = valid_manifest_data()
            data["target"]["repository"] = str(source)  # type: ignore[index]
            data["target"]["revision"] = revision  # type: ignore[index]
            data["commands"]["build"] = [  # type: ignore[index]
                sys.executable,
                "-c",
                "from pathlib import Path; assert Path('parser.c').exists(); Path('build.ok').write_text('ok')",
            ]
            data["commands"]["fuzz"] = [  # type: ignore[index]
                sys.executable,
                "-c",
                "import os; from pathlib import Path; p=Path(os.environ['SCOPEHOUND_ARTIFACTS_DIR']); p.mkdir(parents=True, exist_ok=True); (p/'crash-001').write_bytes(b'boom')",
            ]
            manifest_path = root / "target.json"
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            workspace = root / "state"

            self.assertEqual(self._main(
                "prepare", "--manifest", str(manifest_path), "--workspace", str(workspace),
                "--allow-local-repository", "--execute",
            ), 0)
            self.assertEqual(self._main(
                "build", "--manifest", str(manifest_path), "--workspace", str(workspace), "--execute",
            ), 0)
            self.assertEqual(self._main(
                "fuzz", "--manifest", str(manifest_path), "--workspace", str(workspace),
                "--duration", "5", "--execute",
            ), 0)

            target = workspace / "targets" / "example-parser"
            artifacts = target / "artifacts"
            triage_output = target / "triage.json"
            report_output = target / "reports" / "crash-001.md"
            self.assertEqual(self._main(
                "triage", "--artifacts", str(artifacts), "--output", str(triage_output)
            ), 0)
            self.assertEqual(self._main(
                "report", "--manifest", str(manifest_path),
                "--artifact", str(artifacts / "crash-001"), "--output", str(report_output)
            ), 0)

            self.assertTrue((target / "repo" / "build.ok").exists())
            self.assertTrue((target / "logs" / "prepare-1.log").exists())
            self.assertTrue((target / "logs" / "prepare-2.log").exists())
            self.assertTrue((target / "logs" / "build.log").exists())
            self.assertTrue((target / "logs" / "fuzz.log").exists())
            self.assertTrue(triage_output.exists())
            self.assertIn(revision, report_output.read_text(encoding="utf-8"))

    @staticmethod
    def _git(cwd: Path, *args: str) -> str:
        completed = subprocess.run(
            ("git", *args), cwd=cwd, text=True, capture_output=True, check=True
        )
        return completed.stdout

    @staticmethod
    def _main(*args: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(list(args))


if __name__ == "__main__":
    unittest.main()
