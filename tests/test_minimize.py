from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from scopehound.findings import parse_sanitizer_output
from scopehound.manifest import validate_manifest
from scopehound.minimize import minimize_artifact
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


class MinimizeTests(unittest.TestCase):
    def test_minimization_writes_child_with_parent_digest_and_preserves_signal(self) -> None:
        sanitizer = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:1:1 in parse\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = Workspace(root / "state")
            repo = workspace.repo_dir("example-parser")
            repo.mkdir(parents=True)
            artifact_dir = workspace.artifacts_dir("example-parser")
            artifact_dir.mkdir(parents=True)
            artifact = artifact_dir / "crash"
            artifact.write_bytes(b"noise-CRASH-noise")
            data = valid_manifest_data()
            data["commands"]["reproduce"] = [  # type: ignore[index]
                sys.executable, "-c",
                "from pathlib import Path; import sys; p=Path(sys.argv[1]); print(" + repr(sanitizer) + ") if b'CRASH' in p.read_bytes() else None",
                "{artifact}",
            ]
            manifest = validate_manifest(data)
            expected = parse_sanitizer_output(sanitizer)[0].fingerprint

            result = minimize_artifact(manifest, workspace, artifact, expected, execute=True, timeout_seconds=10)
            payload = json.loads((workspace.provenance_dir("example-parser") / "minimize-crash.json").read_text(encoding="utf-8"))
            child_bytes = Path(result.child).read_bytes()

        self.assertEqual(result.status, "minimized")
        self.assertNotEqual(result.parent_sha256, result.child_sha256)
        self.assertEqual(payload["parent_sha256"], result.parent_sha256)
        self.assertIn(b"CRASH", child_bytes)


if __name__ == "__main__":
    unittest.main()
