from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.manifest import validate_manifest
from scopehound.runner import build_plan, fuzz_plan, prepare_plans
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


class WorkspaceTests(unittest.TestCase):
    def test_derived_paths_stay_beneath_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir) / "state")

            target = workspace.target_dir("parser")
            logs = workspace.logs_dir("parser")
            artifacts = workspace.artifacts_dir("parser")
            generated = workspace.generated_dir("parser")
            binaries = workspace.binaries_dir("parser")
            corpus = workspace.corpus_dir("parser")
            coverage = workspace.coverage_dir("parser")
            toolchain = workspace.toolchain_dir("parser")
            provenance = workspace.provenance_dir("parser")

            self.assertEqual(target, workspace.root / "targets" / "parser")
            self.assertEqual(logs, target / "logs")
            self.assertEqual(artifacts, target / "artifacts")
            self.assertEqual(generated, target / "generated")
            self.assertEqual(binaries, target / "binaries")
            self.assertEqual(corpus, target / "corpus")
            self.assertEqual(coverage, target / "coverage")
            self.assertEqual(toolchain, target / "toolchain")
            self.assertEqual(provenance, target / "provenance")

    def test_path_traversal_slug_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))

            with self.assertRaises(ScopeHoundError) as raised:
                workspace.target_dir("../escape")

        self.assertEqual(raised.exception.category, "unsafe_path")

    def test_prepare_rejects_existing_checkout(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            workspace.repo_dir(manifest.target.name).mkdir(parents=True)

            with self.assertRaises(ScopeHoundError) as raised:
                prepare_plans(manifest, workspace)

        self.assertEqual(raised.exception.category, "workspace_exists")

    def test_local_repository_requires_explicit_permission(self) -> None:
        data = valid_manifest_data()
        data["target"]["repository"] = "/tmp/authorized-fixture"  # type: ignore[index]
        manifest = validate_manifest(data)
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))

            with self.assertRaises(ScopeHoundError) as raised:
                prepare_plans(manifest, workspace)

            plans = prepare_plans(manifest, workspace, allow_local_repository=True)

        self.assertEqual(raised.exception.category, "local_repository_not_allowed")
        self.assertEqual(plans[0].argv[:3], ("git", "clone", "--no-checkout"))
        self.assertEqual(plans[1].argv, ("git", "checkout", "--detach", "v1.2.3"))

    def test_build_and_fuzz_plans_use_checkout_and_bounded_duration(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))

            build = build_plan(manifest, workspace)
            fuzz = fuzz_plan(manifest, workspace, duration_seconds=30)

        self.assertEqual(build.cwd, workspace.repo_dir("example-parser"))
        self.assertEqual(build.argv, ("cmake", "--build", "build"))
        self.assertEqual(fuzz.cwd, workspace.repo_dir("example-parser"))
        self.assertEqual(fuzz.timeout_seconds, 40)
        self.assertEqual(
            fuzz.environment["SCOPEHOUND_ARTIFACTS_DIR"],
            str(workspace.artifacts_dir("example-parser")),
        )

    def test_fuzz_duration_has_strict_bounds(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            for duration in (0, -1, 86401):
                with self.subTest(duration=duration):
                    with self.assertRaises(ScopeHoundError) as raised:
                        fuzz_plan(manifest, workspace, duration_seconds=duration)
                    self.assertEqual(raised.exception.category, "duration_invalid")


if __name__ == "__main__":
    unittest.main()
