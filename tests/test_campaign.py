from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scopehound.campaign import (
    create_campaign,
    load_campaign,
    run_stage,
)
from scopehound.errors import ScopeHoundError
from scopehound.manifest import validate_manifest
from scopehound.workspace import Workspace

from tests.fixtures import valid_manifest_data


class CampaignTests(unittest.TestCase):
    def test_campaign_creation_records_digest_and_directories(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))

            state = create_campaign(manifest, workspace, engine="standalone", backend="native")
            loaded = load_campaign(workspace.campaign_file(manifest.target.name))

            self.assertEqual(loaded.manifest_digest, state.manifest_digest)
            self.assertTrue(workspace.artifacts_dir(manifest.target.name).is_dir())
            self.assertTrue(workspace.controls_dir(manifest.target.name).is_dir())

    def test_resume_rejects_changed_manifest_without_overwriting_evidence(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        changed_data = valid_manifest_data()
        changed_data["target"]["revision"] = "different-immutable-commit"  # type: ignore[index]
        changed = validate_manifest(changed_data)
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            state = create_campaign(manifest, workspace, engine="standalone", backend="native")

            with self.assertRaises(ScopeHoundError) as raised:
                run_stage(
                    state,
                    changed,
                    workspace,
                    "build",
                    changed.commands.build_steps,
                    execute=False,
                )

            self.assertEqual(raised.exception.category, "campaign_stale")
            self.assertEqual(load_campaign(workspace.campaign_file(manifest.target.name)), state)

    def test_dry_run_records_planned_stage_and_resume_is_idempotent(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            state = create_campaign(manifest, workspace, engine="standalone", backend="native")

            planned = run_stage(
                state, manifest, workspace, "build", manifest.commands.build_steps, execute=False
            )
            resumed = run_stage(
                planned, manifest, workspace, "build", manifest.commands.build_steps, execute=False
            )

            self.assertEqual(len(planned.stages), 1)
            self.assertEqual(planned.stages[0].status, "planned")
            self.assertEqual(resumed, planned)

    def test_failed_stage_blocks_later_stage(self) -> None:
        manifest_data = valid_manifest_data()
        manifest_data["commands"]["build"] = [["false"]]  # type: ignore[index]
        manifest = validate_manifest(manifest_data)
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            state = create_campaign(manifest, workspace, engine="standalone", backend="native")
            failed = run_stage(
                state, manifest, workspace, "build", manifest.commands.build_steps, execute=True
            )

            with self.assertRaises(ScopeHoundError) as raised:
                run_stage(
                    failed,
                    manifest,
                    workspace,
                    "run",
                    (("true",),),
                    execute=False,
                )

            self.assertEqual(raised.exception.category, "campaign_blocked")

    def test_force_stage_appends_attempt(self) -> None:
        manifest = validate_manifest(valid_manifest_data())
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Workspace(Path(temp_dir))
            state = create_campaign(manifest, workspace, engine="standalone", backend="native")
            first = run_stage(
                state, manifest, workspace, "build", manifest.commands.build_steps, execute=False
            )
            forced = run_stage(
                first,
                manifest,
                workspace,
                "build",
                (("cc", "--version"),),
                execute=False,
                force=True,
            )

            self.assertEqual(len(forced.stages), 2)
            self.assertEqual(forced.stages[-1].attempts, 2)
            json.loads(workspace.campaign_file(manifest.target.name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
