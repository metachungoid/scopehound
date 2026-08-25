from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.runner import CommandPlan, run_plan
from unittest.mock import patch


class RunnerTests(unittest.TestCase):
    def test_dry_run_does_not_execute_or_create_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cwd = root / "not-created"
            marker = root / "marker"
            plan = CommandPlan(
                argv=(sys.executable, "-c", f"open({str(marker)!r}, 'w').write('ran')"),
                cwd=cwd,
                environment={},
                timeout_seconds=5,
                mutates=True,
            )

            result = run_plan(plan, execute=False)

            self.assertFalse(result.executed)
            self.assertFalse(cwd.exists())
            self.assertFalse(marker.exists())

    def test_execute_captures_real_process_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = CommandPlan(
                argv=(sys.executable, "-c", "print('research-ready')"),
                cwd=Path(temp_dir),
                environment={},
                timeout_seconds=5,
                mutates=False,
            )

            result = run_plan(plan, execute=True)

        self.assertTrue(result.executed)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "research-ready")

    def test_timeout_has_stable_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = CommandPlan(
                argv=(sys.executable, "-c", "import time; time.sleep(2)"),
                cwd=Path(temp_dir),
                environment={},
                timeout_seconds=0.05,
                mutates=False,
            )

            with self.assertRaises(ScopeHoundError) as raised:
                run_plan(plan, execute=True)

        self.assertEqual(raised.exception.category, "timeout")

    def test_nonzero_exit_has_stable_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = CommandPlan(
                argv=(sys.executable, "-c", "raise SystemExit(7)"),
                cwd=Path(temp_dir),
                environment={},
                timeout_seconds=5,
                mutates=False,
            )

            with self.assertRaises(ScopeHoundError) as raised:
                run_plan(plan, execute=True)

        self.assertEqual(raised.exception.category, "command_failed")

    def test_requested_unavailable_backend_is_not_replaced_by_native(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = CommandPlan((sys.executable, "-c", "print('unsafe fallback')"), Path(temp_dir), {}, 5, False)
            with patch("scopehound.sandbox.shutil.which", return_value=None):
                with self.assertRaises(ScopeHoundError) as raised:
                    run_plan(plan, execute=False, backend="bubblewrap")

        self.assertEqual(raised.exception.category, "sandbox_unavailable")


if __name__ == "__main__":
    unittest.main()
