from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scopehound.errors import ScopeHoundError
from scopehound.runner import CommandPlan
from scopehound.sandbox import backend_policy, wrap_plan


class SandboxTests(unittest.TestCase):
    def test_native_policy_is_explicit_and_unwrapped(self) -> None:
        plan = CommandPlan(("echo", "ok"), Path("/tmp"), {}, 5, False)

        wrapped = wrap_plan(plan, "native")

        self.assertEqual(wrapped.argv, plan.argv)
        self.assertEqual(backend_policy("native").network, "host")

    def test_bubblewrap_plan_contains_no_network_and_read_only_repo_flags(self) -> None:
        plan = CommandPlan(("tool", "arg"), Path("/tmp/work/repo"), {}, 5, True)

        wrapped = wrap_plan(plan, "bubblewrap", check_available=False)

        self.assertIn("--unshare-net", wrapped.argv)
        self.assertIn("--ro-bind", wrapped.argv)
        self.assertIn("--uid", wrapped.argv)
        self.assertEqual(wrapped.policy.network, "none")

    def test_docker_plan_is_read_only_and_non_networked(self) -> None:
        plan = CommandPlan(("tool", "arg"), Path("/tmp/work/repo"), {}, 5, True)

        wrapped = wrap_plan(plan, "docker", check_available=False)

        self.assertIn("--network", wrapped.argv)
        self.assertIn("none", wrapped.argv)
        self.assertIn("--read-only", wrapped.argv)
        self.assertEqual(wrapped.policy.network, "none")

    def test_unavailable_backend_does_not_fall_back(self) -> None:
        plan = CommandPlan(("echo", "ok"), Path("/tmp"), {}, 5, False)
        with patch("scopehound.sandbox.shutil.which", return_value=None):
            with self.assertRaises(ScopeHoundError) as raised:
                wrap_plan(plan, "bubblewrap")

        self.assertEqual(raised.exception.category, "sandbox_unavailable")


if __name__ == "__main__":
    unittest.main()
