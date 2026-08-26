from __future__ import annotations

import unittest

from scopehound.resource import classify_resource_output


class ResourceTests(unittest.TestCase):
    def test_classifies_timeout_oom_and_hang_without_making_sanitizer_findings(self) -> None:
        self.assertEqual(classify_resource_output("process timed out after 10 seconds").kind, "timeout")
        self.assertEqual(classify_resource_output("out of memory: killed process").kind, "oom")
        self.assertEqual(classify_resource_output("hang detected by watchdog").kind, "hang")
        self.assertIsNone(classify_resource_output("program exited normally"))


if __name__ == "__main__":
    unittest.main()
