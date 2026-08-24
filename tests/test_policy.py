from __future__ import annotations

import unittest

from scopehound.errors import ScopeHoundError
from scopehound.manifest import validate_manifest
from scopehound.policy import require_authorized

from tests.fixtures import valid_manifest_data


class PolicyTests(unittest.TestCase):
    def test_authorized_memory_corruption_target_is_allowed(self) -> None:
        require_authorized(validate_manifest(valid_manifest_data()))

    def test_non_authorized_status_is_rejected(self) -> None:
        data = valid_manifest_data()
        data["authorization"]["status"] = "permission-needed"  # type: ignore[index]

        with self.assertRaises(ScopeHoundError) as raised:
            require_authorized(validate_manifest(data))

        self.assertEqual(raised.exception.category, "authorization_required")

    def test_missing_memory_corruption_eligibility_is_rejected(self) -> None:
        data = valid_manifest_data()
        data["authorization"]["eligible_classes"] = ["web"]  # type: ignore[index]

        with self.assertRaises(ScopeHoundError) as raised:
            require_authorized(validate_manifest(data))

        self.assertEqual(raised.exception.category, "authorization_required")


if __name__ == "__main__":
    unittest.main()
