from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class CrossBuildConfirmation:
    status: str
    variants: tuple[str, ...]
    root_cause: str | None
    details: Mapping[str, object]


def compare_builds(
    first: Mapping[str, object], second: Mapping[str, object]
) -> CrossBuildConfirmation:
    first_variant = str(first.get("variant", "first"))
    second_variant = str(second.get("variant", "second"))
    first_root = _optional_string(first.get("root_cause"))
    second_root = _optional_string(second.get("root_cause"))
    if (
        first.get("status") == "reproduced"
        and second.get("status") == "reproduced"
        and first_root
        and first_root == second_root
    ):
        status = "confirmed_across_builds"
    else:
        status = "mismatch"
    return CrossBuildConfirmation(
        status=status,
        variants=(first_variant, second_variant),
        root_cause=first_root if first_root == second_root else None,
        details={
            "first": dict(first),
            "second": dict(second),
            "reason": (
                "matching reproduced root-cause identities"
                if status == "confirmed_across_builds"
                else "build outputs did not provide matching reproduced root-cause evidence"
            ),
        },
    )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
