from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceCandidate:
    kind: str
    summary: str
    evidence: str


_RESOURCE_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("hang", ("hang detected", "stalled", "deadlock")),
    ("timeout", ("timed out", "timeout", "watchdog")),
    ("oom", ("out of memory", "oom", "cannot allocate memory")),
)


def classify_resource_output(output: str) -> ResourceCandidate | None:
    if not output or len(output) > 1_000_000:
        return None
    lowered = output.casefold()
    for kind, markers in _RESOURCE_MARKERS:
        for marker in markers:
            if re.search(r"(?<![a-z])" + re.escape(marker) + r"(?![a-z])", lowered):
                return ResourceCandidate(kind, f"resource signal: {kind}", marker)
    return None
