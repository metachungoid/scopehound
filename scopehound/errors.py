from __future__ import annotations


class ScopeHoundError(Exception):
    """An expected failure with a stable machine-readable category."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
