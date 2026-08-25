from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from scopehound.errors import ScopeHoundError


_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


@dataclass(frozen=True)
class Workspace:
    root: Path

    def __init__(self, root: Path) -> None:
        object.__setattr__(self, "root", root.expanduser().resolve())

    def target_dir(self, name: str) -> Path:
        if not _SLUG.fullmatch(name):
            raise ScopeHoundError("unsafe_path", "target name is not a safe slug")
        return self._contained(self.root / "targets" / name)

    def repo_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "repo")

    def logs_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "logs")

    def artifacts_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "artifacts")

    def generated_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "generated")

    def binaries_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "binaries")

    def corpus_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "corpus")

    def coverage_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "coverage")

    def toolchain_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "toolchain")

    def provenance_dir(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "provenance")

    def findings_file(self, name: str) -> Path:
        return self._contained(self.target_dir(name) / "findings.json")

    def _contained(self, path: Path) -> Path:
        resolved = path.resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as error:
            raise ScopeHoundError(
                "unsafe_path", f"path escapes workspace: {resolved}"
            ) from error
        return resolved
