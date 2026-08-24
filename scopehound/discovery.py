from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class HarnessCandidate:
    path: Path
    entrypoint: str
    confidence: str
    evidence: str


_SIGNATURES = (
    ("LLVMFuzzerTestOneInput", re.compile(r"\bLLVMFuzzerTestOneInput\b")),
    ("FUZZ_TEST", re.compile(r"\bFUZZ_TEST\s*\(")),
    ("DEFINE_PROTO_FUZZER", re.compile(r"\bDEFINE_PROTO_FUZZER\s*\(")),
)
_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
_SKIP = {".git", "build", "out", "dist", "target", "node_modules"}


def discover_harnesses(repository: Path) -> tuple[HarnessCandidate, ...]:
    root = repository.resolve()
    if not root.is_dir():
        raise ScopeHoundError("repository_invalid", f"repository is not a directory: {repository}")
    candidates: list[HarnessCandidate] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _EXTENSIONS:
            continue
        if any(part in _SKIP for part in path.relative_to(root).parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for entrypoint, pattern in _SIGNATURES:
            if pattern.search(source):
                candidates.append(HarnessCandidate(path.relative_to(root), entrypoint, "high", f"matched {entrypoint}"))
                break
    candidates.sort(key=lambda candidate: (0 if "fuzz" in candidate.path.name.lower() else 1, str(candidate.path)))
    return tuple(candidates)


def write_harnesses(candidates: tuple[HarnessCandidate, ...], output: Path) -> None:
    payload = []
    for candidate in candidates:
        item = asdict(candidate)
        item["path"] = str(candidate.path)
        payload.append(item)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write harnesses {output}: {error}") from error
