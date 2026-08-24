from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class HarnessCandidate:
    path: Path
    function: str
    parameters: str
    confidence: str
    status: str
    source: str


_DECLARATION = re.compile(
    r"(?m)^\s*(?P<return>[A-Za-z_][\w\s:*&<>]*?)\s+(?P<function>[A-Za-z_]\w*)\s*\((?P<parameters>[^;{}]*)\)\s*;"
)
_BUFFER = re.compile(
    r"(?P<type>(?:(?:const|volatile)\s+)?(?:(?:unsigned|signed)\s+)?"
    r"(?:char|uint8_t|byte|void)\s*\*+)\s*(?P<name>[A-Za-z_]\w*)"
)
_LENGTH = re.compile(
    r"(?P<type>(?:const\s+)?(?:size_t|u?int(?:8|16|32|64)_t|"
    r"unsigned(?:\s+long)?|long|int))\s+(?P<name>[A-Za-z_]\w*)",
    re.IGNORECASE,
)
_LENGTH_NAME = re.compile(r"^(?:size|len|length|count|n|bytes?)$", re.IGNORECASE)
_SKIP = {".git", "build", "out", "dist", "target", "node_modules"}
_EXTENSIONS = {".h", ".hh", ".hpp", ".c", ".cc", ".cpp", ".cxx"}


def generate_harnesses(repository: Path) -> tuple[HarnessCandidate, ...]:
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
        for match in _DECLARATION.finditer(source):
            return_type = match.group("return").strip()
            parameters = " ".join(match.group("parameters").split())
            if return_type == "void" or not _BUFFER.search(parameters) or not _find_length(parameters):
                continue
            function = match.group("function")
            candidates.append(HarnessCandidate(
                path=path.relative_to(root), function=function, parameters=parameters,
                confidence="high", status="needs_build_validation",
                source=_render_harness(return_type, function, parameters),
            ))
    candidates.sort(key=lambda item: (_function_priority(item.function), str(item.path), item.function))
    return tuple(candidates)


def write_harnesses(candidates: tuple[HarnessCandidate, ...], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    metadata = []
    for candidate in candidates:
        filename = f"{candidate.function}_fuzzer.cc"
        (output / filename).write_text(candidate.source, encoding="utf-8")
        item = asdict(candidate)
        item["path"] = str(candidate.path)
        item["generated_file"] = filename
        item.pop("source")
        metadata.append(item)
    temporary = output / "harnesses.json.tmp"
    try:
        temporary.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output / "harnesses.json")
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write harness metadata: {error}") from error


def _render_harness(return_type: str, function: str, parameters: str) -> str:
    buffer_match = _BUFFER.search(parameters)
    length_match = _find_length(parameters)
    if buffer_match is None or length_match is None:  # pragma: no cover - guarded by caller
        raise ScopeHoundError("harness_invalid", f"cannot identify input parameters for {function}")
    buffer_type = " ".join(buffer_match.group("type").split())
    buffer_name = buffer_match.group("name")
    length_type = " ".join(length_match.group("type").split())
    length_name = length_match.group("name")
    declaration = f"extern \"C\" {return_type} {function}({parameters});"
    arguments = []
    for parameter in (item.strip() for item in parameters.split(",")):
        if re.search(rf"\b{re.escape(buffer_name)}\b", parameter):
            input_pointer = "data"
            if "const" not in buffer_type.split():
                input_pointer = "const_cast<uint8_t *>(data)"
            arguments.append(f"reinterpret_cast<{buffer_type}>({input_pointer})")
        elif re.search(rf"\b{re.escape(length_name)}\b", parameter):
            arguments.append(f"static_cast<{length_type}>(size)")
        elif "*" in parameter:
            arguments.append("nullptr")
        else:
            arguments.append("{}")
    call = f"{function}({', '.join(arguments)})"
    return f'''#include <cstddef>
#include <cstdint>

{declaration}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
  (void){call};
  return 0;
}}
'''


def _find_length(parameters: str) -> re.Match[str] | None:
    matches = tuple(_LENGTH.finditer(parameters))
    if not matches:
        return None
    return next(
        (match for match in matches if _LENGTH_NAME.fullmatch(match.group("name"))),
        matches[0],
    )


def _function_priority(function: str) -> int:
    name = function.lower()
    if "parse" in name:
        return 0
    if "decode" in name or "deserialize" in name or "read" in name:
        return 1
    return 2
