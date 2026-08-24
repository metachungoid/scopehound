from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class Finding:
    sanitizer: str
    kind: str
    summary: str
    location: str
    function: str
    stack: tuple[str, ...]
    fingerprint: str
    artifact: str | None
    raw_output: str
    reproducibility: str = "unverified"


def load_findings(path: Path) -> tuple[Finding, ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return tuple(
            Finding(
                sanitizer=item["sanitizer"], kind=item["kind"], summary=item["summary"],
                location=item["location"], function=item["function"],
                stack=tuple(item.get("stack", ())), fingerprint=item["fingerprint"],
                artifact=item.get("artifact"), raw_output=item.get("raw_output", ""),
                reproducibility=item.get("reproducibility", "unverified"),
            )
            for item in payload
        )
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read findings {path}: {error}") from error


_ASAN_ERROR = re.compile(r"ERROR: AddressSanitizer: (?P<kind>[^\n]+)")
_ASAN_SUMMARY = re.compile(
    r"SUMMARY: AddressSanitizer: (?P<kind>.+?) (?P<location>(?:/|[\w.-]+/)[^\s]+:\d+(?::\d+)?) in (?P<function>[^\n]+)"
)
_FRAME = re.compile(
    r"^\s*#\d+\s+[^\n]*? in (?P<function>[^\s]+) (?P<location>(?:/|[\w.-]+/)[^\s]+:\d+(?::\d+)?)",
    re.MULTILINE,
)
_UBSAN = re.compile(
    r"^(?P<location>[^:\n]+:\d+:\d+): runtime error: (?P<summary>[^\n]+)$",
    re.MULTILINE,
)
_LIBFUZZER_ARTIFACT = re.compile(
    r"^\s*(?:Test unit written to|artifact(?:_path)?\s*[:=])\s*[\"']?(?P<path>[^\s\"']+)",
    re.IGNORECASE | re.MULTILINE,
)


def parse_sanitizer_output(output: str, artifact: Path | None = None) -> tuple[Finding, ...]:
    if not output.strip():
        return ()
    findings: dict[str, Finding] = {}
    artifact_name = artifact.name if artifact else _infer_artifact(output)
    blocks = _asan_blocks(output)
    for block in blocks:
        error = _ASAN_ERROR.search(block)
        summary = _ASAN_SUMMARY.search(block)
        frames = tuple(
            f"{match.group('function')} at {match.group('location')}"
            for match in _FRAME.finditer(block)
        )
        kind = _clean_kind((summary or error).group("kind") if (summary or error) else "sanitizer failure")
        location = summary.group("location") if summary else (frames[0].split(" at ", 1)[-1] if frames else "unknown")
        function = summary.group("function").strip() if summary else (frames[0].split(" at ", 1)[0] if frames else "unknown")
        fingerprint = _fingerprint("AddressSanitizer", kind, location, function, frames)
        findings[fingerprint] = Finding(
            sanitizer="AddressSanitizer",
            kind=kind,
            summary=kind,
            location=location,
            function=function,
            stack=frames,
            fingerprint=fingerprint,
            artifact=artifact_name,
            raw_output=block.strip(),
        )

    for match in _UBSAN.finditer(output):
        summary = match.group("summary").strip()
        kind = summary.split(":", 1)[0].strip()
        location = match.group("location")
        fingerprint = _fingerprint("UndefinedBehaviorSanitizer", kind, location, "unknown", ())
        findings[fingerprint] = Finding(
            sanitizer="UndefinedBehaviorSanitizer",
            kind=kind,
            summary=summary,
            location=location,
            function="unknown",
            stack=(),
            fingerprint=fingerprint,
            artifact=artifact_name,
            raw_output=match.group(0),
        )
    return tuple(findings[key] for key in sorted(findings))


def write_findings(findings: tuple[Finding, ...], output: Path) -> None:
    payload = []
    for finding in findings:
        item = asdict(finding)
        item["stack"] = list(finding.stack)
        payload.append(item)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write findings {output}: {error}") from error


def _asan_blocks(output: str) -> tuple[str, ...]:
    starts = [match.start() for match in re.finditer(r"(?:ERROR: AddressSanitizer:|==\d+==ERROR: AddressSanitizer:)", output)]
    if not starts:
        return ()
    return tuple(output[start:end] for start, end in zip(starts, starts[1:] + [len(output)]))


def _clean_kind(kind: str) -> str:
    return re.split(r"\s+on address\b|\s+at address\b", kind, maxsplit=1)[0].strip()


def _fingerprint(sanitizer: str, kind: str, location: str, function: str, frames: tuple[str, ...]) -> str:
    source = "|".join((sanitizer, kind, location, function, *frames[:3]))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()[:20]


def _infer_artifact(output: str) -> str | None:
    match = _LIBFUZZER_ARTIFACT.search(output)
    if not match:
        return None
    value = match.group("path").rstrip(",;)")
    return Path(value).name or None
