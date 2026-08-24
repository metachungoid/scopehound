from __future__ import annotations

import json
from pathlib import Path

from scopehound.errors import ScopeHoundError
from scopehound.findings import Finding
from scopehound.manifest import Manifest
from scopehound.reproduction import ReproductionResult
from scopehound.triage import ArtifactRecord


def render_report(
    manifest: Manifest,
    artifact: ArtifactRecord,
    relative_artifact_path: str,
    finding: Finding | None = None,
    reproduction: ReproductionResult | None = None,
) -> str:
    build_command = json.dumps(list(manifest.commands.build))
    fuzz_command = json.dumps(list(manifest.commands.fuzz))
    reproduce_command = (
        json.dumps(list(manifest.commands.reproduce))
        if manifest.commands.reproduce
        else "not configured"
    )
    technical_details = ""
    if finding:
        stack = "".join(f"  - `{frame}`\n" for frame in finding.stack)
        evidence = _code_block(finding.raw_output) if finding.raw_output.strip() else "(not captured)"
        technical_details = f"""## Parsed technical finding

- Sanitizer: {finding.sanitizer}
- Signal: {finding.kind}
- Summary: {finding.summary}
- Location: `{finding.location}`
- Function: `{finding.function}`
- Fingerprint: `{finding.fingerprint}`
- Reproducibility status: `{finding.reproducibility}`
- Stack:
{stack}"""
        technical_details += f"""
- Raw sanitizer evidence:

{evidence}
"""
    reproduction_details = ""
    if reproduction:
        observed = ", ".join(f"`{item}`" for item in reproduction.observed_fingerprints)
        if not observed:
            observed = "(none)"
        replay_stdout = _code_block(reproduction.stdout) if reproduction.stdout else "(empty)"
        replay_stderr = _code_block(reproduction.stderr) if reproduction.stderr else "(empty)"
        reproduction_details = f"""## Reproduction verification

- Status: `{reproduction.status}`
- Artifact: `{reproduction.artifact}`
- Expected fingerprint: `{reproduction.expected_fingerprint}`
- Observed fingerprints: {observed}
- Exit code: `{reproduction.returncode}`
- Replay command: `{json.dumps(list(reproduction.command))}`

### Replay stdout

{replay_stdout}

### Replay stderr

{replay_stderr}
"""
    return f"""---
human_review_required: true
target: {manifest.target.name}
artifact_sha256: {artifact.sha256}
---

# Potential memory-safety finding: {manifest.target.name}

This is an evidence draft, not a vulnerability determination. A researcher
must complete every review item before disclosure.

## Scope evidence

- Repository: {manifest.target.repository}
- Tested revision: {manifest.target.revision}
- Scope policy: {manifest.authorization.policy_url}
- Policy checked: {manifest.authorization.checked_at}
- Eligible classes: {', '.join(manifest.authorization.eligible_classes)}

## Reproduction

- Build command: `{build_command}`
- Fuzz command: `{fuzz_command}`
- Reproduction command: `{reproduce_command}`
- Artifact: `{relative_artifact_path}`
- Artifact size: {artifact.size} bytes
- SHA-256: `{artifact.sha256}`

- [ ] Record exact host/container and compiler versions
- [ ] Add deterministic reproduction steps
- [ ] Attach symbolized sanitizer output

{technical_details}

{reproduction_details}

## Security analysis

- [ ] Confirm attacker-controlled reachability
- [ ] Describe the memory-safety root cause
- [ ] Distinguish a harness defect from a product defect
- [ ] Determine confidentiality or integrity impact
- [ ] Check whether mitigations materially limit impact

## Duplicate and version checks

- [ ] Search for duplicate reports and root causes
- [ ] Reproduce against the latest eligible revision
- [ ] Confirm the issue is not already patched upstream

## Disclosure review

- [ ] Recheck the current scope policy before submission
- [ ] Remove secrets, personal data, and unrelated artifacts
- [ ] Submit through the policy's designated private channel
"""


def write_report(text: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError(
            "output_failed", f"cannot write report {output}: {error}"
        ) from error


def _code_block(text: str, limit: int = 12_000) -> str:
    excerpt = text[:limit]
    if len(text) > limit:
        excerpt += "\n[raw sanitizer output truncated]"
    fence = "```"
    while fence in excerpt:
        fence += "`"
    return f"{fence}text\n{excerpt}\n{fence}"
