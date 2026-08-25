from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from scopehound.errors import ScopeHoundError
from scopehound.findings import Finding


@dataclass(frozen=True)
class KnownIssue:
    fingerprint: str
    summary: str
    first_seen_revision: str | None = None
    fixed_revision: str | None = None


@dataclass(frozen=True)
class IssueComparison:
    fingerprint: str
    label: str
    issue_summary: str | None
    fixed_revision: str | None


def load_known_issues(path: Path) -> tuple[KnownIssue, ...]:
    try:
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8") as handle:
                rows: list[dict[str, str]] = list(csv.DictReader(handle))
            payload: object = rows
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, csv.Error) as error:
        raise ScopeHoundError("input_invalid", f"cannot read known issues {path}: {error}") from error
    if isinstance(payload, dict):
        payload = payload.get("issues", [])
    if not isinstance(payload, list):
        raise ScopeHoundError("input_invalid", "known issues must be an array")
    issues: list[KnownIssue] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict) or not isinstance(item.get("fingerprint"), str):
            raise ScopeHoundError("input_invalid", f"known issue {index} lacks fingerprint")
        issues.append(
            KnownIssue(
                fingerprint=item["fingerprint"],
                summary=str(item.get("summary", "")),
                first_seen_revision=_optional_string(item.get("first_seen_revision")),
                fixed_revision=_optional_string(item.get("fixed_revision")),
            )
        )
    return tuple(sorted(issues, key=lambda issue: issue.fingerprint))


def compare_known_issues(
    findings: tuple[Finding, ...], issues: tuple[KnownIssue, ...], *, current_revision: str
) -> tuple[IssueComparison, ...]:
    index = {issue.fingerprint: issue for issue in issues}
    comparisons: list[IssueComparison] = []
    for finding in findings:
        issue = index.get(finding.fingerprint)
        if issue is None:
            label = "new_candidate"
        elif issue.fixed_revision and current_revision != issue.fixed_revision:
            label = "possible_regression"
        else:
            label = "possible_duplicate"
        comparisons.append(IssueComparison(finding.fingerprint, label, issue.summary if issue else None, issue.fixed_revision if issue else None))
    return tuple(sorted(comparisons, key=lambda item: item.fingerprint))


def write_comparisons(comparisons: tuple[IssueComparison, ...], output: Path) -> None:
    payload = [asdict(item) for item in comparisons]
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        raise ScopeHoundError("output_failed", f"cannot write known issue comparison {output}: {error}") from error


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
