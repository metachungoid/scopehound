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
    root_cause: str | None = None
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class IssueComparison:
    fingerprint: str
    label: str
    issue_summary: str | None
    fixed_revision: str | None
    matched_by: str | None = None
    root_cause: str | None = None


@dataclass(frozen=True)
class DuplicateEvidence:
    source: str
    status: str
    checked_at: str
    query: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if self.status not in {"no_match", "match", "inconclusive"}:
            raise ScopeHoundError("duplicate_invalid", f"unsupported duplicate evidence status: {self.status}")
        if not self.source or not self.checked_at:
            raise ScopeHoundError("duplicate_invalid", "duplicate evidence source and checked_at are required")


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
                root_cause=_optional_string(item.get("root_cause")),
                aliases=_aliases(item.get("aliases")),
            )
        )
    return tuple(sorted(issues, key=lambda issue: issue.fingerprint))


def compare_known_issues(
    findings: tuple[Finding, ...], issues: tuple[KnownIssue, ...], *, current_revision: str
) -> tuple[IssueComparison, ...]:
    index: dict[str, tuple[KnownIssue, str]] = {}
    for issue in issues:
        index[issue.fingerprint] = (issue, "fingerprint")
        if issue.root_cause:
            index.setdefault(issue.root_cause, (issue, "root_cause"))
        for alias in issue.aliases:
            index.setdefault(alias, (issue, "alias"))
    comparisons: list[IssueComparison] = []
    for finding in findings:
        matched = index.get(finding.fingerprint) or index.get(finding.root_cause)
        if matched is None:
            label = "new_candidate"
            issue = None
            matched_by = None
        else:
            issue, matched_by = matched
            label = (
                "possible_regression"
                if issue.fixed_revision and current_revision != issue.fixed_revision
                else "possible_duplicate"
            )
        comparisons.append(
            IssueComparison(
                finding.fingerprint,
                label,
                issue.summary if issue else None,
                issue.fixed_revision if issue else None,
                matched_by,
                finding.root_cause,
            )
        )
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


def _aliases(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()
