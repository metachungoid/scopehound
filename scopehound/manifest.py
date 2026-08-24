from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlparse

from scopehound.errors import ScopeHoundError


_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_MOVING_REVISIONS = {"head", "main", "master", "trunk", "develop", "development"}
_OPPORTUNITY_FIELDS = (
    "bounty_eligibility",
    "attacker_reachability",
    "code_criticality",
    "change_recency",
    "fuzzing_gap",
    "build_reproducibility",
    "duplicate_risk",
)


@dataclass(frozen=True)
class Target:
    name: str
    repository: str
    revision: str
    language: str


@dataclass(frozen=True)
class Authorization:
    status: str
    policy_url: str
    checked_at: str
    eligible_classes: tuple[str, ...]
    notes: str = ""


@dataclass(frozen=True)
class Commands:
    build: tuple[str, ...]
    fuzz: tuple[str, ...]


@dataclass(frozen=True)
class Opportunity:
    bounty_eligibility: float
    attacker_reachability: float
    code_criticality: float
    change_recency: float
    fuzzing_gap: float
    build_reproducibility: float
    duplicate_risk: float


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    target: Target
    authorization: Authorization
    commands: Commands
    environment: Mapping[str, str]
    opportunity: Opportunity


def load_manifest(path: Path) -> Manifest:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("manifest_invalid", f"cannot read manifest: {error}") from error
    return validate_manifest(data)


def validate_manifest(data: object) -> Manifest:
    try:
        root = _mapping(data, "manifest")
        if root.get("schema_version") != 1:
            _invalid("schema_version must be 1")

        target_data = _mapping(root.get("target"), "target")
        name = _string(target_data.get("name"), "target.name")
        if not _SLUG.fullmatch(name):
            _invalid("target.name must be a lowercase slug of at most 63 characters")
        repository = _string(target_data.get("repository"), "target.repository")
        _validate_repository(repository)
        revision = _string(target_data.get("revision"), "target.revision")
        if revision.casefold() in _MOVING_REVISIONS:
            _invalid("target.revision must be an immutable commit or release tag")
        language = _string(target_data.get("language"), "target.language")
        if language not in {"c", "cpp"}:
            _invalid("target.language must be 'c' or 'cpp'")

        authorization_data = _mapping(root.get("authorization"), "authorization")
        checked_at = _string(authorization_data.get("checked_at"), "authorization.checked_at")
        try:
            date.fromisoformat(checked_at)
        except ValueError as error:
            raise ScopeHoundError(
                "manifest_invalid", "authorization.checked_at must be an ISO date"
            ) from error
        eligible_classes = _string_tuple(
            authorization_data.get("eligible_classes"), "authorization.eligible_classes"
        )
        authorization = Authorization(
            status=_string(authorization_data.get("status"), "authorization.status"),
            policy_url=_string(authorization_data.get("policy_url"), "authorization.policy_url"),
            checked_at=checked_at,
            eligible_classes=eligible_classes,
            notes=_optional_string(authorization_data.get("notes", ""), "authorization.notes"),
        )

        commands_data = _mapping(root.get("commands"), "commands")
        commands = Commands(
            build=_command(commands_data.get("build"), "commands.build"),
            fuzz=_command(commands_data.get("fuzz"), "commands.fuzz"),
        )

        environment_data = _mapping(root.get("environment", {}), "environment")
        environment: dict[str, str] = {}
        for key, value in environment_data.items():
            environment[_string(key, "environment key")] = _string(
                value, f"environment.{key}"
            )

        opportunity_data = _mapping(root.get("opportunity"), "opportunity")
        values = {
            field: _factor(opportunity_data.get(field), f"opportunity.{field}")
            for field in _OPPORTUNITY_FIELDS
        }
        opportunity = Opportunity(**values)

        return Manifest(
            schema_version=1,
            target=Target(name, repository, revision, language),
            authorization=authorization,
            commands=commands,
            environment=MappingProxyType(environment),
            opportunity=opportunity,
        )
    except ScopeHoundError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ScopeHoundError("manifest_invalid", str(error)) from error


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        _invalid(f"{field} must be an object")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _invalid(f"{field} must be a non-empty string")
    return value


def _optional_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        _invalid(f"{field} must be a string")
    return value


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        _invalid(f"{field} must be a non-empty array")
    return tuple(_string(item, f"{field} item") for item in value)


def _command(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        _invalid(f"{field} must be a non-empty argument array")
    return tuple(_string(item, f"{field} argument") for item in value)


def _factor(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _invalid(f"{field} must be a number")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        _invalid(f"{field} must be between 0 and 1")
    return result


def _validate_repository(repository: str) -> None:
    parsed = urlparse(repository)
    if parsed.scheme in {"https", "ssh", "file"}:
        if not parsed.netloc and parsed.scheme != "file":
            _invalid("target.repository URL must include a host")
        return
    if repository.startswith("git@") and ":" in repository:
        return
    if Path(repository).is_absolute():
        return
    _invalid("target.repository must be an HTTPS/SSH Git URL or absolute local path")


def _invalid(message: str) -> None:
    raise ScopeHoundError("manifest_invalid", message)
