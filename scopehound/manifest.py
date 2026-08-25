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
SUPPORTED_PLACEHOLDERS = frozenset(
    {"repo", "source", "binary", "corpus", "dictionary", "artifact", "duration"}
)
_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
_COVERAGE_MODES = {"none", "llvm"}


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
    reproduce: tuple[str, ...] | None = None
    harness_build: tuple[str, ...] | None = None


@dataclass(frozen=True)
class CorpusConfig:
    seed_dir: str | None = None
    dictionary: str | None = None
    max_input_size: int = 1_048_576
    coverage_mode: str = "none"


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
    corpus: CorpusConfig


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
            reproduce=_reproduction_command(commands_data.get("reproduce")),
            harness_build=_harness_build_command(commands_data.get("harness_build")),
        )

        corpus_data = _mapping(root.get("corpus", {}), "corpus")
        corpus = CorpusConfig(
            seed_dir=_relative_optional_path(corpus_data.get("seed_dir"), "corpus.seed_dir"),
            dictionary=_relative_optional_path(
                corpus_data.get("dictionary"), "corpus.dictionary"
            ),
            max_input_size=_positive_int(
                corpus_data.get("max_input_size", 1_048_576), "corpus.max_input_size"
            ),
            coverage_mode=_coverage_mode(
                corpus_data.get("coverage_mode", "none"), "corpus.coverage_mode"
            ),
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
            corpus=corpus,
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
    command = tuple(_string(item, f"{field} argument") for item in value)
    _validate_command_placeholders(command, field)
    return command


def _reproduction_command(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    command = _command(value, "commands.reproduce")
    _validate_command_placeholders(command, "commands.reproduce", required=("artifact",))
    return command


def _harness_build_command(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    command = _command(value, "commands.harness_build")
    _validate_command_placeholders(
        command, "commands.harness_build", required=("source", "binary")
    )
    return command


def _validate_command_placeholders(
    command: tuple[str, ...], field: str, required: tuple[str, ...] = ()
) -> None:
    counts = {name: 0 for name in SUPPORTED_PLACEHOLDERS}
    for argument in command:
        for match in _PLACEHOLDER.finditer(argument):
            name = match.group(1)
            if name not in SUPPORTED_PLACEHOLDERS:
                _invalid(f"{field} uses unsupported placeholder {{{name}}}")
            counts[name] += 1
        if "{" in argument or "}" in argument:
            leftovers = _PLACEHOLDER.sub("", argument).replace("{{", "").replace("}}", "")
            if "{" in leftovers or "}" in leftovers:
                _invalid(f"{field} contains malformed placeholder syntax")
    for name in required:
        if counts[name] != 1:
            _invalid(f"{field} must contain exactly one {{{name}}} placeholder")


def _relative_optional_path(value: object, field: str) -> str | None:
    if value is None:
        return None
    path = _string(value, field)
    parsed = Path(path)
    if parsed.is_absolute() or any(part == ".." for part in parsed.parts):
        _invalid(f"{field} must be a relative path inside the target workspace")
    return path


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 64 * 1024 * 1024:
        _invalid(f"{field} must be an integer between 1 and 67108864")
    return value


def _coverage_mode(value: object, field: str) -> str:
    mode = _string(value, field)
    if mode not in _COVERAGE_MODES:
        _invalid(f"{field} must be one of: {', '.join(sorted(_COVERAGE_MODES))}")
    return mode


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
