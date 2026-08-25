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
    {
        "repo", "source", "source_c", "object", "binary", "corpus", "dictionary",
        "artifact", "duration", "revision",
    }
)
_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
_COVERAGE_MODES = {"none", "llvm"}

Command = tuple[str, ...]
CommandGroup = tuple[Command, ...]


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
    build: Command
    fuzz: Command
    reproduce: Command | None = None
    harness_build: Command | None = None
    prepare_steps: CommandGroup = ()
    build_steps: CommandGroup = ()
    fuzz_steps: CommandGroup = ()
    reproduce_steps: CommandGroup = ()
    harness_build_steps: CommandGroup = ()


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
        build_steps = _command_group(commands_data.get("build"), "commands.build")
        fuzz_steps = _command_group(commands_data.get("fuzz"), "commands.fuzz")
        reproduce_steps = _optional_command_group(commands_data.get("reproduce"), "commands.reproduce")
        harness_build_steps = _optional_command_group(
            commands_data.get("harness_build"), "commands.harness_build"
        )
        prepare_steps = _optional_command_group(commands_data.get("prepare"), "commands.prepare")
        _validate_group_required(reproduce_steps, "commands.reproduce", ("artifact",))
        _validate_group_required(harness_build_steps, "commands.harness_build", ("source", "binary"))
        commands = Commands(
            build=_first_command(build_steps),
            fuzz=_first_command(fuzz_steps),
            reproduce=_first_optional_command(reproduce_steps),
            harness_build=_first_optional_command(harness_build_steps),
            prepare_steps=prepare_steps,
            build_steps=build_steps,
            fuzz_steps=fuzz_steps,
            reproduce_steps=reproduce_steps,
            harness_build_steps=harness_build_steps,
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


def _command(value: object, field: str) -> Command:
    if not isinstance(value, list) or not value:
        _invalid(f"{field} must be a non-empty argument array")
    command = tuple(_string(item, f"{field} argument") for item in value)
    _validate_command_placeholders(command, field)
    return command


def _command_group(value: object, field: str) -> CommandGroup:
    if not isinstance(value, list) or not value:
        _invalid(f"{field} must be a non-empty argument array or command group")
    if all(isinstance(item, str) for item in value):
        return (_command(value, field),)
    if not all(isinstance(item, list) for item in value):
        _invalid(f"{field} must contain only argument arrays")
    commands = tuple(_command(item, f"{field}[{index}]") for index, item in enumerate(value))
    if not commands:
        _invalid(f"{field} must contain at least one command")
    return commands


def _optional_command_group(value: object, field: str) -> CommandGroup:
    if value is None:
        return ()
    return _command_group(value, field)


def _first_command(group: CommandGroup) -> Command:
    return group[0]


def _first_optional_command(group: CommandGroup) -> Command | None:
    return group[0] if group else None


def _validate_group_required(
    group: CommandGroup, field: str, required: tuple[str, ...]
) -> None:
    if not group:
        return
    counts = {name: 0 for name in required}
    for command in group:
        for argument in command:
            for match in _PLACEHOLDER.finditer(argument):
                if match.group(1) in counts:
                    counts[match.group(1)] += 1
    for name, count in counts.items():
        if count != 1:
            _invalid(f"{field} command group must contain exactly one {{{name}}} placeholder")


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
