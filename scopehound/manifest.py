from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
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
_CAMPAIGN_ENGINES = {"standalone", "libfuzzer", "afl++", "honggfuzz", "centipede"}
_ORACLE_KINDS = {"differential", "metamorphic", "roundtrip"}

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
    policy_digest: str = ""


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
class BuildVariant:
    name: str
    build_steps: CommandGroup = ()
    fuzz_steps: CommandGroup = ()
    environment: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    changed_functions: tuple[str, ...] = ()


@dataclass(frozen=True)
class OracleConfig:
    name: str
    kind: str
    command: Command


@dataclass(frozen=True)
class CampaignConfig:
    max_workers: int = 1
    max_retries: int = 0
    share_corpus: bool = False
    wall_clock_seconds: int = 600
    cpu_seconds: int = 600
    process_limit: int = 1
    engines: tuple[str, ...] = ("standalone",)
    build_variants: tuple[BuildVariant, ...] = ()
    changed_functions: tuple[str, ...] = ()
    oracles: tuple[OracleConfig, ...] = ()
    optimizer: "OptimizerConfig" = field(default_factory=lambda: OptimizerConfig())


@dataclass(frozen=True)
class OptimizerConfig:
    exploration_fraction: float = 0.2
    halving_factor: int = 2
    candidate_weight: float = 0.7
    duplicate_weight: float = 0.15
    replay_weight: float = 0.1
    coverage_weight: float = 0.05


@dataclass(frozen=True)
class Economics:
    expected_reward: float | None = None
    reward_confidence: float = 0.0
    cpu_hour_cost: float = 0.0


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    target: Target
    authorization: Authorization
    commands: Commands
    environment: Mapping[str, str]
    opportunity: Opportunity
    corpus: CorpusConfig
    campaign: CampaignConfig = field(default_factory=CampaignConfig)
    economics: Economics = field(default_factory=Economics)


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
            policy_digest=_optional_digest(authorization_data.get("policy_digest", ""), "authorization.policy_digest"),
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

        campaign = _campaign_config(root.get("campaign", {}))
        economics = _economics_config(root.get("economics", {}))

        return Manifest(
            schema_version=1,
            target=Target(name, repository, revision, language),
            authorization=authorization,
            commands=commands,
            environment=MappingProxyType(environment),
            opportunity=opportunity,
            corpus=corpus,
            campaign=campaign,
            economics=economics,
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


def _optional_string_tuple(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        _invalid(f"{field} must be an array")
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


def _bounded_int(value: object, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _invalid(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _nonnegative_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _invalid(f"{field} must be a number")
    result = float(value)
    if result < 0.0:
        _invalid(f"{field} must be non-negative")
    return result


def _optional_nonnegative_number(value: object, field: str) -> float | None:
    if value is None:
        return None
    return _nonnegative_number(value, field)


def _optional_digest(value: object, field: str) -> str:
    if value in (None, ""):
        return ""
    text = _string(value, field)
    if len(text) != 64:
        _invalid(f"{field} must be a SHA-256 hex digest")
    try:
        int(text, 16)
    except ValueError as error:
        raise ScopeHoundError("manifest_invalid", f"{field} must be hexadecimal") from error
    return text


def _coverage_mode(value: object, field: str) -> str:
    mode = _string(value, field)
    if mode not in _COVERAGE_MODES:
        _invalid(f"{field} must be one of: {', '.join(sorted(_COVERAGE_MODES))}")
    return mode


def _campaign_config(value: object) -> CampaignConfig:
    data = _mapping(value, "campaign")
    engines_value = data.get("engines", ["standalone"])
    engines = _string_tuple(engines_value, "campaign.engines")
    if any(engine not in _CAMPAIGN_ENGINES for engine in engines):
        _invalid(
            "campaign.engines must contain only: "
            + ", ".join(sorted(_CAMPAIGN_ENGINES))
        )
    build_variants_value = data.get("build_variants", [])
    if not isinstance(build_variants_value, list):
        _invalid("campaign.build_variants must be an array")
    variants = tuple(
        _build_variant(item, f"campaign.build_variants[{index}]")
        for index, item in enumerate(build_variants_value)
    )
    oracle_value = data.get("oracles", [])
    if not isinstance(oracle_value, list):
        _invalid("campaign.oracles must be an array")
    oracles = tuple(
        _oracle_config(item, f"campaign.oracles[{index}]")
        for index, item in enumerate(oracle_value)
    )
    optimizer = _optimizer_config(data.get("optimizer", {}))
    share_corpus = data.get("share_corpus", False)
    if not isinstance(share_corpus, bool):
        _invalid("campaign.share_corpus must be a boolean")
    return CampaignConfig(
        max_workers=_bounded_int(
            data.get("max_workers", 1), "campaign.max_workers", minimum=1, maximum=64
        ),
        max_retries=_bounded_int(
            data.get("max_retries", 0), "campaign.max_retries", minimum=0, maximum=100
        ),
        share_corpus=share_corpus,
        wall_clock_seconds=_bounded_int(
            data.get("wall_clock_seconds", 600),
            "campaign.wall_clock_seconds",
            minimum=1,
            maximum=86_400,
        ),
        cpu_seconds=_bounded_int(
            data.get("cpu_seconds", 600),
            "campaign.cpu_seconds",
            minimum=1,
            maximum=86_400,
        ),
        process_limit=_bounded_int(
            data.get("process_limit", 1), "campaign.process_limit", minimum=1, maximum=1024
        ),
        engines=engines,
        build_variants=variants,
        changed_functions=_optional_string_tuple(
            data.get("changed_functions"), "campaign.changed_functions"
        ),
        oracles=oracles,
        optimizer=optimizer,
    )


def _optimizer_config(value: object) -> OptimizerConfig:
    data = _mapping(value, "campaign.optimizer")
    return OptimizerConfig(
        exploration_fraction=_factor(data.get("exploration_fraction", 0.2), "campaign.optimizer.exploration_fraction"),
        halving_factor=_bounded_int(data.get("halving_factor", 2), "campaign.optimizer.halving_factor", minimum=2, maximum=16),
        candidate_weight=_factor(data.get("candidate_weight", 0.7), "campaign.optimizer.candidate_weight"),
        duplicate_weight=_factor(data.get("duplicate_weight", 0.15), "campaign.optimizer.duplicate_weight"),
        replay_weight=_factor(data.get("replay_weight", 0.1), "campaign.optimizer.replay_weight"),
        coverage_weight=_factor(data.get("coverage_weight", 0.05), "campaign.optimizer.coverage_weight"),
    )


def _build_variant(value: object, field: str) -> BuildVariant:
    data = _mapping(value, field)
    name = _string(data.get("name"), f"{field}.name")
    if not _SLUG.fullmatch(name):
        _invalid(f"{field}.name must be a lowercase slug of at most 63 characters")
    build = _optional_command_group(data.get("build"), f"{field}.build")
    fuzz = _optional_command_group(data.get("fuzz"), f"{field}.fuzz")
    environment_data = _mapping(data.get("environment", {}), f"{field}.environment")
    environment: dict[str, str] = {}
    for key, item in environment_data.items():
        environment[_string(key, f"{field}.environment key")] = _string(
            item, f"{field}.environment.{key}"
        )
    return BuildVariant(
        name=name,
        build_steps=build,
        fuzz_steps=fuzz,
        environment=MappingProxyType(environment),
        changed_functions=_optional_string_tuple(
            data.get("changed_functions"), f"{field}.changed_functions"
        ),
    )


def _oracle_config(value: object, field: str) -> OracleConfig:
    data = _mapping(value, field)
    name = _string(data.get("name"), f"{field}.name")
    if not _SLUG.fullmatch(name):
        _invalid(f"{field}.name must be a lowercase slug of at most 63 characters")
    kind = _string(data.get("kind"), f"{field}.kind")
    if kind not in _ORACLE_KINDS:
        _invalid(f"{field}.kind must be one of: {', '.join(sorted(_ORACLE_KINDS))}")
    command = _command(data.get("command"), f"{field}.command")
    return OracleConfig(name=name, kind=kind, command=command)


def _economics_config(value: object) -> Economics:
    data = _mapping(value, "economics")
    confidence = _factor(data.get("reward_confidence", 0.0), "economics.reward_confidence")
    return Economics(
        expected_reward=_optional_nonnegative_number(
            data.get("expected_reward"), "economics.expected_reward"
        ),
        reward_confidence=confidence,
        cpu_hour_cost=_nonnegative_number(
            data.get("cpu_hour_cost", 0.0), "economics.cpu_hour_cost"
        ),
    )


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
