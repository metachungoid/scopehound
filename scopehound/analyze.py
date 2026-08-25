from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from scopehound.errors import ScopeHoundError
from scopehound.harness import HarnessCandidate


@dataclass(frozen=True)
class AstFunction:
    name: str
    qualified_name: str
    file: str
    line: int | None
    parameters: tuple[str, ...]
    namespace: str


@dataclass(frozen=True)
class ReachabilityMetadata:
    source: str
    reachability: Mapping[str, float]
    covered: Mapping[str, bool]
    coverage: Mapping[str, float]


@dataclass(frozen=True)
class RankedCandidate:
    path: str
    function: str
    score: float
    authorization: float
    buildability: float
    reachability: float
    coverage_gap: float
    input_suitability: float
    duplicate_risk: float


def parse_ast_json(path: Path) -> tuple[AstFunction, ...]:
    payload = _read_json(path, "Clang AST JSON")
    functions: list[AstFunction] = []

    def walk(node: object, namespaces: tuple[str, ...]) -> None:
        if not isinstance(node, dict):
            return
        kind = node.get("kind")
        current = namespaces
        if kind == "NamespaceDecl" and isinstance(node.get("name"), str):
            current = (*namespaces, node["name"])
        if kind == "FunctionDecl" and isinstance(node.get("name"), str):
            name = node["name"]
            qualified = node.get("qualifiedName") if isinstance(node.get("qualifiedName"), str) else "::".join((*current, name))
            loc = node.get("loc") if isinstance(node.get("loc"), dict) else {}
            file_name = loc.get("file") if isinstance(loc.get("file"), str) else "unknown"
            line = loc.get("line") if isinstance(loc.get("line"), int) else None
            parameters: list[str] = []
            inner = node.get("inner")
            if isinstance(inner, list):
                for child in inner:
                    if isinstance(child, dict) and child.get("kind") == "ParmVarDecl":
                        type_data = child.get("type")
                        if isinstance(type_data, dict) and isinstance(type_data.get("qualType"), str):
                            parameters.append(type_data["qualType"])
            functions.append(AstFunction(name, qualified, file_name, line, tuple(parameters), "::".join(current)))
        children = node.get("inner")
        if isinstance(children, list):
            for child in children:
                walk(child, current)

    walk(payload, ())
    return tuple(sorted(functions, key=lambda item: (item.qualified_name, item.file, item.line or 0)))


def import_fuzz_introspector(path: Path) -> ReachabilityMetadata:
    resolved = path.expanduser().resolve()
    if resolved.is_dir():
        options = (resolved / "fuzz_introspector.json", resolved / "report.json")
        resolved = next((candidate for candidate in options if candidate.is_file()), resolved / "fuzz_introspector.json")
    payload = _read_json(resolved, "Fuzz Introspector report")
    if not isinstance(payload, dict):
        raise ScopeHoundError("input_invalid", "Fuzz Introspector report must be an object")
    entries = payload.get("functions", payload.get("targets", []))
    if not isinstance(entries, list):
        raise ScopeHoundError("input_invalid", "Fuzz Introspector functions must be an array")
    reachability: dict[str, float] = {}
    covered: dict[str, bool] = {}
    coverage: dict[str, float] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("functionName", entry.get("name", entry.get("function")))
        if not isinstance(name, str) or not name:
            continue
        reachability[name] = _bounded_number(entry.get("reachability", entry.get("functionReachability", 0.0)))
        coverage[name] = _bounded_number(entry.get("coverage", entry.get("coveragePercentage", 0.0)))
        covered[name] = bool(entry.get("covered", coverage[name] > 0.0))
    return ReachabilityMetadata(str(resolved), MappingProxyType(dict(sorted(reachability.items()))), MappingProxyType(dict(sorted(covered.items()))), MappingProxyType(dict(sorted(coverage.items()))))


def rank_candidates(
    candidates: Sequence[HarnessCandidate],
    *,
    authorized: bool,
    reachability: Mapping[str, float] | None = None,
    covered: Mapping[str, bool] | None = None,
    buildability: Mapping[str, float] | None = None,
    duplicate_risk: Mapping[str, float] | None = None,
) -> tuple[RankedCandidate, ...]:
    reachability = reachability or {}
    covered = covered or {}
    buildability = buildability or {}
    duplicate_risk = duplicate_risk or {}
    ranked: list[RankedCandidate] = []
    for candidate in candidates:
        key = candidate.function
        authorization_score = 1.0 if authorized else 0.0
        build_score = buildability.get(key, _buildability_from_status(candidate.status))
        reach_score = _bounded_number(reachability.get(key, 0.5))
        gap_score = 0.0 if covered.get(key, False) else 1.0
        input_score = {"high": 1.0, "medium": 0.65, "low": 0.3}.get(candidate.confidence, 0.3)
        duplicate_score = _bounded_number(duplicate_risk.get(key, 0.0))
        score = (
            0.20 * authorization_score + 0.20 * build_score + 0.20 * reach_score
            + 0.20 * gap_score + 0.15 * input_score + 0.05 * (1.0 - duplicate_score)
        )
        ranked.append(RankedCandidate(str(candidate.path), key, round(score, 6), authorization_score, build_score, reach_score, gap_score, input_score, duplicate_score))
    ranked.sort(key=lambda item: (-item.score, item.function, item.path))
    return tuple(ranked)


def _buildability_from_status(status: str) -> float:
    return {"built": 1.0, "syntax_valid": 0.75, "needs_build_validation": 0.4, "build_failed": 0.0, "syntax_invalid": 0.0}.get(status, 0.25)


def _bounded_number(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, number))


def _read_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScopeHoundError("input_invalid", f"cannot read {label} {path}: {error}") from error
