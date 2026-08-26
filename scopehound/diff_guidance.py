from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FunctionPriority:
    name: str
    score: float
    changed_hint: bool
    coverage_gap: bool
    explanation: str
    vulnerability_claim: bool = False


def rank_changed_functions(
    functions: tuple[str, ...],
    *,
    changed_functions: tuple[str, ...],
    covered_functions: tuple[str, ...],
) -> tuple[FunctionPriority, ...]:
    changed = set(changed_functions)
    covered = set(covered_functions)
    result: list[FunctionPriority] = []
    for name in functions:
        changed_hint = name in changed
        coverage_gap = name not in covered
        score = (0.65 if changed_hint else 0.0) + (0.35 if coverage_gap else 0.0)
        reasons = []
        if changed_hint:
            reasons.append("researcher-supplied changed-function hint")
        if coverage_gap:
            reasons.append("not present in supplied coverage set")
        result.append(
            FunctionPriority(
                name=name,
                score=round(score, 6),
                changed_hint=changed_hint,
                coverage_gap=coverage_gap,
                explanation="; ".join(reasons) or "no prioritization signal",
            )
        )
    return tuple(sorted(result, key=lambda item: (-item.score, item.name)))
