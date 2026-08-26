from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from scopehound.approval import ApprovalRecord
from scopehound.campaign import manifest_digest
from scopehound.errors import ScopeHoundError
from scopehound.manifest import BuildVariant, Manifest
from scopehound.policy import require_approved


@dataclass(frozen=True)
class ExperimentArm:
    arm_id: str
    target: str
    harness: str
    build_variant: str
    engine: str
    corpus_strategy: str
    oracle: str
    manifest_digest: str
    approval_revision: str
    objective: str = "promotable_candidates_per_cpu_hour"

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def expand_experiment_arms(manifest: Manifest, approval: ApprovalRecord | None) -> tuple[ExperimentArm, ...]:
    if approval is None:
        raise ScopeHoundError("approval_required", "adaptive experiment expansion requires an approval record")
    require_approved(manifest, approval)
    variants = manifest.campaign.build_variants or (BuildVariant("default"),)
    engines = manifest.campaign.engines or ("standalone",)
    corpora = ("seeded", "generated") if manifest.corpus.seed_dir else ("generated",)
    oracles = tuple(oracle.name for oracle in manifest.campaign.oracles) or ("none",)
    arms: list[ExperimentArm] = []
    for variant in variants:
        for engine in engines:
            for corpus in corpora:
                for oracle in oracles:
                    identity = "|".join((manifest.target.name, variant.name, engine, corpus, oracle, approval.revision))
                    arm_id = hashlib.sha256(identity.encode()).hexdigest()[:16]
                    arms.append(ExperimentArm(
                        arm_id=arm_id,
                        target=manifest.target.name,
                        harness="default",
                        build_variant=variant.name,
                        engine=engine,
                        corpus_strategy=corpus,
                        oracle=oracle,
                        manifest_digest=manifest_digest(manifest),
                        approval_revision=approval.revision,
                    ))
    return tuple(sorted(arms, key=lambda arm: arm.arm_id))
