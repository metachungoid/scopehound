# Adaptive Bug-Bounty Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with review checkpoints. Steps use checkbox syntax for tracking.

**Goal:** Refactor ScopeHound into an approval-gated, adaptive local research pipeline that maximizes promotable new memory-safety candidates per CPU-hour and emits client-ready disclosure drafts for human submission.

**Architecture:** Add a read-only discovery catalog and immutable approval records before execution. Split experiment expansion, adaptive successive-halving optimization, verification, and report-profile rendering into focused modules while preserving existing commands and JSON records. Existing `campaign-matrix` and `issue` APIs become compatibility adapters over the new core.

**Tech Stack:** Python 3.11 standard library, existing shell-free runner/backends, JSON records with atomic replacement, `unittest`, deterministic local fixtures, and the existing C/cJSON integration tests. No required runtime dependencies or live-network tests.

**Spec:** `docs/superpowers/specs/2026-08-26-adaptive-bounty-pipeline-design.md`

## Global Constraints

- Discovery may read public program metadata, `security.txt`, repository security policies, and researcher-supplied catalogs.
- Discovery may fetch metadata and create pinned source snapshots, but it does not execute repository code, probe services, contact maintainers, or submit findings.
- Only targets with a current human approval record enter build, harness, fuzz, oracle, replay, or minimization stages.
- Every executable command remains a validated argument array and runs through ScopeHound's bounded runner and selected isolation backend.
- ScopeHound creates channel-shaped disclosure drafts, but a human must review, redact, and send them through the program's designated private channel.
- The primary optimization objective is promotable new candidates per CPU-hour; researcher-entered bounty estimates are secondary metadata and never a payout guarantee.
- Existing schema-version-1 manifests, command names, JSON keys, findings, reproduction, comparison, bundle, and issue records remain loadable; new fields are additive.
- No live provider test may depend on network availability; provider failures are isolated records.
- Every production change follows TDD: write a focused failing test, run it to observe the intended failure, implement the smallest complete behavior, rerun focused tests, then the full suite.

---

## Task 1: Build the read-only discovery catalog

**Files:**
- Create: `scopehound/catalog/__init__.py`
- Create: `scopehound/catalog/model.py`
- Create: `scopehound/catalog/providers.py`
- Create: `scopehound/catalog/store.py`
- Create: `tests/test_catalog.py`
- Create: `tests/fixtures/catalog/security.txt`
- Create: `tests/fixtures/catalog/SECURITY.md`

**Interfaces:**
- `CatalogCandidate`: frozen record with `candidate_id`, `project`, `repository`, `policy_urls`, `disclosure_channels`, `eligible_classes`, `policy_digest`, `source_names`, `source_confidence`, `status`, `discovered_at`, and `checked_at`.
- `DiscoveryProvider.discover(source: str) -> tuple[CatalogCandidate, ...]`.
- `discover_local_metadata(root: Path) -> tuple[CatalogCandidate, ...]` reads only fixture files and never executes repository content.
- `merge_candidates(candidates: Iterable[CatalogCandidate]) -> tuple[CatalogCandidate, ...]` deduplicates canonical repository and policy identities.
- `write_catalog(candidates: tuple[CatalogCandidate, ...], output: Path) -> None` and `load_catalog(path: Path) -> tuple[CatalogCandidate, ...]` use schema version 1, stable ordering, and atomic replacement.

- [ ] **Step 1: Write failing catalog tests**

Add tests that parse a local `security.txt` and `SECURITY.md`, produce `scope_unverified` candidates, compute a stable policy digest, merge the same repository from two sources, preserve source confidence, and reject malformed catalog records.

- [ ] **Step 2: Run the focused tests**

Run: `python3 -m unittest tests.test_catalog -v`

Expected: import failures for `scopehound.catalog` because the new catalog modules do not exist.

- [ ] **Step 3: Implement catalog models and local providers**

Implement canonical URL/repository normalization, bounded text reads, SHA-256 policy digests, deterministic timestamps supplied by the caller in tests, and source-specific records. Local providers may inspect metadata files but must not run hooks, build scripts, or target code.

- [ ] **Step 4: Verify focused and full suites**

Run `python3 -m unittest tests.test_catalog -v` and `python3 -m unittest discover -s tests -q`.

- [ ] **Step 5: Commit**

```bash
git add scopehound/catalog tests/test_catalog.py tests/fixtures/catalog
git commit -m "feat: add read-only target discovery catalog"
```

## Task 2: Add immutable approval and stale-policy gates

**Files:**
- Create: `scopehound/approval.py`
- Create: `tests/test_approval.py`
- Modify: `scopehound/policy.py`
- Modify: `scopehound/manifest.py`
- Modify: `scopehound/campaign.py`

**Interfaces:**
- `ApprovalRecord`: frozen schema-versioned record containing candidate identity, repository, revision, reviewer, approved/checked/expiry dates, policy URL/digest, eligible classes, testing mode, and notes.
- `create_approval(candidate: CatalogCandidate, *, revision: str, reviewer: str, approved_at: str, expires_at: str, eligible_classes: tuple[str, ...], testing_mode: str, notes: str = "") -> ApprovalRecord`.
- `write_approval(record: ApprovalRecord, output: Path) -> None` and `load_approval(path: Path) -> ApprovalRecord`.
- `require_current_approval(manifest: Manifest, approval: ApprovalRecord, *, required_class: str, now: date) -> None` raises `ScopeHoundError("approval_stale", ...)` for identity, revision, policy digest, expiry, mode, or eligible-class mismatches.

- [ ] **Step 1: Write failing approval tests**

Test creation, stable serialization, expired approvals, changed policy digests, moving revisions, target mismatch, missing `memory-corruption`, unsupported testing modes, and a valid approval that permits execution.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python3 -m unittest tests.test_approval -v`

Expected: import failure for `scopehound.approval`.

- [ ] **Step 3: Implement approval records and policy checks**

Use date parsing and SHA-256 comparisons. Keep the existing authorization check intact; the approval gate is additive and must be called before executable campaign stages. Never mutate an existing approval file.

- [ ] **Step 4: Integrate the gate into campaign entry points**

Add optional `--approval` paths to new execution APIs while leaving legacy manifests valid. If an approval is supplied, validate it; if adaptive commands require an approval, return `approval_required` rather than silently treating a catalog entry as authorized.

- [ ] **Step 5: Verify and commit**

Run focused tests and `python3 -m unittest discover -s tests -q`, then commit:

```bash
git add scopehound/approval.py scopehound/policy.py scopehound/manifest.py scopehound/campaign.py tests/test_approval.py
git commit -m "feat: gate execution on immutable scope approvals"
```

## Task 3: Extract experiment arms and additive optimizer configuration

**Files:**
- Create: `scopehound/experiments.py`
- Create: `tests/test_experiments.py`
- Modify: `scopehound/manifest.py`
- Modify: `scopehound/campaign.py`
- Modify: `tests/test_manifest.py`

**Interfaces:**
- `ExperimentArm`: frozen record with `arm_id`, target/revision/approval digest, harness, build variant, engine, corpus strategy, oracle, command digests, limits, changed-function hints, and status.
- `expand_experiment_arms(manifest: Manifest, approval: ApprovalRecord, *, harnesses: tuple[str, ...], corpus_strategies: tuple[str, ...], oracles: tuple[str, ...]) -> tuple[ExperimentArm, ...]`.
- `arm_digest(arm: ExperimentArm) -> str`.
- `OptimizerConfig`: additive manifest configuration with `initial_budget_seconds`, `rounds`, `growth_factor`, `exploration_fraction`, `max_total_cpu_seconds`, and non-negative reward weights where `candidate_weight` is greater than every single proxy weight.

- [ ] **Step 1: Write failing arm/config tests**

Test deterministic arm expansion, stable IDs, approval digest linkage, moving-revision rejection, unresolved-placeholder rejection, unavailable required-engine classification, unsafe paths, valid optimizer defaults, and invalid reward weights/budgets.

- [ ] **Step 2: Run focused tests and observe failure**

Run: `python3 -m unittest tests.test_experiments tests.test_manifest -v`

Expected: import failure for `scopehound.experiments` and absent optimizer fields.

- [ ] **Step 3: Implement focused arm expansion**

Build arms from existing manifest command groups and campaign variants without executing commands. Include all inputs in a canonical JSON digest. Keep legacy `CampaignConfig` defaults unchanged when `optimizer` is absent.

- [ ] **Step 4: Verify backwards compatibility**

Run the focused tests and existing campaign/manifest tests. Confirm schema-version-1 fixtures still validate exactly as before.

- [ ] **Step 5: Commit**

```bash
git add scopehound/experiments.py scopehound/manifest.py scopehound/campaign.py tests/test_experiments.py tests/test_manifest.py
git commit -m "feat: model deterministic approved experiment arms"
```

## Task 4: Implement adaptive reward and successive-halving optimizer

**Files:**
- Create: `scopehound/optimizer.py`
- Create: `tests/test_optimizer.py`
- Modify: `scopehound/economics.py`
- Modify: `scopehound/matrix.py`

**Interfaces:**
- `ArmMetrics`: observed CPU seconds, coverage delta, new corpus features, candidate count, promotable count, replay success, duplicates, flakes, failures, and resource outcomes.
- `RewardBreakdown`: each weighted positive/negative component, total reward, rank, and stop reason.
- `OptimizerState`: schema-versioned rounds, arm digests, budgets, metrics, reward breakdowns, exploration reservation, and manifest/approval digests.
- `select_next_round(arms: tuple[ExperimentArm, ...], metrics: Mapping[str, ArmMetrics], config: OptimizerConfig, *, round_number: int) -> tuple[str, ...]` selects strongest arms and deterministic exploration arms.
- `record_round(state: OptimizerState, results: Mapping[str, ArmMetrics], config: OptimizerConfig) -> OptimizerState` appends an atomic round without deleting evidence.
- `load_optimizer_state(path: Path) -> OptimizerState` refuses mismatched state digests.

- [ ] **Step 1: Write failing optimizer simulation tests**

Use deterministic arm fixtures to prove candidate-heavy arms outrank coverage-only arms, duplicate-heavy arms are penalized, failed/stalled arms stop, the exploration fraction reserves arms, budgets cannot exceed target/global caps, ties use stable arm IDs, and identical inputs produce identical state.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python3 -m unittest tests.test_optimizer -v`

Expected: import failure for `scopehound.optimizer`.

- [ ] **Step 3: Implement reward breakdown and selection**

Normalize metrics to bounded values, require candidate weight dominance, calculate every component independently, perform deterministic successive halving, and retain an exploration set each round. Treat manual reward estimates only as tie-break metadata.

- [ ] **Step 4: Integrate with matrix execution**

Adapt `campaign-matrix` state into optimizer rounds while preserving existing job records. Each round invokes existing runner/engine adapters, records coverage/findings/replay/duplicate metrics, and writes the optimizer decision before launching the next round.

- [ ] **Step 5: Verify and commit**

Run focused, matrix, economics, integration, and full tests, then commit:

```bash
git add scopehound/optimizer.py scopehound/economics.py scopehound/matrix.py tests/test_optimizer.py
git commit -m "feat: allocate campaign CPU with adaptive rewards"
```

## Task 5: Extract verification orchestration and public-duplicate evidence

**Files:**
- Create: `scopehound/verification.py`
- Create: `tests/test_verification.py`
- Modify: `scopehound/issue.py`
- Modify: `scopehound/known_issues.py`
- Modify: `scopehound/reproduction.py`
- Modify: `scopehound/triage.py`

**Interfaces:**
- `DuplicateCheck`: source, checked-at, query/identity, result, and evidence digest.
- `VerificationInput`: finding, artifact, reproduction, minimization, confirmation, known comparison, approval, latest-revision record, and duplicate checks.
- `VerificationDecision`: `status`, ordered `reasons`, gate map, root-cause identity, replay counts, duplicate evidence, and report eligibility.
- `verify_candidate(input: VerificationInput) -> VerificationDecision`.
- `promote_issue` delegates to `verify_candidate` and keeps its current call signature compatible.

- [ ] **Step 1: Write failing verification tests**

Cover valid promotion, missing approval, stale approval, one replay, mismatched command/revision, minimization root-cause drift, harness defect, resource-only output, known alias, prior campaign duplicate, missing public-check record, and all-gates-passing promotion.

- [ ] **Step 2: Run focused tests and observe failure**

Run: `python3 -m unittest tests.test_verification tests.test_issue -v`

Expected: import failure for `scopehound.verification`.

- [ ] **Step 3: Implement pure verification orchestration**

Compose existing typed records without rerunning commands. Return every failure reason in stable order. Keep public duplicate checks as evidence supplied by a researcher or optional read-only provider; do not claim that absence from local data proves global novelty.

- [ ] **Step 4: Integrate issue promotion**

Make the issue package serialize the gate map, approval digest, duplicate checks, and unresolved review fields. Preserve the existing `new_candidate`/`novelty: unverified` language and immutable output behavior.

- [ ] **Step 5: Verify and commit**

Run focused, issue, reproduction, triage, integration, and full tests, then commit:

```bash
git add scopehound/verification.py scopehound/issue.py scopehound/known_issues.py scopehound/reproduction.py scopehound/triage.py tests/test_verification.py
git commit -m "feat: centralize candidate verification gates"
```

## Task 6: Add report profiles and split command wiring

**Files:**
- Create: `scopehound/reports.py`
- Create: `scopehound/commands/catalog.py`
- Create: `scopehound/commands/approval.py`
- Create: `scopehound/commands/experiments.py`
- Create: `scopehound/commands/optimizer.py`
- Create: `scopehound/commands/reports.py`
- Create: `tests/test_reports.py`
- Create: `tests/test_command_modules.py`
- Modify: `scopehound/cli.py`

**Interfaces:**
- `ReportProfile`: `channel_neutral`, `hackerone`, `bugcrowd`, and `private_email`.
- `render_client_draft(package: IssuePackage, profile: str) -> str`.
- `write_report_package(package: IssuePackage, *, profile: str, output: Path) -> None`.
- Command modules expose `configure_parser(subparsers)` and `dispatch(args) -> int`; parser/bootstrap remains backward compatible.

- [ ] **Step 1: Write failing profile and command tests**

Assert every profile contains scope, affected revision, impact hypothesis, exact reproduction, artifact hash, root-cause evidence, duplicate status, remediation area, and human-review fields. Assert prohibited words such as `zero-day`, `confirmed vulnerability`, and `guaranteed bounty` are absent. Assert existing command help and JSON keys remain present after wiring extraction.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python3 -m unittest tests.test_reports tests.test_command_modules -v`

Expected: import failures for `scopehound.reports` and command modules.

- [ ] **Step 3: Implement canonical report/profile model**

Render profiles from the same evidence model; only field order and concise wording vary. Write `client-draft.md` atomically beside the existing technical report. Never add credentials, network clients, or submit actions.

- [ ] **Step 4: Extract CLI wiring incrementally**

Move parser/dispatch logic by command group, leave compatibility shims in `cli.py`, and run CLI tests after each extraction. Add new commands `discover-targets`, `approve-target`, `plan-experiments`, `optimize-campaign`, and `draft-report` with dry-run/default-safe behavior.

- [ ] **Step 5: Verify and commit**

Run focused, all CLI, issue, reporting, and full tests, then commit:

```bash
git add scopehound/reports.py scopehound/commands scopehound/cli.py tests/test_reports.py tests/test_command_modules.py
git commit -m "refactor: split command wiring and client report profiles"
```

## Task 7: End-to-end discovery-to-report workflow and documentation

**Files:**
- Create: `tests/integration/test_adaptive_pipeline.py`
- Create: `examples/approved-target.json`
- Create: `docs/adaptive-pipeline.md`
- Modify: `README.md`
- Modify: `docs/campaign-matrix.md`
- Modify: `tests/fixtures/controlled_bug.c`

- [ ] **Step 1: Write failing end-to-end test**

Use local catalog fixtures, create an approval, expand a controlled C target into multiple arms, run two optimizer rounds, verify low-yield arm stopping and exploration, pass the controlled sanitizer candidate through verification, and create channel-neutral and private-email drafts without network access.

- [ ] **Step 2: Run the integration test and observe failure**

Run: `python3 -m unittest tests.integration.test_adaptive_pipeline -v`

Expected: import or command failures for the new catalog/approval/optimizer/report flow.

- [ ] **Step 3: Add executable example and documentation**

Document discovery versus approval, the adaptive reward components, the exact promotion gates, client draft profiles, stale-policy behavior, resumability, and the human submission boundary. Keep the example local/controlled and label it as a positive test, never a third-party vulnerability.

- [ ] **Step 4: Run complete verification**

Run:

```bash
python3 -m unittest discover -s tests -q
python3 -m unittest tests.integration.test_adaptive_pipeline -v
python3 -m scopehound --help
python3 -m scopehound engines --all --json
python3 -m scopehound validate --manifest examples/approved-target.json --json
python3 -m compileall -q scopehound tests
git diff --check
git status --short
```

Expected: all tests pass, controlled compiler-dependent tests either pass or report their explicit skip, and the working tree is clean after commit.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_adaptive_pipeline.py examples/approved-target.json docs/adaptive-pipeline.md README.md docs/campaign-matrix.md tests/fixtures/controlled_bug.c
git commit -m "docs: add adaptive discovery-to-report workflow"
```

## Final verification

- Run the complete test suite and retain exact counts.
- Inspect every new JSON schema and report profile for stable ordering and prohibited claims.
- Confirm no network client, submission integration, shell-string execution, or automatic maintainer contact was added.
- Confirm no target code runs without an approval record in the new adaptive APIs.
- Use `superpowers:finishing-a-development-branch` after all tasks and verification to summarize integration options. Do not push or disclose anything automatically.
