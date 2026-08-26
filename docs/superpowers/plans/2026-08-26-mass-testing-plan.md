# ScopeHound High-Throughput Campaign Optimizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to execute this plan task-by-task with verification checkpoints.

**Goal:** Turn ScopeHound into a high-throughput, scope-aware campaign optimizer that maximizes expected candidate yield per CPU-hour for authorized local C/C++ research while preserving evidence quality and human-controlled disclosure.

**Architecture:** Extend the existing manifest with optional matrix, budget, oracle, and researcher-entered economics metadata. Add a bounded, resumable matrix scheduler that produces stable job records and expected-yield metrics. Strengthen finding identity and replay accounting, add explicit resource/differential candidate classification, and add an immutable issue-promotion package that is gated by artifact, two matching replays, known-issue aliases, and scope controls. Keep existing single-target commands backward compatible.

**Tech Stack:** Python 3.11 standard library, `unittest`, existing ScopeHound command runner and workspace model, local C compiler/sanitizer for the controlled proof.

**Spec:** `docs/superpowers/specs/2026-08-26-mass-testing-design.md`

## Global Constraints

- Work on the user-authorized `master` checkout; do not create remote changes or contact repositories/maintainers.
- Use argument arrays and existing runner policy; never add shell-string execution, remote probing, automatic disclosure, bounty scraping, or automatic submission.
- “Profit” is represented only as a transparent expected-yield-per-CPU-hour prioritization metric using researcher-entered inputs; never claim a payout, severity, global novelty, or a zero-day.
- Preserve existing JSON and CLI behavior. New fields are optional, and old reproduction records load with one attempt so they cannot pass the strengthened promotion gate accidentally.
- Every new behavior is developed test-first: add a focused failing test, run it to observe the expected failure, implement the smallest complete behavior, then rerun focused and full tests.
- Write outputs atomically, use stable JSON key ordering, refuse immutable package overwrites, and keep all paths inside the declared workspace or package.

## Task 1: Extend manifest models for matrix, budgets, oracles, and economics

**Files:** `scopehound/manifest.py`, `tests/test_manifest.py`, `tests/fixtures.py`, `docs/superpowers/specs/2026-08-26-mass-testing-design.md`

1. Add failing tests for optional `campaign` configuration: `max_workers`, `max_retries`, `share_corpus`, `wall_clock_seconds`, `cpu_seconds`, engine list, build variants, changed-function hints, differential oracle groups, and researcher-entered `economics` fields. Assert invalid worker/budget values, unsafe paths, unsupported engines, and malformed oracle commands are rejected.
2. Run the focused manifest tests and confirm they fail because the new model and validation do not exist.
3. Implement frozen dataclasses (`BudgetConfig`, `BuildVariant`, `OracleConfig`, `CampaignConfig`, `Economics`) with conservative defaults, integrate them as optional `Manifest` fields, include them in `manifest_digest`, and validate all command placeholders and relative paths.
4. Keep `Opportunity` and every existing manifest fixture valid without new keys. Add JSON round-trip coverage for defaults and explicit values.
5. Run `python3 -m unittest tests.test_manifest -v` and then the full suite.
6. Commit as `feat: add authorized campaign matrix configuration`.

## Task 2: Add expected-yield and campaign economics calculations

**Files:** `scopehound/scoring.py`, `scopehound/economics.py`, `tests/test_scoring.py`, `tests/test_economics.py`

1. Add failing tests for deterministic calculations: opportunity score, candidate rate, replay success, duplicate penalty, CPU cost, expected candidates per CPU-hour, and an expected-value-per-CPU-hour estimate that becomes zero for missing/invalid researcher-entered reward data. Assert no division-by-zero and no negative values.
2. Run the focused tests and observe the missing module/functions.
3. Implement pure functions and dataclasses with explicit input/output names, bounded numeric normalization, and a human-review disclaimer in serialized output. Include observed campaign metrics without treating them as payout predictions.
4. Add a markdown/JSON-friendly serializer and tests for stable ordering and reproducibility.
5. Run focused and full tests.
6. Commit as `feat: add expected-yield campaign metrics`.

## Task 3: Strengthen finding identity, aliases, and resource classification

**Files:** `scopehound/findings.py`, `scopehound/known_issues.py`, `scopehound/triage.py`, `scopehound/resource.py`, `tests/test_findings.py`, `tests/test_known_issues.py`, `tests/test_triage.py`, `tests/test_resource.py`

1. Add failing tests for normalized root-cause signatures, known-issue aliases, duplicate grouping by either fingerprint or root-cause signature, and classification of timeout/OOM/hang output as `resource_candidate` rather than sanitizer memory corruption.
2. Run focused tests and confirm failures.
3. Add an optional `root_cause` field to `Finding`, compute it from stable sanitizer/kind/function/source-basename/top-frame data, and load old records with a deterministic fallback. Extend `KnownIssue` with aliases and make comparisons report matched identity (`fingerprint`, `root_cause`, or alias) and label.
4. Add a small resource parser with bounded marker matching and a typed record; integrate only where logs are already being parsed, without changing sanitizer findings.
5. Update triage clustering to use both identities and expose the reason for each duplicate group.
6. Run focused and full tests.
7. Commit as `feat: improve root-cause deduplication and resource triage`.

## Task 4: Add replay-attempt accounting and cross-build confirmation

**Files:** `scopehound/reproduction.py`, `scopehound/reporting.py`, `scopehound/confirmation.py`, `tests/test_reproduction.py`, `tests/test_confirmation.py`, `tests/test_reporting.py`

1. Add failing tests for backward-compatible one-attempt loads, two matching attempts on the same revision/command, different-fingerprint attempts, and cross-build confirmation records that preserve toolchain/build labels.
2. Run focused tests and confirm failures.
3. Add `attempts` and `matching_attempts` to `ReproductionResult` with old-record defaults; make `reproduce_finding` accept an optional attempt number and merge records through a pure `record_replay_attempt` helper.
4. Implement `CrossBuildConfirmation` and a comparator that requires matching root-cause identity across two explicitly named local variants; do not infer a bug from output differences alone.
5. Render replay counts and cross-build status in report output while keeping existing callers valid.
6. Run focused and full tests.
7. Commit as `feat: require repeatable and cross-build evidence`.

## Task 5: Add engine availability adapters, corpus metadata, and structure-aware inputs

**Files:** `scopehound/engines.py`, `scopehound/corpus.py`, `scopehound/cli.py`, `tests/test_engines.py`, `tests/test_corpus.py`, `tests/test_cli.py`

1. Add failing tests for explicit availability records for `standalone`, `libfuzzer`, `afl++`, `honggfuzz`, and `centipede`; assert unavailable binaries are skipped, never substituted. Add tests for seed/dictionary hashes, shared-corpus records, and deterministic structure-aware mutation metadata.
2. Run focused tests and confirm failures.
3. Extend `list_engines` with optional executable detection and adapter metadata; retain existing `EngineInfo` fields. Add corpus inventory/merge helpers with path containment, SHA-256 records, and bounded input sizes. Add structure-aware seed records that preserve parent/input/oracle provenance without inventing parser semantics.
4. Add CLI JSON output for engine adapters and corpus inventory; leave actual optional engines as availability-aware command adapters rather than installing or invoking them implicitly.
5. Run focused and full tests.
6. Commit as `feat: add bounded engine and corpus adapters`.

## Task 6: Implement differential/metamorphic and diff-guided job metadata

**Files:** `scopehound/oracles.py`, `scopehound/diff_guidance.py`, `scopehound/manifest.py`, `scopehound/cli.py`, `tests/test_oracles.py`, `tests/test_diff_guidance.py`

1. Add failing tests for deterministic differential comparisons, round-trip/metamorphic comparisons, timeout/error classification, changed-function prioritization, and the rule that oracle disagreement alone is not a memory-safety finding.
2. Run focused tests and confirm failures.
3. Implement local command-array oracle execution through the existing `CommandPlan`/runner, with bounded input and output capture, stable input hashes, and statuses `match`, `disagreement`, `timeout`, `error`, and `planned`.
4. Implement a conservative changed-function ranker driven only by researcher-supplied changed-function hints and coverage gaps; return explainable factors and never label a vulnerability.
5. Add CLI JSON serializers for oracle and ranking records.
6. Run focused and full tests.
7. Commit as `feat: add differential and change-guided oracles`.

## Task 7: Implement the bounded resumable matrix scheduler

**Files:** `scopehound/matrix.py`, `scopehound/campaign.py`, `scopehound/workspace.py`, `scopehound/cli.py`, `tests/test_matrix.py`, `tests/test_campaign.py`, `tests/test_workspace.py`

1. Add failing tests for matrix expansion into target × variant × engine jobs, stable job keys, worker caps, queued/running/completed/failed/timed-out/skipped states, unavailable-engine skips, digest-based resume, explicit retries, isolated target paths, and expected-yield aggregation.
2. Run focused tests and confirm failures.
3. Implement `MatrixJob`, `MatrixState`, expansion, and a bounded `ThreadPoolExecutor` scheduler that delegates actual command execution to existing campaign/runner functions. Use per-job directories under `Workspace`, atomic state files, digest matching, and no deletion of previous evidence.
4. Record CPU seconds, wall time, engine/variant/toolchain metadata, resource status, candidate counts, replay counts, duplicate counts, and economics metrics. Support dry-run planning and explicit `--execute` only.
5. Add `campaign-matrix` CLI command with `--manifest`, `--workspace`, `--duration`, `--execute`, `--retry`, and `--json`; reject matrix execution without authorized manifests.
6. Run focused and full tests.
7. Commit as `feat: add resumable bounded campaign matrix`.

## Task 8: Implement gated immutable issue promotion

**Files:** `scopehound/issue.py`, `scopehound/reporting.py`, `scopehound/cli.py`, `scopehound/bundling.py`, `tests/test_issue.py`, `tests/test_reporting.py`, `tests/test_bundling.py`, `tests/test_cli.py`

1. Add failing positive and negative tests for the promotion gate: missing artifact, one replay, mismatch, known fingerprint, known alias/root-cause, resource candidate, cross-build mismatch, and a valid two-replay `new_candidate`. Assert immutable output refusal and path containment.
2. Run focused tests and confirm failures.
3. Implement typed gate decisions and `promote_issue` that validates all supplied records, hashes artifacts/minimized artifacts, checks revision/command consistency, requires two matching attempts, and writes stable `issue.json` plus a human-review `report.md` and copied evidence.
4. Add `issue` CLI arguments for required inputs and optional triage/minimization/coverage/campaign/confirmation/economics records. Return a nonzero typed error for blocked candidates without deleting evidence.
5. Ensure the report says “potential finding,” includes exact commands, root-cause/replay/cross-build details, expected-yield disclaimer, and explicit disclosure checklist.
6. Run focused and full tests.
7. Commit as `feat: add gated issue evidence packages`.

## Task 9: Controlled C proof, documentation, and release verification

**Files:** `tests/integration/test_campaign_matrix.py`, `tests/fixtures/controlled_bug.c`, `examples/campaign-matrix.json`, `README.md`, `docs/campaign-matrix.md`, `docs/evidence/controlled-c-positive.md`

1. Add a failing integration test that compiles a tiny local C fixture with ASan, runs the matrix in dry-run and execute modes, performs two matching local replays, and promotes a `new_candidate` package. Add negative assertions for a known fingerprint and one replay.
2. Run the integration test to confirm it fails before the implementation is complete.
3. Add the intentionally buggy fixture with an explicit controlled-positive label, an example matrix manifest using a local absolute repository path, and documentation for scope/authorization, engines, corpora, oracles, economics, resource candidates, and the human disclosure boundary.
4. Run the integration test, the complete suite, `scopehound --help`, `scopehound engines --json`, and `git diff --check`.
5. Self-review all diffs for unsafe command execution, remote side effects, accidental novelty claims, and missing atomic writes. Record exact test counts and controlled fixture results.
6. Commit as `docs: document high-throughput authorized campaigns`.

## Final verification

- Run `python3 -m unittest discover -s tests -q` and retain the output.
- Run the controlled C integration test with the local compiler if available; if the compiler is absent, report the explicit skip and verify all parser/scheduler tests.
- Run `python3 -m scopehound --help` and `python3 -m scopehound engines --json`.
- Run `git status --short` and `git diff --check`; do not claim completion until the suite and checks are green.
- Use `superpowers:finishing-a-development-branch` after verification to summarize integration options. No remote push or disclosure is performed by this task.
