# ScopeHound Adaptive Bug-Bounty Pipeline

## Status

Approved design. Implementation begins only after review of this written
specification.

## Mission

Make ScopeHound a local-first, highly automated research pipeline that finds
previously unrecognized, reproducible memory-safety candidates in explicitly
approved C/C++ libraries and produces client-ready reports for human review and
submission.

The primary optimization objective is **promotable new candidates per
CPU-hour**. Researcher-entered bounty estimates are a secondary ordering signal
and never a promise of payout. A ScopeHound `new_candidate` means that the
finding passed the configured local and public duplicate checks; global novelty
remains `unverified` until a researcher completes the report checklist.

## Safety and human boundaries

- Discovery may read public program metadata, `security.txt`, repository
  security policies, and researcher-supplied catalogs.
- Discovery may fetch metadata and create pinned source snapshots, but it does
  not execute repository code, probe services, contact maintainers, or submit
  findings.
- Only targets with a current human approval record enter build, harness, fuzz,
  oracle, replay, or minimization stages.
- Every executable command remains a validated argument array and runs through
  ScopeHound's bounded runner and selected isolation backend.
- ScopeHound creates channel-shaped disclosure drafts, but a human must review,
  redact, and send them through the program's designated private channel.
- Changed, expired, missing, or contradictory policy evidence blocks new work
  for that target without destroying existing evidence.

## Pipeline

```text
discover -> review/approve -> plan experiments -> explore -> allocate ->
triage -> reproduce/minimize -> cross-check -> package reports -> human sends
```

### 1. Discovery catalog

Discovery providers implement one normalized interface and emit candidates
from:

- public bug-bounty program listings;
- repository `SECURITY.md` files and security-policy metadata;
- domain `/.well-known/security.txt` records; and
- local researcher-maintained JSON catalogs.

Each candidate records source URLs, repository URL, project name, eligible
classes when stated, disclosure channel, observed policy text digest, discovery
timestamp, last-checked timestamp, and source confidence. Candidates are
deduplicated by canonical repository identity and policy identity. Discovery
results start in `scope_unverified` and cannot be executed.

Network-backed providers are optional adapters. The core catalog, normalization,
ranking, approval, and tests do not require network access. Provider failures
are recorded independently and do not erase successful results from other
providers.

### 2. Approval records

A researcher approves a candidate by creating an immutable record containing:

- target and canonical repository identity;
- immutable source revision;
- reviewer identity or local reviewer label;
- approval timestamp;
- policy URL and policy content digest;
- policy checked date and expiry/recheck date;
- eligible vulnerability classes;
- permitted testing mode (`local_source`, `sandboxed_build`, or another
  explicitly configured local mode); and
- notes describing ambiguity or restrictions.

Execution verifies that the candidate, revision, eligible class, and policy
digest still match the approval. A recheck records a new approval rather than
mutating history.

### 3. Target ranking

Pre-execution ranking prioritizes targets using explainable factors:

- explicit bounty eligibility and eligible memory-safety classes;
- attacker-controlled input reachability;
- code criticality and deployment breadth supplied by the researcher;
- recent parser or memory-management changes;
- existing harness and fuzzing coverage gaps;
- deterministic buildability;
- duplicate saturation from local/public evidence; and
- estimated setup and CPU cost.

Ranking never establishes authorization, novelty, impact, severity, or payout.
It selects which approved target receives the next exploration budget.

### 4. Experiment model

The planner expands every approved target into experiment arms. An arm is the
stable tuple:

```text
target x revision x harness x build variant x engine x corpus strategy x oracle
```

Arm records contain stable IDs and digests, exact commands, environment,
sanitizers, toolchain, seeds/dictionaries/custom-mutator metadata, input limits,
process/memory/CPU/wall limits, parent corpus, changed-function hints, and the
approval digest.

The planner rejects unresolved placeholders, moving revisions, missing approval,
unavailable required tools, unsafe paths, and command groups that exceed policy
limits. Unavailable optional engines produce visible skips rather than silent
substitution.

### 5. Adaptive optimizer

The optimizer uses bounded successive halving with periodic exploration:

1. Give every valid arm a small initial budget.
2. Measure coverage growth, new corpus features, unique root-cause candidates,
   replay success, build reliability, duplicate production, stalls, and CPU
   cost.
3. Stop arms with sustained zero growth, repeated build failure, excessive
   flakiness, or duplicate saturation.
4. Double the next-round budget for the strongest arms within target and global
   campaign caps.
5. Reserve a configurable exploration fraction for new changed-code, corpus,
   harness, and oracle arms.

The primary reward is:

```text
reward =
    unique_promotable_candidates * candidate_weight
  + normalized_coverage_growth * coverage_weight
  + new_corpus_features * feature_weight
  + replay_success * replay_weight
  - duplicate_rate * duplicate_penalty
  - flake_rate * flake_penalty
  - failure_rate * failure_penalty
  - normalized_cpu_cost * cost_penalty
```

Weights are explicit campaign configuration, validated as non-negative finite
numbers, and recorded in state. Candidate weight must remain greater than every
single proxy weight so coverage alone cannot dominate actual findings.

Tie-breaking may use the existing opportunity score and manually supplied
expected reward. Expected dollars never override a materially stronger measured
candidate yield.

Every allocation decision records arm metrics, reward components, rank,
allocated budget, stopped reason, configuration digest, and timestamp. Resume
requires matching approval, manifest, arm, and optimizer digests.

### 6. Triage and verification

Sanitizer findings and resource candidates remain separate. ScopeHound clusters
memory findings by artifact hash, sanitizer fingerprint, normalized root-cause
signature, and known aliases.

A finding is promotable only when all applicable gates pass:

1. target approval and policy evidence remain current;
2. the artifact is a regular contained file with complete provenance;
3. a supported memory-safety sanitizer signal is present;
4. the minimized artifact preserves the same normalized root cause;
5. at least two matching replay attempts use the same revision and command;
6. meaningful cross-build or cross-sanitizer confirmation agrees when available;
7. the latest eligible revision was tested;
8. the result is not classified as a harness defect, resource-only failure,
   known issue, regression, alias match, or earlier campaign duplicate; and
9. local/public duplicate checks are recorded with timestamps and sources.

Failed gates retain evidence and machine-readable reasons. They do not create a
client-ready `new_candidate` report.

### 7. Report factory

For each promoted candidate, ScopeHound creates one immutable report package:

```text
issue.json
report.md
client-draft.md
scope-evidence.json
commands.json
findings.json
reproduction.json
comparison.json
confirmation.json             # when supplied
minimization.json              # when supplied
coverage.json                  # when supplied
campaign.json
artifact
minimized-artifact             # when supplied
```

`report.md` contains technical evidence and the complete human checklist.
`client-draft.md` is concise and shaped for a selected output profile:
channel-neutral, HackerOne form, Bugcrowd form, or private email. Profiles only
change field order and wording; they never transmit data or store credentials.

Every draft includes target and affected revision, scope evidence, concise
impact hypothesis, exact reproduction steps, minimized artifact hash,
sanitizer/root-cause evidence, affected-version checks, duplicate-review status,
suggested remediation area, and explicit unresolved human-review fields.

The package uses “potential memory-safety finding,” `new_candidate`, and
`novelty: unverified`. It never calls a result a confirmed vulnerability,
zero-day, or guaranteed bounty.

## Component boundaries

### `scopehound/catalog/`

- provider protocol and provider result types;
- candidate normalization and repository identity;
- catalog merge/deduplication;
- policy evidence records; and
- target ranking inputs.

### `scopehound/approval.py`

- immutable approval schema;
- approval creation/loading;
- policy digest and expiry checks; and
- execution gate returning typed reasons.

### `scopehound/experiments.py`

- arm definitions and stable digests;
- target-to-arm expansion;
- tool/command/path validation; and
- arm provenance serialization.

### `scopehound/optimizer.py`

- round metrics and reward calculation;
- successive-halving selection;
- exploration reservation;
- budget enforcement; and
- atomic resumable state.

### `scopehound/verification.py`

- orchestration over existing findings, triage, minimization, reproduction,
  confirmation, resource, and known-issue modules;
- promotion gate decisions; and
- duplicate-check evidence aggregation.

### `scopehound/reports.py`

- canonical report model;
- client draft profiles;
- immutable package inventory; and
- redaction and unresolved-review checklists.

### CLI

The current large `scopehound/cli.py` becomes parser/bootstrap code. Commands
move into focused command modules while preserving public command names and JSON
output compatibility. New commands are:

- `discover-targets`: collect and rank read-only candidates;
- `approve-target`: create a local immutable approval;
- `plan-experiments`: expand approved targets into arms;
- `optimize-campaign`: run or resume adaptive rounds; and
- `draft-report`: render a selected client profile from a promoted package.

Existing `campaign-matrix` and `issue` remain compatible entry points and may
delegate to the new APIs.

## Data flow and state

Catalog, approval, experiment, optimizer, verification, and report records are
versioned JSON with stable ordering and atomic replacement. Artifact content is
addressed by SHA-256. Records link upstream inputs by digest, so changed scope,
configuration, commands, revision, or corpus produces a new state lineage rather
than silently altering historical evidence.

No stage deletes earlier evidence. Explicit retries and policy rechecks append
attempts or create new records. Workspace containment applies to executable
inputs, artifacts, corpora, logs, and report copies.

## Error handling

- Discovery provider failures are per-provider results.
- Ambiguous or missing policy evidence remains `scope_unverified`.
- Expired/mismatched approval returns `approval_stale` and blocks execution.
- Invalid arms return typed plan errors without stopping unrelated arms.
- Worker timeout, OOM, hang, build failure, and sanitizer-free nonzero exit are
  distinct outcomes.
- Optimizer state with mismatched digests returns `campaign_stale`.
- Report promotion failures return every blocked gate reason and preserve input
  evidence.
- Existing report-package directories are immutable and refused.

## Migration and compatibility

- Existing schema-version-1 target manifests remain valid.
- Existing `campaign`, `campaign-matrix`, findings, reproduction, comparison,
  bundle, and issue records continue to load.
- New catalog and optimizer records use their own schema versions instead of
  changing the target manifest's required fields.
- Legacy campaigns can be imported as one-round optimizer state with their
  recorded CPU, coverage, finding, replay, and duplicate metrics.
- CLI JSON keeps existing top-level keys; new fields are additive.

## Testing strategy

- Provider contract tests use deterministic local HTTP/text fixtures and never
  depend on live bounty platforms.
- Catalog tests cover canonical repository identities, merge conflicts, policy
  digests, and source confidence.
- Approval tests cover creation, expiry, changed policy digests, revision
  mismatch, eligible classes, and immutable history.
- Experiment tests cover stable expansion/digests, unsafe paths, missing tools,
  unavailable adapters, and resource bounds.
- Optimizer simulations cover reward components, deterministic successive
  halving, exploration reservation, stalled/duplicate-heavy arms, campaign caps,
  and exact resume behavior.
- Verification tests cover all positive and negative promotion gates.
- Report tests cover every client profile, evidence inventory, immutable output,
  redaction checklist, and prohibited novelty/severity language.
- End-to-end tests use the controlled C positive, controlled negatives, and the
  existing cJSON vulnerable/fixed/current regression campaign.
- The full existing suite remains green.

## Acceptance criteria

1. Discovery produces normalized, deduplicated `scope_unverified` candidates
   without executing repository code.
2. No target code executes without a matching current approval record.
3. Approved targets expand into stable experiment arms with explicit limits.
4. The optimizer deterministically stops low-value arms and reallocates bounded
   budget to stronger measured arms while preserving exploration.
5. Scheduler output explains every score and allocation.
6. Only candidates passing every verification gate enter report generation.
7. Reports are client-ready drafts with complete evidence and unresolved-review
   fields, but no transmission capability.
8. Existing commands and records remain compatible.
9. Controlled positive/negative and cJSON regression tests pass.
10. Documentation explains discovery, approval, adaptive optimization,
    verification semantics, and the human submission boundary.
