# ScopeHound High-Throughput Authorized Campaigns

## Status

Approved direction; implementation follows the additional yield, coverage,
oracle, and reporting requirements below.

## Goal

Make ScopeHound effective at finding memory-safety bug-bounty candidates by
running many bounded test variants across an explicit, authorized matrix of
pinned C/C++ repositories, while preserving reproducibility, provenance,
deduplication, and human-controlled disclosure.

“New” means a finding not present in the supplied local known-issue index. The
tool must use `new_candidate` and `novelty: unverified` until a researcher
performs source review and public/private duplicate checks. It must never claim
global novelty or submit a report automatically.

## Scope and safety boundaries

- Campaigns accept only manifests that declare authorization, a policy URL,
  checked date, eligible classes, and an immutable repository revision.
- Repository preparation and testing remain local command execution; the
  scheduler does not probe services, scan arbitrary GitHub repositories, or
  contact maintainers.
- Every target and worker has explicit CPU, memory, input-size, process-count,
  and wall-clock limits inherited from the existing runner.
- Each target receives an isolated workspace, corpus, artifact directory, and
  log namespace. Paths are contained within the campaign workspace.
- Disclosure output is an evidence draft and issue package for human review;
  there is no submission or messaging integration.

## Architecture

### 1. Target matrix

Add a manifest-level matrix containing target names, pinned revisions,
authorization records, build groups, fuzz groups, corpus settings, known-issue
indexes, and per-target budgets. Existing single-target manifests remain
valid. Matrix entries refer to the existing command-array model, so commands
are executed without a shell and retain current placeholder validation.

### 2. Local scheduler

Add a resumable scheduler that expands the matrix into independent target ×
build-variant × engine jobs. It uses a bounded worker pool, records queued,
running, completed, timed-out, skipped, and failed states, and resumes only
when manifest and stage digests match. A job can be retried explicitly without
deleting earlier evidence. Parallelism is capped by a campaign setting and
defaults conservatively.

The first implementation supports the existing `standalone` engine and
`libfuzzer` when available. It must record unavailable engines instead of
silently substituting another engine. Build variants are command groups, not
an implicit compiler or sanitizer installer.

The scheduler also records a stable job key, per-job CPU seconds, worker
limits, retry count, corpus seed/dictionary metadata, and a resumable digest.
Optional AFL++ and Honggfuzz/Centipede integrations are represented as
availability-aware adapters; an absent binary is a visible skip rather than a
fallback. Shared-corpus jobs may be enabled explicitly and remain bounded by
the manifest's input, process, and wall-clock limits.

### 3. Finding gate

After each job, ScopeHound parses sanitizer output, normalizes stacks, hashes
artifacts, and clusters duplicate fingerprints. A candidate is eligible for
promotion only when:

1. the finding has a regular artifact inside the target workspace;
2. the finding is reproduced by the configured replay command;
3. the replay record contains at least two matching attempts for the same
   revision and command;
4. the known-issue comparison labels it `new_candidate`; and
5. no artifact, stack-signature, or explicit known-issue alias marks it as a
   duplicate or regression.

Failed gates produce a machine-readable blocked reason and retain evidence;
they cannot be promoted as new issues.

Finding identity includes both the existing sanitizer fingerprint and a
normalized root-cause signature (sanitizer, kind, function, source basename,
and top frames). Known issues may list aliases for either identity. Timeout,
OOM, and hang signals are recorded as resource candidates in a separate class;
they are never silently promoted as memory-corruption findings.

### 4. Issue package

Add an issue-promotion command that writes a new review package containing:

- `issue.json` with schema version, candidate status, novelty state, target
  revision, finding and comparison records, replay counts, artifact hashes,
  provenance, and explicit missing-review fields;
- `report.md` with title, impact, affected component, exact build/fuzz/replay
  commands, artifact and minimized-artifact hashes, sanitizer evidence,
  observed behavior, and human-review checklists;
- copies of the manifest, finding, triage, known-issue comparison,
  reproduction, minimization, campaign, and artifact files when supplied.

The package is immutable once created: an existing output directory is refused
unless the caller selects a new path. The report uses “potential finding” and
“new candidate,” never “confirmed vulnerability” or “zero-day.”

Issue metadata includes a manually supplied target opportunity score and a
transparent expected-yield estimate. The estimate is an operational
prioritization metric based on scope confidence, attacker reachability,
criticality, duplicate risk, observed candidate rate, replay rate, and CPU
cost. It is not a bounty prediction, a guarantee of profit, or a substitute
for program terms and human severity assessment.

Optional differential/metamorphic jobs compare two authorized local build
variants or a round-trip oracle. The result records the oracle, input digest,
and both outputs; oracle disagreements remain candidates until sanitizer and
scope gates pass. A changed-function hint may prioritize jobs, but ScopeHound
does not infer a vulnerability from a diff alone.

### 5. Proof-of-concept validation

The implementation will run against a small local C fixture with an
intentional sanitizer-detectable memory error. This validates the scheduler,
replay-count gate, known-issue comparison, and issue-package generation. The
fixture is explicitly labeled a controlled positive test, not a third-party
bug-bounty finding. A real library run may produce a candidate only if it
passes the same gates and subsequent human duplicate review.

## Interfaces

- Existing single-target commands continue to work unchanged.
- New campaign scheduling is exposed through the existing `campaign` command
  with a matrix manifest and JSON output containing per-job state.
- A `campaign-matrix` command expands and executes the bounded target matrix,
  returning per-job states and expected-yield metrics without remote scanning.
- New issue promotion is exposed as `issue` with required manifest, artifact,
  findings, reproduction, and known-issue comparison inputs; optional triage,
  minimization, coverage, and campaign records are copied when present.
- Reproduction JSON remains backward compatible; older records load with one
  attempt and cannot satisfy the two-attempt promotion gate until replayed.

## Error handling

- Invalid authorization, unpinned revisions, unsafe paths, malformed records,
  missing artifacts, and failed gates return typed `ScopeHoundError` values.
- A worker timeout or sanitizer-free nonzero command is recorded as a failed
  job and does not create an issue candidate.
- A duplicate or regression is recorded with its reason and exits nonzero from
  issue promotion without deleting evidence.
- JSON records are written atomically and use stable key ordering.
- No command scrapes bounty programs, probes remote targets, or submits a
  disclosure. Any payout or program metadata is researcher-entered and is
  preserved as provenance only.

## Testing and acceptance criteria

- Unit tests cover matrix expansion, worker limits, resume/digest behavior,
  replay attempt accounting, promotion gate decisions, alias deduplication,
  issue JSON schema, report rendering, path containment, engine availability,
  differential/resource candidate classification, and expected-yield math.
- End-to-end tests run the controlled C fixture through two matching replays
  and verify a `new_candidate` issue package.
- End-to-end negative tests verify that a known fingerprint, a different
  replay fingerprint, one replay only, and a timeout cannot be promoted.
- The existing full test suite remains green.
- Documentation describes the matrix schema, resource controls, candidate
  semantics, and the human review/disclosure boundary.
