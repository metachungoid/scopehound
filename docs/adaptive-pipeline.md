# Adaptive pipeline operator guide

ScopeHound's adaptive path is a local research queue, not an authorization
oracle or an automatic disclosure client. The intended sequence is:

```text
read metadata -> human approval -> expand arms -> measure local rounds
  -> successive halving -> verify evidence -> draft -> human review/send
```

## 1. Discover and approve

`discover-targets` reads only the supplied repository's `security.txt` or
`SECURITY.md`. Results begin as `scope_unverified`. A reviewer chooses the
candidate, pins an immutable revision, checks the current policy, and creates
an `ApprovalRecord`. Approval files are immutable; a recheck creates a new
file. The policy content digest is copied into the manifest so a changed
policy blocks execution as `approval_stale`.

The adaptive execution boundary accepts only `sandboxed-local` approvals. A
`read-only` approval can document a target or feed planning review but cannot
start builds, fuzzing, replay, minimization, or oracles.

## 2. Plan and allocate

`plan-experiments` expands the approved target into stable arms:

```text
target × revision × harness × build variant × engine × corpus strategy × oracle
```

Each arm carries a digest and approval revision. `optimize-campaign` consumes
local metrics and applies bounded successive halving. The reward is dominated
by promotable candidates per CPU-hour; coverage, replay, and duplicate quality
are proxy signals. The optimizer is deterministic for identical inputs, keeps
an explicit exploration fraction, and never treats expected dollars as a
finding or a payout promise.

Metrics are intentionally researcher-supplied records. A typical round file
is a JSON object keyed by arm ID:

```json
{
  "arm-id": {
    "cpu_seconds": 900,
    "promotable_candidates": 1,
    "candidate_count": 2,
    "duplicate_count": 1,
    "matching_replays": 2,
    "replay_attempts": 2,
    "coverage_delta": 0.12
  }
}
```

## 3. Verify before drafting

`verify_candidate` records machine-readable gates and reasons. Promotion
requires a regular contained artifact, a supported sanitizer signal, two
matching replay attempts, a normalized root-cause review, attacker-controlled
reachability review, cross-build confirmation, public and private duplicate
evidence, a latest eligible revision check, and a scope/disclosure recheck.
Failed gates keep their evidence and do not become a `new_candidate` report.

Duplicate evidence is evidence of the searches performed, not proof of global
novelty. Reports use `potential memory-safety finding`, `new_candidate`, and
`novelty: unverified`; they do not use “zero-day”, “confirmed vulnerability”,
or “guaranteed bounty”.

## 4. Draft and disclose manually

`draft-report` supports `neutral`, `private-email`, and `platform-form`
profiles. Profiles only change field order and handoff wording. They never
send data, contact maintainers, or store credentials. A human must redact
secrets and unrelated data, verify the current policy and designated private
channel, assess impact/severity, and submit the reviewed draft.

The legacy `campaign`, `campaign-matrix`, `issue`, and `report` commands remain
loadable for existing schema-version-1 records. Use the adaptive path for new
work and retain old records as compatibility evidence.
