# Authorized campaign matrix

ScopeHound's matrix mode is a local scheduler for researcher-supplied,
authorized C/C++ targets. It is designed to spend bounded compute on the
highest-information experiments while retaining evidence needed for a human
bug-bounty report.

## Safety and scope

Use an immutable repository revision and a policy URL that you personally
checked. Matrix mode runs only the argument-array commands in the manifest. It
does not crawl repositories, probe remote services, scrape bounty programs, or
submit findings. `new_candidate` means “not in the supplied local known-issue
index”; novelty remains `unverified` until source review and duplicate checks.

## Matrix controls

`campaign.max_workers` bounds concurrency. `max_retries`, wall-clock/CPU
budgets, process limits, input-size limits, seed/dictionary hashes, engine
availability, and build-variant names are recorded in `matrix.json`. Existing
state is resumed only when the manifest digest matches. `--retry` appends an
attempt and keeps prior evidence.

The core adapters are `standalone` and `libfuzzer`. `afl++`, `honggfuzz`, and
`centipede` are availability-aware adapters; ScopeHound records a visible skip
when their binaries are absent or their execution integration is not enabled.

## Candidate economics

The `economics` section is optional, manual metadata. The resulting estimate is
based on observed candidate/replay/duplicate rates, the opportunity score, CPU
cost, and the entered reward confidence. It is an operational expected-yield
metric, not a payout forecast or a promise of profit.

## Oracles and evidence

Differential, round-trip, and metamorphic oracle results record an input hash,
both outputs, bounded duration, and an explicit status. Disagreement is a
logic candidate and must still pass sanitizer, scope, replay, and root-cause
review before it can enter an issue package. Timeout, OOM, and hang signals are
resource candidates kept separate from memory-corruption findings.

## Promotion gate

`scopehound issue` creates an immutable package only when the artifact is a
regular file, the finding has a normalized root-cause signature, the same
reproduction is observed in at least two matching attempts, and the local
known-issue comparison says `new_candidate`. Optional cross-build evidence
must agree when supplied. The package contains `issue.json`, `report.md`,
commands, hashes, provenance, and review checklists. It is a draft for a human
to verify and disclose through the program's designated private channel.

The controlled proof in
[`docs/evidence/controlled-c-positive.md`](evidence/controlled-c-positive.md)
is intentionally buggy test code and is not an upstream or bounty finding.
