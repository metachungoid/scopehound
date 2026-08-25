# ScopeHound Campaign Engine and Real-Library Validation Design

## Status

Approved in conversation on 2026-08-25. This specification extends the
high-ROI pipeline with resumable campaigns, pluggable local fuzz engines, and
an executable real-library control matrix. Implementation remains local-only;
no fresh finding or private evidence is published automatically.

## Goal

Make ScopeHound useful for ethical bug-bounty research by reducing the gap
between a pinned C/C++ checkout and a defensible, reproducible disclosure
record. A campaign must be able to configure and build a real target, link a
reviewed harness, run bounded sanitizer-backed input generation, compare
vulnerable/fixed/current controls, and preserve enough evidence for a human to
verify scope, root cause, impact, and reproduction.

## Real-library validation target

The first integration target is Dave Gamble’s cJSON ANSI C library:

- v1.7.17: positive control for the publicly documented `parse_string`
  heap-buffer-overflow when `cJSON_ParseWithLength` receives malformed input
  without a trailing newline.
- v1.7.18: fixed-version negative control for the same input.
- a separately pinned current revision: bounded exploratory campaign only.

The control issue is already public and is used solely to validate the tool.
Any signal from the current revision is private workspace evidence until a
human confirms authorization, current scope, reproducibility, duplicate status,
root cause, and disclosure channel.

The target pack records the public references alongside the control metadata:
the [cJSON repository](https://github.com/DaveGamble/cJSON), its
[security policy](https://github.com/DaveGamble/cJSON/security), and the
[public issue describing the malformed-input sanitizer failure](https://github.com/DaveGamble/cJSON/issues/800).

## Scope and safety constraints

1. Every target-code execution requires an authorized manifest and explicit
   `--execute`.
2. Repository revisions are immutable commit IDs; tags are resolved before a
   campaign is recorded.
3. All commands are argv arrays and run with `shell=False`; no shell snippets,
   remote services, automatic issue creation, email, or bounty submission are
   supported.
4. Campaigns operate on local checkouts and local artifacts only. Network is
   permitted only for an explicit repository preparation step and is never
   available to the target process.
5. Fresh current-version signals are written beneath the workspace and are not
   committed to the repository or uploaded by ScopeHound.
6. A benchmark pass is not a vulnerability determination and does not infer
   severity, exploitability, or bounty eligibility.

## Architecture

### 1. Multi-step build pipeline

Manifests gain optional command groups while preserving existing single-command
fields:

```json
{
  "commands": {
    "prepare": [["cmake", "-S", ".", "-B", "build"]],
    "build": [["cmake", "--build", "build", "--parallel", "2"]],
    "harness_build": [["cc", "-fsanitize=address,undefined", "-c", "{source_c}", "-o", "{object}"], ["c++", "{source}", "{object}", "-o", "{binary}"]],
    "run": [["{binary}", "{artifact}"]],
    "reproduce": [["{binary}", "{artifact}"]]
  }
}
```

Each group is a sequence of bounded argv plans. A step can consume only
approved placeholders (`{repo}`, `{source}`, `{source_c}`, `{object}`,
`{binary}`, `{corpus}`, `{dictionary}`, `{artifact}`, `{duration}`, and
`{revision}`). Every step records planned, executed, or failed status, argv,
cwd, output, timeout, and backend policy. A later step cannot run after a
failed prerequisite.

### 2. Pluggable local fuzz engines

The engine interface accepts a built binary, corpus directory, dictionary,
duration, artifact directory, and resource limits, and returns a normalized run
record. Two engines are implemented:

- `libfuzzer`: uses a Clang/libFuzzer-compatible binary and preserves native
  engine statistics, corpus growth, and crash artifacts.
- `standalone`: uses a generated C/C++ driver that reads one input at a time,
  invokes `LLVMFuzzerTestOneInput`, and applies deterministic bounded mutations.
  It works with GCC plus AddressSanitizer/UndefinedBehaviorSanitizer when
  Clang/libFuzzer is unavailable. Every mutation records its parent seed and
  deterministic seed value.

The standalone engine is a compatibility fallback, not a replacement for
coverage-guided fuzzing. Reports identify the engine so CPU-hour comparisons
remain honest.

### 3. Reviewed harness recipes and cleanup

Generated candidates remain speculative. A target pack can supply a reviewed
harness recipe with:

- source/header includes and exact API symbol
- input and length expressions
- optional cleanup expression for returned allocations
- compile/link source files and libraries
- expected sanitizer runtime

The generic generator remains available, but target-specific cleanup is
required for cJSON so successful parses call `cJSON_Delete`. A candidate is
promoted only after syntax validation, link success, execution, and a
reproducible result.

### 4. Resumable campaign state

`campaign` creates a target-scoped state record with immutable manifest digest,
target revision, engine, backend, stage statuses, and paths to all records:

```text
target/
  campaign.json
  repo/
  build/
  generated/
  binaries/
  corpus/
  artifacts/
  coverage/
  findings.json
  provenance/
  reports/
```

Rerunning a campaign resumes completed stages only when their input digests
match. `--force-stage` is explicit and writes a new attempt instead of
overwriting evidence.

### 5. Control matrix and current-version gate

The cJSON target pack runs the same reviewed harness/input through the positive
control, fixed control, and current revision. The report must show:

- revision and resolved commit ID
- build and harness-link status
- engine/backend/toolchain
- expected versus observed sanitizer fingerprints
- replay and minimization status
- known-issue label and fixed-version comparison
- coverage/corpus deltas and CPU seconds

The current run is a private exploratory result. A known positive control does
not make a current signal valid; it only proves the pipeline can detect the
class of failure.

### 6. Evidence and disclosure workflow

Every finding links to a run provenance record, input digest, mutation lineage,
raw and normalized sanitizer output, replay result, minimized child (when
requested), control comparison, and human review checklist. Bundles include
the original artifact and minimized child separately. The tool never generates
severity claims or sends the bundle.

## CLI additions

- `campaign`: run or resume the authorized local pipeline with `--engine`,
  `--backend`, `--duration`, `--target-pack`, and `--execute`.
- `engines`: list available engines and explicit tool skips.
- `controls`: run the positive/fixed/current revision matrix and write a
  comparison record.

Existing commands remain valid. `build-harnesses` and `run-harness` become
wrappers over the same engine and campaign records.

## Testing strategy

- Unit tests for command-group validation, placeholder safety, stage
  prerequisites, mutation determinism, cleanup metadata, and state resumption.
- Compiler-backed tests skip only when the required compiler is unavailable;
  GCC/ASan standalone tests are the portable baseline.
- Integration test clones cJSON at immutable controls, builds a reviewed
  harness, reproduces the public v1.7.17 signal, verifies v1.7.18 does not
  reproduce it, and runs a bounded current-version campaign.
- The integration test records tool availability and never fails by silently
  substituting a different engine or revision.
- Full existing test suite remains green; current-version evidence is stored in
  a temporary workspace and excluded from commits.

## Acceptance criteria

1. A manifest can express configure/build/link/run as bounded multi-step argv
   groups without breaking existing manifests.
2. A real C target can run through a local GCC/ASan standalone engine when
   Clang/libFuzzer is unavailable.
3. The cJSON positive control reproduces its known public sanitizer fingerprint
   and the fixed control does not.
4. A current pinned revision can run a bounded campaign with explicit engine,
   backend, corpus, and provenance records.
5. Resume behavior refuses stale state and preserves prior evidence.
6. A report/bundle contains reproducibility commands, exact toolchain/revision
   data, input lineage, control comparison, and a minimized child when
   requested.
7. No network, remote-service testing, automatic disclosure, or unreviewed
   current-version finding publication occurs.
