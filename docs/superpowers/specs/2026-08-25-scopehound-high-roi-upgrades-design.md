# ScopeHound High-ROI Upgrades Design

## Status

Approved design implemented incrementally from 2026-08-25 onward. This
document remains the architectural authority for the runnable candidate,
coverage, provenance, sandbox, and benchmark workflow.

## Goal

Turn ScopeHound from a scope-aware crash-evidence pipeline into a measured,
reproducible local fuzzing workflow that can build and execute generated
harnesses, improve coverage, prioritize under-tested code, and produce a
review-ready evidence bundle without transmitting anything.

## Current baseline

The repository already provides:

- authorization-gated manifests and pinned repository preparation
- bounded shell-free build and fuzz commands
- sanitizer parsing, artifact hashing, fingerprint clustering, and replay
- candidate harness generation and syntax validation
- Markdown reports and non-transmitting disclosure bundles

The main gap is the distance between a generated candidate and a target that
actually links, runs, improves coverage, and produces measurable evidence.

## Non-goals

- remote scanning or testing of services
- automatic bounty submission, email, issue creation, or maintainer contact
- automatic severity or exploitability claims
- unreviewed LLM-generated code being treated as a production fuzz target
- distributed scheduling before the local workflow has benchmarked value
- silently executing repository code without explicit authorization and
  `--execute`

## Design principles

1. Every code-executing stage requires an authorized manifest and explicit
   `--execute`.
2. Commands remain argument arrays and run with `shell=False`.
3. Every generated or observed artifact gets stable provenance: target,
   revision, command, toolchain, timestamp, and digest where applicable.
4. Candidate generation is speculative until it links, reaches target code,
   and produces a reproducible signal.
5. Native local execution remains available; sandboxing is an opt-in backend
   and a prerequisite for high-volume operation.
6. Each stage emits deterministic JSON that can be consumed by later stages or
   reviewed independently.

## Staged architecture

### Stage 1: Runnable generated targets

Extend the manifest with an optional harness build and run configuration:

```json
{
  "commands": {
    "build": ["cmake", "--build", "build"],
    "fuzz": ["./build/parser_fuzzer", "{corpus}"],
    "reproduce": ["./build/parser_fuzzer", "{artifact}"],
    "harness_build": [
      "clang++", "-fsanitize=fuzzer,address,undefined",
      "-I", "{repo}", "{source}", "-o", "{binary}"
    ]
  }
}
```

Supported placeholders are `{repo}`, `{source}`, `{binary}`, `{corpus}`,
`{dictionary}`, `{artifact}`, and `{duration}`. Manifest validation requires
that each command use only supported placeholders and that required
placeholders appear exactly once. Substitution is per argv element; no shell
interpolation is introduced.

The new `build-harnesses` stage will:

1. load generated metadata
2. copy or reference sources inside the target workspace
3. create a target-specific generated-binaries directory
4. execute one bounded build plan per candidate when `--execute` is present
5. record `planned`, `built`, or `build_failed` plus compiler output

The new `run-harness` stage will execute only candidates marked `built`, pass a
corpus directory and artifact directory, parse sanitizer output, and attach
the resulting finding to the candidate. A build failure is evidence about the
candidate, not a security finding.

### Stage 2: Corpus and coverage feedback

Add a `CorpusConfig` section to the manifest with optional seed directory,
dictionary path, maximum input size, and coverage mode. The workspace gains
per-target directories for `corpus`, `coverage`, and `toolchain` metadata.

The fuzz plan will support explicit placeholders rather than silently
rewriting researcher commands. A libFuzzer-compatible command can therefore
use `{corpus}`, `{dictionary}`, and `{duration}` while other engines can use
their own argument forms.

The coverage stage will record:

- engine statistics emitted by the fuzzer
- corpus input count and total bytes before and after a run
- coverage artifact paths and SHA-256 digests
- function/edge deltas when LLVM coverage tools are available
- CPU seconds and finding count per harness

The workflow will support corpus minimization as a separate, bounded action.
Minimization output is never substituted for the original crash artifact.

### Stage 3: AST and reachability-aware target selection

Keep the current regex scanner as a portable fallback, but add an analyzer
backend that consumes `compile_commands.json` and Clang AST JSON when present.
The analyzer records:

- fully qualified function name and declaration location
- resolved parameter types and namespaces
- source/header ownership
- whether a candidate is already covered by a discovered harness
- static reachability and dynamic coverage values when imported

An optional Fuzz Introspector importer will accept a local report directory or
JSON export. Imported data is treated as advisory metadata; it never causes
remote access. Ranking will combine authorization, buildability, static
reachability, coverage gap, input suitability, and duplicate risk.

The official references motivating this stage are LLVM’s
[libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html), OSS-Fuzz’s
[Fuzz Introspector documentation](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/),
and its [target-generation evaluation](https://google.github.io/oss-fuzz/research/llms/target_generation/).

### Stage 4: Provenance, minimization, and regression checks

Add a provenance record to each execution and finding containing:

- repository URL, immutable revision, and manifest digest
- exact argv and selected environment values
- host platform, Python version, compiler versions, and sanitizer runtime
- source and binary digests when available
- corpus/dictionary digests
- start/end timestamps and bounded timeout

Add optional symbolization using `llvm-symbolizer` and stack normalization that
preserves both the raw log and the normalized fingerprint. Add a crash
minimization command that writes a new artifact and records its parent digest.

Add a known-issue adapter interface. The first adapter is local JSON/CSV input
for prior findings and fixed revisions; later adapters may consume OSV/GHSA/CVE
exports explicitly supplied by the researcher. ScopeHound will label possible
duplicates and regression ranges, never suppress them silently.

### Stage 5: Sandboxed execution

Add an execution backend interface with:

- `native`: current subprocess behavior, still bounded and explicit
- `bubblewrap`: no network, non-root user, read-only repository, isolated
  workspace, CPU/memory/process limits
- `docker`: equivalent policy when Docker is available

The backend records its policy and availability in provenance. If a requested
sandbox backend is unavailable, execution fails clearly instead of silently
falling back to native mode. Dry-run output includes the complete sandbox
plan.

### Stage 6: Benchmark and quality gates

Add a versioned benchmark fixture set containing:

- known memory-safety bugs with expected sanitizer fingerprints
- compile-failing generated candidates
- non-security crashes and harness-only failures
- duplicate artifacts with distinct bytes
- replayable and non-replayable findings

The benchmark command reports link success rate, coverage delta, unique
fingerprints per CPU-hour, replay success rate, duplicate rate, and false
positive rate. A change that improves feature count but regresses these metrics
will not be treated as an effectiveness improvement.

## CLI additions

The following commands are added incrementally:

- `build-harnesses`: compile generated candidates in the authorized workspace
- `run-harness`: execute one built candidate for a bounded duration
- `coverage`: collect and summarize corpus/coverage results
- `analyze`: import AST/coverage metadata and rank candidates
- `minimize`: produce a child artifact with parent provenance
- `known-issues`: compare findings against researcher-supplied issue data
- `benchmark`: run local effectiveness fixtures

Existing commands remain backward-compatible. New manifest fields are
optional, and existing `build`, `fuzz`, `reproduce`, `triage`, `report`, and
`bundle` behavior remains valid when the fields are absent.

## Data flow

```text
manifest + pinned repo
        |
        v
AST/discovery + existing harnesses ----> ranked candidates
        |                                      |
        v                                      v
generated source ----> build-harnesses ----> built binary
                                                |
                 corpus/dictionary ----------> run-harness
                                                |
                       coverage + sanitizer + provenance
                                                |
                       triage -> reproduce -> report -> bundle
```

Every arrow produces a file-backed record under the target workspace. A later
stage can be rerun from those records without repeating earlier stages.

## Testing strategy

- unit tests for placeholder validation, path containment, and deterministic
  JSON schemas
- compiler-backed tests when `c++`/`clang++` is available, skipped otherwise
- sandbox policy tests that verify no fallback when a backend is unavailable
- fixture tests for coverage deltas and malformed tool output
- end-to-end local repository tests covering candidate build, run, finding,
  replay, triage, report, and bundle
- benchmark assertions with stable expected fingerprints and explicit tool
  availability skips

## Acceptance criteria

The upgrade is complete when:

1. at least one generated candidate can be built and run through the same
   authorized workspace pipeline as a supplied harness; the `build-harnesses`
   and `run-harness` commands now provide this lifecycle
2. corpus and coverage records are produced without requiring network access
3. target ranking can consume AST metadata and an optional local Introspector
   report
4. a finding bundle contains exact toolchain/provenance data and a minimized
   child artifact when requested
5. native and sandbox execution have distinct, auditable policies
6. the benchmark command measures effectiveness and all existing tests remain
   green; the versioned fixture set lives under `benchmarks/fixtures`
