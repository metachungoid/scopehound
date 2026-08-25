# ScopeHound High-ROI Upgrades Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ScopeHound able to build and run reviewed generated C/C++ harnesses, measure corpus and coverage feedback, preserve end-to-end provenance, compare known issues, execute through explicit sandbox backends, and benchmark effectiveness without remote side effects.

**Architecture:** Extend the existing standard-library-only package with small modules for manifest/configuration, generated-candidate lifecycle, coverage/provenance, analysis, sandbox execution, and benchmark fixtures. Existing commands keep their current behavior when optional fields are absent. New operations produce deterministic JSON records under the target workspace and remain dry-run unless `--execute` is supplied.

**Tech Stack:** Python 3.11+, `unittest`, `dataclasses`, `argparse`, `json`, `subprocess`, `hashlib`, `pathlib`, optional local Clang/LLVM tools, optional bubblewrap/Docker.

**Spec:** `docs/superpowers/specs/2026-08-25-scopehound-high-roi-upgrades-design.md`

## Global Constraints

- Every code-executing stage requires an authorized manifest and explicit `--execute`.
- Commands remain argument arrays and run with `shell=False`.
- Every generated or observed artifact records target, immutable revision, command, toolchain, timestamp, and digest where applicable.
- Candidate generation is speculative until it links, reaches target code, and produces a reproducible signal.
- Native execution remains available; requested unavailable sandbox backends fail clearly and never fall back.
- No network access, automatic submission, email, issue creation, or severity/exploitability decisions.
- New manifest fields are optional and existing commands remain backward-compatible.

---

### Task 1: Manifest placeholders, corpus configuration, and workspace layout

**Files:**
- Modify: `scopehound/manifest.py`
- Modify: `scopehound/workspace.py`
- Modify: `examples/example-target.json`
- Test: `tests/test_manifest.py`, `tests/test_workspace.py`

**Interfaces:**
- Add `Commands.harness_build: tuple[str, ...] | None`.
- Add `CorpusConfig(seed_dir: str | None, dictionary: str | None, max_input_size: int, coverage_mode: str)`.
- Add `Manifest.corpus: CorpusConfig`.
- Add `SUPPORTED_PLACEHOLDERS = {repo, source, binary, corpus, dictionary, artifact, duration}` and validate every optional command against it.
- Add workspace methods `generated_dir`, `binaries_dir`, `corpus_dir`, `coverage_dir`, `toolchain_dir`, and `provenance_dir`.

- [ ] Write failing tests for exact placeholder validation, required `{source}`/`{binary}` in `harness_build`, optional corpus defaults, invalid corpus paths/sizes/modes, and deterministic workspace containment.
- [ ] Run `python3 -m unittest tests.test_manifest tests.test_workspace -v` and observe the new tests fail.
- [ ] Implement frozen configuration models, placeholder scanning with `str.format`-style names (reject unknown names and escaped shell syntax), and the new workspace paths.
- [ ] Update the example manifest with an absent optional harness build and explicit corpus defaults so old manifests still validate.
- [ ] Run the focused tests and commit `feat: add harness and corpus manifest configuration`.

### Task 2: Generated candidate build and bounded run pipeline

**Files:**
- Create: `scopehound/candidates.py`
- Modify: `scopehound/runner.py`
- Modify: `scopehound/cli.py`
- Test: `tests/test_candidates.py`, `tests/test_cli.py`, `tests/test_end_to_end.py`

**Interfaces:**
- `CandidateRecord` reads `harnesses.json` and preserves generated filename, source path, function, status, and metadata.
- `build_harnesses(manifest, workspace, harnesses_dir, compiler, execute) -> tuple[CandidateBuild, ...]` creates one shell-free `CommandPlan` per candidate, writes `harness-build.json`, and uses statuses `planned`, `built`, `build_failed`.
- `run_harness(manifest, workspace, candidate_id, duration, execute) -> HarnessRun` only accepts `built` candidates, creates corpus/artifact directories, parses sanitizer output, and writes a run record.
- Placeholder substitution is per argv element and rejects paths outside the target workspace.

- [ ] Write failing tests for candidate metadata loading, dry-run plans, source/binary containment, build failure being non-finding evidence, and refusal to run a non-built candidate.
- [ ] Run the focused tests and verify failure for the missing module/commands.
- [ ] Implement candidate IDs from stable source/function hashes, atomic JSON records, compiler command construction, and bounded runs through `runner.run_plan(..., allow_failure=True)`.
- [ ] Parse sanitizer output into candidate-attached findings and preserve stdout/stderr in the run record.
- [ ] Add `build-harnesses` and `run-harness` argparse dispatch with `--compiler`, `--harnesses-dir`, `--candidate`, and `--duration`.
- [ ] Run focused and full tests; commit `feat: build and run generated harness candidates`.

### Task 3: Corpus and coverage feedback

**Files:**
- Create: `scopehound/coverage.py`
- Modify: `scopehound/cli.py`
- Modify: `scopehound/reporting.py`
- Test: `tests/test_coverage.py`, `tests/test_cli.py`, `tests/test_end_to_end.py`

**Interfaces:**
- `CorpusStats(count: int, bytes: int, digest: str | None)` and `CoverageRecord` capture before/after corpus, engine statistics, coverage files/digests, deltas, CPU seconds, and finding count.
- `collect_coverage(manifest, workspace, candidate_id, before_dir, after_dir, execute) -> CoverageRecord` is read-only unless the selected tool is explicitly run.
- `summarize_engine_output(text) -> Mapping[str, float | int]` tolerates malformed lines and never fails the whole run.
- `coverage` CLI writes `<target>/coverage/<candidate>.json` and can import an LLVM `llvm-cov export` JSON file supplied by path.

- [ ] Write failing tests for deterministic corpus counts/digests, malformed libFuzzer stats, coverage artifact hashing, and function/edge delta calculation.
- [ ] Run focused tests to verify red.
- [ ] Implement bounded directory scanning, optional LLVM export parsing, and atomic JSON output; never overwrite crash artifacts during corpus measurement.
- [ ] Add CLI command and report section linking coverage records and CPU/finding metrics.
- [ ] Run focused/full tests; commit `feat: record corpus and coverage feedback`.

### Task 4: AST/reachability analysis and ranking

**Files:**
- Create: `scopehound/analyze.py`
- Modify: `scopehound/harness.py`
- Modify: `scopehound/scoring.py`
- Modify: `scopehound/cli.py`
- Test: `tests/test_analyze.py`, `tests/test_harness.py`, `tests/test_scoring.py`

**Interfaces:**
- `AstFunction(name, qualified_name, file, line, parameters, namespace)` parses Clang AST JSON records.
- `ReachabilityMetadata` imports optional local coverage/Fuzz Introspector JSON and records advisory source, covered status, and values.
- `rank_candidates(candidates, authorization, reachability, coverage) -> tuple[RankedCandidate, ...]` combines authorization, buildability, reachability, coverage gap, input suitability, and duplicate risk with deterministic tie-breaking.
- Regex discovery remains the fallback when `compile_commands.json` or Clang output is unavailable.

- [ ] Write failing fixtures for AST extraction, malformed/imported Introspector data, existing-harness coverage, and ranking tie-breaks.
- [ ] Run focused tests and verify red.
- [ ] Implement parser/importer with local-path-only checks, preserve advisory provenance, and expose `analyze` CLI output.
- [ ] Add ranking fields to generated harness metadata without changing existing source generation behavior.
- [ ] Run focused/full tests; commit `feat: rank candidates with local reachability metadata`.

### Task 5: Provenance, symbolization, minimization, and known-issue comparison

**Files:**
- Create: `scopehound/provenance.py`
- Create: `scopehound/minimize.py`
- Create: `scopehound/known_issues.py`
- Modify: `scopehound/findings.py`
- Modify: `scopehound/reproduction.py`
- Modify: `scopehound/reporting.py`
- Modify: `scopehound/cli.py`
- Test: `tests/test_provenance.py`, `tests/test_minimize.py`, `tests/test_known_issues.py`, `tests/test_findings.py`, `tests/test_reproduction.py`

**Interfaces:**
- `ProvenanceRecord` captures repository URL/revision, manifest digest, argv/environment keys, host/Python/compiler/sanitizer versions, digests, timestamps, timeout, and execution backend.
- `symbolize_stack(raw_stack, symbolizer, cwd, execute) -> tuple[str, ...]` is optional and preserves raw frames.
- `minimize_artifact(manifest, workspace, artifact, candidate_id, timeout, execute) -> MinimizedArtifact` writes a child artifact with parent digest and never replaces the original.
- `load_known_issues(path)` accepts local JSON/CSV, and `compare_known_issues(findings, issues)` labels `possible_duplicate`, `possible_regression`, or `new_candidate` without suppression.
- All new records are linked into findings/reproduction/report/bundle JSON.

- [ ] Write failing tests for stable manifest/toolchain digests, raw/normalized stacks, child artifact provenance, CSV/JSON issue matching, and regression labels.
- [ ] Run focused tests to verify red.
- [ ] Implement records with UTC timestamps, SHA-256 hashing, bounded optional subprocesses, and safe local file reads.
- [ ] Add `minimize` and `known-issues` CLI commands and report sections.
- [ ] Run focused/full tests; commit `feat: add provenance minimization and known issue comparison`.

### Task 6: Explicit execution backends and sandbox policy

**Files:**
- Create: `scopehound/sandbox.py`
- Modify: `scopehound/runner.py`
- Modify: `scopehound/cli.py`
- Test: `tests/test_sandbox.py`, `tests/test_runner.py`, `tests/test_cli.py`

**Interfaces:**
- `ExecutionBackend` protocol and `BackendPolicy(name, network, read_only_repo, limits)`.
- Implement `native`, `bubblewrap`, and `docker` command wrappers; availability is detected without executing target code.
- `run_plan(..., backend="native")` records backend/policy and raises `sandbox_unavailable` for unavailable requested backends; no fallback.
- Dry-run output contains the complete wrapped argv and policy.

- [ ] Write failing tests for policy serialization, native behavior, unavailable-backend errors, no-network/read-only flags, and absence of fallback.
- [ ] Run focused tests and observe red.
- [ ] Implement backend detection and wrappers using fixed argv fragments, rejecting unsafe workspace paths and never using a shell.
- [ ] Wire `--backend` into build/fuzz/harness/reproduce commands and provenance.
- [ ] Run focused/full tests; commit `feat: add auditable execution backends`.

### Task 7: Benchmark fixtures, documentation, and release verification

**Files:**
- Create: `scopehound/benchmark.py`
- Create: `benchmarks/fixtures/README.md`
- Create: `benchmarks/fixtures/known-bug/`
- Modify: `scopehound/cli.py`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-25-scopehound-high-roi-upgrades-design.md`
- Test: `tests/test_benchmark.py`, `tests/test_cli.py`

**Interfaces:**
- `BenchmarkResult` reports link success, coverage delta, unique fingerprints/CPU-hour, replay success, duplicate rate, false-positive rate, and explicit tool skips.
- `run_benchmark(fixtures_dir, workspace, execute) -> BenchmarkResult` runs only local fixtures and records versioned expected fingerprints.
- `benchmark` CLI emits deterministic JSON and a Markdown summary.

- [ ] Write failing tests for fixture discovery, expected sanitizer fingerprint matching, denominator-zero handling, and tool-availability skips.
- [ ] Run focused tests and verify red.
- [ ] Implement local fixture runner with no network operations and stable metric formulas.
- [ ] Document the full workflow, safety boundaries, manifest examples, sandbox choices, provenance fields, known-issue review, benchmark interpretation, and exact CLI commands.
- [ ] Run `python3 -m unittest discover -s tests -q`, `python3 -m compileall -q scopehound tests`, and `git diff --check`; fix all failures.
- [ ] Commit `feat: add local effectiveness benchmarks and complete documentation`.

