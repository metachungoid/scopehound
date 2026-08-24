# ScopeHound MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local-first Python CLI that gates authorized C/C++ research, scores targets, prepares pinned repositories, runs bounded local commands, triages artifacts, and produces human-reviewable reports.

**Architecture:** A standard-library-only `scopehound` package separates manifest validation, policy, scoring, workspace operations, subprocess execution, triage, reporting, and CLI presentation. Mutating or code-executing actions are dry-run by default and require both an authorized manifest and `--execute`.

**Tech Stack:** Python 3.11+, `unittest`, `dataclasses`, `argparse`, `json`, `subprocess`, `hashlib`, `pathlib`, Git CLI.

**Spec:** `docs/superpowers/specs/2026-08-24-scopehound-design.md`

## Global Constraints

- Python 3.11 or newer.
- No required runtime dependencies.
- JSON manifests only in the MVP.
- Commands are argument arrays and execute without a shell.
- Clone, build, and fuzz are dry-run unless `--execute` is supplied.
- Execution requires `authorization.status` equal to `authorized` and a non-empty policy URL.
- Fuzz execution requires a positive explicit duration and always has a timeout.
- No remote service testing or automatic vulnerability submission.

---

### Task 1: Package, Manifest Validation, Policy, and Scoring

**Files:**
- Create: `pyproject.toml`
- Create: `scopehound/__init__.py`
- Create: `scopehound/errors.py`
- Create: `scopehound/manifest.py`
- Create: `scopehound/policy.py`
- Create: `scopehound/scoring.py`
- Create: `tests/__init__.py`
- Create: `tests/test_manifest.py`
- Create: `tests/test_policy.py`
- Create: `tests/test_scoring.py`

**Interfaces:**
- Produces: `load_manifest(path: Path) -> Manifest`
- Produces: `validate_manifest(data: object) -> Manifest`
- Produces: `require_authorized(manifest: Manifest) -> None`
- Produces: `score_opportunity(opportunity: Opportunity) -> ScoreResult`
- Produces: `ScopeHoundError(category: str, message: str)`

- [ ] **Step 1: Write failing manifest, policy, and scoring tests**

Create tests that construct the complete example manifest, assert normalization into frozen dataclasses, and assert stable categories for malformed slugs, missing revisions, shell-string commands, moving revisions such as `main`, invalid dates, unsupported languages, factor values outside `[0, 1]`, and unauthorized execution. Assert the scoring formula with:

```python
opportunity = Opportunity(
    bounty_eligibility=1.0,
    attacker_reachability=0.8,
    code_criticality=0.7,
    change_recency=0.6,
    fuzzing_gap=0.9,
    build_reproducibility=0.8,
    duplicate_risk=0.4,
)
result = score_opportunity(opportunity)
self.assertAlmostEqual(result.score, 55.256, places=3)
self.assertEqual(result.factors["duplicate_risk"], 0.4)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_manifest tests.test_policy tests.test_scoring -v`

Expected: FAIL because the `scopehound` package does not exist.

- [ ] **Step 3: Implement immutable models and validation**

Define `Target`, `Authorization`, `Commands`, `Opportunity`, `Manifest`, and `ScoreResult` as frozen dataclasses. Validate exact required keys, slug pattern `[a-z0-9][a-z0-9-]{0,62}`, language membership in `{c, cpp}`, HTTPS/SSH/local repository forms, pinned non-empty revision, ISO date, non-empty argument arrays, and numeric factors. Raise `ScopeHoundError("manifest_invalid", detail)` for every manifest failure.

- [ ] **Step 4: Implement policy and transparent score calculation**

`require_authorized` rejects any status other than `authorized`, missing policy URLs, or missing `memory-corruption` eligibility. `score_opportunity` computes the six-factor geometric mean and applies `(1 - 0.75 * duplicate_risk)`, returning the rounded score and an ordered factor dictionary.

- [ ] **Step 5: Run the focused tests**

Run: `python3 -m unittest tests.test_manifest tests.test_policy tests.test_scoring -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml scopehound tests
git commit -m "feat: validate and score authorized targets"
```

### Task 2: Safe Workspace and Bounded Command Runner

**Files:**
- Create: `scopehound/workspace.py`
- Create: `scopehound/runner.py`
- Create: `tests/test_workspace.py`
- Create: `tests/test_runner.py`

**Interfaces:**
- Consumes: `Manifest`, `ScopeHoundError`, `require_authorized`
- Produces: `Workspace(root: Path)` with `target_dir(name)`, `logs_dir(name)`, and `artifacts_dir(name)`
- Produces: `CommandPlan(argv, cwd, environment, timeout_seconds, mutates)`
- Produces: `CommandResult(argv, returncode, stdout, stderr, executed)`
- Produces: `prepare_plan(manifest, workspace, allow_local_repository=False) -> CommandPlan`
- Produces: `build_plan(manifest, workspace) -> CommandPlan`
- Produces: `fuzz_plan(manifest, workspace, duration_seconds) -> CommandPlan`
- Produces: `run_plan(plan, execute=False) -> CommandResult`

- [ ] **Step 1: Write failing path and runner tests**

Assert that target paths remain beneath a resolved temporary workspace, existing checkout paths are rejected, local repositories require `allow_local_repository=True`, prepare uses `git clone --no-checkout` plus a separately representable checkout action, build uses the target checkout as its working directory, fuzz duration must be positive and no greater than 86,400 seconds, dry-run does not invoke subprocesses, execution captures output, and timeouts raise `ScopeHoundError("timeout", ...)`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_workspace tests.test_runner -v`

Expected: FAIL because workspace and runner modules do not exist.

- [ ] **Step 3: Implement safe path derivation and command plans**

Resolve all roots and verify containment using `Path.relative_to`. Store repositories at `<root>/targets/<slug>/repo`, logs at `<root>/targets/<slug>/logs`, and artifacts at `<root>/targets/<slug>/artifacts`. Construct commands as tuples of strings and merge only manifest-declared environment values into a copy of the process environment.

- [ ] **Step 4: Implement dry-run and bounded execution**

Use `subprocess.run(..., shell=False, capture_output=True, text=True, timeout=...)`. A dry run returns `executed=False` and never creates directories. Non-zero exits raise `ScopeHoundError("command_failed", ...)` while preserving concise stdout/stderr details.

- [ ] **Step 5: Run focused tests**

Run: `python3 -m unittest tests.test_workspace tests.test_runner -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scopehound/workspace.py scopehound/runner.py tests/test_workspace.py tests/test_runner.py
git commit -m "feat: add safe workspace and bounded runner"
```

### Task 3: Artifact Triage and Disclosure Drafts

**Files:**
- Create: `scopehound/triage.py`
- Create: `scopehound/reporting.py`
- Create: `tests/test_triage.py`
- Create: `tests/test_reporting.py`

**Interfaces:**
- Consumes: `Manifest`, `Workspace`, `ScopeHoundError`
- Produces: `ArtifactRecord(path, sha256, size)`
- Produces: `TriageResult(unique, duplicates)`
- Produces: `triage_artifacts(directory: Path) -> TriageResult`
- Produces: `write_triage(result, output: Path) -> None`
- Produces: `render_report(manifest, artifact, relative_artifact_path) -> str`
- Produces: `write_report(text: str, output: Path) -> None`

- [ ] **Step 1: Write failing artifact and report tests**

Create temporary artifacts containing `b"alpha"`, `b"alpha"`, and `b"beta"`. Assert two unique groups, one duplicate mapping, stable SHA-256 values, deterministic JSON ordering, and rejection of non-files. Assert the Markdown report contains the repository, revision, policy URL, verification date, build and fuzz argument arrays, artifact hash, `human_review_required: true`, and unchecked human analysis items.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_triage tests.test_reporting -v`

Expected: FAIL because triage and reporting modules do not exist.

- [ ] **Step 3: Implement byte-identical artifact grouping**

Read artifacts in sorted filename order, stream files into SHA-256 in 64 KiB chunks, group by `(sha256, size)`, and select the lexicographically first path as the canonical artifact. Write JSON atomically via a sibling temporary file followed by `Path.replace`.

- [ ] **Step 4: Implement deterministic Markdown report rendering**

Render data as plain Markdown without executing artifact content. Include explicit sections for scope evidence, reproduction, sanitizer evidence, reachability, impact, duplicate search, latest-version confirmation, and disclosure review.

- [ ] **Step 5: Run focused tests**

Run: `python3 -m unittest tests.test_triage tests.test_reporting -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scopehound/triage.py scopehound/reporting.py tests/test_triage.py tests/test_reporting.py
git commit -m "feat: triage artifacts and draft reports"
```

### Task 4: CLI and Local End-to-End Workflow

**Files:**
- Create: `scopehound/__main__.py`
- Create: `scopehound/cli.py`
- Create: `tests/test_cli.py`
- Create: `tests/test_end_to_end.py`
- Create: `examples/example-target.json`
- Create: `.gitignore`

**Interfaces:**
- Consumes: all prior task interfaces
- Produces: `main(argv: Sequence[str] | None = None) -> int`
- Produces commands: `validate`, `score`, `prepare`, `build`, `fuzz`, `triage`, and `report`

- [ ] **Step 1: Write failing CLI tests**

Call `main()` with redirected stdout/stderr. Assert `--help`, text and `--json` validation, explained scoring, dry-run prepare/build/fuzz output, authorization errors with stable categories, duration validation, triage JSON creation, and report creation. Assert error exit code `2`, command failure exit code `1`, and success exit code `0`.

- [ ] **Step 2: Write the failing local end-to-end test**

Create a temporary local Git repository containing a minimal C program and a Python artifact-producing fuzz fixture. Pin its commit in a manifest, run prepare with `--allow-local-repository --execute`, run build and bounded fuzz with `--execute`, triage the artifact directory, and generate a report. Skip the compilation assertion only when no C compiler is installed.

- [ ] **Step 3: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_cli tests.test_end_to_end -v`

Expected: FAIL because the CLI modules do not exist.

- [ ] **Step 4: Implement argparse commands and stable output**

Each command accepts `--manifest` and `--workspace` where relevant. Mutating commands expose `--execute`; prepare exposes `--allow-local-repository`; fuzz requires `--duration`; triage accepts `--artifacts`; report accepts `--artifact` and `--output`. Catch `ScopeHoundError` in one location and render either JSON or concise text.

- [ ] **Step 5: Run CLI and end-to-end tests**

Run: `python3 -m unittest tests.test_cli tests.test_end_to_end -v`

Expected: PASS.

- [ ] **Step 6: Run the entire suite**

Run: `python3 -m unittest discover -s tests -v`

Expected: all tests PASS without network access.

- [ ] **Step 7: Commit**

```bash
git add scopehound/__main__.py scopehound/cli.py tests/test_cli.py tests/test_end_to_end.py examples/example-target.json .gitignore
git commit -m "feat: expose ScopeHound CLI workflow"
```

### Task 5: Documentation and Release Verification

**Files:**
- Create: `README.md`
- Create: `LICENSE`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: the completed CLI
- Produces: install instructions, authorization model, safe local demonstration, command reference, and project metadata

- [ ] **Step 1: Write README command examples**

Document editable installation, manifest validation, scoring, dry-run behavior, explicit execution, bounded fuzzing, triage, reporting, and the fact that scope terms must be rechecked by a human. Use only the bundled example for non-executing examples and a local repository placeholder for executing examples.

- [ ] **Step 2: Add packaging metadata and license**

Expose `scopehound = "scopehound.cli:entrypoint"`, require Python `>=3.11`, declare no dependencies, and include an MIT license file.

- [ ] **Step 3: Verify installation and commands in a temporary virtual environment**

Run: `python3 -m venv /tmp/scopehound-venv && /tmp/scopehound-venv/bin/pip install -e .`

Run: `/tmp/scopehound-venv/bin/scopehound --help`

Run: `/tmp/scopehound-venv/bin/scopehound validate --manifest examples/example-target.json`

Expected: installation succeeds, help lists all seven commands, and the example validates.

- [ ] **Step 4: Run final quality checks**

Run: `python3 -m unittest discover -s tests -v`

Run: `python3 -m compileall -q scopehound tests`

Run: `git diff --check`

Expected: all commands exit zero.

- [ ] **Step 5: Commit**

```bash
git add README.md LICENSE pyproject.toml
git commit -m "docs: document safe ScopeHound workflow"
```
