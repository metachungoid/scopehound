# ScopeHound Campaign Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Build a resumable, scope-gated local campaign engine that can compile and exercise a reviewed C harness through GCC/ASan, compare cJSON vulnerable/fixed/current controls, and preserve reproducible evidence without remote disclosure.

**Architecture:** Extend the existing manifest and shell-free runner with normalized multi-step command groups, then layer a file-backed campaign state machine over those steps. Add an engine registry with a native libFuzzer adapter and a deterministic standalone adapter that executes a generated file-input driver. Add a cJSON target pack and control-matrix runner that records immutable revisions, expected/observed sanitizer fingerprints, replay, minimization, and provenance. Keep all current CLI behavior backward-compatible and make every target-code stage require authorization plus `--execute`.

**Tech Stack:** Python 3.11 standard library, `unittest`, `subprocess` with `shell=False`, GCC/AddressSanitizer/UndefinedBehaviorSanitizer when available, optional Clang/libFuzzer, Git, local JSON/Markdown records.

**Spec:** `docs/superpowers/specs/2026-08-25-scopehound-campaign-engine-design.md`

## Global Constraints

- Every target-code execution requires an authorized manifest and explicit `--execute`.
- Repository revisions are immutable commit IDs; tags are resolved before a campaign is recorded.
- All commands are argv arrays and run with `shell=False`; no shell snippets, remote services, automatic issue creation, email, or bounty submission are supported.
- Campaigns operate on local checkouts and local artifacts only; network is allowed only for explicit repository preparation and is unavailable to the target process.
- Fresh current-version signals remain under the workspace and are never committed or uploaded by ScopeHound.
- A benchmark pass is not a vulnerability determination and does not infer severity, exploitability, or bounty eligibility.
- Existing flat manifest command arrays and all existing CLI commands continue to work.

---

### Task 1: Normalize command groups and campaign workspace paths

**Files:**
- Modify: `scopehound/manifest.py`
- Modify: `scopehound/workspace.py`
- Modify: `scopehound/runner.py`
- Modify: `tests/test_manifest.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_runner.py`

**Interfaces:**
- `CommandGroup = tuple[tuple[str, ...], ...]` in `manifest.py`.
- `Commands.build_steps`, `Commands.fuzz_steps`, `Commands.reproduce_steps`, and `Commands.harness_build_steps` expose normalized command groups; the existing `.build`, `.fuzz`, `.reproduce`, and `.harness_build` properties remain available as the first flat command for old callers.
- `validate_command_group(value: object, field: str, required: tuple[str, ...] = ()) -> CommandGroup` accepts either an existing flat argv array or a list of argv arrays, rejects empty groups, duplicate required placeholders, unsupported placeholders, malformed braces, and non-string arguments.
- `Workspace.campaign_file(name)`, `Workspace.build_dir(name)`, `Workspace.reports_dir(name)`, and `Workspace.controls_dir(name)` return contained paths beneath the target directory.
- `command_plans(manifest: Manifest, workspace: Workspace, group: CommandGroup, *, stage: str, timeout_seconds: float, mutates: bool) -> tuple[CommandPlan, ...]` substitutes approved placeholders and emits one plan per command without shell interpolation.

- [ ] **Step 1: Write failing tests for flat and grouped command normalization.**

```python
def test_accepts_grouped_build_steps_and_preserves_flat_compatibility(self):
    data = valid_manifest_data()
    data["commands"]["build"] = [["cc", "-c", "a.c"], ["cc", "a.o", "-o", "a"]]

    manifest = validate_manifest(data)

    self.assertEqual(manifest.commands.build, ("cc", "-c", "a.c"))
    self.assertEqual(manifest.commands.build_steps, (
        ("cc", "-c", "a.c"), ("cc", "a.o", "-o", "a"),
    ))

def test_rejects_grouped_command_with_unknown_placeholder(self):
    data = valid_manifest_data()
    data["commands"]["prepare"] = [["git", "-C", "{repo}", "{shell}"]]
    with self.assertRaises(ScopeHoundError):
        validate_manifest(data)
```

- [ ] **Step 2: Run the focused tests and verify they fail for the missing group fields.**

Run: `python3 -m unittest tests.test_manifest -v`

Expected: the new grouped-command assertions fail because `Commands` has no normalized group fields and `prepare` is not accepted.

- [ ] **Step 3: Implement normalized groups and placeholder validation.**

Add `prepare_steps` as an optional group, normalize flat lists into one-step groups, preserve existing flat attributes, and add `{source_c}`, `{object}`, and `{revision}` to the approved placeholder set. Validate that all nested argv elements are non-empty strings and that required placeholders occur exactly once in the command where required.

- [ ] **Step 4: Add workspace containment tests and implementation.**

```python
def test_campaign_paths_are_contained(self):
    workspace = Workspace(Path(temp_dir))
    self.assertEqual(workspace.campaign_file("example-parser"),
                     workspace.target_dir("example-parser") / "campaign.json")
    self.assertTrue(workspace.controls_dir("example-parser").is_relative_to(workspace.root))
```

Add the four workspace accessors and keep `_contained` as the single path-safety gate.

- [ ] **Step 5: Add command-group plan tests and implementation.**

```python
def test_command_plans_substitute_each_step_without_shell(self):
    manifest = validate_manifest(valid_manifest_data())
    group = (("cc", "-I", "{repo}", "-o", "{binary}"), ("./{binary}", "{artifact}"))
    plans = command_plans(manifest, Workspace(Path(temp_dir)), group,
                          stage="harness", timeout_seconds=30, mutates=True)
    self.assertEqual(plans[0].argv[0], "cc")
    self.assertNotIn("{repo}", plans[0].argv)
    self.assertFalse(any(";" in argument for argument in plans[1].argv))
```

Resolve each placeholder to a workspace-contained path, reject unresolved placeholders, and preserve the existing `build_plan`, `fuzz_plan`, and `run_plan` behavior by routing new callers through this helper only when grouped commands are configured.

- [ ] **Step 6: Run all affected tests and commit.**

Run: `python3 -m unittest tests.test_manifest tests.test_workspace tests.test_runner -v`

Expected: all focused tests pass, including the pre-existing flat-command tests.

Commit: `git add scopehound/manifest.py scopehound/workspace.py scopehound/runner.py tests/test_manifest.py tests/test_workspace.py tests/test_runner.py && git commit -m "feat: normalize campaign command groups"`

### Task 2: Add resumable campaign state and staged execution

**Files:**
- Create: `scopehound/campaign.py`
- Modify: `scopehound/workspace.py`
- Modify: `scopehound/runner.py`
- Modify: `scopehound/errors.py`
- Create: `tests/test_campaign.py`
- Modify: `tests/test_end_to_end.py`

**Interfaces:**
- `StageRecord(stage: str, status: str, input_digest: str, attempts: int, commands: tuple[dict[str, object], ...], error: str | None)` is JSON-serializable.
- `CampaignState(campaign_id: str, target: str, manifest_digest: str, revision: str, engine: str, backend: str, created_at: str, updated_at: str, stages: tuple[StageRecord, ...])` is JSON-serializable.
- `create_campaign(manifest: Manifest, workspace: Workspace, *, engine: str, backend: str) -> CampaignState` creates `campaign.json` atomically and creates `repo`, `build`, `generated`, `binaries`, `corpus`, `artifacts`, `coverage`, `provenance`, `reports`, and `controls` directories.
- `load_campaign(path: Path) -> CampaignState` rejects malformed or missing state with `input_invalid`.
- `run_stage(state: CampaignState, manifest: Manifest, workspace: Workspace, stage: str, group: CommandGroup, *, execute: bool, force: bool = False) -> CampaignState` refuses a stale input digest, preserves previous attempts, blocks execution after a failed prerequisite, and writes an atomic updated state.
- `manifest_digest(manifest: Manifest) -> str` hashes canonical JSON containing target, authorization, commands, environment, opportunity, and corpus.

- [ ] **Step 1: Write failing tests for state creation, atomic persistence, and stale resume rejection.**

```python
def test_campaign_creation_records_digest_and_directories(self):
    state = create_campaign(manifest, workspace, engine="standalone", backend="native")
    self.assertEqual(load_campaign(workspace.campaign_file("example-parser")).manifest_digest,
                     state.manifest_digest)
    self.assertTrue(workspace.artifacts_dir("example-parser").is_dir())

def test_resume_rejects_changed_manifest_without_overwriting_evidence(self):
    state = create_campaign(manifest, workspace, engine="standalone", backend="native")
    changed_data = valid_manifest_data()
    changed_data["target"]["revision"] = "different-immutable-commit"
    changed = validate_manifest(changed_data)
    with self.assertRaises(ScopeHoundError) as raised:
        run_stage(state, changed, workspace, "build", changed.commands.build_steps,
                  execute=False)
    self.assertEqual(raised.exception.category, "campaign_stale")
```

- [ ] **Step 2: Run the campaign tests and verify the missing-module failures.**

Run: `python3 -m unittest tests.test_campaign -v`

Expected: import failures for `scopehound.campaign` and no campaign record.

- [ ] **Step 3: Implement canonical manifest hashing and state records.**

Serialize dataclasses recursively with sorted keys and compact separators, hash UTF-8 JSON with SHA-256, use UTC ISO-8601 timestamps, and write via `<path>.tmp` followed by `Path.replace`. Store stage attempts as append-only records; never delete a prior result.

- [ ] **Step 4: Implement stage prerequisites and explicit force behavior.**

Allow `prepare -> build -> harness_build -> run -> controls` ordering. A failed or missing prerequisite raises `campaign_blocked`; a changed manifest/group digest raises `campaign_stale`; `force=True` appends an attempt with a new input digest rather than replacing the previous attempt.

- [ ] **Step 5: Run focused and end-to-end state tests, then commit.**

Run: `python3 -m unittest tests.test_campaign tests.test_end_to_end -v`

Expected: state creation, resume, stale rejection, failed-prerequisite blocking, and atomic writes pass.

Commit: `git add scopehound/campaign.py scopehound/workspace.py scopehound/runner.py scopehound/errors.py tests/test_campaign.py tests/test_end_to_end.py && git commit -m "feat: add resumable campaign state"`

### Task 3: Implement local fuzz engines and deterministic standalone execution

**Files:**
- Create: `scopehound/engines.py`
- Create: `scopehound/standalone_driver.c`
- Modify: `scopehound/runner.py`
- Create: `tests/test_engines.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- `EngineInfo(name: str, available: bool, executable: str | None, reason: str)` describes one engine without silently falling back.
- `EngineRun(engine: str, status: str, command: tuple[str, ...], duration_seconds: float, input_count: int, corpus_before: int, corpus_after: int, artifacts: tuple[str, ...], mutations: tuple[dict[str, object], ...], stdout: str, stderr: str, toolchain: Mapping[str, str], skipped_reason: str | None)` is JSON-serializable.
- `list_engines() -> tuple[EngineInfo, ...]` reports `standalone` when GCC is available and `libfuzzer` only when a Clang/libFuzzer compiler is available.
- `deterministic_mutations(seed: bytes, *, max_input_size: int, count: int, seed_value: int) -> tuple[bytes, ...]` returns stable bounded mutations.
- `run_standalone(binary: Path, corpus: Path, artifacts: Path, *, duration_seconds: int, max_input_size: int, seed_value: int, execute: bool, backend: str) -> EngineRun` invokes the file-input driver once per seed/mutation, records parent digest and mutation seed, and keeps sanitizer output per invocation.
- `run_libfuzzer(binary: Path, corpus: Path, artifacts: Path, *, duration_seconds: int, dictionary: Path | None, execute: bool, backend: str) -> EngineRun` builds a shell-free libFuzzer argv and records an explicit unavailable result when Clang is missing.

- [ ] **Step 1: Write failing tests for engine discovery and deterministic mutation lineage.**

```python
def test_mutations_are_deterministic_and_size_bounded(self):
    first = deterministic_mutations(b"{}", max_input_size=8, count=4, seed_value=7)
    second = deterministic_mutations(b"{}", max_input_size=8, count=4, seed_value=7)
    self.assertEqual(first, second)
    self.assertTrue(all(len(item) <= 8 for item in first))

def test_engine_listing_does_not_claim_missing_libfuzzer(self):
    names = {item.name: item for item in list_engines()}
    self.assertIn("standalone", names)
    self.assertIn("libfuzzer", names)
    if shutil.which("clang") is None:
        self.assertFalse(names["libfuzzer"].available)
```

- [ ] **Step 2: Run the engine tests and verify they fail before implementation.**

Run: `python3 -m unittest tests.test_engines -v`

Expected: import failures for `scopehound.engines` and `scopehound.standalone_driver` integration helpers.

- [ ] **Step 3: Implement deterministic mutations and engine discovery.**

Use `random.Random(seed_value)` with operations limited to byte replacement, insertion, deletion, and truncation. Enforce `max_input_size` after every operation. Report tool versions from `gcc --version` and `clang --version` through bounded argv calls.

- [ ] **Step 4: Add the standalone C file-input driver.**

The driver must compile as C11, accept exactly one artifact path, read at most the configured input limit, call `LLVMFuzzerTestOneInput(data, size)`, free the buffer, and return the callback status. It must never open sockets or execute a command.

- [ ] **Step 5: Implement standalone and libFuzzer run records.**

Run each input with `subprocess.run(..., shell=False, timeout=...)`, write stdout/stderr beneath the attempt directory, copy only sanitizer artifacts into the campaign artifact directory, and record `parent_sha256`, `mutation_seed`, and `input_sha256` for each generated input. An unavailable requested engine raises `engine_unavailable`; it never substitutes another engine.

- [ ] **Step 6: Run focused tests and commit.**

Run: `python3 -m unittest tests.test_engines tests.test_runner tests.test_cli -v`

Expected: deterministic mutation, tool availability, bounded command, explicit skip, and JSON serialization tests pass.

Commit: `git add scopehound/engines.py scopehound/standalone_driver.c scopehound/runner.py tests/test_engines.py tests/test_cli.py && git commit -m "feat: add explicit local fuzz engines"`

### Task 4: Add reviewed target packs and cJSON control matrix

**Files:**
- Create: `scopehound/targetpacks.py`
- Create: `scopehound/controls.py`
- Create: `target-packs/cjson.json`
- Create: `tests/test_targetpacks.py`
- Create: `tests/test_controls.py`
- Modify: `scopehound/manifest.py`

**Interfaces:**
- `HarnessRecipe(name: str, source: str, includes: tuple[str, ...], api_symbol: str, cleanup: str, compile_sources: tuple[str, ...], compile_flags: tuple[str, ...], link_flags: tuple[str, ...], expected_sanitizer: str)` is explicit reviewed metadata.
- `ControlRevision(label: str, requested_revision: str, commit: str | None, expected: str, role: str)` records positive, fixed, and current controls.
- `cjson_target_pack() -> Mapping[str, object]` returns the repository URL, reviewed harness recipe, public malformed-input seed, and requested control tags.
- `resolve_revision(repo: Path) -> str` returns `git rev-parse HEAD` from a detached checkout and rejects moving refs in recorded state.
- `run_control_matrix(pack: Mapping[str, object], workspace: Workspace, *, engine: str, backend: str, duration_seconds: int, execute: bool) -> Mapping[str, object]` runs the same harness/input against positive, fixed, and current checkouts and writes `controls/<control>.json` plus `controls/comparison.json`.
- `compare_controls(records: Sequence[Mapping[str, object]]) -> Mapping[str, object]` labels `positive_reproduced`, `fixed_not_reproduced`, `current_observed`, `current_not_observed`, or `inconclusive` from observed fingerprints and return codes without assigning severity.

- [ ] **Step 1: Write failing tests for recipe cleanup and immutable control metadata.**

```python
def test_cjson_recipe_requires_cleanup_and_public_seed(self):
    pack = cjson_target_pack()
    recipe = pack["harness"]
    self.assertEqual(recipe.cleanup, "cJSON_Delete(json)")
    self.assertEqual(pack["seed"], b'{"1":1,')
    self.assertEqual({item.role for item in pack["controls"]}, {"positive", "fixed", "current"})

def test_compare_controls_distinguishes_fixed_and_current(self):
    result = compare_controls([
        {"label": "v1.7.17", "expected": "heap-buffer-overflow", "fingerprints": ["parse_string"]},
        {"label": "v1.7.18", "expected": "no-crash", "fingerprints": []},
        {"label": "current", "expected": "exploratory", "fingerprints": []},
    ])
    self.assertEqual(result["positive_status"], "positive_reproduced")
    self.assertEqual(result["fixed_status"], "fixed_not_reproduced")
    self.assertEqual(result["current_status"], "current_not_observed")
```

- [ ] **Step 2: Run target-pack tests and verify they fail before implementation.**

Run: `python3 -m unittest tests.test_targetpacks tests.test_controls -v`

Expected: import failures for `scopehound.targetpacks` and `scopehound.controls`.

- [ ] **Step 3: Implement the reviewed cJSON pack and manifest serialization.**

Use the official repository URL and requested tags `v1.7.17`, `v1.7.18`, and a caller-supplied current revision. Store the public issue URL and seed as metadata; do not claim a current-version result in the pack. Validate cleanup is non-empty for cJSON and serialize recipe/control objects with sorted keys.

- [ ] **Step 4: Implement detached-revision resolution and control comparison.**

Run only `git rev-parse HEAD` inside an already prepared local checkout. Reject `HEAD`, `main`, `master`, and other moving values in a recorded control record. Preserve raw logs and normalized sanitizer fingerprints for each control and treat missing toolchains as explicit `inconclusive` records.

- [ ] **Step 5: Run focused tests and commit.**

Run: `python3 -m unittest tests.test_targetpacks tests.test_controls tests.test_manifest -v`

Expected: recipe, public seed, control roles, immutable revision, and comparison tests pass.

Commit: `git add scopehound/targetpacks.py scopehound/controls.py target-packs/cjson.json scopehound/manifest.py tests/test_targetpacks.py tests/test_controls.py && git commit -m "feat: add cJSON control matrix"`

### Task 5: Wire campaign, engines, controls, and evidence into the CLI

**Files:**
- Modify: `scopehound/cli.py`
- Modify: `scopehound/reporting.py`
- Modify: `scopehound/bundling.py`
- Modify: `scopehound/findings.py`
- Modify: `README.md`
- Modify: `examples/example-target.json`
- Create: `tests/test_campaign_cli.py`
- Modify: `tests/test_reporting.py`
- Modify: `tests/test_bundling.py`

**Interfaces:**
- `scopehound engines --json` prints every engine with availability and skip reason.
- `scopehound campaign --manifest PATH --workspace PATH --engine standalone --backend native --duration 5 [--force-stage STAGE] [--execute] --json` creates/resumes a state record and emits stage summaries.
- `scopehound controls --target-pack cjson --workspace PATH --engine standalone --backend native --duration 5 [--execute] --json` writes the control matrix and comparison record; it requires an authorized pack manifest when execution is requested.
- Reports and bundles include `campaign_id`, exact revision/commit, engine/backend/toolchain, control statuses, input lineage, and minimized-child parent digest while retaining the existing no-severity/no-send checklist.

- [ ] **Step 1: Write failing CLI tests for engine listing, campaign dry-run, and controls refusal without authorization.**

```python
def test_engines_json_lists_explicit_availability(self):
    result = subprocess.run([sys.executable, "-m", "scopehound", "engines", "--json"],
                            capture_output=True, text=True, check=False)
    payload = json.loads(result.stdout)
    self.assertEqual({item["name"] for item in payload["engines"]}, {"standalone", "libfuzzer"})

def test_campaign_dry_run_writes_state_without_running_target(self):
    code = main(["campaign", "--manifest", str(manifest_path), "--workspace", str(root),
                 "--engine", "standalone", "--backend", "native", "--duration", "1", "--json"])
    self.assertEqual(code, 0)
    self.assertTrue((root / "targets" / "example-parser" / "campaign.json").is_file())

def test_controls_requires_authorized_manifest_for_execution(self):
    code = main(["controls", "--target-pack", "cjson", "--workspace", str(root),
                 "--engine", "standalone", "--backend", "native", "--duration", "1", "--execute"])
    self.assertNotEqual(code, 0)
```

- [ ] **Step 2: Run the CLI tests and verify failures are caused by missing subcommands.**

Run: `python3 -m unittest tests.test_campaign_cli -v`

Expected: argparse rejects `engines`, `campaign`, and `controls` before implementation.

- [ ] **Step 3: Add CLI dispatch and stable JSON output.**

Keep all existing parser helpers, add explicit engine/backend/duration arguments, return structured `ScopeHoundError` categories, and ensure dry-run never creates a target checkout or launches a target process.

- [ ] **Step 4: Link control/campaign records into report and bundle output.**

Add optional `--campaign` and `--controls` paths. Render exact commands, immutable commits, toolchain, engine/backend policy, raw/normalized sanitizer data, original artifact digest, minimized child digest, and human review gates. Never render a current signal as a confirmed vulnerability and never invoke network or messaging code.

- [ ] **Step 5: Update README and example configuration.**

Document the cJSON workflow, the distinction between positive/fixed/current controls, GCC/ASan fallback requirements, explicit engine skips, dry-run behavior, local evidence paths, and the human disclosure checklist. Add grouped command syntax without removing the existing flat example.

- [ ] **Step 6: Run focused CLI/report/bundle tests and commit.**

Run: `python3 -m unittest tests.test_campaign_cli tests.test_reporting tests.test_bundling -v`

Expected: subcommands, JSON records, disclosure-safe rendering, and backwards-compatible output pass.

Commit: `git add scopehound/cli.py scopehound/reporting.py scopehound/bundling.py scopehound/findings.py README.md examples/example-target.json tests/test_campaign_cli.py tests/test_reporting.py tests/test_bundling.py && git commit -m "feat: expose campaign and control workflows"`

### Task 6: Execute and verify the real cJSON integration

**Files:**
- Create: `tests/integration/test_cjson_campaign.py`
- Create: `docs/real-library-validation.md`
- Modify: `README.md`
- Create: `scripts/run_cjson_validation.sh`

**Interfaces:**
- The integration test uses a temporary directory, clones only the cJSON repository when network access is explicitly available, resolves tags to commit IDs, compiles the reviewed harness with GCC and `-fsanitize=address,undefined`, and stores current evidence outside the repository.
- `scripts/run_cjson_validation.sh` accepts `--workspace`, `--duration`, and `--execute`; it prints exact skipped-tool reasons and exits nonzero for a requested execution that cannot prove the positive/fixed controls.
- `docs/real-library-validation.md` records the tested commit IDs, tool versions, command lines, positive/fixed observed fingerprints, current status, and cleanup instructions without publishing current artifacts.

- [ ] **Step 1: Write the integration test and fixture driver before implementation changes.**

```python
def test_cjson_positive_reproduces_and_fixed_does_not(self):
    if shutil.which("gcc") is None or shutil.which("git") is None:
        self.skipTest("gcc and git are required for the real-library validation")
    result = run_cjson_validation(temp_dir, duration_seconds=2, execute=True)
    self.assertEqual(result["positive"]["status"], "positive_reproduced")
    self.assertEqual(result["fixed"]["status"], "fixed_not_reproduced")
    self.assertRegex(result["positive"]["fingerprint"], r"parse_string|heap-buffer-overflow")
    self.assertNotIn("current", result["published_paths"])
```

- [ ] **Step 2: Run the integration test once to verify environmental prerequisites and expected initial failure.**

Run: `python3 -m unittest tests.integration.test_cjson_campaign -v`

Expected: it skips only when Git/GCC/network are unavailable; otherwise it fails because the validation runner has not been implemented.

- [ ] **Step 3: Implement the temporary-workspace cJSON runner.**

Clone with explicit Git argv, checkout the requested tags, record `git rev-parse HEAD`, compile `cJSON.c` plus the reviewed file-input harness, run the public malformed seed, parse ASan output, and run the same binary/input against v1.7.18. Pin the current revision from a resolved commit supplied by the caller and bound its run by the requested duration.

- [ ] **Step 4: Add validation documentation and command wrapper.**

Print the positive/fixed/current matrix, exact compiler/tool versions, SHA-256 input digest, and replay command. Keep temporary evidence under the supplied workspace, add it to `.gitignore` if the workspace is inside the repository, and state that current observations require human scope/root-cause/duplicate review.

- [ ] **Step 5: Run the full verification suite and commit the integration assets.**

Run: `python3 -m unittest discover -s tests -q && python3 -m compileall -q scopehound tests && git diff --check`

Expected: all unit tests pass; the integration test either passes the cJSON positive/fixed controls or reports a precise environmental skip; no current evidence is tracked by Git.

Commit: `git add tests/integration/test_cjson_campaign.py docs/real-library-validation.md scripts/run_cjson_validation.sh README.md && git commit -m "test: validate cJSON control matrix"`

## Final verification

After all tasks, run:

```bash
python3 -m unittest discover -s tests -q
python3 -m compileall -q scopehound tests
python3 -m scopehound engines --json
python3 -m scopehound validate --manifest examples/example-target.json --json
git diff --check
git status --short
```

The expected final state is a clean worktree except for intentionally ignored temporary campaign evidence, 100% passing existing tests, explicit engine availability output, and a committed real-library validation record that contains no current-version crash artifact.
