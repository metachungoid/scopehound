# ScopeHound

ScopeHound is a local-first command-line assistant for authorized
memory-safety research on C and C++ open-source projects. It makes scope
evidence part of the executable workflow, ranks research opportunities, runs
researcher-supplied build and fuzz commands, deduplicates local artifacts, and
creates disclosure drafts for human review.

ScopeHound does **not** establish authorization, test remote services, develop
exploits, decide severity, or submit reports. Program terms change: verify the
current policy yourself before every campaign and again before disclosure.

## Requirements

- Python 3.11 or newer
- Git for repository preparation
- Project-specific compilers, build tools, fuzz harnesses, and sanitizers

The Python package has no required runtime dependencies.

## Install

From this repository:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/scopehound --help
```

You can also run it without installing:

```bash
python3 -m scopehound --help
```

## Start with the manifest

Copy `examples/example-target.json` and replace every template value. The
bundled example deliberately uses `permission-needed`; it validates and scores,
but execution remains blocked.

An executable target must include:

- the exact repository and immutable commit or release tag
- `authorization.status` set to `authorized`
- the policy URL and the date you personally checked it
- `memory-corruption` among the eligible classes
- build and fuzz commands expressed as argument arrays
- an optional artifact replay command with an explicit `{artifact}` placeholder
- optional `commands.harness_build` with `{repo}`, `{source}`, and `{binary}`
  placeholders for reviewed generated harnesses
- optional grouped command arrays (`commands.prepare`, grouped `build`, grouped
  `harness_build`, and grouped `fuzz`) for multi-step campaigns; flat arrays
  remain supported
- optional `corpus` settings for seed paths, dictionaries, input-size limits,
  and LLVM coverage collection
- opportunity factors between zero and one

The authorization record is an audit checkpoint, not proof that its claims are
true. The researcher remains responsible for complying with the program,
repository, and applicable law.

Validate and score a manifest:

```bash
scopehound validate --manifest examples/example-target.json
scopehound score --manifest examples/example-target.json
scopehound score --manifest examples/example-target.json --json
```

## Safe-by-default execution

Repository preparation, builds, and fuzz runs are dry-run operations unless
you add `--execute`:

```bash
scopehound prepare --manifest target.json --workspace .scopehound
scopehound build --manifest target.json --workspace .scopehound
scopehound fuzz --manifest target.json --workspace .scopehound --duration 300
```

Review the printed commands and paths. When they are correct:

```bash
scopehound prepare --manifest target.json --workspace .scopehound --execute
scopehound build --manifest target.json --workspace .scopehound --execute
scopehound fuzz --manifest target.json --workspace .scopehound --duration 300 --execute
```

Commands execute directly without a shell. Fuzz duration must be from 1 through
86,400 seconds, and ScopeHound applies a process timeout. The target's fuzz
command receives `SCOPEHOUND_ARTIFACTS_DIR`, pointing to:

```text
<workspace>/targets/<target-name>/artifacts
```

Executed command output is recorded beneath the target's `logs` directory. A
fuzz run also parses ASan/UBSan output into `findings.json`; a non-zero fuzz
exit is accepted as a finding when sanitizer evidence is present, but remains
an error when no sanitizer finding can be extracted.

## Resumable campaigns and local engines

The `campaign` command creates a target-scoped `campaign.json` and resumes only
when the manifest and stage input digests still match. It records every command
argv, result, timeout, backend policy, and failed prerequisite without deleting
previous attempts:

```bash
scopehound campaign \
  --manifest target.json \
  --workspace .scopehound \
  --engine standalone \
  --backend native \
  --duration 30 \
  --json
scopehound campaign \
  --manifest target.json \
  --workspace .scopehound \
  --engine standalone \
  --backend native \
  --duration 30 \
  --execute
```

`--force-stage STAGE` appends a new attempt when a stage's input digest has
changed. The `engines` command reports both available engines and explicit
tool skips:

```bash
scopehound engines --json
```

`standalone` runs a generated file-input driver and deterministic, bounded
mutations, so GCC plus AddressSanitizer/UndefinedBehaviorSanitizer is a useful
portable baseline when Clang/libFuzzer is unavailable. `libfuzzer` is reported
as unavailable unless Clang is installed; ScopeHound never silently substitutes
one engine for another.

## High-throughput candidate prioritization

For authorized local targets, `campaign-matrix` expands the manifest into
target × build-variant × engine jobs. It uses a bounded worker pool, isolated
state, stable job digests, explicit unavailable-engine skips, and resumable
JSON evidence:

```bash
scopehound campaign-matrix \
  --manifest campaign-matrix.json \
  --workspace .scopehound-matrix \
  --duration 60 \
  --json
scopehound campaign-matrix \
  --manifest campaign-matrix.json \
  --workspace .scopehound-matrix \
  --duration 60 \
  --execute \
  --retry \
  --json
```

Use `scopehound engines --all --json` to see optional AFL++, Honggfuzz, and
Centipede adapters. An unavailable adapter is recorded as skipped; the tool
does not install tools or silently replace one engine with another. Seeds and
dictionaries are hashed and size-bounded, and differential/metamorphic oracles
are recorded as input/output evidence. An oracle disagreement is not itself a
memory-safety finding.

The manifest's `economics` fields are researcher-entered prioritization
metadata. ScopeHound reports candidate rate, replay rate, duplicate rate,
CPU cost, and an expected-value-per-CPU-hour estimate only when a researcher
supplies reward metadata. That number is not a bounty prediction, severity
assessment, or guarantee of profit. Program terms, authorization, root cause,
duplicates, and impact still require human review.

See [`docs/campaign-matrix.md`](docs/campaign-matrix.md) and the runnable
[`examples/campaign-matrix.json`](examples/campaign-matrix.json) for the schema.

## Real-library control validation

The cJSON target pack uses the same reviewed `cJSON_ParseWithLength` harness and
public malformed-input seed across three local controls: v1.7.17 as a public
positive control, v1.7.18 as the fixed negative control, and a caller-supplied
immutable current commit for bounded exploration. The positive control validates
the pipeline; it does not establish a current-version vulnerability or severity.

Plan the matrix before execution:

```bash
scopehound controls \
  --target-pack cjson \
  --workspace .scopehound-cjson \
  --engine standalone \
  --backend native \
  --current-revision fb16e5cf358798aabb049655975cde8427101056 \
  --duration 5 \
  --json
```

Execution requires an authorized manifest and a resolved current commit. The
matrix writes `controls/comparison.json` with positive/fixed/current statuses,
exact revision and toolchain metadata, raw/normalized sanitizer evidence, and
no remote submission path. Current-version artifacts stay in the local
workspace until a human verifies scope, root cause, reproducibility, duplicates,
and the designated private disclosure channel.

The reviewed recipe includes cleanup (`cJSON_Delete(json)`) and the standalone
C driver is available at `scopehound/standalone_driver.c`. The cJSON metadata and
public references are in `target-packs/cjson.json`.

The real-library regression test is runnable from the repository and uses a
temporary checkout:

```bash
python3 -m unittest tests.integration.test_cjson_campaign -v
```

The verified control result reproduces the public v1.7.17 sanitizer signal and
does not reproduce it on v1.7.18. The pinned current revision is exercised in
the same run, but its evidence remains local and is never promoted or sent by
ScopeHound. A passing run reports `122` tests when included in the full suite:

```bash
python3 -m unittest discover -s tests -q
```

For a retained local record, use the validation wrapper described in
[`docs/real-library-validation.md`](docs/real-library-validation.md). Its
comparison record is written to:

```text
<workspace>/targets/cjson/controls/comparison.json
```

Local fixture repositories require an additional deliberate flag:

```bash
scopehound prepare \
  --manifest local-fixture.json \
  --workspace .scopehound \
  --allow-local-repository \
  --execute
```

Additional retained control reports are available under
[`docs/evidence/`](docs/evidence/):

- [`cJSON v1.7.17`](docs/evidence/cjson-v1.7.17-known-control.md) — known
  parser heap-buffer-overflow control.
- [`libyaml`](docs/evidence/libyaml-known-double-free.md) — known event-
  ownership double-free control.
- [`zlib v1.2.12`](docs/evidence/zlib-cve-2022-37434-known-control.md) —
  CVE-2022-37434 gzip-header extra-field control, compared with v1.2.13.

These are historical validation artifacts for the pipeline. They do not claim
new vulnerabilities, and ScopeHound does not transmit findings to maintainers.

## Triage and report drafts

After preparation, inspect the checkout for existing libFuzzer and OSS-Fuzz
harnesses:

```bash
scopehound discover \
  --repo .scopehound/targets/example-parser/repo \
  --output .scopehound/targets/example-parser/harnesses.json
```

The discovery report prioritizes files containing `LLVMFuzzerTestOneInput`,
`FUZZ_TEST`, or `DEFINE_PROTO_FUZZER`. It identifies candidates; it does not
pretend that a candidate is buildable until the project build validates it.

If a checkout has no existing harness, generate review-only libFuzzer
candidates from buffer-and-length APIs:

```bash
scopehound generate-harnesses \
  --repo .scopehound/targets/example-parser/repo \
  --output-dir .scopehound/targets/example-parser/generated-harnesses
```

Generated sources are marked `needs_build_validation` and must be reviewed and
built against the target before fuzzing. ScopeHound does not assume that a
declaration is safe, reachable, or ABI-compatible merely because it matches.

After preparing the authorized checkout, syntax-check those candidates without
linking or executing them:

```bash
scopehound validate-harnesses \
  --manifest target.json \
  --workspace .scopehound \
  --harnesses-dir .scopehound/targets/example-parser/generated-harnesses \
  --output .scopehound/targets/example-parser/harness-validation.json \
  --execute
```

The validation record distinguishes `planned`, `syntax_valid`, and
`syntax_invalid`. A successful syntax check is only a compiler-front-end check;
it does not establish linkability, reachability, or security impact.

## Build and run generated candidates

Generated sources become runnable only when the manifest opts in to a build
command. Placeholders are substituted per argument; shell interpolation is
never enabled:

```json
"commands": {
  "fuzz": ["{binary}", "-max_total_time={duration}", "{corpus}"],
  "harness_build": [
    "clang++", "-fsanitize=fuzzer,address,undefined",
    "-I", "{repo}", "{source}", "-o", "{binary}"
  ]
},
"corpus": {
  "seed_dir": "seeds",
  "dictionary": "parser.dict",
  "max_input_size": 1048576,
  "coverage_mode": "llvm"
}
```

Build candidates in the authorized workspace and inspect the compiler output:

```bash
scopehound build-harnesses \
  --manifest target.json \
  --workspace .scopehound \
  --harnesses-dir .scopehound/targets/example-parser/generated-harnesses \
  --execute
```

The result is `generated/harness-build.json` with one stable candidate ID and a
`planned`, `built`, `build_failed`, or `unconfigured` status. A build failure
is not converted into a security finding. Run only a candidate recorded as
`built`:

```bash
scopehound run-harness \
  --manifest target.json --workspace .scopehound \
  --candidate CANDIDATE_ID --duration 300 --execute
```

The run record is stored under `provenance/`; sanitizer findings are merged
into the target `findings.json` with normalized stacks and the full execution
provenance.

## Coverage feedback and target selection

Record corpus growth, engine statistics, coverage artifact digests, LLVM
function/edge deltas, CPU seconds, and finding counts:

```bash
scopehound coverage \
  --manifest target.json --workspace .scopehound \
  --candidate CANDIDATE_ID \
  --before .scopehound/targets/example-parser/corpus-before \
  --after .scopehound/targets/example-parser/corpus/CANDIDATE_ID \
  --engine-log .scopehound/targets/example-parser/logs/harness.log \
  --cpu-seconds 300 --finding-count 1
```

AST and Fuzz Introspector inputs are local advisory metadata. They never cause
network access:

```bash
scopehound analyze \
  --manifest target.json \
  --repo .scopehound/targets/example-parser/repo \
  --harnesses .scopehound/targets/example-parser/generated-harnesses/harnesses.json \
  --ast .scopehound/targets/example-parser/ast.json \
  --introspector .scopehound/targets/example-parser/fuzz-introspector.json \
  --output .scopehound/targets/example-parser/analysis.json
```

Ranking combines authorization, buildability, static reachability, coverage
gap, input suitability, and duplicate risk. The regex generator remains the
portable fallback when compiler metadata is unavailable.

## Provenance, minimization, and known issues

Executed findings and replays record the immutable revision, canonical manifest
digest, exact argv, selected environment, host/Python/compiler data, sanitizer
runtime, digests, timestamps, timeout, and backend policy. Raw sanitizer output
is preserved alongside normalized stack frames.

Minimize a crash only through the configured replay command. The original
artifact is never replaced; the child records its parent SHA-256:

```bash
scopehound minimize \
  --manifest target.json --workspace .scopehound \
  --artifact .scopehound/targets/example-parser/artifacts/crash-001 \
  --expected-fingerprint FINGERPRINT \
  --output .scopehound/targets/example-parser/provenance/minimize.json \
  --execute
```

Compare findings with researcher-supplied local JSON or CSV issue data:

```bash
scopehound known-issues \
  --manifest target.json \
  --findings .scopehound/targets/example-parser/findings.json \
  --issues researcher-known-issues.csv \
  --output .scopehound/targets/example-parser/known-issues.json
```

Results are `possible_duplicate`, `possible_regression`, or `new_candidate`;
none are silently suppressed.

## Execution backends

Native execution remains the default and is still bounded, shell-free, and
explicit. Request an isolated backend when the local tools are available:

```bash
scopehound run-harness ... --backend bubblewrap --execute
scopehound fuzz ... --backend docker --execute
```

`bubblewrap` uses a non-root user, no network, a read-only repository, and
resource limits. Docker uses the equivalent `--network none`, read-only
filesystem/repository, dropped capabilities, and process/memory limits. A
requested unavailable backend fails with `sandbox_unavailable`; ScopeHound
never falls back to native mode. Dry-run output includes the wrapped argv and
serialized policy.

## Benchmark effectiveness

Run the versioned local fixture set:

```bash
scopehound benchmark \
  --fixtures-dir benchmarks/fixtures \
  --workspace .scopehound-benchmark \
  --output benchmark.json --markdown benchmark.md
```

The report measures link success, mean coverage delta, unique fingerprints per
CPU-hour, replay success, duplicate rate, and false-positive rate. Missing LLVM
tools are explicit skips. A feature-count increase is not considered an
effectiveness improvement if these quality metrics regress.

For a finding with an artifact-specific baseline, add an authorized replay
command to the manifest, such as:

```json
"reproduce": ["./build/parser_fuzzer", "{artifact}"]
```

Then compare the replay's sanitizer fingerprint:

```bash
scopehound reproduce \
  --manifest target.json \
  --workspace .scopehound \
  --artifact .scopehound/targets/example-parser/artifacts/crash-001 \
  --findings .scopehound/targets/example-parser/findings.json \
  --output .scopehound/targets/example-parser/reproduction.json \
  --execute
```

The command is bounded and shell-free. A matching fingerprint marks the
baseline finding `reproduced`; a different or absent sanitizer signal is
recorded separately for human review.

Pass the resulting JSON to `scopehound report` with `--reproduction` to embed
the replay status, fingerprints, exit code, and captured output in the draft.

Deduplicate byte-identical artifacts and write stable JSON:

```bash
scopehound triage \
  --artifacts .scopehound/targets/example-parser/artifacts \
  --findings .scopehound/targets/example-parser/findings.json \
  --output .scopehound/targets/example-parser/triage.json
```

When `--findings` is supplied, triage adds deterministic sanitizer-fingerprint
groups so distinct input files that reach the same crash signature can be
documented as one issue candidate.

Parse an existing sanitizer log directly:

```bash
scopehound findings \
  --log .scopehound/targets/example-parser/logs/fuzz.log \
  --artifact .scopehound/targets/example-parser/artifacts/crash-001 \
  --output .scopehound/targets/example-parser/findings.json
```

Each finding includes the sanitizer, signal, source location, function,
symbolized stack frames when present, stable fingerprint, artifact name, raw
sanitizer block, and reproducibility status. Identical root-cause signatures
are deduplicated.

Create a Markdown evidence draft for one artifact:

```bash
scopehound report \
  --manifest target.json \
  --artifact .scopehound/targets/example-parser/artifacts/crash-001 \
  --findings .scopehound/targets/example-parser/findings.json \
  --campaign .scopehound/targets/example-parser/campaign.json \
  --controls .scopehound/targets/cjson/controls/comparison.json \
  --output .scopehound/targets/example-parser/reports/crash-001.md
```

The draft requires human completion of reachability, root-cause, impact,
duplicate, current-version, and scope-policy checks. ScopeHound never transmits
the report.

Package the local evidence for review without contacting a company:

```bash
scopehound bundle \
  --manifest target.json \
  --artifact .scopehound/targets/example-parser/artifacts/crash-001 \
  --findings .scopehound/targets/example-parser/findings.json \
  --triage .scopehound/targets/example-parser/triage.json \
  --reproduction .scopehound/targets/example-parser/reproduction.json \
  --minimization .scopehound/targets/example-parser/provenance/minimize.json \
  --coverage .scopehound/targets/example-parser/coverage/CANDIDATE_ID.json \
  --campaign .scopehound/targets/example-parser/campaign.json \
  --controls .scopehound/targets/cjson/controls/comparison.json \
  --output-dir .scopehound/targets/example-parser/disclosure-bundle
```

The bundle refuses to overwrite a non-empty directory and contains
`manifest.json`, the artifact, selected evidence files, an optional minimized
child artifact, `report.md`, and `bundle.json`. Review and redact it before any
private disclosure.

## Command summary

- `validate`: parse and validate a target manifest
- `score`: calculate and explain the opportunity score
- `prepare`: plan or clone an authorized repository at a pinned revision
- `build`: plan or run the manifest's build command
- `fuzz`: plan or run the bounded local fuzz command
- `discover`: find existing C/C++ fuzz harnesses in a checkout
- `generate-harnesses`: generate review-only libFuzzer harness candidates
- `validate-harnesses`: syntax-check generated harnesses under an authorized checkout
- `build-harnesses`: compile generated candidates and record link status
- `run-harness`: execute one built generated candidate for a bounded duration
- `coverage`: record corpus and coverage feedback
- `analyze`: rank candidates using local AST/reachability metadata
- `reproduce`: replay an artifact and compare its sanitizer fingerprint
- `minimize`: create a replay-preserving child artifact with parent provenance
- `known-issues`: compare findings with local JSON/CSV issue data
- `findings`: parse ASan/UBSan logs into structured findings
- `triage`: hash and group local artifacts
- `report`: render a human-review Markdown disclosure draft
- `bundle`: package local evidence into a human-review directory
- `benchmark`: measure local fixture effectiveness and quality gates
- `engines`: list local engines and explicit availability/skip reasons
- `campaign`: run or resume a staged, scope-gated local campaign
- `controls`: plan a cJSON positive/fixed/current control matrix

Every command supports `--help`; result-producing commands also support
`--json` for automation.

## Opportunity score

The score uses the geometric mean of bounty eligibility, attacker reachability,
code criticality, change recency, fuzzing gap, and build reproducibility. It
then applies a duplicate-risk penalty. A near-zero prerequisite therefore
cannot be hidden by several optimistic factors. Treat the score as a triage
aid, not a probability of payout.

## Development

Run the test suite without network access:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q scopehound tests
```

The end-to-end test creates a temporary local Git repository, checks out an
immutable commit, performs fixture build/fuzz commands, triages the generated
artifact, and writes a report draft.
