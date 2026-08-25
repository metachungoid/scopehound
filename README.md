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

Local fixture repositories require an additional deliberate flag:

```bash
scopehound prepare \
  --manifest local-fixture.json \
  --workspace .scopehound \
  --allow-local-repository \
  --execute
```

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
  --output-dir .scopehound/targets/example-parser/disclosure-bundle
```

The bundle refuses to overwrite a non-empty directory and contains
`manifest.json`, the artifact, selected evidence files, `report.md`, and
`bundle.json`. Review and redact it before any private disclosure.

## Command summary

- `validate`: parse and validate a target manifest
- `score`: calculate and explain the opportunity score
- `prepare`: plan or clone an authorized repository at a pinned revision
- `build`: plan or run the manifest's build command
- `fuzz`: plan or run the bounded local fuzz command
- `discover`: find existing C/C++ fuzz harnesses in a checkout
- `generate-harnesses`: generate review-only libFuzzer harness candidates
- `validate-harnesses`: syntax-check generated harnesses under an authorized checkout
- `reproduce`: replay an artifact and compare its sanitizer fingerprint
- `findings`: parse ASan/UBSan logs into structured findings
- `triage`: hash and group local artifacts
- `report`: render a human-review Markdown disclosure draft
- `bundle`: package local evidence into a human-review directory

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
