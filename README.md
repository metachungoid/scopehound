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

Executed command output is recorded beneath the target's `logs` directory.

Local fixture repositories require an additional deliberate flag:

```bash
scopehound prepare \
  --manifest local-fixture.json \
  --workspace .scopehound \
  --allow-local-repository \
  --execute
```

## Triage and report drafts

Deduplicate byte-identical artifacts and write stable JSON:

```bash
scopehound triage \
  --artifacts .scopehound/targets/example-parser/artifacts \
  --output .scopehound/targets/example-parser/triage.json
```

Create a Markdown evidence draft for one artifact:

```bash
scopehound report \
  --manifest target.json \
  --artifact .scopehound/targets/example-parser/artifacts/crash-001 \
  --output .scopehound/targets/example-parser/reports/crash-001.md
```

The draft requires human completion of reachability, root-cause, impact,
duplicate, current-version, and scope-policy checks. ScopeHound never transmits
the report.

## Command summary

- `validate`: parse and validate a target manifest
- `score`: calculate and explain the opportunity score
- `prepare`: plan or clone an authorized repository at a pinned revision
- `build`: plan or run the manifest's build command
- `fuzz`: plan or run the bounded local fuzz command
- `triage`: hash and group local artifacts
- `report`: render a human-review Markdown disclosure draft

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
