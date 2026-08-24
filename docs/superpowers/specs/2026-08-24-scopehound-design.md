# ScopeHound Design

## Purpose

ScopeHound is a local-first command-line research assistant for authorized
memory-safety testing of C and C++ open-source projects. It turns an explicit
scope record into reproducible build and fuzzing work, ranks targets by likely
research value, and packages reproducible crash evidence for human review.

The tool does not test remote services, infer authorization from repository
popularity, submit vulnerability reports, or claim that every sanitizer crash
is a security vulnerability.

## Goals

- Make authorization and bounty eligibility a prerequisite for execution.
- Clone an approved repository at an immutable revision.
- Run project-supplied build and fuzz commands with sanitizer-oriented
  environment settings.
- Rank authorized targets using transparent, editable opportunity factors.
- Collect, fingerprint, and deduplicate local crash artifacts.
- Cluster distinct artifacts by sanitizer fingerprint for issue-level triage.
- Produce a report bundle containing reproduction and scope evidence.
- Operate safely in dry-run mode by default.

## Non-goals

- Automatic exploit development or severity guarantees.
- Remote scanning, denial-of-service testing, or credential testing.
- Automatic bounty submission or communication with maintainers.
- General-purpose distributed fuzzing in the first release.
- Automatic generation of production-quality fuzz harnesses in the first
  release. The MVP records harness commands supplied by a researcher.

## User Flow

1. A researcher creates a target manifest containing the repository, pinned
   revision, scope-policy URL, authorization status, eligible issue classes,
   build command, fuzz command, and opportunity factors.
2. `scopehound validate` checks the manifest. Commands that execute project
   code require `authorization.status: authorized` and a non-empty policy URL.
3. `scopehound score` explains the target's opportunity score and each factor.
4. `scopehound prepare` clones the repository into a target-specific workspace
   and checks out the pinned revision. It prints the planned actions unless the
   user explicitly supplies `--execute`.
5. `scopehound build` runs the approved build command with configured sanitizer
   environment variables. It is also dry-run by default.
6. `scopehound fuzz` runs the manifest's local fuzz command for a bounded number
   of seconds and stores artifacts beneath the workspace. It is dry-run by
   default and rejects unbounded durations.
7. `scopehound reproduce` replays an artifact through an explicitly configured
   command and compares the sanitizer fingerprint against the baseline finding.
8. `scopehound triage` fingerprints artifact files, groups duplicates and
   sanitizer signatures, records hashes and metadata, and creates one report
   directory per unique artifact.
9. `scopehound report` renders a Markdown disclosure draft for human review.

## Architecture

ScopeHound is a Python 3.11+ package with no required runtime dependencies.
Configuration uses JSON so parsing remains in the standard library. YAML can
be added later behind an optional dependency.

The package is divided into focused modules:

- `manifest`: parse, validate, and normalize target manifests.
- `scoring`: calculate and explain opportunity scores.
- `policy`: enforce authorization gates and safe command constraints.
- `workspace`: derive safe paths and manage local repository preparation.
- `runner`: construct and execute bounded subprocesses.
- `triage`: hash artifacts, group duplicates, and write triage metadata.
- `reporting`: render human-reviewable Markdown reports.
- `validation`: syntax-check generated harness candidates and record status.
- `cli`: expose stable subcommands and JSON output.

All state lives under a user-selected workspace, defaulting to
`.scopehound/` in the current directory. Target names must be simple slugs, and
all derived paths are verified to remain inside the workspace.

## Manifest Model

The initial JSON manifest has these sections:

```json
{
  "schema_version": 1,
  "target": {
    "name": "example-parser",
    "repository": "https://example.invalid/project.git",
    "revision": "full-commit-or-release-tag",
    "language": "c"
  },
  "authorization": {
    "status": "authorized",
    "policy_url": "https://example.invalid/security-policy",
    "checked_at": "2026-08-24",
    "eligible_classes": ["memory-corruption"],
    "notes": "Local testing of this repository is permitted."
  },
  "commands": {
    "build": ["cmake", "-S", ".", "-B", "build"],
    "fuzz": ["./build/parser_fuzzer"],
    "reproduce": ["./build/parser_fuzzer", "{artifact}"]
  },
  "environment": {
    "CC": "clang",
    "CXX": "clang++",
    "CFLAGS": "-O1 -g -fsanitize=address,undefined",
    "CXXFLAGS": "-O1 -g -fsanitize=address,undefined"
  },
  "opportunity": {
    "bounty_eligibility": 1.0,
    "attacker_reachability": 0.8,
    "code_criticality": 0.7,
    "change_recency": 0.6,
    "fuzzing_gap": 0.9,
    "build_reproducibility": 0.8,
    "duplicate_risk": 0.4
  }
}
```

Commands are arrays rather than shell strings. They are executed without a
shell, preventing shell expansion and making the recorded command exact.

## Authorization and Safety

- Execution requires an explicitly authorized manifest and policy URL.
- Dry-run is the default for clone, build, and fuzz commands.
- The repository URL must use HTTPS or SSH Git syntax; local paths are allowed
  only when explicitly selected with `--allow-local-repository`.
- Revisions are required; a moving default branch is rejected.
- Commands run without a shell and with a bounded timeout.
- Fuzzing is local and receives an explicit maximum duration.
- Workspace paths are resolved and checked before file creation.
- Existing target checkouts are never overwritten automatically.
- Reports include a conspicuous `human_review_required` field.
- Scope records contain the date on which the researcher verified the policy,
  because program terms can change.

The tool cannot prove that a scope declaration is truthful. It creates a
deliberate authorization checkpoint and auditable record; the researcher
remains responsible for confirming current program rules.

## Opportunity Scoring

Each factor is a number from 0 through 1. The score is:

```text
100 * geometric_mean(
  bounty eligibility,
  attacker reachability,
  code criticality,
  change recency,
  fuzzing gap,
  build reproducibility
) * (1 - 0.75 * duplicate risk)
```

The geometric mean prevents a very high score in one category from hiding a
near-zero prerequisite. Duplicate risk applies a strong but non-terminal
penalty. Output always includes the factors and formula inputs so researchers
can challenge the ranking.

## Triage and Reporting

The MVP treats each artifact as untrusted bytes. It computes SHA-256 and a
normalized filename-independent fingerprint, records file size, and groups
byte-identical artifacts. When findings are supplied, triage also groups
distinct artifacts by their sanitizer fingerprint; this is an issue candidate,
not a root-cause or severity determination.

Each report draft contains:

- target repository and revision
- scope-policy URL and verification date
- build and fuzz commands
- artifact hash and relative path
- sanitizer fingerprint groups and reproduction evidence when available
- reproduction placeholder
- impact and reachability placeholders
- duplicate-search and current-version confirmation checklists
- a warning that human security analysis is required

No report is transmitted by ScopeHound.

## Error Handling

CLI commands return structured JSON on `--json` and concise text otherwise.
Expected failures use stable categories such as `manifest_invalid`,
`authorization_required`, `unsafe_path`, `command_failed`, and `timeout`.
Subprocess output is saved to target-specific log files when execution is
enabled. Secrets are not accepted as manifest fields and environment output is
limited to variables declared by the manifest.

## Testing

The test suite uses `unittest` and temporary directories. Tests cover:

- valid and invalid manifests
- authorization gating
- revision, repository, slug, and command validation
- scoring math and boundary values
- path-containment protections
- dry-run command construction
- bounded subprocess behavior
- artifact hashing and deduplication
- deterministic report generation
- an end-to-end flow using a temporary local Git repository

Implementation follows test-driven development: each behavior begins with a
failing test, followed by the smallest production change that makes it pass.

## MVP Acceptance Criteria

- `python -m scopehound --help` works on Python 3.11 or newer.
- A bundled example manifest validates and produces an explained score.
- All mutating or code-executing commands are dry-run unless `--execute` is
  present.
- An unauthorized or incomplete manifest cannot clone, build, or fuzz.
- A local fixture repository can be prepared, built, fuzzed for a bounded
  duration, triaged, and rendered into a report draft.
- The complete test suite passes without network access.
- README documentation explains the authorization model and includes a safe
  local demonstration.

## Deferred Work

- Automatic OSS-Fuzz and bounty-program metadata ingestion.
- Coverage import and Fuzz Introspector integration.
- LLM-assisted harness generation and repair.
- Stack-based crash clustering and regression-range detection.
- Container backends, job queues, and multi-machine scheduling.
- YAML manifests and a browser interface.
