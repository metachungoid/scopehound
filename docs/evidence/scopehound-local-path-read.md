# SH-LOCAL-001: minimization child path escaped the evidence scope (fixed)

> Newly identified in a review of ScopeHound itself. This is a local-tool
> security finding, not a third-party CVE or a zero-day claim.

## Executive summary

Before this fix, ScopeHound's bundle creator accepted a minimization record
containing a `child` path and copied that file into the output bundle. The path
was resolved and checked for regular-file status, but it was not constrained to
the artifact/evidence workspace. A crafted `minimization.json` could therefore
make the process copy a readable regular file into a bundle that might later be
shared with maintainers.

## Finding SH-LOCAL-001

- **Severity:** Medium in workflows that share bundles; Low for single-user,
  trusted-input operation
- **Class:** Local arbitrary-file inclusion / information disclosure
- **Affected code:** [`scopehound/bundling.py:73-78`](/home/flip/Development/scopehound/scopehound/bundling.py:73)
  and [`scopehound/bundling.py:166-177`](/home/flip/Development/scopehound/scopehound/bundling.py:166)
- **Precondition:** The operator invokes bundling with `--minimization` (or
  the API's `minimization_path`) and processes a record that is not trusted.
- **Impact before the fix:** Any regular file readable by the ScopeHound
  process could be copied into the review bundle, creating an accidental
  disclosure channel.

### Reproduction

The local proof created `outside-workspace/operator-secret.txt`, pointed
`minimization.json` at that file, and called `create_bundle()` against the
vulnerable implementation. The observed result was:

```text
copied_exists=True
copied_contents=SCOPEHOUND_CANARY_SECRET
```

After the fix, the same input is rejected with
`ScopeHoundError("unsafe_path", "minimization child must remain inside the artifact directory")`,
and the regression test confirms that no outside file is copied.

The proof script and output log are retained locally at:

`/home/flip/Development/scopehound-research/scopehound-local-path-read-poc.py`

`/home/flip/Development/scopehound-research/scopehound-local-path-read.log`

### Root cause

Before the fix, `_minimized_child()` called
`Path(child).expanduser().resolve()` and only checked regular-file status. It
did not compare the resolved path with the artifact directory, the
minimization record's directory, or another explicit evidence root.
`create_bundle()` then passed the unchecked path to `_copy_input()` and wrote it
into the bundle.

### Remediation implemented

`create_bundle()` now passes the artifact directory as the trusted evidence
root. `_minimized_child()` resolves the candidate and requires
`candidate.relative_to(artifact_root)` to succeed before copying it. Paths
outside the artifact directory, including symlink-resolved escapes, are
rejected with `ScopeHoundError("unsafe_path", ...)`. The bundling test suite
includes an outside-workspace canary regression test.

## Disclosure status

This was a newly identified local finding in ScopeHound and is now remediated
in the working tree. No external maintainer was contacted, and no private file
contents were committed. The original canary contained only the literal test
string `SCOPEHOUND_CANARY_SECRET`.
