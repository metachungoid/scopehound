# Real-library validation: cJSON

ScopeHound includes a local cJSON control validation for testing the evidence
pipeline against a real ANSI C library. It uses the public malformed-input
control described in [cJSON issue #800](https://github.com/DaveGamble/cJSON/issues/800):
the exact seed is `{"1":1,` with no trailing newline.

The matrix has three roles:

- `positive`: cJSON v1.7.17, expected to reproduce the public
  `heap-buffer-overflow` in `parse_string`.
- `fixed`: cJSON v1.7.18, expected not to reproduce that signal.
- `current`: a caller-selected immutable commit, bounded exploratory evidence
  only. Current observations are not published or treated as findings by the
  tool.

## Run

Execution requires a manifest whose authorization status is `authorized` and
whose policy has been personally verified for the intended local research:

```bash
scripts/run_cjson_validation.sh \
  --manifest cjson-authorized.json \
  --workspace .scopehound-cjson \
  --current-revision fb16e5cf358798aabb049655975cde8427101056 \
  --duration 5 \
  --execute
```

The command clones the repository only for this explicit preparation step,
detaches at each requested revision, records `git rev-parse HEAD`, compiles
`cJSON.c` with GCC `-fsanitize=address,undefined` and the reviewed harness, and
executes only the local file-input driver. The target process receives no
network service or submission capability. The input SHA-256, compiler version,
exact compile/run argv, raw sanitizer output, normalized fingerprint, and
positive/fixed/current statuses are written under the supplied workspace.

Plan without cloning or execution:

```bash
scripts/run_cjson_validation.sh --workspace .scopehound-cjson --duration 5
```

The output is evidence for human review. Before any private disclosure, verify
scope, root cause, attacker-controlled reachability, reproducibility, duplicate
status, latest eligible revision, and the program's designated channel.
