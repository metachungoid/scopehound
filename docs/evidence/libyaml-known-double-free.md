# libyaml event-ownership double-free control

> Historical upstream bug evidence. This is not a new vulnerability or a
> zero-day claim.

## Summary

ScopeHound's findings parser identified a reproducible double-free in the
libyaml event API at revision
`90a56d4500aa1a1798514c5cb55c3ad4cb095f94`. The behavior is publicly tracked
as [libyaml issue #297](https://github.com/yaml/libyaml/issues/297).

The caller initializes a sequence-start event with an allocated anchor, passes
the event to `yaml_emitter_emit`, destroys the emitter, and then destroys the
original event. The emitter queue stores a shallow copy of the event. Emitter
destruction frees the queued copy's anchor; deleting the caller's original
event frees the same allocation a second time.

## ScopeHound evidence

- **Target:** libyaml
- **Revision:** `90a56d4500aa1a1798514c5cb55c3ad4cb095f94`
- **Compiler:** GCC `(Ubuntu 15.2.0-16ubuntu1)`
- **Flags:** `-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined`
- **Runs:** 2/2 reproduced with return code `1`
- **Parsed findings:** 1
- **Kind:** `double-free`
- **Fingerprint:** `d604f8749b15f6ef749f`
- **Location:** `src/api.c:53` in `yaml_free`
- **Stack:** `yaml_event_delete` → `yaml_emitter_delete` → caller event cleanup
- **Binary SHA-256:** `701e491fdc6d04812333aeaa92cf8a0cf47adad1d85d534e426a534759bd30e9`

The full sanitizer log and the machine-readable ScopeHound finding remain in
the local evidence workspace:

`/home/flip/Development/libyaml-research/run-2026-08-25/`

## Security classification

This is a known API ownership bug, not a newly discovered issue. A CVE number
was once reserved in connection with the upstream report, but later public
tracking records state that the candidate was withdrawn; this report therefore
makes no CVE or severity claim. See the [upstream issue](https://github.com/yaml/libyaml/issues/297)
and [Ubuntu's status record](https://ubuntu.com/security/CVE-2024-35325).

Applications should follow the library's documented event-ownership contract
and avoid deleting an event after ownership has been transferred and consumed
by the emitter. Maintainers should define and enforce ownership semantics, or
make the emitter copy owned fields instead of retaining shallow aliases.

## Reproduction boundary

The PoC source is retained locally and is not committed here. This repository
records the exact revision, sanitizer classification, reproducibility count,
and upstream references without publishing a new exploit artifact.
