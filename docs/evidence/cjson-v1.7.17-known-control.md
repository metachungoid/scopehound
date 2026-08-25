# cJSON v1.7.17 known memory-safety control

> Historical control evidence only. This is not a new vulnerability or a
> zero-day claim.

## Summary

ScopeHound reproduced the publicly documented cJSON issue [#800](https://github.com/DaveGamble/cJSON/issues/800)
against cJSON v1.7.17. The issue is an AddressSanitizer-reported
heap-buffer-overflow in `parse_string` when `cJSON_ParseWithLength` receives a
truncated object input without a trailing NUL byte.

The parser reaches the object-member path after a trailing comma. In v1.7.17,
`parse_object` increments the input offset and calls `parse_string` without
first checking that another byte is available. `parse_string` then reads past
the caller-supplied buffer while looking for a string terminator. The v1.7.18
control adds a `cannot_access_at_index(input_buffer, 1)` guard before that
increment and returns a parse failure instead.

## ScopeHound evidence

| Control | Revision | Result |
| --- | --- | --- |
| Positive | `87d8f0961a01bf09bef98ff89bae9fdec42181ee` (v1.7.17) | `positive_reproduced` |
| Fixed | `acc76239bee01d8e9c858ae2cab296704e52d916` (v1.7.18) | `fixed_not_reproduced` |
| Current | `fb16e5cf358798aabb049655975cde8427101056` | `current_not_observed` |

The positive sanitizer fingerprint was `heap-buffer-overflow in
parse_string`. The positive process exited with return code `-6`; fixed and
current controls exited normally. All three controls used the same 7-byte
input, whose SHA-256 is:

`d77007aae7cf6b1644150a7aff86a158a29bd72410bd2b9c14c6d1a3589164a8`

Builds used GCC with `-g -O1 -fsanitize=address,undefined` and the reviewed
`cJSON_ParseWithLength` harness. The machine-readable comparison is retained
outside this repository at:

`/home/flip/Development/cjson-validation-results/scopehound-cli-run-2026-08-25/targets/cjson/controls/comparison.json`

## Reproduction boundary

The raw input and sanitizer logs remain in the local evidence workspace rather
than being committed here. This repository records the immutable revisions,
input digest, sanitizer classification, and fixed/current comparison so the
result is auditable without publishing a new exploit artifact.

## Classification

- **Finding type:** known historical memory-safety regression
- **Novelty:** previously reported upstream; not a zero-day
- **Affected control:** cJSON v1.7.17
- **Fixed control:** cJSON v1.7.18
- **Disclosure action:** none; upstream issue #800 is already public
