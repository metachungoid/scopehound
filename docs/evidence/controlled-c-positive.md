# Controlled C positive proof

This record validates ScopeHound's local matrix, sanitizer parser, replay
accounting, and issue-package gate. `tests/fixtures/controlled_bug.c` contains
an intentional one-byte heap write past a one-byte allocation. It is a test
fixture, not a third-party library and not a vulnerability disclosure.

The integration test compiles it with a locally available C compiler and ASan,
runs the bounded `campaign-matrix`, captures the sanitizer output, replays the
same artifact twice, compares against an empty local known-issue index, and
writes an immutable package with `candidate_status: new_candidate` and
`novelty: unverified`.

Run it with:

```bash
python3 -m unittest tests.integration.test_campaign_matrix -v
```

The proof demonstrates pipeline behavior only. It does not establish global
novelty, severity, exploitability, authorization for any external target, or a
bounty payout.
