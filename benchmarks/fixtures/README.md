# ScopeHound benchmark fixtures

This fixture set is local and deterministic. It measures whether changes make
generated candidates more useful, rather than rewarding feature count alone.

`benchmark.json` is versioned. Each entry records link status, coverage delta,
CPU seconds, replay outcome, unique fingerprints, duplicate count, and
false-positive count. The current fixture categories cover a known sanitizer
signal, a compile-failing candidate, a non-security harness crash, duplicate
artifacts, and a non-replayable signal.

The benchmark never contacts a repository or service. Missing LLVM tools are
reported as explicit skips. Treat a higher link rate or feature count as an
improvement only when replay success and false-positive/duplicate rates do not
regress.
