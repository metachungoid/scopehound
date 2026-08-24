from __future__ import annotations


def valid_manifest_data() -> dict[str, object]:
    return {
        "schema_version": 1,
        "target": {
            "name": "example-parser",
            "repository": "https://example.invalid/project.git",
            "revision": "v1.2.3",
            "language": "c",
        },
        "authorization": {
            "status": "authorized",
            "policy_url": "https://example.invalid/security-policy",
            "checked_at": "2026-08-24",
            "eligible_classes": ["memory-corruption"],
            "notes": "Local testing is permitted.",
        },
        "commands": {
            "build": ["cmake", "--build", "build"],
            "fuzz": ["./build/parser_fuzzer"],
        },
        "environment": {
            "CC": "clang",
            "CFLAGS": "-O1 -g -fsanitize=address,undefined",
        },
        "opportunity": {
            "bounty_eligibility": 1.0,
            "attacker_reachability": 0.8,
            "code_criticality": 0.7,
            "change_recency": 0.6,
            "fuzzing_gap": 0.9,
            "build_reproducibility": 0.8,
            "duplicate_risk": 0.4,
        },
    }
