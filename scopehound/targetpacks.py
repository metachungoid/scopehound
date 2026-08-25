from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from scopehound.errors import ScopeHoundError


@dataclass(frozen=True)
class HarnessRecipe:
    name: str
    source: str
    includes: tuple[str, ...]
    api_symbol: str
    input_expression: str
    length_expression: str
    cleanup: str
    compile_sources: tuple[str, ...]
    compile_flags: tuple[str, ...]
    link_flags: tuple[str, ...]
    expected_sanitizer: str


@dataclass(frozen=True)
class ControlRevision:
    label: str
    requested_revision: str
    commit: str | None
    expected: str
    role: str


_CJSON_HARNESS = r'''#include "cJSON.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    cJSON *json = cJSON_ParseWithLength((const char *)data, size);
    if (json != NULL) {
        cJSON_Delete(json);
    }
    return 0;
}
'''


def cjson_target_pack(current_revision: str = "current") -> Mapping[str, object]:
    recipe = HarnessRecipe(
        name="cjson-parse-with-length",
        source=_CJSON_HARNESS,
        includes=("cJSON.h",),
        api_symbol="cJSON_ParseWithLength",
        input_expression="(const char *)data",
        length_expression="size",
        cleanup="cJSON_Delete(json)",
        compile_sources=("cJSON.c", "cjson_harness.c", "standalone_driver.c"),
        compile_flags=("-g", "-O1", "-fsanitize=address,undefined"),
        link_flags=("-fsanitize=address,undefined",),
        expected_sanitizer="heap-buffer-overflow in parse_string",
    )
    controls = (
        ControlRevision("v1.7.17", "v1.7.17", None, "heap-buffer-overflow", "positive"),
        ControlRevision("v1.7.18", "v1.7.18", None, "no-crash", "fixed"),
        ControlRevision(current_revision, current_revision, None, "exploratory", "current"),
    )
    return {
        "name": "cjson",
        "repository": "https://github.com/DaveGamble/cJSON.git",
        "public_references": (
            "https://github.com/DaveGamble/cJSON",
            "https://github.com/DaveGamble/cJSON/security",
            "https://github.com/DaveGamble/cJSON/issues/800",
        ),
        "seed": b'{"1":1,',
        "harness": recipe,
        "controls": controls,
    }


def resolve_revision(repo: Path) -> str:
    repository = repo.resolve()
    if not repository.is_dir():
        raise ScopeHoundError("workspace_missing", f"repository checkout is missing: {repository}")
    try:
        branch = subprocess.run(
            ("git", "symbolic-ref", "--quiet", "--short", "HEAD"),
            cwd=repository, capture_output=True, text=True, shell=False, timeout=30, check=False,
        )
        if branch.returncode == 0 and branch.stdout.strip():
            raise ScopeHoundError("revision_not_immutable", "checkout must be detached before recording")
        result = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=repository, capture_output=True, text=True, shell=False, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScopeHoundError("revision_failed", f"could not resolve checkout revision: {error}") from error
    commit = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ScopeHoundError("revision_failed", "checkout did not yield an immutable commit ID")
    return commit.lower()
