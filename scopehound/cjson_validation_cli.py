from __future__ import annotations

import argparse
import json
from pathlib import Path

from scopehound.cjson_validation import run_cjson_validation
from scopehound.errors import ScopeHoundError
from scopehound.manifest import load_manifest
from scopehound.targetpacks import CJSON_CURRENT_COMMIT


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local cJSON control validation")
    parser.add_argument("--workspace", type=Path, default=Path(".scopehound-cjson"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--current-revision", default=CJSON_CURRENT_COMMIT)
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest) if args.manifest else None
        result = run_cjson_validation(
            workspace=args.workspace, current_revision=args.current_revision,
            duration_seconds=args.duration, execute=args.execute, manifest=manifest,
        )
    except ScopeHoundError as error:
        print(json.dumps({"ok": False, "error": error.category, "message": error.message}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.execute:
        comparison = result.get("comparison", {})
        if comparison.get("positive_status") != "positive_reproduced":
            return 1
        if comparison.get("fixed_status") != "fixed_not_reproduced":
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
