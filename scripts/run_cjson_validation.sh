#!/bin/sh
set -eu

exec python3 -m scopehound.cjson_validation_cli "$@"
