#!/usr/bin/env sh
# Compatibility launcher for users of AlextheYounga/keyv_scan.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "$SCRIPT_DIR/scan.sh" "$@"
