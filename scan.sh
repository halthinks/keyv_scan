#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'Error: Node.js 18 or newer is required.' >&2
  exit 2
fi
NODE_MAJOR=$(node -p "process.versions.node.split('.')[0]" 2>/dev/null || printf '0')
if [ "$NODE_MAJOR" -lt 18 ] 2>/dev/null; then
  printf '%s\n' "Error: Node.js 18 or newer is required; found $(node -p 'process.versions.node' 2>/dev/null || printf unknown)." >&2
  exit 2
fi
exec node "$SCRIPT_DIR/bin/keyv-scan.js" scan "$@"
