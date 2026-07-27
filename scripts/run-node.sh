#!/usr/bin/env bash
# Start a local Hassan node (loopback API + Tor-only P2P dial by default).
# Usage: ./scripts/run-node.sh [archive|validator|light] [extra hassan args...]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "$HERE/hassan" ]]; then
  BIN="$HERE/hassan"
elif [[ -x "$HERE/../target/release/hassan" ]]; then
  BIN="$HERE/../target/release/hassan"
  HERE="$(cd "$HERE/.." && pwd)"
elif [[ -x "$HERE/target/release/hassan" ]]; then
  BIN="$HERE/target/release/hassan"
else
  echo "hassan binary not found. Build first:"
  echo "  cargo build --release --bin hassan"
  echo "  or: ./scripts/build-dist.sh"
  exit 1
fi

ROLE="${1:-validator}"
shift || true
case "$ROLE" in
  archive|validator|light|full|help|-h|--help) ;;
  *)
    # First arg was not a role — pass it through as a hassan flag.
    set -- "$ROLE" "$@"
    ROLE="validator"
    ;;
esac

export HASSAN_DATA_DIR="${HASSAN_DATA_DIR:-$HERE/hassan-data}"
export HASSAN_API_BIND="${HASSAN_API_BIND:-127.0.0.1:8080}"

mkdir -p "$HASSAN_DATA_DIR"
echo "role:  $ROLE"
echo "data:  $HASSAN_DATA_DIR"
echo "api:   http://${HASSAN_API_BIND}/"
echo "bin:   $BIN"
exec "$BIN" "$ROLE" "$@"
