#!/usr/bin/env bash
# Build a local Hassan release package under dist/hassan-<os>-<arch>/.
# Includes node binary, explorer, genesis docs, checksums, and VERSION
# metadata. Wallet/signer live in MMKUK/Hassan-Wallet.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Always write into this repo's ./target (ignore a redirected CARGO_TARGET_DIR).
export CARGO_TARGET_DIR="$ROOT/target"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  mingw*|msys*|cygwin*) OS=windows ;;
  darwin) OS=darwin ;;
  linux) OS=linux ;;
esac
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
esac

CRATE_VERSION="$(grep -E '^version\s*=' Cargo.toml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY=""
if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
  GIT_DIRTY="+dirty"
fi
BUILD_TIME_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GENESIS_DOMAIN="$(grep -E 'GENESIS_DOMAIN' src/genesis.rs | head -1 | sed -E 's/.*b"([^"]+)".*/\1/' || echo hassan-genesis)"
OUT="dist/hassan-${OS}-${ARCH}"
STAGE="${OUT}.staging.$$"

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/explorer" "$STAGE/docs" "$STAGE/scripts"

echo "==> cargo build --release (hassan)"
cargo build --release --bin hassan

NODE_BIN="$CARGO_TARGET_DIR/release/hassan"
if [[ "$OS" == "windows" ]]; then
  NODE_BIN="${NODE_BIN}.exe"
fi
test -f "$NODE_BIN" || { echo "missing $NODE_BIN"; exit 1; }

NODE_NAME="hassan"
if [[ "$OS" == "windows" ]]; then
  NODE_NAME="hassan.exe"
fi

cp -f "$NODE_BIN" "$STAGE/bin/$NODE_NAME"
chmod +x "$STAGE/bin/$NODE_NAME" 2>/dev/null || true

# Flat alias at package root (convenient for run-node.sh)
cp -f "$STAGE/bin/$NODE_NAME" "$STAGE/$NODE_NAME"
chmod +x "$STAGE/$NODE_NAME" 2>/dev/null || true

cp -f scripts/run-node.sh "$STAGE/run-node.sh"
cp -f scripts/run-node.cmd "$STAGE/run-node.cmd"
cp -f scripts/run-node.sh "$STAGE/scripts/run-node.sh"
cp -f scripts/run-node.cmd "$STAGE/scripts/run-node.cmd"
chmod +x "$STAGE/run-node.sh" "$STAGE/scripts/run-node.sh"

cp -f NODE.md "$STAGE/docs/NODE.md"
cp -f SECURITY.md "$STAGE/docs/SECURITY.md"
cp -f PUBLIC.md "$STAGE/docs/PUBLIC.md" 2>/dev/null || true
cp -f RELEASE.md "$STAGE/docs/RELEASE.md" 2>/dev/null || true
cp -f genesis.toml "$STAGE/genesis.toml"
cp -f NODE.md "$STAGE/NODE.md"
cp -f RELEASE.md "$STAGE/RELEASE.md" 2>/dev/null || true

# Standalone explorer (also embedded in the node binary at compile time)
cp -f hassan-explorer/index.html "$STAGE/explorer/index.html"
cp -f hassan-explorer/app.js "$STAGE/explorer/app.js"
cp -f hassan-explorer/style.css "$STAGE/explorer/style.css"
cp -f hassan-explorer/README.md "$STAGE/explorer/README.md"

# Indexer / ops notes (served as docs; runtime DB is under HASSAN_DATA_DIR/indexer/)
cat > "$STAGE/docs/INDEXER.md" <<'EOF'
# Hassan explorer indexer

The node maintains a checksummed archival index under:

  $HASSAN_DATA_DIR/indexer/index.bin

Separate from hot chainstate.bin. Indexes selected-chain blocks, transfers,
address activity, labels, and analytics series for fast explorer search.

Enable archival history for full pruning-proof downloads:

  export HASSAN_ARCHIVAL=1

API:

  GET /api/v1/indexer/status
  GET /api/v1/search?q=
  GET /api/v1/analytics/history?limit=
  GET /api/v1/address/<addr>/history
  GET /api/v1/labels
  GET /api/v1/audit/pack
  GET /api/v1/audit/diff?from=&to=
  GET /api/v1/pruning/proof
  GET /api/v1/utxo/snapshot?limit=
  GET /api/v1/fees/history
  GET /api/v1/block/<id>/audit
  GET /api/v1/block/<id>/mergeset
  GET /api/v1/events/sse

Public API is rate-limited per IP. Write routes require Authorization: Bearer
$HASSAN_API_TOKEN when HASSAN_PUBLIC=1 or when binding a non-loopback API.
EOF
cp -f "$STAGE/docs/INDEXER.md" "$STAGE/INDEXER.md" 2>/dev/null || true


cat > "$STAGE/VERSION.json" <<EOF
{
  "name": "hassan",
  "crate_version": "${CRATE_VERSION}",
  "git_commit": "${GIT_COMMIT}${GIT_DIRTY}",
  "build_time_utc": "${BUILD_TIME_UTC}",
  "target": "${OS}-${ARCH}",
  "genesis_domain": "${GENESIS_DOMAIN}",
  "pow_algo": "blake3-512",
  "layout": {
    "bin": ["bin/${NODE_NAME}"],
    "explorer": "explorer/",
    "docs": ["docs/NODE.md", "docs/SECURITY.md", "docs/INDEXER.md", "docs/RELEASE.md"],
    "genesis": "genesis.toml"
  },
  "notes": "Local dist package — verify SHA256SUMS before running binaries."
}
EOF

cat > "$STAGE/VERSION.txt" <<EOF
Hassan local dist
=================
crate_version: ${CRATE_VERSION}
git_commit:    ${GIT_COMMIT}${GIT_DIRTY}
build_time:    ${BUILD_TIME_UTC}
target:        ${OS}-${ARCH}
genesis:       ${GENESIS_DOMAIN}
pow:           blake3-512
EOF

cat > "$STAGE/README.txt" <<EOF
Hassan node package (${OS}-${ARCH})
===================================

Layout
------
  hassan                   — node binary (also under bin/)
  run-node.sh / run-node.cmd
  explorer/                — Hassan Explorer (HTML/JS/CSS)
  genesis.toml             — consensus parameters (documentation)
  VERSION.json / VERSION.txt
  SHA256SUMS
  docs/NODE.md, docs/SECURITY.md, docs/INDEXER.md
  INDEXER.md               — explorer indexer + audit API notes

Quick start — hardest local stack (node + indexer + explorer)
------------------------------------------------------------
  ./run-node.sh            # macOS / Linux
  run-node.cmd             # Windows

  Then open: http://127.0.0.1:8080/

  The node serves the explorer at the same origin as the JSON API and
  maintains a checksummed indexer under HASSAN_DATA_DIR/indexer/.

  Optional archival (full pruning proofs):
    export HASSAN_ARCHIVAL=1
    ./run-node.sh

Standalone explorer (optional / CDN)
------------------------------------
  Point any static file server at explorer/, then use the connect panel
  to set the node API base (e.g. http://127.0.0.1:8080). Static assets
  are served with Cache-Control when embedded in the node.

Wallet / signer
---------------
  Not in this package. See https://github.com/MMKUK/Hassan-Wallet
  for hassan-wallet, hassan-signer, and the watch web UI.

Mining (CPU / laptop / mobile-friendly path)
--------------------------------------------
  PoW: Blake3-512 XOF. Bootstrap floor 7000 until 1M HSN minted, then hard
  floor 2^24. Target block time 100ms; parallel tips raise aggregate BPS with
  more nodes. Solo miner runs inside the node; stratum helpers and
  GET /api/v1/mining/light support share-difficulty hashing on commodity CPUs.

Verify this package (Monero-style checksums)
--------------------------------------------
  # Always verify BEFORE running binaries
  ./scripts/verify-dist.sh .
  # or:
  shasum -a 256 -c SHA256SUMS          # macOS
  sha256sum -c SHA256SUMS              # Linux

  Optional: SHA256SUMS.asc (GPG), SHA256SUMS.sig (SSH/cosign),
  or SHA256SUMS.abs.json (Hassan-Wallet hassan-signer ML-DSA ABS) when signed.

See docs/NODE.md, docs/RELEASE.md, and docs/INDEXER.md.
This folder is a local build artifact — not a worldwide release mirror.
EOF

# Checksums over package contents (exclude the sums / signature files)
(
  cd "$STAGE"
  if command -v sha256sum >/dev/null 2>&1; then
    find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.blake3 ! -name SHA256SUMS.sig ! -name SHA256SUMS.asc ! -name SHA256SUMS.abs.json ! -name SIGNED | sort | xargs sha256sum > SHA256SUMS
  else
    find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.blake3 ! -name SHA256SUMS.sig ! -name SHA256SUMS.asc ! -name SHA256SUMS.abs.json ! -name SIGNED | sort | while read -r f; do
      shasum -a 256 "$f"
    done > SHA256SUMS
  fi
)

# Optional detached signature. Never claim "signed" without a successful sign.
SIGNED_FLAG=0
if [[ -n "${COSIGN_KEY:-}" ]] && command -v cosign >/dev/null 2>&1; then
  echo "==> cosign signing SHA256SUMS"
  cosign sign-blob --key "$COSIGN_KEY" --output-signature "$STAGE/SHA256SUMS.sig" "$STAGE/SHA256SUMS"
  SIGNED_FLAG=1
elif [[ -n "${HASSAN_DIST_SSH_KEY:-}" ]] && command -v ssh-keygen >/dev/null 2>&1; then
  echo "==> ssh-keygen signing SHA256SUMS"
  ssh-keygen -Y sign -f "$HASSAN_DIST_SSH_KEY" -n file "$STAGE/SHA256SUMS"
  mv -f "$STAGE/SHA256SUMS.sig" "$STAGE/SHA256SUMS.sig"
  SIGNED_FLAG=1
elif [[ -n "${HASSAN_DIST_GPG_KEY:-}" ]] && command -v gpg >/dev/null 2>&1; then
  echo "==> gpg signing SHA256SUMS"
  gpg --detach-sign --armor -u "$HASSAN_DIST_GPG_KEY" -o "$STAGE/SHA256SUMS.asc" "$STAGE/SHA256SUMS"
  SIGNED_FLAG=1
elif [[ -n "${HASSAN_DIST_SIGNER_KEYSTORE:-}" ]]; then
  SIGNER_BIN=""
  if command -v hassan-signer >/dev/null 2>&1; then SIGNER_BIN=hassan-signer
  elif [[ -x "${HASSAN_SIGNER_BIN:-}" ]]; then SIGNER_BIN="$HASSAN_SIGNER_BIN"
  fi
  if [[ -z "$SIGNER_BIN" ]]; then
    echo "HASSAN_DIST_SIGNER_KEYSTORE set but hassan-signer not on PATH (build MMKUK/Hassan-Wallet)" >&2
    exit 1
  fi
  echo "==> hassan-signer ABS signing SHA256SUMS (HASSAN_DIST_SIGNER_KEYSTORE)"
  SUMS_HEX="$(xxd -p -c 256 "$STAGE/SHA256SUMS" | tr -d '\n')"
  if [[ -z "${HASSAN_WALLET_PASSWORD:-}" && "${HASSAN_DIST_SIGNER_INSECURE:-}" != "1" ]]; then
    echo "set HASSAN_WALLET_PASSWORD for the release keystore, or HASSAN_DIST_SIGNER_INSECURE=1" >&2
    exit 1
  fi
  "$SIGNER_BIN" sign-hex hassan-dist-sha256sums "$SUMS_HEX" \
    "$HASSAN_DIST_SIGNER_KEYSTORE" > "$STAGE/SHA256SUMS.abs.json"
  SIGNED_FLAG=1
else
  echo "==> no signing key (COSIGN_KEY / HASSAN_DIST_SSH_KEY / HASSAN_DIST_GPG_KEY / HASSAN_DIST_SIGNER_KEYSTORE) — leaving package unsigned"
fi
echo "$SIGNED_FLAG" > "$STAGE/SIGNED"
if [[ "$SIGNED_FLAG" -eq 0 ]]; then
  echo "signed: no" >> "$STAGE/VERSION.txt"
else
  echo "signed: yes" >> "$STAGE/VERSION.txt"
fi

cp -f scripts/verify-dist.sh "$STAGE/scripts/verify-dist.sh" 2>/dev/null || true
chmod +x "$STAGE/scripts/verify-dist.sh" 2>/dev/null || true

# Blake3-512 of VERSION.json when the just-built binary is available
if [[ -x "$STAGE/$NODE_NAME" ]] || [[ -f "$STAGE/$NODE_NAME" ]]; then
  # Record binary sizes for operators
  {
    echo "node_bytes=$(wc -c < "$STAGE/$NODE_NAME" | tr -d ' ')"
  } >> "$STAGE/VERSION.txt"
fi

rm -rf "$OUT"
mv "$STAGE" "$OUT"

echo "==> packed: $OUT"
echo "==> VERSION:"
cat "$OUT/VERSION.txt"
echo "==> contents:"
find "$OUT" -type f | sort | sed 's|^|  |'
echo "==> verify with: scripts/verify-dist.sh $OUT"
