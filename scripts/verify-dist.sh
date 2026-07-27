#!/usr/bin/env bash
# Verify a Hassan dist package: SHA256SUMS (+ optional detached signature).
set -euo pipefail

DIR="${1:-}"
if [[ -z "$DIR" || ! -d "$DIR" ]]; then
  echo "usage: $0 <dist/hassan-os-arch>" >&2
  exit 2
fi

cd "$DIR"

if [[ ! -f SHA256SUMS ]]; then
  echo "missing SHA256SUMS" >&2
  exit 1
fi

echo "==> checking SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS
fi

SIGNED=0
if [[ -f SHA256SUMS.abs.json ]]; then
  SIGNER_BIN=""
  if [[ -x ./hassan-signer ]]; then SIGNER_BIN=./hassan-signer
  elif [[ -x ./bin/hassan-signer ]]; then SIGNER_BIN=./bin/hassan-signer
  elif command -v hassan-signer >/dev/null 2>&1; then SIGNER_BIN=hassan-signer
  fi
  if [[ -n "$SIGNER_BIN" ]]; then
    echo "==> verifying hassan-signer ABS signature"
    SUMS_HEX="$(xxd -p -c 256 SHA256SUMS | tr -d '\n')"
    "$SIGNER_BIN" verify-hex hassan-dist-sha256sums "$SUMS_HEX" SHA256SUMS.abs.json
    SIGNED=1
  else
    echo "SHA256SUMS.abs.json present but hassan-signer binary not found in package" >&2
    exit 1
  fi
elif [[ -f SHA256SUMS.sig ]]; then
  if command -v cosign >/dev/null 2>&1 && [[ -n "${COSIGN_YES:-}" || -f "${COSIGN_KEY:-}" ]]; then
    echo "==> verifying cosign signature"
    cosign verify-blob --signature SHA256SUMS.sig ${COSIGN_KEY:+--key "$COSIGN_KEY"} SHA256SUMS
    SIGNED=1
  elif command -v ssh-keygen >/dev/null 2>&1 && [[ -f SHA256SUMS.sig ]]; then
    if [[ -n "${HASSAN_DIST_SSH_PUBKEY:-}" && -f "${HASSAN_DIST_SSH_PUBKEY}" ]]; then
      echo "==> verifying ssh-keygen signature"
      ssh-keygen -Y verify -f "$HASSAN_DIST_SSH_PUBKEY" -n file -s SHA256SUMS.sig < SHA256SUMS
      SIGNED=1
    fi
  fi
elif [[ -f SHA256SUMS.asc ]] && command -v gpg >/dev/null 2>&1; then
  echo "==> verifying gpg signature"
  gpg --verify SHA256SUMS.asc SHA256SUMS
  SIGNED=1
fi

if [[ -f SIGNED ]]; then
  claim="$(tr -d '[:space:]' < SIGNED || true)"
  if [[ "$claim" == "1" || "$claim" == "true" || "$claim" == "yes" ]]; then
    if [[ "$SIGNED" -ne 1 ]]; then
      echo "SIGNED claims true but no verifiable detached signature present" >&2
      exit 1
    fi
  fi
fi

if [[ "$SIGNED" -eq 1 ]]; then
  echo "==> checksums + signature OK"
else
  echo "==> checksums OK (package is unsigned — build with a signing key to attach a sig)"
fi
