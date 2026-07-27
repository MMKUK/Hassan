# Hassan operator runbooks

Factual procedures for running nodes. No maturity slogans. See also
`SECURITY.md`, `NODE.md`, `PUBLIC.md`.

## Coordinated upgrade (STATE_FORMAT / genesis bump)

Example: v30 → v31 (`hassan-genesis-v31`, `STATE_FORMAT_VERSION = 31`).

1. Publish the binary and wipe note to every operator.
2. Stop miners / stratum on every node.
3. Wipe each `HASSAN_DATA_DIR` (or delete `chainstate.bin` + `.bak` / `.bak.1`).
4. Deploy the **same** new binary everywhere.
5. Start archival seed(s) first, then peers.
6. Confirm `/api/v1/status` shows matching genesis domain and tip growth.

Do not mix state-format versions or genesis domains — nodes will fork.

Wire `PROTOCOL_VERSION` (currently 7) is independent of state format. A wire
bump without a state bump still requires matching binaries for gossip.

## Corrupt or unreadable `chainstate.bin`

- The process **exits** if the file exists but fails to load (fail-closed).
- Restore `chainstate.bak` or `chainstate.bak.1`, or wipe the data dir and
  re-sync (IBD / genesis).
- Never hand-edit `chainstate.bin`.

## Deep reorg / finality

- Economic finality depth is `FINALITY_DEPTH` blues
  (`FINALITY_TARGET_HOURS × 3_600_000 / BLOCK_TIME_MS`; production = 432000 ≈ 12 h
  at 100 ms). API `is_final` uses the same threshold.
- Reorg attempts that rewrite history deeper than the finality point are
  rejected by consensus.
- If honest tips diverge across a partition longer than finality, treat as an
  incident: stop writers, compare `chain_hash` / tips, restore from known-good
  archival peers, wipe and IBD if necessary.

## Peer version skew

- Hello negotiates protocol version; incompatible peers disconnect.
- Ban score + IP bans (public mode) apply to invalid blocks, oversized
  messages, and STARK budget abuse.
- Pruning-proof adopt uses hard `verified_work` / linear `cumulative_work`
  only, plus freshness / upgrade gates (stale PP rejection, genesis match).

## Peer identity pins (close TOFU)

```bash
# File or comma-separated hex ML-DSA-87 pubkeys (optional hex@host:port)
export HASSAN_PEER_PINS=/etc/hassan/peer-pins.txt
# Reject unpinned identities (recommended for known seed sets)
export HASSAN_PEER_PINS_STRICT=1
```

Pin file: one entry per line; `#` comments allowed. Without pins, first
contact remains TOFU.

## Stratum

```bash
export HASSAN_STRATUM_PASSWORD='…'   # required
```

Share path enforces: password auth, submit rate limits, duplicate-nonce
reject, stale-job reject, consecutive-reject temporary ban, max workers.

## Bootstrap PoW policy (unchanged issuance rule)

- Floor **7000** while minted &lt; 1M HSN; then hard floor **`2^24`**.
- Optional `HASSAN_BOOTSTRAP_EASY=1` keeps 7000 after 1M (peers must match).
- DAA is blue-work weighted (window 661) on top of this floor schedule.
