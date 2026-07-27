# Hassan node on another computer

Build the node (and CLI wallet) from this repo. Same hardcoded genesis
(`hassan-genesis-v31`) on every machine — consensus is compile-time only
(`src/genesis.rs`); `genesis.toml` is documentation, never loaded at runtime.

**Wipe note:** v31 raises economic finality to 432000 blues (~12 h), switches
DAA to a blue-work weighted 661-sample window, and tightens multilevel hop
DAA clamp anchors. Delete the data dir (and peers’ dirs) before running a
v31 binary after an upgrade from v30/earlier.

**Finality derivation:** `FINALITY_TARGET_HOURS (12) × 3_600_000 / BLOCK_TIME_MS (100) = 432000` blues. Pruning depth = `2 × finality`. See `OPERATORS.md`.

**Peer pins:** `HASSAN_PEER_PINS` (file or hex list); `HASSAN_PEER_PINS_STRICT=1` rejects unpinned ML-DSA identities.

**Corrupt / unreadable `chainstate.bin`:** the node **exits** rather than
silently restarting at genesis (which would overwrite the file on the next
save). Restore `chainstate.bak` / `chainstate.bak.1`, or wipe the data dir
explicitly after a version upgrade.

**P2P:** wire `PROTOCOL_VERSION` is 7 (UTXO gossip + headers-first body fetch).
Peers must run matching binaries; this is not a state-format wipe by itself.
Version skew → disconnect; invalidity → ban score / IP ban under public mode.

**Chain id** is `u64` LE of the first 8 bytes of `blake3(b"hassan")` (replay
protection in txs) — e.g. `16858749123010493047`. For wallets, prefer
**chain_hash**: Blake3-512 hex of `genesis_domain ‖ chain_id ‖ genesis_block_hash`
from `/api/v1/status` (or `hassan-wallet network`).

**Addresses** are bech32m `hsn1…` (32-byte Blake3 fingerprint of the ML-DSA-87
pubkey). Legacy `hsn:<128 hex>` is still accepted.

## Requirements

- Rust toolchain: https://rustup.rs (`rustc` 1.75+ is fine)
- macOS, Linux, or Windows
- Disk for `HASSAN_DATA_DIR` (chainstate grows with height)

## Build (any machine)

```bash
git clone <YOUR_REPO_URL> Hassan
cd Hassan
cargo build --release --bin hassan --bin hassan-wallet
```

Or use the packager (writes a folder under `dist/`):

```bash
./scripts/build-dist.sh
```

Binaries land in:

- `target/release/hassan` — node (API + miner + optional P2P + explorer)
- `target/release/hassan-wallet` — CLI wallet (talks to a running node)

Windows (PowerShell, after Rust is installed):

```powershell
cargo build --release --bin hassan --bin hassan-wallet
.\scripts\run-node.cmd
```

## Node roles (CLI)

```bash
./target/release/hassan --help
./target/release/hassan validator          # pruned; default; cheap VPS / laptop
./target/release/hassan archive            # full history seed / IBD helper
./target/release/hassan light              # cheapest mine profile (no indexer)
# future: true headers-only / mobile light client
```

**Default safety (all roles):** API on `127.0.0.1:8080`; Tor-only P2P dials
(`HASSAN_TOR=1`); no clearnet listen; when `HASSAN_PEER_PINS` is set, strict
pin checks turn on. Stratum / mining write routes need `HASSAN_API_TOKEN`
(and `HASSAN_STRATUM_PASSWORD` for stratum submits).

```bash
# Tor-only dial of a known peer (install a local Tor SOCKS, default :9050)
./target/release/hassan validator --peer yourseed.onion:9333

# Clearnet mesh (explicit)
./target/release/hassan validator --clearnet --listen 0.0.0.0:9333 --peer 1.2.3.4:9333
```

Or: `./scripts/run-node.sh validator`

## Run a local node (~0.10s solo under bootstrap)

```bash
rm -rf ./hassan-data   # wipe after audit / genesis bump
export HASSAN_DATA_DIR=./hassan-data
export HASSAN_API_BIND=127.0.0.1:8080
./target/release/hassan validator
# or: ./scripts/run-node.sh validator
```

No special env is required for easy CPU mining at genesis. **Default consensus**
uses bootstrap PoW floor **7000** until **1M HSN** is minted, then hard floor
**`2^24`**. Target block interval is **100 ms**. The solo producer searches one
template for up to 100 ms and paces so measured inter-block time stays near
**0.10 s** while PoW finishes early in the bootstrap era.

- API + explorer: http://127.0.0.1:8080/
- Indexer: `$HASSAN_DATA_DIR/indexer/index.bin` (see [`INDEXER.md`](INDEXER.md))
- Fresh data dir → starts at genesis **height 0**
- Old / wrong-format `chainstate.bin` is rejected → delete it to restart from 0

### Optional: stay on bootstrap floor after 1M minted

```bash
export HASSAN_BOOTSTRAP_EASY=1
```

Only needed if you want floor 7000 **past** the 1M HSN threshold. Every peer
must match or they fork. Not required for normal laptop mining from genesis.

### More nodes → more speed (DAG parallel throughput)

Per selected-parent DAA still targets ~100 ms. Honest nodes mining together
create sibling tips; GHOSTDAG admits them (k=40) and merges raise blue score by
mergeset size. Aggregate accepted blocks/sec scales with honest hashrate / node
count.

```bash
# Seed
export HASSAN_DATA_DIR=./data-seed
export HASSAN_P2P_LISTEN=0.0.0.0:9333
export HASSAN_API_BIND=127.0.0.1:8080
./target/release/hassan

# Peer (replace SEED_IP)
export HASSAN_DATA_DIR=./data-peer
export HASSAN_P2P_LISTEN=0.0.0.0:9334
export HASSAN_P2P_PEER=SEED_IP:9333
export HASSAN_API_BIND=127.0.0.1:8081
./target/release/hassan
```

Compare `tips` / block growth on `/api/v1/status` with one vs two miners.

```bash
cargo test --lib pow_eras_bootstrap_then_hard
cargo test --test multi_node_sim -- --test-threads=1
```

### Stratum

Set `HASSAN_STRATUM_PASSWORD` before workers call `mining.authorize`. Authorize
and submit fail without a matching password.

### Hardest local stack

```bash
export HASSAN_DATA_DIR=./hassan-data
export HASSAN_API_BIND=127.0.0.1:8080
export HASSAN_ARCHIVAL=1
./target/release/hassan
```

## Second computer (peer)

On the seed:

```bash
export HASSAN_DATA_DIR=./data-seed
export HASSAN_P2P_LISTEN=0.0.0.0:9333
export HASSAN_API_BIND=127.0.0.1:8080
export HASSAN_ARCHIVAL=1
./target/release/hassan
```

On the peer (replace `SEED_IP`):

```bash
export HASSAN_DATA_DIR=./data-peer
export HASSAN_P2P_LISTEN=0.0.0.0:9334
export HASSAN_P2P_PEER=SEED_IP:9333
export HASSAN_API_BIND=127.0.0.1:8081
./target/release/hassan
```

Open API / explorer only on loopback unless you set `HASSAN_API_TOKEN` and intentionally bind a public address (see `PUBLIC.md`).

## CLI wallet (until a GUI `.exe` exists)

```bash
export HASSAN_WALLET_PASSWORD='choose-a-strong-secret'
./target/release/hassan-wallet new my-wallet.json
./target/release/hassan-wallet address my-wallet.json
./target/release/hassan-wallet balance hsn:ADDR 127.0.0.1:8080
./target/release/hassan-wallet help
```

Password is required for `new`. Pass `--insecure` only for throwaway plaintext
keystores.

## Consensus (must match on every node)

| Parameter | Value |
|---|---|
| Genesis | `hassan-genesis-v31` (hardcoded) |
| Block time | 100 ms |
| PoW | Blake3-512 XOF |
| Bootstrap PoW floor | 7000 (0 → 1M HSN minted) |
| Hard-era PoW floor | 16_777_216 (`2^24`) after 1M HSN |
| Optional override | `HASSAN_BOOTSTRAP_EASY=1` keeps 7000 after 1M |
| DAA window | 661 blue-work weighted samples (test builds use a short window) |
| Finality depth | 432000 blues (~12 h at target rate) |
| Pruning depth | 864000 |
| Pruning-proof recent window | `2 × DAA_WINDOW` (succinct IBD; not full finality) |
| GHOSTDAG k | 40 (derived for λ≈10/s, D≈2s) |
| Chain id | 16858749123010493047 |
| Min fee | `max(1000, bytes × 1)`; rises under ≥75% mempool fill |
| Disk | Pruned by default (not archival); mempools not saved; Blake3-512 integrity tag on chainstate |

## Why Rust (not C++)

Stay on the Rust node. Memory safety plus the existing PQ/crypto/P2P stack
beats a C++ rewrite for this codebase. See `SECURITY.md`.

## Mining on CPU / laptop / mobile

- Node solo miner hashes Blake3-512 under the era difficulty floor.
- Search budget per template = **100 ms** in release (matches block time).
- Under bootstrap (before 1M HSN), a single laptop should mine near **~0.10 s**.
- `GET /api/v1/mining/light?max=50000` — bounded share-difficulty probe (hashrate check).
- `GET /api/v1/mining/template` + `/api/v1/stratum` — template / stratum helpers (`HASSAN_STRATUM_PASSWORD` required).
- `hassan-wallet mine [API] [max_hashes]` — CLI light-mine path.

## Copy a prebuilt binary

If you already built on one machine of the **same OS/CPU**:

```bash
./scripts/build-dist.sh
# copy dist/hassan-<os>-<arch>/ to the other computer
cd dist/hassan-<os>-<arch>
./run-node.sh          # macOS / Linux
run-node.cmd           # Windows
```

Cross-OS binaries are not produced by this script — build on each OS, or use CI later.

## Upgrade / corrupt-state / peer skew

Full procedures: [`OPERATORS.md`](OPERATORS.md).

1. **Format bump (e.g. v30 → v31):** stop miners, wipe every `HASSAN_DATA_DIR`,
   deploy the same new binary everywhere, restart, confirm matching genesis.
2. **Corrupt `chainstate.bin`:** node exits; restore `.bak` / `.bak.1` or wipe
   and re-sync. Do not hand-edit.
3. **Peer skew:** wire protocol 7 peers must match; incompatible Hello →
   disconnect. Public mode adds IP bans for invalidity / STARK budget abuse.
4. **Deep reorg past finality:** stop writers; compare tips / `chain_hash`;
   restore from archival or wipe + IBD.

