# Hassan

Transparent settlement BlockDAG — ML-DSA-87 · Blake3-512 · GHOSTDAG.

## Qualities

| Quality | What Hassan has |
|---------|-----------------|
| **Post-quantum signatures** | ML-DSA-87 (FIPS 204) on blocks and spends; optional SLH-DSA dual-sig on custody |
| **Strong hashing** | Blake3-512 digests end-to-end (PoW, Merkle, commitments) |
| **BlockDAG speed** | GHOSTDAG (`k=40`), ~100 ms target block time, parallel tips |
| **Hard money schedule** | 25M HSN cap · 50 HSN subsidy · halving every 250k blue-score |
| **PoW eras** | Bootstrap floor 7000 until 1M minted, then hard floor `2^24` |
| **Long economic finality** | ~12 h finality depth (432000 blues); pruning at 2× |
| **Blue-work DAA** | Difficulty follows blue-work weighted window (661) |
| **UTXO settlement** | Peer value on UTXO path; fees to miner; RBF + fee estimates |
| **Peer escrow** | On-chain BDPE vault (2-of-2 or buyer timeout) — no bank trustee |
| **Title registry** | On-chain titles / liens with harden escrow rules |
| **Public lock** | Explicit API token; refuses soft/lab overrides on open peers |
| **API locked by default** | HTTP on loopback; write routes authenticated |
| **P2P hardening** | Headers-first sync, in-flight caps, ban scores, peer pin directory |
| **Tor dials** | Optional SOCKS5 outbound for P2P (`.onion` peers) |
| **Fail-closed state** | Corrupt `chainstate.bin` exits — does not silently wipe the ledger |
| **Cheap node roles** | `archive` · `validator` · `light` for ordinary machines |
| **Wallet + signer** | Encrypted keystore CLI; offline `hassan-signer` for ABS signatures |
| **Glass explorer** | Embedded UI: blocks, wallet watch, escrow storyboard |
| **Honest security docs** | `SECURITY.md` maps real vs not-implemented claims |

| | |
|---|---|
| Consensus | GHOSTDAG (`k=40`), target block time 100 ms |
| PoW | Blake3-512; bootstrap floor 7000 until 1M HSN, then `2^24` |
| Signatures | ML-DSA-87 (FIPS 204) |
| Genesis | `hassan-genesis-v31` · state format 31 · wire protocol 7 |
| Supply | 25,000,000 HSN · 50 HSN subsidy · halving every 250,000 blue-score |

## Build

```bash
cargo build --release --bin hassan --bin hassan-wallet --bin hassan-signer
```

| Binary | Role |
|--------|------|
| `hassan` | Node (archive / validator / light) |
| `hassan-wallet` | Wallet CLI (balance, send, escrow) |
| `hassan-signer` | Offline key + ML-DSA-87 sign / verify |

```bash
# Offline signer
export HASSAN_WALLET_PASSWORD='secret'
./target/release/hassan-signer new keys.json
./target/release/hassan-signer sign hassan-doc "hello" keys.json > sig.json
./target/release/hassan-signer verify hassan-doc "hello" sig.json
```

## Node roles

```bash
./target/release/hassan --help

# Local / private (Tor-only dial, API on loopback)
./target/release/hassan validator
./target/release/hassan archive
./target/release/hassan light

# Open-internet peers (public lock)
export HASSAN_API_TOKEN="$(openssl rand -hex 32)"
./target/release/hassan archive --public --listen 0.0.0.0:9333
./target/release/hassan validator --public --listen 0.0.0.0:9334 --peer SEED_HOST:9333
```

**Public lock** (`--public` / `HASSAN_PUBLIC=1`): explicit API token required;
unauth writes, relax-net, and bootstrap-easy are refused; API still defaults to
`127.0.0.1` (set `--api-bind` only when you intend remote HTTP).

Wallet: `./target/release/hassan-wallet --help`  

**Simple guides (start here):**

- [`GUIDE-NODE.md`](GUIDE-NODE.md) — run a node  
- [`GUIDE-WALLET.md`](GUIDE-WALLET.md) — keys, balance, send  
- [`GUIDE-SIGNER.md`](GUIDE-SIGNER.md) — offline sign / verify  
- [`GUIDE-ESCROW.md`](GUIDE-ESCROW.md) — peer escrow  

More detail: [`NODE.md`](NODE.md) · [`PUBLIC.md`](PUBLIC.md) · [`SECURITY.md`](SECURITY.md) · [`OPERATORS.md`](OPERATORS.md) · [`RELEASE.md`](RELEASE.md) · [`QUALITIES.md`](QUALITIES.md)

## Public testnet

Hassan is ready to run as a **public testnet** when every peer shares the same
v31 binary, a wiped data dir, and the public lock above.

### Ready checklist

- [x] Genesis / state format pinned (`hassan-genesis-v31`, format 31)
- [x] Wire protocol 7 (UTXO gossip + headers-first bodies)
- [x] Public lock: token required, soft overrides refused
- [x] API loopback by default; non-loopback bind needs token
- [x] P2P ban scores, message caps, peer pins (`HASSAN_PEER_PINS`)
- [x] Fail-closed chainstate load (corrupt file does not wipe to genesis)
- [x] Archive + validator (+ light mine) roles for cheap machines
- [ ] Publish seed `host:9333` (and optional pin file) to participants
- [ ] At least one archival seed online for IBD
- [ ] Operators read [`PUBLIC.md`](PUBLIC.md) + [`OPERATORS.md`](OPERATORS.md)

### Seed (example)

```bash
rm -rf ./hassan-data
export HASSAN_API_TOKEN="$(openssl rand -hex 32)"
export HASSAN_DATA_DIR=./hassan-data
./target/release/hassan archive --public --listen 0.0.0.0:9333
# Explorer (local): http://127.0.0.1:8080/
```

### Peer (example)

```bash
rm -rf ./hassan-data
export HASSAN_API_TOKEN="$(openssl rand -hex 32)"
./target/release/hassan validator --public --listen 0.0.0.0:9333 --peer SEED_HOST:9333
```

This network is for public testing. It is **not** production money. Economic
security tracks real hashrate and operator discipline — see [`SECURITY.md`](SECURITY.md).

## License

MIT
