# Hassan Public Deployment Run-Book

How to stand up and operate a Hassan node for **open-internet peers**.
Use the **public lock** (`--public` or `HASSAN_PUBLIC=1`).

**v31 consensus** (all nodes must match): size-based min fee
(`max(1000, bytes × 1)`); PoW bootstrap floor **7000** until **1M HSN** minted,
then hard floor **`2^24`**; `FINALITY_DEPTH = 432000` (~12 h); blue-work weighted
`DAA_WINDOW = 661`; `GHOSTDAG_K = 40`; genesis `hassan-genesis-v31`;
bech32m `hsn1…` addresses; MultiSig requires ML-DSA cosigner signatures;
**fees pay miner coinbase**. Wipe `chainstate.bin` on upgrade from earlier formats.

---

## Public lock (required for open internet)

Nothing is “unhackable.” Public lock makes cheap attacks expensive and closes
obvious ops holes. You still need competent operators.

```bash
export HASSAN_API_TOKEN="$(openssl rand -hex 32)"   # REQUIRED (no ephemeral)
cargo build --release --bin hassan

# Archival seed
./target/release/hassan archive --public --listen 0.0.0.0:9333 \
  --data-dir ./data-seed

# Pruned peer
./target/release/hassan validator --public --listen 0.0.0.0:9334 \
  --peer SEED_HOST:9333 --data-dir ./data-node2
```

API stays on `127.0.0.1:8080` unless you pass `--api-bind`. Remote HTTP needs
the same token on every write route.

### What public lock turns on

| Control | Effect |
|---|---|
| Consensus floors | Bootstrap 7000 until 1M HSN, then `2^24`; size-priced fees |
| `HASSAN_API_TOKEN` | **Required** in the environment (ephemeral refused) |
| Refused overrides | `HASSAN_ALLOW_UNAUTH_WRITES`, `HASSAN_RELAX_NET`, `HASSAN_BOOTSTRAP_EASY` |
| Non-loopback API bind | Refused unless token is set |
| Strict dials | No RFC1918 / loopback gossip dials (`.onion` ok) |
| STARK verify budget | Per-peer cap before winterfell runs |
| Ban by socket IP | Misbehaving peers cannot reconnect from a new listen addr |
| Pruning-proof adopt | Only strictly higher hard `cumulative_work` / multilevel `verified_work` |
| CORS | No `*`; allowlist via `HASSAN_CORS_ORIGIN` |

### Submit a transfer (authenticated)

```bash
curl -sS -X POST "http://127.0.0.1:8080/api/v1/tx/submit" \
  -H "Authorization: Bearer $HASSAN_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @tx.json
```

---

## 1. Build

```bash
cargo build --release --bin hassan --bin hassan-wallet
```

Binary: `./target/release/hassan`. Dist packages: `./scripts/build-dist.sh`.
See [`NODE.md`](NODE.md).

## 2. Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `HASSAN_PUBLIC` | unset | `1` = public lock (also set by `--public`) |
| `HASSAN_API_TOKEN` | required when public | Bearer for write routes |
| `HASSAN_STRICT_DIALS` | on when public | Deny private/loopback gossip dials |
| `HASSAN_CORS_ORIGIN` | unset | Comma-separated allowlist (no `*` in public mode) |
| `HASSAN_DATA_DIR` | `./hassan-data` | Chain state + `indexer/` |
| `HASSAN_ARCHIVAL` | role-dependent | `1` = keep full history |
| `HASSAN_P2P_LISTEN` | required when public | e.g. `0.0.0.0:9333` |
| `HASSAN_P2P_PEER` / `HASSAN_P2P_PEERS` | unset | Seed peers |
| `HASSAN_API_BIND` | `127.0.0.1:8080` | HTTP bind |
| `HASSAN_TOR` | unset | `1` = outbound P2P via SOCKS5 |
| `HASSAN_PEER_PINS` | unset | Out-of-band ML-DSA peer pins |
| `HASSAN_STRATUM_PASSWORD` | unset | Required for stratum submits |

Key consensus parameters (`genesis.toml` / `src/genesis.rs`):

- Max supply: 25,000,000 HSN
- Block reward: 50 HSN, halving every 250,000 blue-score
- **MIN_DIFFICULTY: 7000** (bootstrap); hard floor **16_777_216** (`2^24`) after 1M HSN minted
- **Min fee:** `max(1000, wire_bytes × 1)`
- Block time: 100 ms · chain id: `16858749123010493047`
- Finality / pruning: 432000 / 864000 blue-score (~12 h / ~24 h)
- Genesis domain: `hassan-genesis-v31`

## 3. Local laptop (no open-internet exposure)

```bash
./target/release/hassan validator
# Tor-only dial + loopback API; see NODE.md
```

## 4. Honest limits

- No real economic security until hashrate is real.
- STARK companion proofs are sequential-work witnesses, not privacy ZK.
- Bridge exit/enter are **disabled**.
- See `SECURITY.md` for the full claim map.

## 5. Upgrade from older genesis versions

1. Stop all nodes.
2. Delete each `HASSAN_DATA_DIR` (or at least `chainstate.bin` + `.bak`).
3. Deploy the same v31 binary everywhere.
4. Restart archival seed first, then peers — each node starts at genesis (height 0).
