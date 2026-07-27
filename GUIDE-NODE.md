# Guide: Hassan Node

**One sentence:** The node is the computer that keeps the Hassan ledger, mines or validates blocks, and talks to other nodes.

You need a node running before the wallet or escrow can talk to the network.

---

## 1. Build once

```bash
cargo build --release --bin hassan
```

Binary: `./target/release/hassan`

---

## 2. Pick a role (3 kinds)

| Role | Meaning | When to use |
|------|---------|-------------|
| `validator` | Keeps a **pruned** copy of the chain | Normal laptop / cheap VPS (default) |
| `archive` | Keeps **full history** | Seed node so others can sync |
| `light` | Pruned + mine, no indexer | Smallest machine that still mines |

```bash
./target/release/hassan --help
```

---

## 3. Run on your machine (simplest)

```bash
./target/release/hassan validator
```

What you get:

- Explorer + API at **http://127.0.0.1:8080/**
- A write token printed in the terminal (save it if you will use the wallet for sends)
- Tor-only P2P dials (no open listen) unless you add flags

Open the explorer in a browser: `http://127.0.0.1:8080/`

---

## 4. Join other people (public lock)

Every peer must use the **same** binary generation and a **fresh** data folder after a genesis upgrade.

```bash
# Create a long secret once; share only with your operators, not the world
export HASSAN_API_TOKEN="$(openssl rand -hex 32)"

# Seed (full history)
rm -rf ./hassan-data
./target/release/hassan archive --public --listen 0.0.0.0:9333

# Another machine (pruned)
export HASSAN_API_TOKEN="same-token-as-seed-if-you-share-API"
./target/release/hassan validator --public --listen 0.0.0.0:9333 --peer SEED_IP:9333
```

Rules of public lock:

- You **must** set `HASSAN_API_TOKEN` yourself (no auto secret)
- API stays on **localhost** unless you pass `--api-bind`
- Soft “lab” flags are refused

---

## 5. Everyday commands

```bash
# Help
./target/release/hassan --help

# Validator, custom data folder
./target/release/hassan validator --data-dir ./my-node-data

# Dial one peer (Tor / onion when not using --public)
./target/release/hassan validator --peer something.onion:9333

# Validate only (do not mine)
./target/release/hassan validator --no-mine
```

Useful env vars:

| Env | What |
|-----|------|
| `HASSAN_DATA_DIR` | Where chain files live (default `./hassan-data`) |
| `HASSAN_API_TOKEN` | Password for write API / mining helpers |
| `HASSAN_API_BIND` | API listen address (default `127.0.0.1:8080`) |
| `HASSAN_PEER_PINS` | Optional file of trusted peer keys |

---

## 6. Check it is alive

1. Terminal prints height / blue score every few seconds  
2. Browser: `http://127.0.0.1:8080/` → Home shows height  
3. Wallet: `hassan-wallet network` shows the same genesis / chain hash  

---

## 7. Stop / wipe / upgrade

- **Stop:** `Ctrl+C` (saves chain state)
- **Wipe (fresh chain):** `rm -rf ./hassan-data` then start again  
- **Upgrade note:** all peers must wipe and run the same genesis version together — see `NODE.md`

---

## Picture

```
[ Your PC ]
    |
    v
 hassan validator / archive / light
    |
    +---> saves blocks in hassan-data/
    +---> API + Explorer on 127.0.0.1:8080
    +---> P2P to other nodes (--peer / --listen)
```

More detail: `NODE.md` · `PUBLIC.md` · `OPERATORS.md`
