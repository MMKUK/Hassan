# Hassan Explorer

Glass-clean ledger UI (HTML/CSS/JS, no build step). Embedded in the node
binary and shippable as static files.

## Primary surfaces

| Route | Purpose |
|-------|---------|
| `#/` | Home overview |
| `#/escrow` | Cartoon guide + live vaults |
| `#/blocks` | Block list / detail |
| `#/mempool` | Pending transfers |

Advanced pages live under **More** (fees, supply, network, audit, …).

Open Wallet / Escrow from the top nav, or Home CTAs.

## Run

```bash
cargo build --release --bin hassan && ./target/release/hassan
# → http://127.0.0.1:8080/
# → http://127.0.0.1:8080/
# → http://127.0.0.1:8080/#/escrow
```

Escrow signing: [Hassan-Wallet](https://github.com/MMKUK/Hassan-Wallet) (`hassan-wallet`).
