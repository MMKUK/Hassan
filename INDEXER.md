# Hassan explorer indexer

The node maintains a checksummed archival index under:

```
$HASSAN_DATA_DIR/indexer/index.bin
```

Separate from hot `chainstate.bin`. Indexes selected-chain blocks, transfers,
address activity, labels, and analytics series for fast explorer search.

## Run (hardest local stack)

```bash
export HASSAN_DATA_DIR=./hassan-data
export HASSAN_API_BIND=127.0.0.1:8080
export HASSAN_ARCHIVAL=1   # optional: full history + pruning proofs
cargo build --release --bin hassan
./target/release/hassan
# open http://127.0.0.1:8080/
```

## API

| Route | Purpose |
|---|---|
| `GET /api/v1/indexer/status` | Index tip, sizes, Blake3 checksum |
| `GET /api/v1/search?q=` | Height, hash, txid, address, outpoint, `op:` / `label:` |
| `GET /api/v1/analytics/history?limit=` | Series for charts |
| `GET /api/v1/address/<addr>/history` | Indexed transfers for an address |
| `GET /api/v1/labels` | Entity tags |
| `GET /api/v1/audit/pack` | Multi-section audit JSON |
| `GET /api/v1/audit/diff?from=&to=` | Replayable selected-chain state-root steps |
| `GET /api/v1/pruning/proof` | Linear + multilevel proof bytes/metadata |
| `GET /api/v1/utxo/snapshot?limit=` | Bounded UTXO dump |
| `GET /api/v1/fees/history` | Fee-sample export |
| `GET /api/v1/block/<id>/audit` | Full block body dump |
| `GET /api/v1/block/<id>/mergeset` | Mergeset blues/reds + edges |
| `GET /api/v1/events/sse` | Tip/mempool SSE stream |

Public API is rate-limited per IP. Write routes require
`Authorization: Bearer $HASSAN_API_TOKEN` when `HASSAN_PUBLIC=1` or when
binding a non-loopback API address.
