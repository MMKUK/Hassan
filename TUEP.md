# TUEP / BDPE

## Quick start

Peer escrow on Hassan: buyer locks HSN, then both settle/refund — or buyer reclaim after timeout.

1. Read **[`ESCROW.md`](ESCROW.md)**.
2. CLI: `hassan-wallet escrow tutorial` (aliases: `sketch`, `guide`).
3. Explorer: **Escrow** `#/escrow` (live vaults) · **Wallet** `#/wallet` (address balance / UTXOs / vaults).

“Publish” = run `escrow fund` (and later settle/refund/timeout) so txs hit the node API and vaults show on-chain.

## Spec & code

See [`tuep-escrow/SPEC.md`](tuep-escrow/SPEC.md) for Phase 1 law and vault layout.

- LAW crate: `tuep-escrow/`
- VAULT adapter: `src/bdpe.rs` (UTXO MultiSig 2-of-2 + AbsoluteLock timeout)
- Wallet: `hassan-wallet escrow …` · help: `escrow help` / `escrow tutorial`
- Explorer: `#/escrow` · `#/wallet`
- Registry overlay: hardened in `src/registry.rs` (no seller self-pay; timeout-claim)
