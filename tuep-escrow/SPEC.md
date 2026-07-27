# TUEP / BDPE — Phase 1

Bank-Decoupled Payment Escrow: value is locked by Hassan consensus predicates.
No bank, admin key, or status-only “Locked” state can move funds.

## Layout

| Layer | Role |
|-------|------|
| `tuep-escrow` | LAW — types, clocks, payout vectors, typed events, state machine |
| Hassan `bdpe` adapter | VAULT — UTXO `Or(MultiSig 2-of-2, AbsoluteLock buyer@timeout)` |
| `hassan-wallet` | tutorial / open / fund / settle / refund / timeout-claim / status / history |
| Indexer / explorer | MIRROR — `#/escrow` lists vaults / registry escrows (history only) |

Peer value under v27+ is UTXO-first. Registry escrow is title/account overlay and
is hardened against unilateral seller release; BDPE money movement uses the UTXO vault.

## Phase 1 paths

1. **Open** — parties + amount + absolute blue timeout + seed → escrow id (off-chain terms).
2. **Fund** — buyer spends a UTXO into the vault predicate (phase → `funded`; value locked).
3. **Coop settle** — buyer + seller ML-DSA 2-of-2 → payout vector `to_seller`.
4. **Coop refund** — buyer + seller 2-of-2 → payout vector `to_buyer`.
5. **Timeout-claim** — after `media_blue ≥ timeout_blue`, buyer alone → `to_buyer`.

Illegal: seller alone paying seller; any path that marks Locked without a spendable vault.

## Phase 2 stubs

Arbiter honeypot / `Disputed` transitions are defined in types but rejected by the
Phase 1 state machine.

## Clocks

`Clock::AbsoluteBlue { unlock_blue }` — consensus media blue score, not wall clock.

## Events

Typed enum only (`Opened`, `Funded`, `CoopSettled`, `CoopRefunded`, `TimeoutClaimed`).
No `action: String`.
