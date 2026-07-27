# Hassan Security Model

This document maps every claim in the "8-layer, 512-bit Ultimate Security
Architecture" concept to what is **actually implemented in this codebase**
today, what is **real but out of scope for a protocol** (operator/deployment
responsibility), and what is **aspirational / not implemented**. The goal is
to never let marketing language stand in for an audited security guarantee.
If a row below says "not implemented," treat any claim to the contrary
(in docs, a pitch deck, or a whitepaper) as false until this file changes.

## How to read this

- **Protocol-enforced** — every honest node verifies this; it's consensus
  code, covered by the test suite referenced.
- **Operator responsibility** — a real, valuable practice, but it lives in
  *how you run a node*, not in the Rust code. No line of consensus code can
  force an operator to use a Faraday cage.
- **Not implemented** — described in the concept document, does not exist in
  this codebase. Building it is a real, scoped engineering project, not a
  documentation change.

## The 8 layers

| # | Layer | Status | Detail |
|---|---|---|---|
| 1 | Physical (HSMs, air-gaps, Faraday cages, tamper seals, self-destruct) | **Operator responsibility** | No software can enforce physical security. If you're running a validator with meaningful stake, use an HSM for your signing key and standard datacenter physical controls. Hassan has no HSM integration today — `generate_keypair`/`sign_message` in `src/lib.rs` hold secret key bytes in process memory like almost all reference blockchain clients. |
| 2 | Network (Tor, I2P, multi-hop VPN, satellite) | **Partially implemented + operator responsibility** | `src/tor.rs` is a real RFC 1928 SOCKS5 client. With `HASSAN_TOR=1`, **outbound P2P dials** in `src/p2p.rs` go through the SOCKS proxy (`HASSAN_TOR_PROXY`, default `127.0.0.1:9050`), including domain-type CONNECT for `.onion` peers. Clearnet remains the default when Tor is unset. Scope limits (honest): no `ADD_ONION` / published hidden service; inbound listen is still clearnet TCP; I2P / multi-hop VPN / satellite are not implemented. |
| 3 | Cryptographic (post-quantum, ZK, homomorphic encryption) | **Partially implemented** | Real: ML-DSA-87 (FIPS 204) on every Birth Certificate and transfer; Blake3-512 everywhere; optional SLH-DSA-SHAKE-256s (FIPS 205 / SPHINCS+ family) dual-signature on custody certificates for algorithm diversity (`src/dual_sig.rs`). Not implemented: ZK privacy, homomorphic encryption, or MPC. There is no `PhantomZk`/`PhantomHe`/`PhantomMpc` in this codebase. |
| 4 | Protocol (anonymous consensus, sharding, verifiable randomness) | **Partially implemented** | Real: 512-bit Blake3 Merkle roots and GHOSTDAG blue-set commitments throughout consensus (`src/ghostdag.rs`, `src/consensus.rs`). Not implemented: sharding, verifiable randomness beacons, or anonymous consensus (senders/receivers are pseudonymous `hsn:` addresses, not anonymous — see "Privacy" note below). |
| 5 | Application (formal verification, WASM sandbox) | **Not implemented** | Hassan has no smart-contract / WASM execution layer today, so there is nothing to sandbox or formally verify. `Account.code_hash`/`storage_root` fields exist as placeholders in `src/lib.rs` but are not wired to any VM. |
| 6 | Human (social-engineering / coercion resistance) | **Operator responsibility** | No consensus-level "duress password" or plausible-deniability wallet exists in Hassan-Wallet today. This is a real, buildable wallet-UX feature (e.g. a decoy passphrase revealing a low-balance wallet) but it does not exist yet. |
| 7 | Temporal (time-locks, security decay, upgrade deadlines) | **Partially implemented** | Real: `src/custody.rs` implements on-chain stake lock/unlock as first-class state transitions with explicit unlock heights. Not implemented: any protocol-level "mandatory upgrade deadline" or scheduled cryptographic-agility mechanism. |
| 8 | Biological (DNA-encoded keys, biometric binding) | **Not implemented, theoretical** | The concept document itself labels this "(future)" / "Theoretical ultra-long-term storage." Nothing to map to code. |

## The "supporting systems" claims

| Claim | Status |
|---|---|
| PhantomZk (STARK + Bulletproofs) | **Not implemented.** `src/stark.rs` exists for an unrelated internal proof format tied to block validity, not a general-purpose ZK privacy system. There is no Bulletproofs range-proof or hybrid ZK scheme in this repo. |
| PhantomHe (homomorphic encryption) | **Not implemented.** No HE library or scheme is used anywhere in this codebase. |
| PhantomMpc (threshold signatures) | **Not implemented.** All signing today is single-key ML-DSA-87; there is no threshold-signature or multi-party key ceremony. |
| "Defeats Nation-State + Quantum Computer + AI Superintelligence threat model" | **Not a claim this project makes.** No blockchain, including Bitcoin, can honestly claim to defeat an unbounded threat model including physical access and unlimited budget. What Hassan *can* honestly claim: its signatures (ML-DSA-87) and hashes (Blake3-512) are believed secure against known classical and quantum (Shor/Grover) attacks, per NIST's FIPS 204 standardization and Blake3's published security margins. That is a narrower, defensible claim. |

## What's real and load-bearing today

- **Post-quantum signatures**: every Birth Certificate and transfer is signed
  with ML-DSA-87 (FIPS 204), not ECDSA/Ed25519. This is a genuine, current
  quantum-resistance property, not aspirational.
- **512-bit hashing everywhere**: Blake3-512 for block hashes, Settlement
  IDs, addresses, and now the Audit Trail hash chain (`src/economics.rs`).
  512-bit output means Grover's algorithm (the best known quantum
  speed-up against hash preimage search) still requires ~2²⁵⁶ quantum
  operations to break — the same margin 256-bit hashes give against
  classical brute force.
- **Deterministic, re-derivable Audit Trail**: every block's verification
  events (PoW check, Birth Certificate check, GHOSTDAG coloring, finality)
  are hash-chained and can be recomputed identically by any node from
  already-verified consensus data — see `AuditTrail` in `src/economics.rs`.
  This is real "audit independence": nothing here needs to be trusted
  because nothing here is stored state, it's a deterministic function of
  data already checked by consensus.
- **On-chain custody as consensus state**: stake lock/unlock are real ledger
  state transitions (`src/custody.rs`). **Bridge exit/enter are consensus-
  disabled** until a real cross-chain bridge ships — a prior `BridgeEnter`
  path could mint supply from a self-consistent (forgeable) certificate with
  no matching exit and no DAG-anchored block. Stake ops must cite a real
  on-DAG block (settlement id / birth cert / issuer pubkey bound).
- **No header-only tip admission**: `Block::header_only()` is for serving /
  pruning proofs only. `add_block` rejects empty-witness stubs so they cannot
  collect subsidy or permanently censor a merklized body.

## Implementation language: Rust (not C++)

Hassan stays in **Rust**. A C++ rewrite would not improve consensus safety here:
memory safety, fearless concurrency around P2P/API threads, and the existing
ML-DSA / Blake3 / Noise / STARK stack already live in this crate. Rewriting
in C++ would reintroduce classes of memory bugs the current node deliberately
avoids, while discarding years of Rust ecosystem crypto libraries already
wired in. Harden *this* codebase (invariants, checksums, decode bounds, ban
scores, property tests) rather than porting to C++.

## Public mode (v31+)

Enable ops hard-mode with `HASSAN_PUBLIC=1` + an **explicit**
`HASSAN_API_TOKEN` (see `PUBLIC.md`). Public lock refuses unauth writes,
relax-net, and bootstrap-easy. Consensus **v31**: size-based min fee
(`max(MIN_TX_FEE, bytes × MIN_FEE_PER_BYTE)`), PoW bootstrap floor **7000**
until **1M HSN** minted then hard **`2^24`** (optional
`HASSAN_BOOTSTRAP_EASY=1` keeps 7000 after 1M), `FINALITY_DEPTH = 432000`
(~12 h at 100 ms), blue-work weighted `DAA_WINDOW = 661`,
`GHOSTDAG_K = 40`, genesis `hassan-genesis-v31`, MultiSig requires real
ML-DSA cosigner signatures over the UTXO sighash, **post-mergeset
`state_root`**, pruning-point ledger download on cold-start IBD,
**fees pay miner coinbase** (subsidy + fees; `fees_burned` legacy/0 on fresh).
Default storage is **pruned** (mempools not on disk). Wipe `chainstate.bin`
on upgrade from earlier versions.

Public mode adds: API write auth, no CORS `*`, strict dials, per-peer STARK
verify budgets, IP bans on misbehavior, pruning-proof adopt only on higher
hard `cumulative_work` / multilevel `verified_work`, tiny registry/custody
mempools.

**Still not “unhackable.”** No chain is. Treat this as a public deployment
with teeth — not as production money.

## Known limitations (do not ignore)

- **Value model (v27):** peer value is **UTXO-only** (`ACCOUNT_PEER_TRANSFERS=false`).
  Coinbase mints UTXO; ordinary spends are `UtxoTx`. Account balances remain for
  registry escrow and custody stake only (funded via `CreditAccount` bridges).
  `supply_invariant_ok` must hold. Do not claim full BTC UTXO-wallet maturity.
- **PoW eras (v29+):** bootstrap floor **7000** while minted &lt; 1M HSN; then
  hard floor **`2^24`**. Optional `HASSAN_BOOTSTRAP_EASY=1` keeps 7000 after
  1M (forks peers without the flag). Owner policy for early mining. STARK verify
  DoS is mitigated by format precheck + per-peer budgets + ban weight — not
  eliminated.
- **Registry escrow (v30):** release = buyer only; funded refund = seller only;
  timeout = blue-score (`timeout_blue`); arbiter cannot move funds alone.
- **Finality depth** = `FINALITY_TARGET_HOURS × 3_600_000 / BLOCK_TIME_MS`
  (12 h × 36e5 / 100 ms = **432000 blues**). Multilevel IBD recent windows
  stay on the order of `2 × DAA_WINDOW` (not full finality) so deep finality
  does not force O(finality) proof downloads.
- **DAA (v31):** blue-work weighted window of 661 samples (mergeset blues along
  the selected-parent walk); ±25% clamp vs selected parent. Multilevel hop
  difficulties must also sit inside extrapolated DAA clamp anchors. Bootstrap
  PoW floor policy (7000 → `2^24` at 1M HSN) is unchanged.
- **IBD freshness (v31):** pruning-proof adopt rejects wrong genesis (upgrade
  gate), future tips, weaker `verified_work`, and stale PPs on live nodes
  (tip older than one finality window behind local tip).
- **Peer pins (v31):** `HASSAN_PEER_PINS` + optional `HASSAN_PEER_PINS_STRICT=1`
  (`src/peer_pin.rs`) close TOFU when configured.
- **UTXO mempool (v31):** ancestor package count/byte caps, CPFP (spend
  mempool outputs), conflict+descendant RBF, package-feerate eviction, min
  relay rises under ≥75% mempool occupancy.
- **Stratum (v31):** submit rate limits, duplicate-nonce reject, stale-job
  reject, consecutive-reject ban, max workers (password still required).

## Permanent residual (cannot close in this repo)

- **Production age / live hashrate / real money at stake.** Kaspa has secured
  value under public hashrate since 2021. No amount of local consensus code
  substitutes for years of adversarial mainnet pressure. Do not claim parity
  on this axis.
- **Ecosystem review volume** and practiced coordinated upgrades at scale
  likewise require time and external participants.
- **FIXED (brutal audit Jul 2026, pass 1→v25):** MultiSig address-tag unlock (C1);
  bootstrap CPU-toy floor default (C2); ~20s finality (C3); false cross-chain
  banner (H1); stratum open auth (H2); PQ Noise overclaim (H3); GHOSTDAG k
  for 100ms (H4); mint_coinbase double-credit (H5 partial); plaintext wallet default
  (H8); unused versionbits looking live (H9); p2p identity mode 0600 (M1).
- **FIXED (re-audit pass → v26):** fee-to-miner coinbase (M5); orphan body
  floor wired to verified pruning point (M2); loopback API token default (M3);
  STARK claims narrowed + API `stark_is_validity_zk=false` (H6); assume_valid
  wired for pin/ancestors (M6); explorer CSP (M4); HashLock docs (M7); tighter
  non-public net budgets (M9).
- **FIXED (re-audit pass → v27):** peer account transfers disabled / UTXO
  mempool (H5); adversarial net tests (H7); persistence tag+backup harden (M8);
  bech32m-only new outputs (L1); dist SHA256SUMS + optional sig hook (L2);
  Noise banner + ML-DSA channel-bound auth claims aligned (H3).
- **STARK companion proofs** are sequential-work witnesses, not privacy ZK and
  not validity ZK of transactions.
- **Interlinks** must equal `compute_interlinks(selected_parent)` at
  admission; multilevel `estimated_total_work` is statistical only and must
  never drive adopt/fork choice. P2P prefers succinct multilevel IBD on the
  wire; linear pruning proofs remain as fallback. After hard-work adopt,
  verified proof headers are imported, then the pruning-point account ledger
  is downloaded and checked against the PP header `state_root` before
  `base` / live accounts are set.
- **Fee estimates** use a confirmation-target success-rate walk over fee
  history (horizons high≈6 / medium≈20 / low≈100 blues; mempool waiters past
  the target count as failures), else mempool percentiles, with monotonic
  tiers floored at the relay minimum — policy only, not consensus. Not a
  full Bitcoin Core bucket/horizon clone.

## What is not implemented (do not claim otherwise)

- Zero-knowledge privacy (no ZK system exists; transfers are transparent
  by design — see `Cargo.toml` description "transparent settlement
  BlockDAG")
- Homomorphic encryption
- Multi-party computation / threshold signatures
- Smart contracts / WASM execution
- Sharding
- Dual-signatures on **every block header** (SLH-DSA ~30 KB/sig would make a
  100ms-block-time chain unusable — deliberately scoped instead; see next bullet)
- Hardware security module integration
- Tor *hidden service* publish (`ADD_ONION`) — outbound SOCKS dials only
- Working cross-chain bridge (exit/enter ops are rejected on-chain)
- Duress passwords / plausible-deniability wallets

## Dual signatures (algorithm diversity) — scoped, real

- **What ships**: `src/dual_sig.rs` implements SLH-DSA-SHAKE-256s (FIPS 205,
  NIST category 5, hash-based / SPHINCS+ family) as an *optional* second
  signature on [`CustodyCertificate`](src/custody.rs) (stake lock/unlock,
  bridge exit/enter). Verification requires both ML-DSA-87 **and** the
  SLH-DSA signature when the latter is present; single-signed (ML-DSA-only)
  certificates remain fully valid.
- **Why not every block**: a ~29.8 KB SLH-DSA signature on every 100ms
  block would cost ~25 GB/day of header overhead. Custody events are
  infrequent and high-value — that is the right place for algorithm
  diversity without breaking the chain.
- **What this is not**: Ed25519 + SPHINCS+-512 dual-sign on Birth Certificates
  (the concept doc). Hassan uses ML-DSA-87 (lattice) + optional SLH-DSA
  (hash-based) — two post-quantum families, no classical ECDSA/Ed25519
  fallback.

## Operator runbooks

See [`OPERATORS.md`](OPERATORS.md) (coordinated upgrades, corrupt state, deep
reorgs, peer skew, peer pins, stratum). Short form also in `NODE.md`.

## External review (process residual)

This project has not completed an independent third-party security audit.
Internal harden passes are not a substitute.

### What an external reviewer should cover

1. Consensus: GHOSTDAG, finality/pruning, blue-work DAA, era PoW floors, supply.
2. UTXO + mempool: predicates, package RBF/CPFP, fee floors.
3. P2P: Noise + ML-KEM + ML-DSA, peer pins, IBD proofs (`verified_work` + freshness), budgets/bans.
4. Crypto bindings: ML-DSA sighash domains, Blake3-512 commitments, SLH-DSA custody scope.
5. API / stratum / wallet: auth, rate limits, keystore defaults.
6. Persistence: chainstate magic/version/checksum, fail-closed load.

### Audit pack

```bash
git archive --format=tar.gz -o hassan-audit-src.tgz HEAD
cargo test --lib 2>&1 | tee audit-test-log.txt
```

Ship archive + test log + `SECURITY.md` / `OPERATORS.md`. Do not claim a
review occurred until an external party delivers a written report.

## Reporting a vulnerability

This network has no production money at stake. If you find a consensus bug,
double-spend vector, or signature-verification flaw, open an issue describing
the exact reproduction steps (test case preferred) rather than a general
architecture concern — this file already tracks the known architectural gaps
above.
