//! Canonical Hassan chain parameters (mirrored from `/genesis.toml`).
//!
//! The node does **not** load `genesis.toml` at runtime — that would allow
//! fork-by-config. Constants here are compile-time consensus. A unit test
//! asserts key values still match the checked-in genesis file.

#[cfg(not(test))]
use std::sync::OnceLock;

/// Domain tag absorbed into genesis / settlement identity.
///
/// v31: Kaspa-class economic finality (~12 h blues), blue-work weighted DAA
/// window (661), hop DAA clamp anchors on multilevel IBD. PoW eras unchanged
/// (bootstrap 7000 → `2^24` at 1M HSN). Wipe `chainstate.bin`.
pub const GENESIS_DOMAIN: &[u8] = b"hassan-genesis-v31";

/// Chain founder (metadata; not a premine allocation).
pub const FOUNDER: &str = "MMK";
/// Chain slogan.
pub const SLOGAN: &str = "Knowing";

/// On-disk state format — bump when monetary policy / hardness eras or the
/// block header format (e.g. `Block::interlinks`, v12) change meaning.
pub const STATE_FORMAT_VERSION: u32 = 31;

/// Peer-to-peer account-balance transfers (`TransparentTx`) are consensus-
/// disabled (v27). Spendable value moves via UTXO. Account balances remain only
/// for registry escrow and custody stake (funded by `CreditAccount` bridges).
pub const ACCOUNT_PEER_TRANSFERS: bool = false;

/// Target block interval (ms). ~10 blocks/s selected-parent cadence.
pub const BLOCK_TIME_MS: u64 = 100;
pub const TARGET_BLOCK_TIME_MS: u64 = BLOCK_TIME_MS;

pub const MAX_BLOCK_SIZE: usize = 22 * 1024;
pub const MAX_BLOCK_BYTES: usize = 256 * 1024;
pub const MAX_BLOCK_PARENTS: usize = 10;
pub const MAX_MERGESET_SIZE: usize = 512;
/// Production DAA sample count (blue-work weighted). Sized near Kaspa’s
/// post-Crescendo high-BPS window (~661) without copying trademarks.
pub const DAA_WINDOW_CONSENSUS: usize = 661;
/// Unit tests use a short window so DAA fixtures stay cheap under STARK seal.
#[cfg(test)]
pub const DAA_WINDOW: usize = 32;
#[cfg(not(test))]
pub const DAA_WINDOW: usize = DAA_WINDOW_CONSENSUS;
pub const MAX_MEMPOOL_SIZE: usize = 10_000;
/// Byte budget for transparent + UTXO mempool payloads (DoS bound).
pub const MAX_MEMPOOL_BYTES: usize = 32 * 1024 * 1024;
/// Max contiguous account-nonce package depth from the account tip (inclusive).
/// Mirrors Bitcoin Core–style ancestor limits so a single sender cannot park an
/// arbitrarily long unpaid nonce chain in every honest mempool.
pub const MAX_MEMPOOL_PACKAGE_NONCES: usize = 25;
/// Max UTXO mempool txs in one ancestor package (BIP125-class graph bound).
pub const MAX_UTXO_PACKAGE_COUNT: usize = 25;
/// Max serialized bytes across one UTXO ancestor package.
/// Sized for ML-DSA-87 multi-KB transfers (~25 × ~8 KiB headroom), not ECDSA.
pub const MAX_UTXO_PACKAGE_BYTES: usize = 512 * 1024;
/// Absolute minimum relay / inclusion fee (base units), even for tiny payloads.
pub const MIN_TX_FEE: u128 = 1_000;
/// Density floor: fee must also cover wire bytes
/// (`fee ≥ max(MIN_TX_FEE, serialized_bytes × MIN_FEE_PER_BYTE)`).
/// ML-DSA-87 transfers are multi-KB; a flat 1000 alone underprices spam.
pub const MIN_FEE_PER_BYTE: u128 = 1;
/// Reject account-transfer amounts below this (dust). Aligned with UTXO dust
/// policy so the account overlay cannot park sub-dust spam balances.
pub const DUST_THRESHOLD: u128 = 546;

/// Target wall-clock economic finality window (hours).
///
/// Derivation (Hassan-tuned, not a Kaspa trademark copy):
/// `FINALITY_DEPTH_CONSENSUS = FINALITY_TARGET_HOURS × 3600 × 1000 / BLOCK_TIME_MS`
/// With `BLOCK_TIME_MS = 100` and 12 h → `12 × 36_000_000 / 100 = 432_000` blues.
/// Choose hours-scale reorg cost so reversing “final” settlement requires
/// sustained work across a long selected-parent window.
pub const FINALITY_TARGET_HOURS: u64 = 12;
/// Consensus finality depth — hours-scale economic hardness at [`BLOCK_TIME_MS`].
///
/// `FINALITY_TARGET_HOURS × 3_600_000 / BLOCK_TIME_MS` blues.
/// Deep reorgs past this window are rejected; API `is_final` uses the same depth.
pub const FINALITY_DEPTH_CONSENSUS: u64 =
    FINALITY_TARGET_HOURS.saturating_mul(3_600_000) / BLOCK_TIME_MS;
/// Unit-test finality depth (same prune/reorg logic; cheaper fixtures).
#[cfg(test)]
pub const FINALITY_DEPTH: u64 = 48;
#[cfg(not(test))]
pub const FINALITY_DEPTH: u64 = FINALITY_DEPTH_CONSENSUS;
pub const PRUNING_DEPTH: u64 = FINALITY_DEPTH.saturating_mul(2);
/// Documented / genesis.toml pruning depth (paired with [`FINALITY_DEPTH_CONSENSUS`]).
pub const PRUNING_DEPTH_CONSENSUS: u64 = FINALITY_DEPTH_CONSENSUS.saturating_mul(2);
/// Fully DAA-checked recent headers in multilevel pruning proofs.
/// Kept on the order of [`DAA_WINDOW`], not [`FINALITY_DEPTH`], so deep
/// economic finality does not force O(finality) IBD downloads.
pub const PRUNING_PROOF_RECENT_WINDOW: usize = DAA_WINDOW.saturating_mul(2);

/// 2026-07-26T00:00:00Z — fixed so every node shares the same genesis hash.
///
/// Keep this close to actual network launch time. Re-genesis (bump this +
/// `GENESIS_DOMAIN` + `STATE_FORMAT_VERSION`) before a real launch if the
/// value has gone stale relative to deployment.
pub const GENESIS_TIMESTAMP_MS: u64 = 1_785_024_000_000;
pub const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000;
/// Numeric chain id for tx replay protection (consensus).
///
/// Derived once as `u64::from_le_bytes(blake3(b"hassan").as_bytes()[0..8])`
/// (little-endian). That is why it looks like a large decimal such as
/// `16858749123010493047` — it is not a sequential network number. Keep this
/// `u64` in signed txs; for wallet “add network” use [`crate::chain_hash_hex`]
/// (Blake3-512 of genesis domain ‖ chain_id ‖ genesis block hash).
pub const CHAIN_ID: u64 = 16_858_749_123_010_493_047;

/// One whole HSN in base units (8 decimals, BTC-like).
pub const COIN: u128 = 100_000_000;
/// Hard cap: 25,000,000 HSN.
pub const MAX_SUPPLY_COINS: u128 = 25_000_000;
pub const MAX_SUPPLY: u128 = MAX_SUPPLY_COINS * COIN;
pub const TOTAL_SUPPLY: u128 = MAX_SUPPLY;
/// Initial subsidy: 50 HSN per block.
pub const BLOCK_REWARD_COINS: u128 = 50;
pub const BLOCK_REWARD: u128 = BLOCK_REWARD_COINS * COIN;
/// Blue-score levels between halvings. `2 × 50 × 250_000 = 25_000_000` coins.
pub const HALVING_INTERVAL: u64 = 250_000;

/// Minted-supply threshold (base units) ending the bootstrap PoW era.
/// While `minted_before < BOOTSTRAP_ERA_END`, the floor is
/// [`BOOTSTRAP_MIN_DIFFICULTY`]; at/after it, [`HARD_ERA_MIN_DIFFICULTY`].
pub const BOOTSTRAP_ERA_END: u128 = 1_000_000 * COIN;
/// Absolute Blake3 difficulty floor after bootstrap (`2^24` = 16_777_216).
pub const HARD_ERA_MIN_DIFFICULTY: u64 = 1u64 << 24;
/// Bootstrap-era PoW floor (0 → 1M HSN minted). Sized so a laptop CPU can mine
/// near the 100 ms target under DAA pacing.
pub const BOOTSTRAP_MIN_DIFFICULTY: u64 = 7000;
/// genesis.toml / API alias for [`BOOTSTRAP_MIN_DIFFICULTY`].
pub const LAB_EASY_DIFFICULTY: u64 = BOOTSTRAP_MIN_DIFFICULTY;

/// Consensus PoW floor for **non-genesis** blocks (= bootstrap floor).
///
/// The live floor for a given block is [`era_min_difficulty`] (rises to
/// [`HARD_ERA_MIN_DIFFICULTY`] after [`BOOTSTRAP_ERA_END`]). Honest nodes that
/// disagree on the era schedule fork immediately.
pub const MIN_DIFFICULTY: u64 = BOOTSTRAP_MIN_DIFFICULTY;

/// Genesis header difficulty claim. PoW on the genesis hash is not a security
/// assumption (every node hard-codes the same genesis); the floor above binds
/// every subsequent block.
pub const GENESIS_DIFFICULTY: u64 = 1;

/// Optional env: keep the bootstrap PoW floor even after 1M HSN minted
/// (local long-running labs). Not required for the default bootstrap era —
/// that is consensus. Peers that disagree on this flag after the hard-era
/// threshold fork.
pub const BOOTSTRAP_EASY_ENV: &str = "HASSAN_BOOTSTRAP_EASY";

/// Whether this process forces the bootstrap PoW floor past [`BOOTSTRAP_ERA_END`].
pub fn lab_easy_pow() -> bool {
    #[cfg(test)]
    {
        // Unit tests may set the env to exercise the override; default off so
        // hard-era assertions see [`HARD_ERA_MIN_DIFFICULTY`] when minted ≥ 1M.
        return matches!(
            std::env::var(BOOTSTRAP_EASY_ENV).ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE")
        );
    }
    #[cfg(not(test))]
    {
        static FLAG: OnceLock<bool> = OnceLock::new();
        *FLAG.get_or_init(|| {
            matches!(
                std::env::var(BOOTSTRAP_EASY_ENV).ok().as_deref(),
                Some("1") | Some("true") | Some("TRUE")
            )
        })
    }
}

/// Effective non-genesis PoW floor at genesis supply (bootstrap era).
pub fn effective_min_difficulty() -> u64 {
    era_min_difficulty(0, GENESIS_TIMESTAMP_MS)
}

/// Block subsidy at `blue_score`: `BLOCK_REWARD` halved each `HALVING_INTERVAL`.
pub fn block_subsidy(blue_score: u64) -> u128 {
    let halvings = blue_score / HALVING_INTERVAL;
    if halvings >= 128 {
        return 0;
    }
    BLOCK_REWARD >> halvings
}

/// Closed-form cumulative scheduled issuance for blue scores `[0, up_to)`.
pub fn cumulative_issuance(up_to_blue: u64) -> u128 {
    let mut total: u128 = 0;
    let mut remaining = up_to_blue;
    let mut reward = BLOCK_REWARD;
    while remaining > 0 && reward > 0 {
        let take = remaining.min(HALVING_INTERVAL);
        total = total.saturating_add(reward.saturating_mul(take as u128));
        remaining -= take;
        reward >>= 1;
    }
    total.min(MAX_SUPPLY)
}

/// Supply-era PoW difficulty floor (default consensus).
///
/// - `minted_before < BOOTSTRAP_ERA_END` → [`BOOTSTRAP_MIN_DIFFICULTY`] (7000)
/// - otherwise → [`HARD_ERA_MIN_DIFFICULTY`] (`2^24`)
///
/// `HASSAN_BOOTSTRAP_EASY=1` keeps the bootstrap floor after 1M minted (optional
/// local override; peers must match).
pub fn era_min_difficulty(minted_before: u128, _timestamp_ms: u64) -> u64 {
    if lab_easy_pow() || minted_before < BOOTSTRAP_ERA_END {
        BOOTSTRAP_MIN_DIFFICULTY
    } else {
        HARD_ERA_MIN_DIFFICULTY
    }
}

/// Illustrative economic-model assumptions — **non-consensus**.
///
/// These constants feed [`crate::economics::CostBasis`] estimates only.
/// Changing them does not affect any node's validation of blocks, the DAA,
/// or the chain's actual history — they are published assumptions for an
/// illustrative issuance-cost model (think mining-profitability calculator),
/// not measured real-world energy/hardware market data. Mirrored in
/// `genesis.toml` under `[economics]`.
pub mod economics {
    /// Assumed energy draw per hash attempt, in joules (~50 nJ/hash is a
    /// ballpark ASIC-class efficiency figure).
    pub const ASSUMED_JOULES_PER_HASH: f64 = 0.000_000_05;
    /// Assumed retail electricity price, USD per kWh.
    pub const ASSUMED_ENERGY_PRICE_USD_PER_KWH: f64 = 0.06;
    /// Assumed mining-hardware unit cost, USD.
    pub const ASSUMED_HARDWARE_COST_USD: f64 = 3_000.0;
    /// Assumed useful hardware life, in blocks (~1 year at the 100ms
    /// target cadence).
    pub const ASSUMED_HARDWARE_AMORTIZATION_BLOCKS: f64 = 315_360_000.0;
    /// Assumed annual opportunity cost of capital tied up in hardware.
    pub const ASSUMED_CAPITAL_ANNUAL_RATE: f64 = 0.05;

    /// Blocks per year at the protocol's target block interval.
    pub fn blocks_per_year() -> f64 {
        (365.0 * 24.0 * 3600.0 * 1000.0) / (super::BLOCK_TIME_MS as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometric_sum_is_exactly_25m_coins() {
        // 2 × R × H in coin units (infinite halvings geometric sum).
        let sum_coins = 2 * BLOCK_REWARD_COINS * (HALVING_INTERVAL as u128);
        assert_eq!(sum_coins, MAX_SUPPLY_COINS);
        assert_eq!(MAX_SUPPLY, MAX_SUPPLY_COINS * COIN);
        assert_eq!(BLOCK_REWARD, 50 * COIN);
    }

    #[test]
    fn cumulative_issuance_respects_cap() {
        // Integer halvings truncate the infinite geometric sum slightly below
        // 2·R·H (same class of dust as Bitcoin's satoshi schedule). The hard
        // cap remains MAX_SUPPLY; apply path clamps by remaining room.
        let far = cumulative_issuance(HALVING_INTERVAL * 200);
        assert!(far <= MAX_SUPPLY);
        assert!(
            far > MAX_SUPPLY - COIN,
            "scheduled mint should reach within 1 HSN of the 25M cap (got {far})"
        );
        assert_eq!(cumulative_issuance(0), 0);
        assert_eq!(cumulative_issuance(1), BLOCK_REWARD);
        assert_eq!(cumulative_issuance(2), 2 * BLOCK_REWARD);
    }

    #[test]
    fn pow_eras_bootstrap_then_hard() {
        assert_eq!(MIN_DIFFICULTY, BOOTSTRAP_MIN_DIFFICULTY);
        assert_eq!(BOOTSTRAP_MIN_DIFFICULTY, 7000);
        assert_eq!(LAB_EASY_DIFFICULTY, BOOTSTRAP_MIN_DIFFICULTY);
        assert_eq!(HARD_ERA_MIN_DIFFICULTY, 16_777_216);
        assert_eq!(FINALITY_TARGET_HOURS, 12);
        assert_eq!(FINALITY_DEPTH_CONSENSUS, 432_000);
        assert_eq!(
            FINALITY_DEPTH_CONSENSUS,
            FINALITY_TARGET_HOURS.saturating_mul(3_600_000) / BLOCK_TIME_MS
        );
        assert_eq!(DAA_WINDOW_CONSENSUS, 661);
        assert_eq!(PRUNING_DEPTH_CONSENSUS, 864_000);
        assert_eq!(
            era_min_difficulty(0, GENESIS_TIMESTAMP_MS),
            BOOTSTRAP_MIN_DIFFICULTY
        );
        assert_eq!(
            era_min_difficulty(BOOTSTRAP_ERA_END.saturating_sub(1), GENESIS_TIMESTAMP_MS),
            BOOTSTRAP_MIN_DIFFICULTY
        );
        assert_eq!(
            era_min_difficulty(BOOTSTRAP_ERA_END, GENESIS_TIMESTAMP_MS),
            HARD_ERA_MIN_DIFFICULTY,
            "at 1M HSN minted the hard floor applies"
        );
        assert_eq!(
            era_min_difficulty(BOOTSTRAP_ERA_END.saturating_add(COIN), GENESIS_TIMESTAMP_MS),
            HARD_ERA_MIN_DIFFICULTY
        );
    }

    #[test]
    fn genesis_toml_mirrors_compile_time_constants() {
        let raw = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/genesis.toml"));
        assert!(raw.contains("name       = \"Hassan\""));
        assert!(raw.contains("symbol     = \"HSN\""));
        assert!(raw.contains("genesis_domain = \"hassan-genesis-v31\""));
        assert!(raw.contains("founder    = \"MMK\""));
        assert!(raw.contains("slogan     = \"Knowing\""));
        assert!(raw.contains(&format!("chain_id   = {CHAIN_ID}")));
        assert!(raw.contains("state_format_version = 31"));
        assert!(raw.contains("account_peer_transfers = false"));
        assert!(raw.contains(&format!("min_difficulty        = {BOOTSTRAP_MIN_DIFFICULTY}")));
        assert!(raw.contains("min_tx_fee            = 1000"));
        assert!(raw.contains("min_fee_per_byte      = 1"));
        assert!(raw.contains("dust_threshold        = 546"));
        assert!(raw.contains("max_supply_coins     = 25000000"));
        assert!(raw.contains("block_reward_coins   = 50"));
        assert!(raw.contains("halving_interval     = 250000"));
        assert!(raw.contains("coin                 = 100000000"));
        assert!(raw.contains(&format!(
            "hard_era_min_diff       = {HARD_ERA_MIN_DIFFICULTY}"
        )));
        assert!(raw.contains(&format!(
            "bootstrap_min_diff       = {BOOTSTRAP_MIN_DIFFICULTY}"
        )));
        assert!(raw.contains("block_time_ms        = 100"));
        assert!(raw.contains("daa_window           = 661"));
        assert!(raw.contains("finality_depth       = 432000"));
        assert!(raw.contains("pruning_depth        = 864000"));
        assert!(raw.contains("ghostdag_k           = 40"));
        assert!(raw.contains(&format!("genesis_timestamp_ms = {GENESIS_TIMESTAMP_MS}")));
        assert_eq!(
            GENESIS_TIMESTAMP_MS, 1_785_024_000_000,
            "bumping this constant means genesis.toml/json must be updated to match"
        );
        assert_eq!(GENESIS_DOMAIN, b"hassan-genesis-v31");
        assert_eq!(FOUNDER, "MMK");
        assert_eq!(SLOGAN, "Knowing");
        assert_eq!(STATE_FORMAT_VERSION, 31);
        assert!(!ACCOUNT_PEER_TRANSFERS);
        assert_eq!(CHAIN_ID, 16_858_749_123_010_493_047);
        // Sanity: CHAIN_ID really is LE u64 of blake3("hassan")[0..8].
        let dig = blake3::hash(b"hassan");
        let mut le = [0u8; 8];
        le.copy_from_slice(&dig.as_bytes()[..8]);
        assert_eq!(u64::from_le_bytes(le), CHAIN_ID);
        assert_eq!(MIN_DIFFICULTY, BOOTSTRAP_MIN_DIFFICULTY);
        assert_eq!(MIN_TX_FEE, 1_000);
        assert_eq!(MIN_FEE_PER_BYTE, 1);
        assert_eq!(DUST_THRESHOLD, 546);
        assert_eq!(MAX_SUPPLY_COINS, 25_000_000);
        assert_eq!(BLOCK_REWARD_COINS, 50);
        assert_eq!(HALVING_INTERVAL, 250_000);
        assert_eq!(COIN, 100_000_000);
        assert_eq!(BOOTSTRAP_ERA_END, 1_000_000 * COIN);
        assert_eq!(HARD_ERA_MIN_DIFFICULTY, 1u64 << 24);
        assert_eq!(BLOCK_TIME_MS, 100);
        assert!(raw.contains("assumed_joules_per_hash            = 0.00000005"));
        assert!(raw.contains(&format!(
            "assumed_hardware_amortization_blk  = {}",
            economics::ASSUMED_HARDWARE_AMORTIZATION_BLOCKS as u64
        )));
        assert_eq!(economics::ASSUMED_JOULES_PER_HASH, 0.000_000_05);
        assert_eq!(economics::ASSUMED_ENERGY_PRICE_USD_PER_KWH, 0.06);
        assert_eq!(economics::ASSUMED_HARDWARE_COST_USD, 3_000.0);
        assert_eq!(economics::ASSUMED_CAPITAL_ANNUAL_RATE, 0.05);
        assert_eq!(economics::ASSUMED_HARDWARE_AMORTIZATION_BLOCKS, 315_360_000.0);
    }
}
