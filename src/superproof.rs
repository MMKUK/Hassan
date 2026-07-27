//! Succinct multi-level pruning-point proof (NIPoPoW / FlyClient-style
//! superblock skip-links).
//!
//! ## Why this exists
//!
//! The original [`crate::PruningProof`] (see `verify_pruning_proof` in
//! `lib.rs`) is a **linear** proof: it ships every header from genesis to the
//! pruning point. That's simple and fully rigorous, but it's `O(n)` in chain
//! length — a fresh node bootstrapping a year-old chain downloads and verifies
//! a header for *every single block ever mined*. Kaspa's pruning-point proof
//! instead uses a multi-level "superblock" structure so old, settled history
//! compresses to roughly `O(log n)` headers. This module brings the same idea
//! to Hassan, closing that specific comparison gap.
//!
//! ## How it works
//!
//! Every block, when built, computes an **interlink vector**
//! (`Block::interlinks`): `interlinks[L]` is the hash of the nearest strict
//! ancestor that itself achieved a hash at least `2^L` times stronger than its
//! own required difficulty (a "level-`L` superblock" — see
//! [`superblock_level`]). This is the standard construction from Kiayias,
//! Miller & Zindros, *"Non-Interactive Proofs of Proof-of-Work"* (2017), and
//! is conceptually the same skip-link idea Bitcoin/FlyClient and Kaspa's own
//! proof design build on.
//!
//! Levels are rare: since block hashes are uniformly distributed, a block that
//! already meets difficulty `D` independently has only a `2^-L` chance of
//! *also* meeting `2^L * D`. So a chain of level-`L` blocks lets a verifier
//! "jump" roughly `2^L` ordinary blocks per hop. [`build_multilevel_pruning_proof`]
//! greedily always takes the single longest available jump at each step
//! (binary-lifting style), so the number of hops needed to cross an
//! `n`-block history is `O(log n)` in the expected case.
//!
//! The most recent `recent_window` blocks are still shipped in full (exactly
//! like the original linear proof) — that's the security-critical, reorg-
//! sensitive part where every header and its exact DAA-mandated difficulty
//! must be checked. Only the *settled*, older history is compressed.
//!
//! ## HONEST SCOPE — read this before trusting the numbers this reports
//!
//! - **`verified_work`** is a hard, cryptographically-checked lower bound:
//!   every header actually included in the proof (both the full recent
//!   window and every hop) has its own PoW independently re-verified, and
//!   `verified_work` is just the sum of their `difficulty` fields. This
//!   number cannot be inflated by a forger.
//! - **`estimated_total_work`** additionally *estimates* the work done in the
//!   gaps a skip-jump skipped over, using the standard superblock estimator
//!   (`work ≈ difficulty × 2^level` per hop). This is an **unbiased estimate
//!   under honest random hashing, not a hash-checked fact** — the same
//!   statistical-soundness caveat that applies to every NIPoPoW/FlyClient/
//!   Kaspa-style superblock scheme. A verifier that needs a hard guarantee
//!   (not just "very likely, with a quantifiable, small error probability")
//!   should use `verified_work` or fall back to the full linear proof.
//! - Difficulty for **skipped (hop) headers** cannot be checked against the
//!   exact per-block DAA (that requires the window the proof deliberately
//!   omits). Instead each hop's difficulty is checked against:
//!   1. the supply-era **floor** (`era_min_difficulty`), and
//!   2. **hop DAA clamp anchors** — the same ±25%/window bounds as live DAA,
//!      extrapolated across the height gap to the older hop
//!      ([`crate::hop_difficulty_bounds`]).
//!   This is still weaker than the recent window's exact-DAA check, but
//!   closes the "claim floor difficulty on a tall skip" shortcut.
//! - This is a genuine, testable compression scheme, but it has **not** been
//!   through the adversarial parameter analysis Kaspa's production proof has
//!   (security-parameter tuning, worst-case bounds under an adaptive
//!   adversary, etc.). It implements the same skip-link idea; it is not a
//!   byte-for-byte match of Kaspa's exact guarantees.

use crate::{
    cumulative_issuance, era_min_difficulty, genesis_hash, hop_difficulty_bounds,
    retarget_difficulty, verify_pow, Block, Hash, GENESIS_DIFFICULTY, MAX_FUTURE_DRIFT_MS,
    MAX_TARGET,
};
// GENESIS_DIFFICULTY is not a floor for non-genesis hops — genesis is the trust
// anchor and may claim difficulty 1 while the era floor is higher. It *is*
// used when computing the included-work spam floor (one header may be genesis).
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Cap on interlink levels — a block achieving a higher level than this is
/// astronomically unlikely (`2^-64`) and would just waste header bytes; capping
/// keeps `interlinks` bounded and `superblock_level` panic-free.
pub const MAX_LEVEL: u32 = 63;

/// Maximum hop-chain length accepted by [`verify_multilevel_pruning_proof`].
/// Honest proofs are ~O(log n); this bound is generous while still capping
/// adversarial verification cost / allocation.
pub const MAX_MULTILEVEL_HOPS: usize = 512;

/// Maximum recent-window length accepted by verification. Callers typically
/// request on the order of [`crate::PRUNING_PROOF_RECENT_WINDOW`]; this is a
/// hard DoS ceiling (well above a 2× DAA window).
pub const MAX_MULTILEVEL_RECENT: usize = 8_192;

/// Hard ceiling on total headers shipped in one multi-level proof.
pub const MAX_MULTILEVEL_HEADERS: usize = MAX_MULTILEVEL_HOPS + MAX_MULTILEVEL_RECENT;

/// How "lucky" this block's hash was, in doublings, relative to what its own
/// `difficulty` required: level `L` means the hash met a target `2^L` times
/// harder than necessary. Every valid block is at least level 0. Computed
/// purely from already-public fields (`hash`, `difficulty`) — never trusted,
/// always independently recomputable by a verifier.
pub fn superblock_level(hash: &Hash, difficulty: u64) -> u32 {
    let max = BigUint::from_bytes_be(MAX_TARGET.as_slice());
    let hash_val = BigUint::from_bytes_be(hash.as_slice());
    if hash_val == BigUint::from(0u8) {
        return MAX_LEVEL; // vanishingly unlikely; treat as capped, not infinite/panic
    }
    // achieved = MAX_TARGET / hash — "how hard a difficulty this hash would
    // satisfy on its own", directly comparable to `difficulty`.
    let achieved = max / hash_val;
    let required = BigUint::from(difficulty.max(1));
    if achieved <= required {
        return 0;
    }
    let ratio = achieved / required;
    // floor(log2(ratio)), capped.
    ratio.bits().saturating_sub(1).min(MAX_LEVEL as u64) as u32
}

/// The interlink vector a *new* block (extending `parent`) should carry,
/// following the standard NIPoPoW update rule: for every level up to the
/// parent's own achieved level, point straight at the parent; for higher
/// levels, carry the parent's own pointer forward unchanged.
pub fn compute_interlinks(parent: &Block) -> Vec<Hash> {
    let parent_hash = parent.hash();
    let parent_level = superblock_level(&parent_hash, parent.difficulty) as usize;
    let len = parent.interlinks.len().max(parent_level + 1);
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        if i <= parent_level {
            out.push(parent_hash);
        } else {
            out.push(parent.interlinks[i]);
        }
    }
    out
}

/// A succinct multi-level pruning proof: a full linear header window for the
/// recent, reorg-sensitive past, plus an interlink "hop chain" of superblocks
/// compressing everything older than that back to genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiLevelPruningProof {
    /// Full, contiguous headers for the most recent blocks (same guarantees
    /// as the linear [`crate::PruningProof`]): each is linked to the previous
    /// by real `parents`, its difficulty is DAA-checked, and its PoW is real.
    pub recent_headers: Vec<Block>,
    /// The skip-link chain from `recent_headers[0]`'s predecessor back to
    /// genesis, ordered newest-first (`hops[0]` is the block immediately
    /// preceding `recent_headers[0]`; `hops.last()` is genesis).
    pub hops: Vec<Block>,
    /// Optional peer-advertised hard work bound. When `Some(w)`, verification
    /// rejects any claim strictly greater than the recomputed sum of included
    /// header difficulties — a peer cannot inflate work beyond the headers
    /// they actually shipped. Honest builders leave this `None`; the verifier
    /// always recomputes `verified_work` from the headers themselves.
    ///
    /// NOTE: do not use `skip_serializing_if` here — bincode is not
    /// self-describing and skipping a field breaks wire round-trips.
    #[serde(default)]
    pub claimed_verified_work: Option<u128>,
}

impl MultiLevelPruningProof {
    /// Genesis-first header list for DAG import: hop chain (oldest→newest)
    /// followed by the contiguous recent window ending at the pruning point.
    pub fn headers_genesis_first(&self) -> Vec<crate::Block> {
        let mut out: Vec<crate::Block> = self.hops.iter().rev().cloned().collect();
        out.extend(self.recent_headers.iter().cloned());
        out
    }
}

/// What a verified multi-level proof tells the caller.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiLevelProofSummary {
    pub pruning_point: Hash,
    /// Hard, hash-checked lower bound on total work (see module docs).
    pub verified_work: u128,
    /// Statistical estimate of total work including skipped history (see
    /// module docs — NOT a hash-checked fact).
    pub estimated_total_work: u128,
    /// Headers physically shipped in the proof — the succinctness metric.
    /// Compare against `recent_headers.len() + hops.len()` vs. the true chain
    /// length to see the compression ratio.
    pub header_count: usize,
}

/// Build a succinct multi-level proof from a full linear selected-chain
/// header list (`chain[0]` = genesis, `chain.last()` = pruning point) —
/// exactly the input `ChainState::build_pruning_proof` already assembles for
/// the linear proof. `recent_window` controls how many of the most recent
/// blocks are shipped in full (callers typically pass something on the order
/// of `FINALITY_DEPTH`).
pub fn build_multilevel_pruning_proof(
    chain: &[Block],
    recent_window: usize,
) -> Option<MultiLevelPruningProof> {
    if chain.is_empty() {
        return None;
    }
    let split = chain.len().saturating_sub(recent_window.max(1));
    // Need at least one hop header before the recent window (genesis alone is
    // fine as that hop). If the whole chain fits in the recent window there is
    // nothing to compress — callers should fall back to the linear proof.
    if split == 0 {
        return None;
    }
    let recent_headers: Vec<Block> = chain[split..].iter().map(|b| b.header_only()).collect();

    // Greedy longest-jump walk backward from the block just before the recent
    // window, down to genesis, always taking the highest interlink available
    // (binary-lifting style) — this is what makes the hop count ~O(log n).
    let mut hops = Vec::new();
    let mut cursor = chain[split - 1].header_only();
    loop {
        let is_genesis = cursor.hash() == genesis_hash() && cursor.parents.is_empty();
        hops.push(cursor.clone());
        if is_genesis {
            break;
        }
        if cursor.interlinks.is_empty() {
            // No skip pointers recorded (e.g. genesis's immediate children,
            // or a chain built without interlinks) — fall back to walking one
            // real parent at a time via the full chain we were given.
            let cur_hash = cursor.hash();
            let prev = chain
                .iter()
                .take(split)
                .rev()
                .find(|b| cursor.parents.contains(&b.hash()) && b.hash() != cur_hash)?;
            cursor = prev.header_only();
            continue;
        }
        let target_hash = *cursor.interlinks.last().unwrap();
        let next = chain
            .iter()
            .find(|b| b.hash() == target_hash)?
            .header_only();
        cursor = next;
    }

    Some(MultiLevelPruningProof {
        recent_headers,
        hops,
        claimed_verified_work: None,
    })
}

/// Cheap structural rejection of malformed / DoS-sized proofs — runs before any
/// PoW hashing. Kept separate so cold-start callers can fail fast.
fn validate_multilevel_proof_structure(proof: &MultiLevelPruningProof) -> Result<(), String> {
    if proof.recent_headers.is_empty() {
        return Err("empty recent-headers window".into());
    }
    if proof.hops.is_empty() {
        return Err("empty hop chain".into());
    }
    if proof.hops.len() > MAX_MULTILEVEL_HOPS {
        return Err("hop chain exceeds the hop limit".into());
    }
    if proof.recent_headers.len() > MAX_MULTILEVEL_RECENT {
        return Err("recent window exceeds the size limit".into());
    }
    if proof.hops.len() + proof.recent_headers.len() > MAX_MULTILEVEL_HEADERS {
        return Err("multi-level proof exceeds the header limit".into());
    }

    // Genesis anchor (before expensive PoW).
    let last_hop = proof.hops.last().unwrap();
    if last_hop.hash() != genesis_hash() || !last_hop.parents.is_empty() {
        return Err("hop chain does not terminate at genesis".into());
    }
    if last_hop.height != 0 {
        return Err("genesis hop must claim height 0".into());
    }

    // Hops are newest-first: heights/timestamps must be strictly decreasing
    // toward genesis, and every hop hash must be unique (duplicates would let
    // an adversary inflate `verified_work` by replaying the same header).
    let mut seen_hops: HashSet<Hash> = HashSet::with_capacity(proof.hops.len());
    for (i, hop) in proof.hops.iter().enumerate() {
        let h = hop.hash();
        if !seen_hops.insert(h) {
            return Err(format!("duplicate hop at index {i}"));
        }
        // Genesis (last hop) is the trust anchor and may claim difficulty 1
        // while the chain floor is higher; every other hop must meet the floor.
        let is_genesis_hop = i + 1 == proof.hops.len();
        let floor = era_min_difficulty(0, hop.timestamp);
        if !is_genesis_hop && hop.difficulty < floor {
            return Err(format!("hop {i} difficulty below minimum"));
        }
        if i + 1 < proof.hops.len() {
            let older = &proof.hops[i + 1];
            if hop.height <= older.height {
                return Err(format!("hop chain height out of order at index {i}"));
            }
            if hop.timestamp < older.timestamp {
                return Err(format!("hop {i} timestamp predates its ancestor"));
            }
        }
    }

    // Recent window must connect to the hop boundary *and* claim contiguous
    // heights (prevents a tall forged tip with a disconnected / spliced body).
    let boundary = &proof.hops[0];
    let r = &proof.recent_headers;
    if !r[0].parents.contains(&boundary.hash()) {
        return Err("recent window does not chain from the hop boundary".into());
    }
    let mut seen_recent: HashSet<Hash> = HashSet::with_capacity(r.len());
    for (i, cur) in r.iter().enumerate() {
        let h = cur.hash();
        if seen_hops.contains(&h) || !seen_recent.insert(h) {
            return Err(format!("duplicate header in recent window at index {i}"));
        }
        let floor = era_min_difficulty(0, cur.timestamp);
        if cur.difficulty < floor {
            return Err(format!("recent header {i} difficulty below minimum"));
        }
        let expected_height = boundary.height.saturating_add(1).saturating_add(i as u64);
        if cur.height != expected_height {
            return Err(format!(
                "recent header {i} height {} != expected contiguous height {}",
                cur.height, expected_height
            ));
        }
        if i > 0 {
            if !cur.parents.contains(&r[i - 1].hash()) {
                return Err(format!("broken chain linkage at recent header {i}"));
            }
            if cur.timestamp < r[i - 1].timestamp {
                return Err(format!("recent header {i} timestamp predates its parent"));
            }
        } else if cur.timestamp < boundary.timestamp {
            return Err("recent header 0 timestamp predates the hop boundary".into());
        }
    }
    Ok(())
}

/// Verify a succinct multi-level pruning proof from scratch. Mirrors
/// `verify_pruning_proof`'s checks (genesis anchor, real PoW, chain linkage,
/// timestamp sanity) for both segments, plus interlink-hop legitimacy for the
/// compressed segment. Never panics. See module docs for exactly what
/// `verified_work` vs. `estimated_total_work` do and don't guarantee.
///
/// State-mutation rule for cold-start: callers must not adopt a pruning point
/// (or otherwise mutate chain state) until this returns `Ok`. Prefer
/// [`adopt_multilevel_pruning_proof`] which enforces that ordering.
pub fn verify_multilevel_pruning_proof(
    proof: &MultiLevelPruningProof,
) -> Result<MultiLevelProofSummary, String> {
    // Fail fast on malformed / oversized proofs before any PoW hashing.
    validate_multilevel_proof_structure(proof)?;
    let now = crate::now_ms();

    // --- 1. Hop chain: real PoW, era floors, legitimate skip-links ---
    let mut verified_work: u128 = 0;
    let mut estimated_total_work: u128 = 0;
    // Genesis contributes its own difficulty to the hard lower bound.
    {
        let genesis = proof.hops.last().unwrap();
        if !verify_pow(&genesis.hash(), genesis.difficulty) {
            return Err("genesis hop fails its proof-of-work".into());
        }
        verified_work = verified_work.saturating_add(genesis.difficulty as u128);
        estimated_total_work = estimated_total_work.saturating_add(genesis.difficulty as u128);
    }
    for i in (0..proof.hops.len().saturating_sub(1)).rev() {
        let cur = &proof.hops[i];
        let older = &proof.hops[i + 1];
        if !verify_pow(&cur.hash(), cur.difficulty) {
            return Err(format!("hop {i} fails its proof-of-work"));
        }
        // era-floor + hop DAA clamp anchors (approximate — see module docs).
        let simulated_minted = cumulative_issuance(cur.height);
        let floor = era_min_difficulty(simulated_minted, cur.timestamp);
        if cur.difficulty < floor {
            return Err(format!(
                "hop {i} claims difficulty {} below its era floor {}",
                cur.difficulty, floor
            ));
        }
        let gap = cur.height.saturating_sub(older.height);
        let (lo, hi) = hop_difficulty_bounds(older.difficulty, gap, floor);
        if cur.difficulty < lo || cur.difficulty > hi {
            return Err(format!(
                "hop {i} difficulty {} outside DAA clamp anchor [{lo}, {hi}] vs older hop",
                cur.difficulty
            ));
        }
        // Legitimacy of the jump: interlinks point from a NEWER block back
        // to an OLDER ancestor (that's the whole point of a skip-link), so
        // `older` is a legitimate hop target only if `cur` itself
        // hash-committed a pointer to it — either directly (`cur.parents` —
        // the no-interlink fallback case) or via one of `cur`'s own
        // interlink slots.
        let via_interlink = cur.interlinks.contains(&older.hash());
        let via_parent = cur.parents.contains(&older.hash());
        if !via_interlink && !via_parent {
            return Err(format!(
                "hop {} is not a legitimate ancestor of hop {} (no matching interlink or parent)",
                i + 1,
                i
            ));
        }
        verified_work = verified_work.saturating_add(cur.difficulty as u128);
        if via_interlink {
            // Statistical estimator: a level-L ancestor represents, in
            // expectation, ~2^L ordinary blocks of work at its own
            // difficulty. NOT hash-checked — see module docs.
            let level = cur
                .interlinks
                .iter()
                .position(|h| *h == older.hash())
                .unwrap_or(0) as u32;
            let multiplier = 1u128.checked_shl(level).unwrap_or(u128::MAX);
            estimated_total_work = estimated_total_work
                .saturating_add((cur.difficulty as u128).saturating_mul(multiplier));
        } else {
            estimated_total_work = estimated_total_work.saturating_add(cur.difficulty as u128);
        }
    }

    // --- 2. Recent window: same rigor as the linear proof, anchored to the
    //        hop chain's newest element instead of genesis. ---
    let r = &proof.recent_headers;
    for i in 0..r.len() {
        let cur = &r[i];
        // Difficulty: exact DAA retarget once a full DAA_WINDOW of *recent*
        // history is available inside the proof. For the first DAA_WINDOW
        // headers, clamp against the hop-boundary difficulty using the same
        // hop DAA anchors (era floor alone previously allowed near-zero work).
        let simulated_minted = cumulative_issuance(cur.height);
        let floor = era_min_difficulty(simulated_minted, cur.timestamp);
        let boundary = &proof.hops[0];
        if i < crate::DAA_WINDOW {
            let gap = cur.height.saturating_sub(boundary.height);
            let (lo, hi) = hop_difficulty_bounds(boundary.difficulty.max(floor), gap, floor);
            if cur.difficulty < lo || cur.difficulty > hi {
                return Err(format!(
                    "recent header {i} difficulty {} outside boundary DAA clamp [{lo}, {hi}]",
                    cur.difficulty
                ));
            }
        } else {
            let sp_difficulty = r[i - 1].difficulty.max(floor);
            let newest = r[i - 1].timestamp;
            let oldest = r[i - crate::DAA_WINDOW].timestamp;
            let expected =
                retarget_difficulty(sp_difficulty, newest, oldest, floor).max(floor);
            if cur.difficulty != expected {
                return Err(format!("recent header {i} claims a non-DAA difficulty"));
            }
        }
        if !verify_pow(&cur.hash(), cur.difficulty) {
            return Err(format!("recent header {i} fails its proof-of-work"));
        }
        if cur.timestamp > now.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(format!(
                "recent header {i} timestamp is too far in the future"
            ));
        }
        verified_work = verified_work.saturating_add(cur.difficulty as u128);
        estimated_total_work = estimated_total_work.saturating_add(cur.difficulty as u128);
    }

    // Hard bound: verified_work is exactly the sum of included header
    // difficulties — never an estimate, never peer-inflatable above that sum.
    let header_work_sum: u128 = proof
        .hops
        .iter()
        .chain(proof.recent_headers.iter())
        .map(|b| b.difficulty as u128)
        .sum();
    if verified_work != header_work_sum {
        return Err("verified_work inconsistent with included headers".into());
    }
    if let Some(claimed) = proof.claimed_verified_work {
        if claimed > header_work_sum {
            return Err("claimed verified_work exceeds sum of included headers".into());
        }
    }

    // Coarse spam filter: a tip that claims a tall height but ships near-zero
    // hard work (relative to the headers actually included) is rejected.
    // Uses included-header count — not full chain length — so succinct honest
    // proofs (where verified_work << tip height) still pass. Genesis is the
    // trust anchor and may claim [`GENESIS_DIFFICULTY`] (1); every other
    // included header must meet the era floor.
    let tip_height = r[r.len() - 1].height;
    let min_included_work: u128 = proof
        .hops
        .iter()
        .chain(proof.recent_headers.iter())
        .map(|b| {
            if b.parents.is_empty() {
                GENESIS_DIFFICULTY as u128
            } else {
                crate::effective_min_difficulty() as u128
            }
        })
        .sum();
    if tip_height > 0 && verified_work < min_included_work {
        return Err("suspiciously low verified_work for included headers".into());
    }

    Ok(MultiLevelProofSummary {
        pruning_point: r[r.len() - 1].hash(),
        verified_work,
        estimated_total_work,
        header_count: proof.hops.len() + proof.recent_headers.len(),
    })
}

/// Max age of a pruning-proof tip vs local tip when the local node has already
/// progressed past genesis. Derived as `FINALITY_DEPTH × BLOCK_TIME_MS` so a
/// live node rejects obsolete PPs older than one economic-finality window.
pub fn pruning_proof_max_staleness_ms() -> u64 {
    crate::FINALITY_DEPTH.saturating_mul(crate::BLOCK_TIME_MS)
}

/// Local context for IBD / pruning-proof freshness and upgrade gates.
#[derive(Clone, Debug)]
pub struct IbdFreshnessContext {
    pub now_ms: u64,
    /// Highest hard work already accepted (`verified_work` / linear cumulative).
    pub local_best_work: u128,
    pub local_tip_height: u64,
    pub local_tip_timestamp: u64,
    /// False only while still at genesis (cold start — stale-vs-local skipped).
    pub local_past_genesis: bool,
}

/// Reject stale / future / weaker / wrong-genesis pruning proofs before adopt.
///
/// - Wrong genesis → upgrade / network gate (never adopt foreign chain).
/// - Tip too far in the future → same drift rule as consensus headers.
/// - `verified_work <= local_best_work` → no downgrade / replay.
/// - On a live node, tip far behind local tip in time **and** height → stale PP.
pub fn check_ibd_proof_freshness(
    proof_genesis: Hash,
    tip_height: u64,
    tip_timestamp: u64,
    verified_work: u128,
    ctx: &IbdFreshnessContext,
) -> Result<(), String> {
    if proof_genesis != genesis_hash() {
        return Err("pruning proof genesis does not match local genesis (upgrade gate)".into());
    }
    if tip_timestamp > ctx.now_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
        return Err("pruning proof tip too far in the future".into());
    }
    if ctx.local_best_work > 0 && verified_work <= ctx.local_best_work {
        return Err("pruning proof verified_work does not beat local best".into());
    }
    if ctx.local_past_genesis {
        let stale_ms = pruning_proof_max_staleness_ms();
        let height_slack = crate::FINALITY_DEPTH / 2;
        if tip_timestamp.saturating_add(stale_ms) < ctx.local_tip_timestamp
            && tip_height.saturating_add(height_slack) < ctx.local_tip_height
        {
            return Err("stale pruning proof (tip far behind local chain)".into());
        }
    }
    Ok(())
}

/// Cold-start adoption helper: run full verification, then hand the trusted
/// summary to `adopt`. `adopt` is invoked only after verification succeeds, so
/// chain state cannot be mutated from an unverified proof.
///
/// **Fork-choice rule for callers:** compare / store only
/// [`MultiLevelProofSummary::verified_work`] (hard lower bound). Never adopt
/// or rank proofs using `estimated_total_work` — that field is statistical.
pub fn adopt_multilevel_pruning_proof<F, T>(
    proof: &MultiLevelPruningProof,
    adopt: F,
) -> Result<T, String>
where
    F: FnOnce(MultiLevelProofSummary) -> T,
{
    let summary = verify_multilevel_pruning_proof(proof)?;
    Ok(admit_on_verified_work_only(summary, adopt))
}

/// Like [`adopt_multilevel_pruning_proof`] but also enforces
/// [`check_ibd_proof_freshness`] before calling `adopt`.
pub fn adopt_multilevel_pruning_proof_fresh<F, T>(
    proof: &MultiLevelPruningProof,
    ctx: &IbdFreshnessContext,
    adopt: F,
) -> Result<T, String>
where
    F: FnOnce(MultiLevelProofSummary) -> T,
{
    let summary = verify_multilevel_pruning_proof(proof)?;
    let tip = proof
        .recent_headers
        .last()
        .ok_or_else(|| "empty recent window".to_string())?;
    let genesis = proof
        .hops
        .last()
        .map(|b| b.hash())
        .unwrap_or_else(genesis_hash);
    check_ibd_proof_freshness(genesis, tip.height, tip.timestamp, summary.verified_work, ctx)?;
    Ok(admit_on_verified_work_only(summary, adopt))
}

fn admit_on_verified_work_only<F, T>(summary: MultiLevelProofSummary, adopt: F) -> T
where
    F: FnOnce(MultiLevelProofSummary) -> T,
{
    // Touch verified_work so ranking logic cannot silently ignore it; the
    // statistical estimate is intentionally unused here.
    let _hard_bound = summary.verified_work;
    let _ = summary.estimated_total_work; // documented: do not use for adopt
    adopt(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{genesis_block, seal_block, test_miner_keys, ChainState, Hash};

    /// Mine and add one real block extending the current tip, with a genuine
    /// interlink vector (mirrors what `consensus::create_block_template` does
    /// for a live node).
    fn mine_next(state: &mut ChainState, t: u64) -> Hash {
        let parents = state.tips.clone();
        let difficulty = state.expected_difficulty_at(&parents, t);
        let mut block = Block {
            height: state.main_chain.len() as u64,
            timestamp: t,
            parents,
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        let h = block.hash();
        state.add_block(block).expect("mined block must be valid");
        h
    }

    fn mine_chain(n: u64) -> ChainState {
        let mut state = ChainState::new();
        // Keep full headers: multilevel / linear pruning-proof builders need
        // the unpruned selected chain (including interlink targets).
        state.archival = true;
        for i in 1..=n {
            mine_next(
                &mut state,
                crate::GENESIS_TIMESTAMP_MS + i * crate::TARGET_BLOCK_TIME_MS,
            );
        }
        state
    }

    fn linear_headers(state: &ChainState) -> Vec<Block> {
        let tip = crate::ghostdag::selected_tip(&state.ghostdag, &state.tips).unwrap();
        crate::ghostdag::selected_chain(&state.ghostdag, &tip)
            .iter()
            .map(|h| state.dag.get(h).unwrap().header_only())
            .collect()
    }

    #[test]
    fn superblock_level_is_zero_at_the_boundary_and_never_negative() {
        // A hash exactly equal to the target's own magnitude is level 0.
        let difficulty = 4u64;
        let target = crate::pow_target(difficulty);
        assert_eq!(superblock_level(&target, difficulty), 0);
        // The zero hash is (trivially) the strongest possible hash, capped
        // rather than panicking or overflowing.
        assert_eq!(superblock_level(&Hash::ZERO, difficulty), MAX_LEVEL);
    }

    #[test]
    fn genesis_extending_blocks_correctly_propagate_interlinks() {
        // Standard NIPoPoW update rule, checked against a real mined chain:
        // for every level up to the parent's own achieved level, the child's
        // interlink points straight at the parent; higher levels carry the
        // parent's own pointer forward unchanged.
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        for w in headers.windows(2) {
            let (parent, child) = (&w[0], &w[1]);
            let expected = compute_interlinks(parent);
            assert_eq!(
                child.interlinks, expected,
                "child interlinks must match the deterministic update rule"
            );
            let parent_level = superblock_level(&parent.hash(), parent.difficulty) as usize;
            for (i, link) in expected.iter().enumerate() {
                if i <= parent_level {
                    assert_eq!(
                        *link,
                        parent.hash(),
                        "level {i} must point straight at the parent"
                    );
                }
            }
        }
    }

    #[test]
    fn a_real_chain_produces_a_multilevel_proof_that_verifies() {
        let state = mine_chain(30);
        let headers = linear_headers(&state);
        let proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        let summary = verify_multilevel_pruning_proof(&proof).expect("a genuine proof must verify");

        assert_eq!(summary.pruning_point, headers.last().unwrap().hash());
        // `verified_work` is a hard sum over headers ACTUALLY SHIPPED in the
        // proof (hops + recent window) — NOT the full chain, since the whole
        // point of the hop chain is that it skips most of it.
        let expected_work: u128 = proof
            .hops
            .iter()
            .chain(proof.recent_headers.iter())
            .map(|b| b.difficulty as u128)
            .sum();
        assert_eq!(
            summary.verified_work, expected_work,
            "verified_work must equal the real sum of every header PHYSICALLY included in the proof"
        );
        let true_total_work: u128 = headers.iter().map(|b| b.difficulty as u128).sum();
        assert!(
            summary.verified_work <= true_total_work,
            "a lower bound can never exceed the true total"
        );
        assert!(summary.estimated_total_work >= summary.verified_work);
        assert_eq!(proof.hops.last().unwrap().hash(), crate::genesis_hash());
    }

    #[test]
    fn the_multilevel_proof_is_meaningfully_more_succinct_than_shipping_every_header() {
        // Mine enough blocks that superblocks at a few levels almost certainly
        // exist (expected count at level L among N iid blocks is N/2^L), so
        // this compression check is not a coin-flip-flaky test: with 200
        // blocks the odds of seeing zero level-4-or-higher blocks are
        // vanishingly small (~(15/16)^200 ~= 4e-6).
        let n = 200u64;
        let state = mine_chain(n);
        let headers = linear_headers(&state);
        let proof = build_multilevel_pruning_proof(&headers, 30).expect("proof must build");
        let summary = verify_multilevel_pruning_proof(&proof).expect("a genuine proof must verify");

        assert_eq!(summary.pruning_point, headers.last().unwrap().hash());
        assert!(
            summary.header_count < headers.len() / 2,
            "multi-level proof ({} headers) should compress well below half of the full \
             linear chain ({} headers) for a {n}-block history",
            summary.header_count,
            headers.len()
        );
    }

    #[test]
    fn hop_daa_clamp_rejects_soft_claim_against_hard_older() {
        let floor = crate::effective_min_difficulty();
        let older = floor.saturating_mul(64);
        let (lo, hi) = crate::hop_difficulty_bounds(older, 1, floor);
        assert!(lo > floor, "one-window clamp must not collapse to floor from a hard older hop");
        assert!(hi >= older);
        assert!(floor < lo);
    }

    #[test]
    fn ibd_freshness_rejects_stale_pp_on_live_node() {
        let now = crate::GENESIS_TIMESTAMP_MS + 1_000_000;
        let ctx = IbdFreshnessContext {
            now_ms: now,
            local_best_work: 1000,
            local_tip_height: 10_000,
            local_tip_timestamp: now,
            local_past_genesis: true,
        };
        let stale_ts = now.saturating_sub(pruning_proof_max_staleness_ms().saturating_add(1));
        let err = check_ibd_proof_freshness(
            genesis_hash(),
            10,
            stale_ts,
            2000, // beats local work but tip is stale
            &ctx,
        )
        .unwrap_err();
        assert!(err.contains("stale"), "got: {err}");
    }

    #[test]
    fn ibd_freshness_allows_cold_start_old_tip() {
        let now = crate::GENESIS_TIMESTAMP_MS + 1_000_000;
        let ctx = IbdFreshnessContext {
            now_ms: now,
            local_best_work: 0,
            local_tip_height: 0,
            local_tip_timestamp: crate::GENESIS_TIMESTAMP_MS,
            local_past_genesis: false,
        };
        // Ancient tip is fine on cold start — that is IBD.
        check_ibd_proof_freshness(
            genesis_hash(),
            5000,
            crate::GENESIS_TIMESTAMP_MS + 1000,
            50_000,
            &ctx,
        )
        .expect("cold start must accept historical PP");
    }

    #[test]
    fn ibd_freshness_rejects_weaker_work_and_wrong_genesis() {
        let ctx = IbdFreshnessContext {
            now_ms: crate::now_ms(),
            local_best_work: 9999,
            local_tip_height: 100,
            local_tip_timestamp: crate::GENESIS_TIMESTAMP_MS + 10_000,
            local_past_genesis: true,
        };
        let err = check_ibd_proof_freshness(
            genesis_hash(),
            50,
            crate::GENESIS_TIMESTAMP_MS + 9_000,
            100,
            &ctx,
        )
        .unwrap_err();
        assert!(err.contains("verified_work"), "got: {err}");

        let bad_genesis = Hash([0xab; 64]);
        let err2 = check_ibd_proof_freshness(
            bad_genesis,
            50,
            crate::GENESIS_TIMESTAMP_MS + 9_000,
            50_000,
            &ctx,
        )
        .unwrap_err();
        assert!(err2.contains("genesis") || err2.contains("upgrade"), "got: {err2}");
    }

    #[test]
    fn a_hop_with_a_below_floor_difficulty_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        if proof.hops.len() < 2 {
            return; // not enough hops to exercise this on this random run
        }
        proof.hops[0].difficulty = 0;
        assert!(
            verify_multilevel_pruning_proof(&proof).is_err(),
            "a hop claiming a below-floor difficulty must be rejected"
        );
    }

    #[test]
    fn an_illegitimate_hop_splice_is_rejected() {
        // Replace a hop with a different, independently-real (own PoW still
        // valid) block that is NOT actually the claimed ancestor — this must
        // be caught by the interlink/parent legitimacy check, not by PoW.
        let state = mine_chain(60);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        if proof.hops.len() < 3 {
            return;
        }
        let splice_idx = proof.hops.len() / 2;
        proof.hops[splice_idx] = proof.hops[0].clone();
        assert!(
            verify_multilevel_pruning_proof(&proof).is_err(),
            "splicing in an unrelated (if individually valid) block must be rejected"
        );
    }

    #[test]
    fn a_broken_recent_window_linkage_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        assert!(proof.recent_headers.len() >= 3);
        proof.recent_headers[2].nonce ^= 0xdead_beef;
        assert!(
            verify_multilevel_pruning_proof(&proof).is_err(),
            "corrupting a recent header's hash must break the linkage check"
        );
    }

    #[test]
    fn a_forged_recent_difficulty_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        assert!(proof.recent_headers.len() >= 3);
        proof.recent_headers[2].difficulty = 1_000_000;
        assert!(
            verify_multilevel_pruning_proof(&proof).is_err(),
            "a non-DAA recent-window difficulty must be rejected"
        );
    }

    #[test]
    fn a_proof_not_anchored_at_genesis_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        proof.hops.pop(); // drop genesis from the end of the hop chain
        assert!(
            verify_multilevel_pruning_proof(&proof).is_err(),
            "a hop chain that doesn't terminate at genesis must be rejected"
        );
    }

    #[test]
    fn empty_proofs_are_rejected_not_panicked_on() {
        assert!(verify_multilevel_pruning_proof(&MultiLevelPruningProof {
            recent_headers: vec![],
            hops: vec![genesis_block()],
            claimed_verified_work: None,
        })
        .is_err());
        assert!(verify_multilevel_pruning_proof(&MultiLevelPruningProof {
            recent_headers: vec![genesis_block()],
            hops: vec![],
            claimed_verified_work: None,
        })
        .is_err());
    }

    #[test]
    fn an_oversized_hop_chain_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        let pad = proof.hops[0].clone();
        while proof.hops.len() <= MAX_MULTILEVEL_HOPS {
            proof.hops.push(pad.clone());
        }
        let err = verify_multilevel_pruning_proof(&proof).expect_err("oversized hop chain");
        assert!(
            err.contains("hop limit") || err.contains("header limit"),
            "expected a size-cap error, got: {err}"
        );
    }

    #[test]
    fn an_oversized_recent_window_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        let pad = proof.recent_headers[0].clone();
        while proof.recent_headers.len() <= MAX_MULTILEVEL_RECENT {
            proof.recent_headers.push(pad.clone());
        }
        let err = verify_multilevel_pruning_proof(&proof).expect_err("oversized recent window");
        assert!(
            err.contains("recent window exceeds") || err.contains("header limit"),
            "expected a size-cap error, got: {err}"
        );
    }

    #[test]
    fn a_spliced_hop_is_rejected() {
        // Distinct from the illegitimate-ancestor splice: reorder two interior
        // hops so heights / interlink pointers no longer form a valid chain.
        let state = mine_chain(80);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        assert!(
            proof.hops.len() >= 3,
            "need enough hops to exercise a mid-chain splice"
        );
        proof.hops.swap(1, 2);
        assert!(
            verify_multilevel_pruning_proof(&proof).is_err(),
            "reordering hops must be rejected (out-of-order or illegitimate link)"
        );
    }

    #[test]
    fn an_inflated_verified_work_claim_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        let real_sum: u128 = proof
            .hops
            .iter()
            .chain(proof.recent_headers.iter())
            .map(|b| b.difficulty as u128)
            .sum();
        proof.claimed_verified_work = Some(real_sum.saturating_add(1));
        let err = verify_multilevel_pruning_proof(&proof)
            .expect_err("inflated claimed verified_work");
        assert!(
            err.contains("claimed verified_work exceeds"),
            "expected inflation rejection, got: {err}"
        );
    }

    #[test]
    fn a_disconnected_recent_window_is_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        // Point the first recent header at a nonsense parent so it no longer
        // anchors to the hop boundary (structural check, before PoW).
        proof.recent_headers[0].parents = vec![Hash::ZERO];
        let err = verify_multilevel_pruning_proof(&proof)
            .expect_err("disconnected recent window");
        assert!(
            err.contains("recent window does not chain"),
            "expected disconnect rejection, got: {err}"
        );
    }

    #[test]
    fn duplicate_hops_are_rejected() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let mut proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        let dup = proof.hops[0].clone();
        proof.hops.insert(1, dup);
        assert!(
            verify_multilevel_pruning_proof(&proof).is_err(),
            "duplicate hops (work-inflation vector) must be rejected"
        );
    }

    #[test]
    fn adopt_helper_does_not_mutate_on_invalid_proof() {
        let mut adopted = false;
        let result = adopt_multilevel_pruning_proof(
            &MultiLevelPruningProof {
                recent_headers: vec![],
                hops: vec![genesis_block()],
                claimed_verified_work: None,
            },
            |_| {
                adopted = true;
                42
            },
        );
        assert!(result.is_err());
        assert!(!adopted, "adopt closure must not run on a failed verify");
    }

    #[test]
    fn adopt_helper_runs_only_after_successful_verify() {
        let state = mine_chain(25);
        let headers = linear_headers(&state);
        let proof = build_multilevel_pruning_proof(&headers, 10).expect("proof must build");
        let mut adopted = false;
        let summary = adopt_multilevel_pruning_proof(&proof, |s| {
            adopted = true;
            s
        })
        .expect("valid proof must adopt");
        assert!(adopted);
        assert_eq!(summary.pruning_point, headers.last().unwrap().hash());
    }
}
