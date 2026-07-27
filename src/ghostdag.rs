//! GHOSTDAG consensus ordering (the PHANTOM/GHOSTDAG protocol of
//! Sompolinsky, Wong & Zohar — <https://eprint.iacr.org/2018/104>).
//!
//! GHOSTDAG replaces this codebase's previous naive "reverse-BFS over all blocks"
//! ordering. It gives the BlockDAG a real, attack-resistant total order by
//! greedily building a *k-cluster* of well-connected ("blue") blocks: blocks
//! whose anticone (the set of blocks neither ancestor nor descendant of them)
//! within the cluster stays at most `K`. Blocks that would violate the
//! k-cluster property are colored "red" and ordered after the blues. An
//! attacker withholding blocks to build a secret parallel chain produces
//! blocks with large anticones relative to the honest cluster, so they get
//! colored red and cannot outweigh the honest blue chain — the same security
//! argument as GHOST/PHANTOM.
//!
//! ## Honest scope — how this differs from Kaspa's production GHOSTDAG
//!
//! This is a faithful *from-scratch* implementation of the algorithm as
//! described in the paper, written to be readable and verifiable, NOT a port
//! of Kaspa's optimized code. Concretely:
//!
//! - **Complexity.** Ancestor queries go through the reachability oracle
//!   (`crate::reachability`), an interval-labelling index that answers
//!   `is_ancestor` in O(1) chain-check + O(log |FCS|) instead of an O(n) BFS —
//!   so coloring is ~O(m · n) rather than O(m² · n) (m = mergeset/blue-set size,
//!   n = DAG size). This keeps block processing flat as the DAG grows. Like
//!   Kaspa, the oracle stores O(1) interval data per block; unlike Kaspa it
//!   reindexes the whole forest on interval exhaustion rather than incrementally
//!   — see `reachability`'s module doc for that honest difference.
//! - **`K` is derived for Hassan's 100ms cadence** — see `GHOSTDAG_K` below.
//! - **Not cross-validated against Kaspa's test vectors.** The unit tests in
//!   this module check the algorithm's *properties* (a linear chain colors
//!   all-blue with strictly increasing score; a wide burst of parallel
//!   blocks colors at most k+1 of them blue at a merge; selected parent is
//!   the highest-blue-score tip) — they do not prove bit-for-bit agreement
//!   with Kaspa.

use crate::reachability::Reachability;
use crate::Block;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub use crate::Hash;

/// Maximum allowed blue anticone size (the k-cluster parameter).
///
/// Derived for Hassan’s target cadence, not copied from Kaspa’s historical
/// 1 blk/s setting:
/// - λ ≈ 10 blk/s (`BLOCK_TIME_MS = 100`)
/// - delay bound D = 2.0 s (conservative regional mesh)
/// - E[|anticone|] ≈ 2λD = 40
///
/// Set `k = 40` so honest parallelism under that delay paints blue. A larger
/// `k` tolerates more honest parallelism but makes coloring compare over
/// larger blue sets.
pub const GHOSTDAG_K: u64 = 40;

/// Per-block GHOSTDAG metadata, stored alongside each block in `ChainState`.
///
/// `mergeset_blues[0]` is always the selected parent (except for genesis,
/// whose mergeset is empty), matching the convention that lets
/// `blue_score = selected_parent.blue_score + mergeset_blues.len()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GhostdagData {
    /// Number of blue blocks strictly in this block's past.
    pub blue_score: u64,
    /// The selected parent — the parent with the highest blue score
    /// (tie-broken by larger hash). `None` only for genesis.
    pub selected_parent: Option<Hash>,
    /// Blocks this block merges and colors blue, in the order they were
    /// colored. `[0]` is the selected parent.
    pub mergeset_blues: Vec<Hash>,
    /// Blocks this block merges that violated the k-cluster rule (red).
    pub mergeset_reds: Vec<Hash>,
}

impl GhostdagData {
    /// GHOSTDAG data for the genesis block: no past, no parent, empty mergeset.
    pub fn genesis() -> Self {
        Self {
            blue_score: 0,
            selected_parent: None,
            mergeset_blues: Vec::new(),
            mergeset_reds: Vec::new(),
        }
    }
}

/// Is `a` a strict ancestor of `b`? (i.e. `a` reachable by following `b`'s
/// The full set of blue blocks in `block`'s past-inclusive view: `{block}`
/// unioned with every `mergeset_blues` entry along its selected-parent chain.
fn materialized_blues(
    dag: &HashMap<Hash, Block>,
    ghostdag: &HashMap<Hash, GhostdagData>,
    block: &Hash,
) -> HashSet<Hash> {
    let _ = dag;
    let mut blues: HashSet<Hash> = HashSet::new();
    blues.insert(*block);
    let mut cursor = Some(*block);
    while let Some(h) = cursor {
        if let Some(data) = ghostdag.get(&h) {
            for b in &data.mergeset_blues {
                blues.insert(*b);
            }
            cursor = data.selected_parent;
        } else {
            break;
        }
    }
    blues
}

/// All blocks in the mergeset of a new block with the given `parents` and
/// `selected_parent`: every ancestor-inclusive block of the non-selected
/// parents that is not already in the selected parent's past-inclusive set.
fn mergeset(dag: &HashMap<Hash, Block>, parents: &[Hash], selected_parent: &Hash) -> Vec<Hash> {
    // past-inclusive of the selected parent = {sp} ∪ past(sp)
    let mut sp_past: HashSet<Hash> = HashSet::new();
    sp_past.insert(*selected_parent);
    {
        let mut stack: Vec<Hash> = dag
            .get(selected_parent)
            .map(|b| b.parents.clone())
            .unwrap_or_default();
        while let Some(x) = stack.pop() {
            if sp_past.insert(x) {
                if let Some(block) = dag.get(&x) {
                    stack.extend(block.parents.iter().copied());
                }
            }
        }
    }

    // Everything reachable from any parent, minus sp_past.
    let mut set: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<Hash> = parents.to_vec();
    while let Some(x) = stack.pop() {
        if sp_past.contains(&x) || set.contains(&x) {
            continue;
        }
        set.insert(x);
        if let Some(block) = dag.get(&x) {
            stack.extend(block.parents.iter().copied());
        }
    }

    set.into_iter().collect()
}

/// Order a mergeset topologically (ancestors before descendants). Uses the
/// number of in-mergeset ancestors as the sort key — a block with fewer
/// in-set ancestors can never come after one with more — with a hash
/// tie-break for determinism among incomparable blocks.
fn topological_order(
    dag: &HashMap<Hash, Block>,
    reach: &Reachability,
    mergeset: &[Hash],
) -> Vec<Hash> {
    let set: HashSet<Hash> = mergeset.iter().copied().collect();
    let mut with_rank: Vec<(usize, Hash)> = mergeset
        .iter()
        .map(|h| {
            let rank = mergeset
                .iter()
                .filter(|other| {
                    *other != h && set.contains(*other) && reach.is_ancestor(other, h, dag)
                })
                .count();
            (rank, *h)
        })
        .collect();
    with_rank.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    with_rank.into_iter().map(|(_, h)| h).collect()
}

/// Pick the selected parent: the parent with the highest blue score,
/// tie-broken by larger hash (deterministic across nodes).
pub fn select_parent(ghostdag: &HashMap<Hash, GhostdagData>, parents: &[Hash]) -> Option<Hash> {
    parents
        .iter()
        .filter(|p| ghostdag.contains_key(*p))
        .copied()
        .max_by(|a, b| {
            let sa = ghostdag[a].blue_score;
            let sb = ghostdag[b].blue_score;
            sa.cmp(&sb).then_with(|| a.cmp(b))
        })
}

/// Compute GHOSTDAG data for a new block with the given parents, with no bound
/// on mergeset size. The block itself need not be in `dag` yet; only its
/// parents (and their ancestors) must be present with computed `GhostdagData`.
pub fn compute_ghostdag_data(
    dag: &HashMap<Hash, Block>,
    ghostdag: &HashMap<Hash, GhostdagData>,
    reach: &Reachability,
    parents: &[Hash],
) -> GhostdagData {
    // `usize::MAX` bound => the size check never fires, so this cannot error.
    try_compute_ghostdag_data(dag, ghostdag, reach, parents, usize::MAX)
        .expect("unbounded ghostdag computation cannot exceed usize::MAX mergeset")
}

/// Like `compute_ghostdag_data`, but rejects blocks whose mergeset exceeds
/// `max_mergeset`. The size is checked *before* the expensive k-cluster
/// coloring, so a hostile block with a pathologically large merge is dropped
/// cheaply rather than forcing O(m²·n) work. Computing the mergeset itself is
/// only an O(n) BFS.
pub fn try_compute_ghostdag_data(
    dag: &HashMap<Hash, Block>,
    ghostdag: &HashMap<Hash, GhostdagData>,
    reach: &Reachability,
    parents: &[Hash],
    max_mergeset: usize,
) -> Result<GhostdagData, String> {
    let selected_parent = match select_parent(ghostdag, parents) {
        Some(sp) => sp,
        // No known parents (should only happen for genesis, handled elsewhere).
        None => return Ok(GhostdagData::genesis()),
    };

    let ms = mergeset(dag, parents, &selected_parent);
    if ms.len() > max_mergeset {
        return Err(format!(
            "Mergeset too large: {} blocks exceeds cap {}",
            ms.len(),
            max_mergeset
        ));
    }

    // Blues we compare candidates against, seeded with the selected parent's
    // full blue set (which already includes the selected parent itself).
    let mut current_blues: HashSet<Hash> = materialized_blues(dag, ghostdag, &selected_parent);

    let mut mergeset_blues: Vec<Hash> = vec![selected_parent];
    let mut mergeset_reds: Vec<Hash> = Vec::new();
    for candidate in topological_order(dag, reach, &ms) {
        if color_candidate_blue(dag, reach, &current_blues, &candidate) {
            current_blues.insert(candidate);
            mergeset_blues.push(candidate);
        } else {
            mergeset_reds.push(candidate);
        }
    }

    let blue_score = ghostdag[&selected_parent].blue_score + mergeset_blues.len() as u64;

    Ok(GhostdagData {
        blue_score,
        selected_parent: Some(selected_parent),
        mergeset_blues,
        mergeset_reds,
    })
}

/// The k-cluster coloring rule for one candidate against the current blue set.
/// Returns true (blue) iff adding the candidate keeps every blue block's blue
/// anticone at most `K`:
///  1. the candidate's own anticone within `current_blues` is at most `K`, and
///  2. no blue block already in the candidate's anticone is already at `K`
///     (adding the candidate would push it to `K + 1`).
fn color_candidate_blue(
    dag: &HashMap<Hash, Block>,
    reach: &Reachability,
    current_blues: &HashSet<Hash>,
    candidate: &Hash,
) -> bool {
    // Blue blocks concurrent with the candidate.
    let candidate_anticone: Vec<Hash> = current_blues
        .iter()
        .filter(|b| reach.in_anticone(b, candidate, dag))
        .copied()
        .collect();

    if candidate_anticone.len() as u64 > GHOSTDAG_K {
        return false;
    }

    for d in &candidate_anticone {
        // How many blue blocks are already in d's anticone? Adding the
        // candidate would add one more, so d must currently be below K.
        let d_anticone = current_blues
            .iter()
            .filter(|b| reach.in_anticone(b, d, dag))
            .count() as u64;
        if d_anticone >= GHOSTDAG_K {
            return false;
        }
    }

    true
}

/// The selected chain (the GHOSTDAG "virtual selected parent chain"): walk
/// selected parents from `tip` back to genesis, then reverse so genesis is
/// first. This is the consensus main chain.
pub fn selected_chain(ghostdag: &HashMap<Hash, GhostdagData>, tip: &Hash) -> Vec<Hash> {
    let mut chain = Vec::new();
    let mut cursor = Some(*tip);
    while let Some(h) = cursor {
        chain.push(h);
        cursor = ghostdag.get(&h).and_then(|d| d.selected_parent);
    }
    chain.reverse();
    chain
}

/// The selected tip: the tip with the highest blue score (tie-break: larger
/// hash). This is the head of the consensus chain.
pub fn selected_tip(ghostdag: &HashMap<Hash, GhostdagData>, tips: &[Hash]) -> Option<Hash> {
    tips.iter()
        .filter(|t| ghostdag.contains_key(*t))
        .copied()
        .max_by(|a, b| {
            let sa = ghostdag[a].blue_score;
            let sb = ghostdag[b].blue_score;
            sa.cmp(&sb).then_with(|| a.cmp(b))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{now_ms, HASH_SIZE};

    /// Minimal block builder for DAG-shape tests — GHOSTDAG only reads
    /// `parents`, so the other fields are placeholders.
    fn block_with_parents(parents: Vec<Hash>, tag: u8) -> Block {
        Block {
            height: 0,
            timestamp: now_ms(),
            parents,
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash([tag; HASH_SIZE]),
            creator_pubkey: vec![],
            nonce: tag as u64,
            difficulty: 1,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        }
    }

    struct TestDag {
        dag: HashMap<Hash, Block>,
        ghostdag: HashMap<Hash, GhostdagData>,
        reach: Reachability,
        tips: Vec<Hash>,
    }

    impl TestDag {
        fn new() -> (Self, Hash) {
            let genesis = block_with_parents(vec![], 0);
            let gh = genesis.hash();
            let mut dag = HashMap::new();
            let mut ghostdag = HashMap::new();
            let mut reach = Reachability::new();
            dag.insert(gh, genesis);
            ghostdag.insert(gh, GhostdagData::genesis());
            reach.add_block(gh, None, &[], &dag);
            (
                Self {
                    dag,
                    ghostdag,
                    reach,
                    tips: vec![gh],
                },
                gh,
            )
        }

        fn add(&mut self, parents: Vec<Hash>, tag: u8) -> Hash {
            let block = block_with_parents(parents.clone(), tag);
            let h = block.hash();
            let data = compute_ghostdag_data(&self.dag, &self.ghostdag, &self.reach, &parents);
            let sp = data.selected_parent;
            let mergeset: Vec<Hash> = data
                .mergeset_blues
                .iter()
                .skip(1)
                .chain(data.mergeset_reds.iter())
                .copied()
                .collect();
            self.dag.insert(h, block);
            self.ghostdag.insert(h, data);
            self.reach.add_block(h, sp, &mergeset, &self.dag);
            for p in &parents {
                self.tips.retain(|t| t != p);
            }
            self.tips.push(h);
            h
        }

        fn score(&self, h: &Hash) -> u64 {
            self.ghostdag[h].blue_score
        }
    }

    #[test]
    fn a_linear_chain_is_all_blue_with_strictly_increasing_score() {
        let (mut t, genesis) = TestDag::new();
        assert_eq!(t.score(&genesis), 0);
        let a = t.add(vec![genesis], 1);
        let b = t.add(vec![a], 2);
        let c = t.add(vec![b], 3);
        assert_eq!(t.score(&a), 1);
        assert_eq!(t.score(&b), 2);
        assert_eq!(t.score(&c), 3);
        // No block in a straight chain is ever red.
        for h in [a, b, c] {
            assert!(t.ghostdag[&h].mergeset_reds.is_empty());
        }
    }

    #[test]
    fn selected_parent_is_the_highest_blue_score_tip() {
        let (mut t, genesis) = TestDag::new();
        // Long branch off genesis.
        let a1 = t.add(vec![genesis], 1);
        let a2 = t.add(vec![a1], 2);
        let a3 = t.add(vec![a2], 3); // blue_score 3
                                     // Short branch off genesis.
        let b1 = t.add(vec![genesis], 10); // blue_score 1
                                           // A merge block pointing at both tips must select the longer branch.
        let merge = t.add(vec![a3, b1], 20);
        assert_eq!(t.ghostdag[&merge].selected_parent, Some(a3));
        assert!(t.score(&merge) > t.score(&b1));
    }

    #[test]
    fn a_merge_never_blues_more_than_k_plus_one_of_a_parallel_burst() {
        // Many sibling blocks all off genesis (a fully-parallel "burst"),
        // then one block that merges all of them. The merge's selected
        // parent is one of the siblings; the rest are in its anticone, so at
        // most K of them can be colored blue (plus the selected parent = the
        // "+1"). The others must be red.
        let (mut t, genesis) = TestDag::new();
        let mut siblings = Vec::new();
        // Use comfortably more than K+1 siblings so, whatever K is, the merge
        // is forced to color some of them red.
        for i in 0..(GHOSTDAG_K as u8 + 8) {
            siblings.push(t.add(vec![genesis], 100 + i));
        }
        let merge = t.add(siblings.clone(), 220);
        let data = &t.ghostdag[&merge];
        // mergeset_blues includes the selected parent, so at most K+1.
        assert!(
            data.mergeset_blues.len() as u64 <= GHOSTDAG_K + 1,
            "blued {} of a parallel burst, K+1 = {}",
            data.mergeset_blues.len(),
            GHOSTDAG_K + 1
        );
        assert!(
            !data.mergeset_reds.is_empty(),
            "a wide burst must produce some red blocks"
        );
        // Every sibling is accounted for as exactly blue or red.
        let blues: HashSet<_> = data.mergeset_blues.iter().copied().collect();
        let reds: HashSet<_> = data.mergeset_reds.iter().copied().collect();
        for s in &siblings {
            assert!(
                blues.contains(s) ^ reds.contains(s),
                "each sibling is exactly one color"
            );
        }
    }

    #[test]
    fn selected_chain_runs_from_genesis_to_the_selected_tip() {
        let (mut t, genesis) = TestDag::new();
        let a = t.add(vec![genesis], 1);
        let b = t.add(vec![a], 2);
        let tip = selected_tip(&t.ghostdag, &t.tips).unwrap();
        assert_eq!(tip, b);
        let chain = selected_chain(&t.ghostdag, &tip);
        assert_eq!(chain, vec![genesis, a, b]);
    }

    #[test]
    fn a_merge_whose_mergeset_exceeds_the_cap_is_rejected_before_coloring() {
        // Build a wide burst so a merging block has a large mergeset, then ask
        // for its ghostdag data with a small cap — it must error out (cheaply,
        // before the expensive coloring) rather than process the whole merge.
        let (mut t, genesis) = TestDag::new();
        let mut siblings = Vec::new();
        for i in 0..8u8 {
            siblings.push(t.add(vec![genesis], 50 + i));
        }
        // The mergeset of a block citing all 8 siblings is 7 (all but the
        // selected parent). Cap of 3 must reject it.
        let err =
            try_compute_ghostdag_data(&t.dag, &t.ghostdag, &t.reach, &siblings, 3).unwrap_err();
        assert!(err.contains("Mergeset too large"), "got: {err}");
        // With a generous cap it succeeds.
        assert!(try_compute_ghostdag_data(&t.dag, &t.ghostdag, &t.reach, &siblings, 100).is_ok());
    }

    #[test]
    fn selected_tip_prefers_higher_blue_work_on_competing_branches() {
        let (mut t, genesis) = TestDag::new();
        let a1 = t.add(vec![genesis], 1);
        let a2 = t.add(vec![a1], 2);
        let a3 = t.add(vec![a2], 3);
        let b1 = t.add(vec![genesis], 10);
        let tip = selected_tip(&t.ghostdag, &t.tips).unwrap();
        assert_eq!(tip, a3, "longer blue branch must win tip selection");
        assert!(t.score(&a3) > t.score(&b1));
        let chain = selected_chain(&t.ghostdag, &tip);
        assert!(chain.contains(&genesis) && chain.contains(&a3));
        assert!(!chain.contains(&b1));
    }

    #[test]
    fn blue_score_monotonic_along_selected_chain() {
        let (mut t, genesis) = TestDag::new();
        let mut prev = genesis;
        for i in 1..12u8 {
            prev = t.add(vec![prev], i);
        }
        let tip = selected_tip(&t.ghostdag, &t.tips).unwrap();
        let chain = selected_chain(&t.ghostdag, &tip);
        let mut last = 0u64;
        for h in &chain {
            let s = t.score(h);
            assert!(s >= last);
            last = s;
        }
    }
}
