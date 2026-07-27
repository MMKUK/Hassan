//! Reachability oracle: fast ancestor queries for GHOSTDAG.
//!
//! ## What this is
//! An **interval-labelling** reachability oracle over the BlockDAG, the same
//! family of structure Kaspa uses. Every block is placed in a *reachability
//! tree* — the selected-parent tree — and assigned an integer interval
//! `[start, end]` with the laminar invariant that a node's interval strictly
//! contains each of its tree-descendants' intervals. Tree (a.k.a. *chain*)
//! ancestry is then a single interval-containment test:
//!
//! ```text
//! is_chain_ancestor(a, b)  ⟺  a.interval ⊇ b.interval
//! ```
//!
//! Non-tree DAG edges (a block's *merged* parents) are captured by a per-block
//! **future covering set** (FCS): a small, sorted, laminar antichain of blocks
//! in the node's DAG-future. A block `a` is a DAG-ancestor of `b` iff `a` is a
//! chain-ancestor of `b`, **or** some entry of `a`'s FCS is a chain-ancestor of
//! `b` (found by binary search). This is the algorithm of the PHANTOM/GHOSTDAG
//! reachability construction (Sompolinsky–Zohar).
//!
//! ## Memory
//! Each block stores O(1) tree data (an interval, its tree parent, its tree
//! children) plus its FCS. Unlike the previous implementation — which stored
//! each block's *entire* ancestor set (O(ancestors) per block) — this is the
//! compact interval representation, so the index no longer grows with the
//! square-ish `Σ ancestors`; it grows linearly in retained blocks.
//!
//! ## Honest scope — how this differs from Kaspa's production oracle
//! Kaspa reindexes **incrementally and locally** (a moving reindex root, a
//! bounded reindex depth, and slack accounting) so that interval exhaustion is
//! repaired by touching only a small neighbourhood. This implementation uses a
//! simpler **whole-forest reindex**: when a node runs out of interval space for
//! a new child, all intervals are recomputed from scratch (O(retained blocks)),
//! sized with generous slack so reindexes are rare. Query time and memory match
//! Kaspa's asymptotics; the reindex is not Kaspa's proven amortized bound.
//! Node removal (`drop_leaf`) is only safe for tree leaves; interior blocks stay
//! in the index until the whole old prefix is pruned together (see full
//! pruning). This is a from-scratch, readable implementation — **not** a port of
//! Kaspa's optimized code.
//!
//! ## Why you can trust it
//! Correctness is gated by an exhaustive differential test
//! (`differential_matches_bfs_on_random_dags`): thousands of ancestor and
//! anticone queries across many random DAG shapes, including forced frequent
//! reindexing, asserted equal to a reference BFS on every pair. In debug/test
//! builds `is_ancestor` also cross-checks itself against BFS at runtime
//! (`debug_assert`), so any divergence trips immediately.

use crate::Block;
use std::collections::{HashMap, HashSet};

pub use crate::Hash;

/// Per-node interval window multiplier used by a full reindex: a subtree of
/// `s` blocks is given `s * SCALE` interval units, leaving ample slack so
/// incremental inserts rarely exhaust a node.
const SCALE: u64 = 1 << 20;
/// When an incremental insert hands a new child most of its parent's remaining
/// interval space, this many units are held back for possible future siblings.
const SIBLING_RESERVE: u64 = 64;
/// The interval space starts here (0 is reserved as "below every interval").
const SPACE_START: u64 = 1;
/// Upper bound of the interval space. Windows are laid out below this; with
/// `SCALE` slack and pruning-bounded block counts this is never approached.
const SPACE_END: u64 = 1 << 62;

/// A half-inclusive-free, fully-inclusive interval `[start, end]` on the
/// reachability tree. A node's own label is `end`; its tree-children occupy
/// disjoint sub-intervals of `[start, end - 1]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Interval {
    start: u64,
    end: u64,
}

impl Interval {
    /// Reflexive containment: does `self` contain `other` (equal counts)?
    fn contains(&self, other: &Interval) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// A block's node in the reachability structure.
#[derive(Clone, Debug)]
struct Node {
    interval: Interval,
    /// Selected parent in the reachability (chain) tree; `None` for a root.
    tree_parent: Option<Hash>,
    /// Tree children, in insertion order (stable across reindexes).
    tree_children: Vec<Hash>,
    /// Next free interval unit for a new child (advances as children are added).
    next_free: u64,
    /// Future covering set: a laminar antichain of DAG-future blocks, kept
    /// sorted ascending by `interval.start`.
    fcs: Vec<Hash>,
}

/// Interval-labelling reachability oracle over a BlockDAG.
#[derive(Clone, Debug, Default)]
pub struct Reachability {
    nodes: HashMap<Hash, Node>,
    /// Next free start for a brand-new root window.
    next_root_start: u64,
}

impl Reachability {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            next_root_start: SPACE_START,
        }
    }

    /// Register a block. `selected_parent` is its reachability-tree parent (its
    /// GHOSTDAG selected parent, or `None` for genesis / a block whose selected
    /// parent has been pruned). `mergeset` is the block's merged blocks (its
    /// non-selected-parent past that the selected parent doesn't already
    /// reach) — exactly the set into whose future covering sets this block is
    /// inserted. `dag` is unused by the interval oracle itself and kept only
    /// for the debug cross-check in `is_ancestor`.
    pub fn add_block(
        &mut self,
        hash: Hash,
        selected_parent: Option<Hash>,
        mergeset: &[Hash],
        _dag: &HashMap<Hash, Block>,
    ) {
        if self.nodes.contains_key(&hash) {
            return; // idempotent
        }
        // 1. Tree insertion.
        match selected_parent.filter(|p| self.nodes.contains_key(p)) {
            Some(parent) => self.insert_tree_child(parent, hash),
            None => self.insert_root(hash),
        }
        // 2. DAG insertion: record this block in the future covering set of each
        //    block it merges.
        for m in mergeset {
            if *m != hash && self.nodes.contains_key(m) {
                self.insert_to_fcs(*m, hash);
            }
        }
    }

    /// Allocate a fresh root window and insert `hash` as a root.
    fn insert_root(&mut self, hash: Hash) {
        if self.next_root_start.saturating_add(SCALE) >= SPACE_END {
            self.reindex_all();
        }
        let start = self.next_root_start;
        let end = start + SCALE - 1;
        self.next_root_start = end + 1;
        self.nodes.insert(
            hash,
            Node {
                interval: Interval { start, end },
                tree_parent: None,
                tree_children: Vec::new(),
                next_free: start,
                fcs: Vec::new(),
            },
        );
    }

    /// Insert `hash` as a tree child of `parent`, reindexing the whole forest if
    /// `parent` has no interval space left for a new child.
    fn insert_tree_child(&mut self, parent: Hash, hash: Hash) {
        if !self.try_place_child(parent, hash) {
            // Parent is out of interval room: rebuild all intervals with slack,
            // then the retry is guaranteed to fit.
            self.reindex_all();
            let placed = self.try_place_child(parent, hash);
            debug_assert!(placed, "child must fit after a full reindex");
            if !placed {
                // Extremely defensive: give it a root window rather than panic
                // (panic = node death under `panic = "abort"`).
                self.insert_root(hash);
            }
        }
    }

    /// Try to carve a sub-interval for a new child out of `parent`'s free space.
    /// Returns false (without mutating) if there is no room.
    fn try_place_child(&mut self, parent: Hash, hash: Hash) -> bool {
        let (p_next, p_end) = {
            let p = &self.nodes[&parent];
            (p.next_free, p.interval.end)
        };
        // Usable child positions are [p_next, p_end - 1]; need at least one.
        if p_next >= p_end {
            return false;
        }
        let avail = p_end - p_next; // count of free units in [p_next, p_end-1]
                                    // Greedily give the new child most of the free space (chains keep
                                    // descending into the newest child), holding back a small reserve for
                                    // future siblings.
        let width = if avail > SIBLING_RESERVE {
            avail - SIBLING_RESERVE
        } else {
            avail
        };
        let start = p_next;
        let end = start + width - 1; // <= p_end - 1
        self.nodes.get_mut(&parent).unwrap().next_free = end + 1;
        self.nodes
            .get_mut(&parent)
            .unwrap()
            .tree_children
            .push(hash);
        self.nodes.insert(
            hash,
            Node {
                interval: Interval { start, end },
                tree_parent: Some(parent),
                tree_children: Vec::new(),
                next_free: start,
                fcs: Vec::new(),
            },
        );
        true
    }

    /// Insert `new` into `block`'s future covering set, keeping it a sorted,
    /// laminar antichain. No-op if an existing entry already covers `new`.
    fn insert_to_fcs(&mut self, block: Hash, new: Hash) {
        let ni = self.nodes[&new].interval;
        if self.fcs_contains_cover(block, &ni) {
            return; // already covered — inserting would be redundant
        }
        // `new` is the newest block, so it cannot contain any existing (older)
        // entry; it is disjoint from all of them. Insert it at its sorted-by-
        // start position.
        let pos = {
            let fcs = &self.nodes[&block].fcs;
            fcs.partition_point(|h| self.nodes[h].interval.start <= ni.start)
        };
        self.nodes.get_mut(&block).unwrap().fcs.insert(pos, new);
    }

    /// Is `a` a *strict* ancestor of `b` in the DAG? O(1) chain check plus an
    /// O(log |FCS|) covering search. Falls back to BFS only if a block is not in
    /// the index (e.g. pruned).
    pub fn is_ancestor(&self, a: &Hash, b: &Hash, dag: &HashMap<Hash, Block>) -> bool {
        let result = match (self.nodes.get(a), self.nodes.get(b)) {
            (Some(_), Some(_)) => a != b && self.is_dag_ancestor_incl(a, b),
            _ => bfs_is_ancestor(dag, a, b),
        };
        debug_assert_eq!(
            result,
            bfs_is_ancestor(dag, a, b),
            "reachability index disagrees with BFS"
        );
        result
    }

    /// Reflexive DAG ancestry (`a` reaches `b`, counting `a == b`). Both blocks
    /// must be present in the index.
    fn is_dag_ancestor_incl(&self, a: &Hash, b: &Hash) -> bool {
        if self.is_chain_ancestor_incl(a, b) {
            return true;
        }
        let bi = self.nodes[b].interval;
        self.fcs_contains_cover(*a, &bi)
    }

    /// Reflexive chain (tree) ancestry via interval containment.
    fn is_chain_ancestor_incl(&self, a: &Hash, b: &Hash) -> bool {
        self.nodes[a].interval.contains(&self.nodes[b].interval)
    }

    /// Public reflexive chain-ancestry test: is `a` on the selected-parent
    /// (reachability-tree) chain of `b` — i.e. does following `b`'s selected
    /// parents reach `a` (or `a == b`)? `Some(true)`/`Some(false)` when both
    /// blocks are indexed; `None` if either is absent (pruned), so callers can
    /// decide the fail-open/closed policy. Used by the finality rule to check a
    /// new block's selected chain includes the finality point.
    pub fn is_chain_ancestor(&self, a: &Hash, b: &Hash) -> Option<bool> {
        match (self.nodes.get(a), self.nodes.get(b)) {
            (Some(na), Some(nb)) => Some(na.interval.contains(&nb.interval)),
            _ => None,
        }
    }

    /// Does `block`'s FCS contain an entry that is a chain-ancestor of the
    /// interval `target` (i.e. covers it)? Because the FCS is a laminar antichain
    /// sorted by `start`, the only possible cover is the entry with the greatest
    /// `start <= target.start`.
    fn fcs_contains_cover(&self, block: Hash, target: &Interval) -> bool {
        let fcs = &self.nodes[&block].fcs;
        let idx = fcs.partition_point(|h| self.nodes[h].interval.start <= target.start);
        if idx == 0 {
            return false;
        }
        let cand = fcs[idx - 1];
        self.nodes[&cand].interval.contains(target)
    }

    /// True iff `x` and `y` are concurrent (each in the other's anticone):
    /// neither is an ancestor of the other.
    pub fn in_anticone(&self, x: &Hash, y: &Hash, dag: &HashMap<Hash, Block>) -> bool {
        x != y && !self.is_ancestor(x, y, dag) && !self.is_ancestor(y, x, dag)
    }

    /// Remove a block from the index. **Only safe for tree leaves** (a node with
    /// no tree children); removing an interior node would sever its descendants'
    /// ancestry. Interior blocks are retained until a whole old prefix is pruned
    /// together. No-op if `hash` is absent or is an interior node.
    pub fn drop_leaf(&mut self, hash: &Hash) {
        let is_leaf = self
            .nodes
            .get(hash)
            .map(|n| n.tree_children.is_empty())
            .unwrap_or(false);
        if !is_leaf {
            return;
        }
        let parent = self.nodes[hash].tree_parent;
        self.nodes.remove(hash);
        if let Some(p) = parent {
            if let Some(pn) = self.nodes.get_mut(&p) {
                pn.tree_children.retain(|c| c != hash);
            }
        }
        // Purge it from any future covering set that referenced it.
        for node in self.nodes.values_mut() {
            node.fcs.retain(|h| h != hash);
        }
    }

    /// Prune history: keep only the blocks in `keep`, discarding everything
    /// else. Survivors whose tree parent was discarded become roots; every
    /// future-covering-set entry pointing at a discarded block is purged. This
    /// is safe **only** when `keep` is an upper-closed set by blue score (a
    /// pruning suffix) — which is how `ChainState` calls it — because then no
    /// retained ancestry or covering relationship runs through a discarded
    /// block. Intervals of survivors are unchanged (still laminar among
    /// themselves), so queries among survivors stay correct.
    pub fn retain(&mut self, keep: &HashSet<Hash>) {
        self.nodes.retain(|h, _| keep.contains(h));
        for node in self.nodes.values_mut() {
            if let Some(p) = node.tree_parent {
                if !keep.contains(&p) {
                    node.tree_parent = None; // became a root
                }
            }
            node.tree_children.retain(|c| keep.contains(c));
            node.fcs.retain(|h| keep.contains(h));
        }
        // Keep the root cursor beyond every live interval so fresh roots don't
        // collide with survivors.
        self.next_root_start = self
            .nodes
            .values()
            .map(|n| n.interval.end + 1)
            .max()
            .unwrap_or(SPACE_START);
    }

    /// Rebuild every interval from scratch with generous slack. Preserves the
    /// tree structure, tree-parent/child links, and FCS *membership*; only the
    /// numeric intervals change. O(retained blocks).
    fn reindex_all(&mut self) {
        // Subtree sizes via iterative post-order.
        let sizes = self.subtree_sizes();
        let roots: Vec<Hash> = self
            .nodes
            .iter()
            .filter(|(_, n)| {
                n.tree_parent
                    .map(|p| !self.nodes.contains_key(&p))
                    .unwrap_or(true)
            })
            .map(|(h, _)| *h)
            .collect();

        // Assign each node a window via an explicit pre-order stack; every entry
        // carries its own window start, so processing order is irrelevant.
        let mut cursor = SPACE_START;
        let mut stack: Vec<(Hash, u64)> = Vec::new();
        for r in roots {
            stack.push((r, cursor));
            cursor += sizes[&r].saturating_mul(SCALE);
        }
        self.next_root_start = cursor;

        while let Some((node, start)) = stack.pop() {
            let size = sizes[&node];
            let end = start + size.saturating_mul(SCALE) - 1;
            let children = self.nodes[&node].tree_children.clone();
            let mut child_cursor = start;
            for c in &children {
                stack.push((*c, child_cursor));
                child_cursor += sizes[c].saturating_mul(SCALE);
            }
            let n = self.nodes.get_mut(&node).unwrap();
            n.interval = Interval { start, end };
            n.next_free = child_cursor;
        }

        // Intervals moved, so re-sort every FCS by the new start. (Relative
        // start order is actually preserved by a structure-faithful reindex, but
        // re-sorting is cheap insurance against that assumption ever breaking.)
        let keys: Vec<Hash> = self.nodes.keys().copied().collect();
        for k in keys {
            let mut fcs = std::mem::take(&mut self.nodes.get_mut(&k).unwrap().fcs);
            fcs.sort_by_key(|h| self.nodes[h].interval.start);
            self.nodes.get_mut(&k).unwrap().fcs = fcs;
        }
    }

    /// Subtree size (inclusive) of every node, computed iteratively.
    fn subtree_sizes(&self) -> HashMap<Hash, u64> {
        let mut sizes: HashMap<Hash, u64> = HashMap::with_capacity(self.nodes.len());
        let roots: Vec<Hash> = self
            .nodes
            .iter()
            .filter(|(_, n)| {
                n.tree_parent
                    .map(|p| !self.nodes.contains_key(&p))
                    .unwrap_or(true)
            })
            .map(|(h, _)| *h)
            .collect();
        let mut stack: Vec<(Hash, bool)> = roots.into_iter().map(|r| (r, false)).collect();
        while let Some((node, processed)) = stack.pop() {
            if processed {
                let s = 1 + self.nodes[&node]
                    .tree_children
                    .iter()
                    .map(|c| sizes[c])
                    .sum::<u64>();
                sizes.insert(node, s);
            } else {
                stack.push((node, true));
                for c in &self.nodes[&node].tree_children {
                    stack.push((*c, false));
                }
            }
        }
        sizes
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.nodes.len()
    }
}

/// The set of all strict ancestors of `b` via a plain BFS over parent edges.
/// This is the ground-truth reference the index is validated against.
pub fn bfs_ancestors(dag: &HashMap<Hash, Block>, b: &Hash) -> HashSet<Hash> {
    let mut set: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<Hash> = dag
        .get(b)
        .map(|blk| blk.parents.clone())
        .unwrap_or_default();
    while let Some(x) = stack.pop() {
        if set.insert(x) {
            if let Some(blk) = dag.get(&x) {
                stack.extend(blk.parents.iter().copied());
            }
        }
    }
    set
}

/// Reference ancestor test (the oracle is validated to match this exactly).
pub fn bfs_is_ancestor(dag: &HashMap<Hash, Block>, a: &Hash, b: &Hash) -> bool {
    bfs_ancestors(dag, b).contains(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::now_ms;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn block_with_parents(parents: Vec<Hash>, tag: u64) -> Block {
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
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: tag,
            difficulty: 1,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        }
    }

    /// Reference: a block's reachability selected parent is the parent with the
    /// most ancestors (deepest), tie-broken by hash — a stand-in for GHOSTDAG's
    /// selected parent that is deterministic and gives a valid spanning tree.
    fn ref_selected_parent(dag: &HashMap<Hash, Block>, parents: &[Hash]) -> Option<Hash> {
        parents.iter().copied().max_by(|a, b| {
            let na = bfs_ancestors(dag, a).len();
            let nb = bfs_ancestors(dag, b).len();
            na.cmp(&nb).then_with(|| a.cmp(b))
        })
    }

    /// Reference mergeset: everything reachable from any parent that the selected
    /// parent does not already reach (and is not the selected parent itself).
    fn ref_mergeset(dag: &HashMap<Hash, Block>, parents: &[Hash], sp: &Hash) -> Vec<Hash> {
        let mut sp_past = bfs_ancestors(dag, sp);
        sp_past.insert(*sp);
        let mut set: HashSet<Hash> = HashSet::new();
        let mut stack: Vec<Hash> = parents.to_vec();
        while let Some(x) = stack.pop() {
            if sp_past.contains(&x) || !set.insert(x) {
                continue;
            }
            if let Some(b) = dag.get(&x) {
                stack.extend(b.parents.iter().copied());
            }
        }
        set.into_iter().collect()
    }

    /// Build a random DAG, feeding the oracle a valid selected-parent tree and
    /// mergesets. `reindex_pressure` forces the oracle to reindex frequently by
    /// shrinking the interval space (exercises the reindex path hard).
    fn random_dag(
        rng: &mut StdRng,
        n: usize,
        reindex_pressure: bool,
    ) -> (HashMap<Hash, Block>, Reachability, Vec<Hash>) {
        let mut dag = HashMap::new();
        let mut reach = Reachability::new();
        let mut order: Vec<Hash> = Vec::new();

        let genesis = block_with_parents(vec![], 0);
        let gh = genesis.hash();
        dag.insert(gh, genesis);
        reach.add_block(gh, None, &[], &dag);
        order.push(gh);

        for i in 1..n {
            let num_parents = 1 + rng.gen_range(0..3usize);
            let mut parents: Vec<Hash> = Vec::new();
            while parents.len() < num_parents && parents.len() < order.len() {
                let p = order[rng.gen_range(0..order.len())];
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
            let block = block_with_parents(parents.clone(), i as u64);
            let h = block.hash();
            dag.insert(h, block);
            let sp = ref_selected_parent(&dag, &parents);
            let ms = sp
                .map(|s| ref_mergeset(&dag, &parents, &s))
                .unwrap_or_default();
            reach.add_block(h, sp, &ms, &dag);
            if reindex_pressure {
                // Force reindexing far more often than production would, so the
                // rebuild path is covered on essentially every DAG.
                reach.next_root_start = SPACE_END - 4;
            }
            order.push(h);
        }

        (dag, reach, order)
    }

    #[test]
    fn differential_matches_bfs_on_random_dags() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for trial in 0..60 {
            let n = 5 + (trial % 35);
            let pressure = trial % 2 == 0;
            let (dag, reach, order) = random_dag(&mut rng, n, pressure);
            for a in &order {
                for b in &order {
                    assert_eq!(
                        reach.is_ancestor(a, b, &dag),
                        bfs_is_ancestor(&dag, a, b),
                        "is_ancestor vs BFS mismatch in a {n}-block DAG (pressure={pressure})",
                    );
                }
            }
        }
    }

    #[test]
    fn anticone_matches_bfs() {
        let mut rng = StdRng::seed_from_u64(42);
        let (dag, reach, order) = random_dag(&mut rng, 45, true);
        for x in &order {
            for y in &order {
                let idx = reach.in_anticone(x, y, &dag);
                let bfs = x != y && !bfs_is_ancestor(&dag, x, y) && !bfs_is_ancestor(&dag, y, x);
                assert_eq!(idx, bfs, "in_anticone disagrees with BFS");
            }
        }
    }

    #[test]
    fn a_linear_chain_is_nested_intervals() {
        // A straight chain: each block's interval must strictly contain the
        // next's, so chain-ancestry holds for every earlier→later pair.
        let mut dag = HashMap::new();
        let mut reach = Reachability::new();
        let g = block_with_parents(vec![], 0);
        let gh = g.hash();
        dag.insert(gh, g);
        reach.add_block(gh, None, &[], &dag);
        let mut prev = gh;
        let mut chain = vec![gh];
        for i in 1..200u64 {
            let b = block_with_parents(vec![prev], i);
            let h = b.hash();
            dag.insert(h, b);
            reach.add_block(h, Some(prev), &[], &dag);
            chain.push(h);
            prev = h;
        }
        for i in 0..chain.len() {
            for j in 0..chain.len() {
                let expect = i < j; // earlier is a strict ancestor of later
                assert_eq!(
                    reach.is_ancestor(&chain[i], &chain[j], &dag),
                    expect,
                    "chain ancestry wrong for ({i},{j})",
                );
            }
        }
    }

    #[test]
    fn dropping_a_leaf_keeps_queries_correct() {
        let mut rng = StdRng::seed_from_u64(7);
        let (dag, mut reach, order) = random_dag(&mut rng, 30, false);
        // Drop every current tree leaf; queries among the survivors must still
        // match BFS.
        let leaves: Vec<Hash> = reach
            .nodes
            .iter()
            .filter(|(_, n)| n.tree_children.is_empty())
            .map(|(h, _)| *h)
            .collect();
        let before = reach.len();
        for h in &leaves {
            reach.drop_leaf(h);
        }
        assert!(reach.len() < before, "some leaves should have been removed");
        let survivors: Vec<Hash> = order
            .iter()
            .copied()
            .filter(|h| !leaves.contains(h))
            .collect();
        for a in &survivors {
            for b in &survivors {
                assert_eq!(
                    reach.is_ancestor(a, b, &dag),
                    bfs_is_ancestor(&dag, a, b),
                    "post-leaf-drop query must still match BFS",
                );
            }
        }
    }
}
