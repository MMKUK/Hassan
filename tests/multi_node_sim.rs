//! In-process multi-node digital-twin harness (simpa-class).
//!
//! Spins N independent `ChainState` instances, mines blocks on one, and
//! gossip-applies them to the others — exercising selected-parent safety and
//! tip convergence without sockets.

use hassan::{
    generate_keypair, genesis_block, seal_block, Block, ChainState, Hash, GENESIS_TIMESTAMP_MS,
    TARGET_BLOCK_TIME_MS,
};

fn enable_lab_pow() {
    // Optional: keep bootstrap floor if a long soak crossed 1M HSN. Not required
    // for genesis-era mining (v29 schedule already uses floor 7000 until 1M).
    std::env::set_var(hassan::BOOTSTRAP_EASY_ENV, "1");
}

fn mine_on(state: &mut ChainState, ts: u64, tag: u8) -> Block {
    enable_lab_pow();
    let parents = state.tips.clone();
    let difficulty = state.expected_difficulty_at(&parents, ts);
    let mut block = Block {
        height: state.tip_height().saturating_add(1),
        timestamp: ts,
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
        nonce: tag as u64,
        difficulty,
        version: hassan::default_block_version(),
        coinbase_entropy: 0,
        stark_proof: vec![],
        birth_certificate: Default::default(),
        size: 0,
    };
    state
        .bind_parent_commitments(&mut block)
        .expect("bind parents");
    let (sk, pk) = generate_keypair();
    seal_block(state, &mut block, &sk, &pk);
    block
}

#[test]
fn twin_nodes_converge_on_selected_tip() {
    enable_lab_pow();
    let n = 3usize;
    let blocks = 8usize;
    let mut nodes: Vec<ChainState> = (0..n).map(|_| ChainState::new()).collect();
    let mut ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;

    for i in 0..blocks {
        let mined = mine_on(&mut nodes[0], ts, i as u8);
        let hash = mined.hash();
        nodes[0].add_block(mined.clone()).expect("miner accepts");
        for node in nodes.iter_mut().skip(1) {
            node.add_block(mined.clone())
                .unwrap_or_else(|e| panic!("peer reject block {i}: {e}"));
        }
        ts = ts.saturating_add(TARGET_BLOCK_TIME_MS);
    }
    let tips: Vec<Hash> = nodes
        .iter()
        .map(|n| hassan::ghostdag::selected_tip(&n.ghostdag, &n.tips).expect("tip"))
        .collect();
    assert!(
        tips.iter().all(|t| *t == tips[0]),
        "nodes diverged: {tips:?}"
    );

    let blues: Vec<u64> = nodes.iter().map(|n| n.selected_tip_blue_score()).collect();
    assert!(blues.iter().all(|b| *b == blues[0]));
    assert!(blues[0] >= blocks as u64);
}

#[test]
fn soak_two_nodes_for_m_blocks() {
    enable_lab_pow();
    let m = 24usize;
    let mut nodes = [ChainState::new(), ChainState::new()];
    let mut ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
    for i in 0..m {
        let miner_idx = i % 2;
        let other_idx = 1 - miner_idx;
        let block = mine_on(&mut nodes[miner_idx], ts, (i % 250) as u8);
        nodes[miner_idx].add_block(block.clone()).expect("local");
        nodes[other_idx].add_block(block).expect("remote");
        ts = ts.saturating_add(TARGET_BLOCK_TIME_MS);
    }
    assert_eq!(
        nodes[0].selected_tip_blue_score(),
        nodes[1].selected_tip_blue_score()
    );
    assert_eq!(
        hassan::ghostdag::selected_tip(&nodes[0].ghostdag, &nodes[0].tips),
        hassan::ghostdag::selected_tip(&nodes[1].ghostdag, &nodes[1].tips)
    );
}

/// Honest parallel tips: two miners extend the same parent → both blocks
/// admit; tip count grows (DAG width). Aggregate accepted blocks/sec can
/// scale with nodes/hashrate while per-selected-parent DAA still targets
/// `TARGET_BLOCK_TIME_MS`.
#[test]
fn parallel_sibling_tips_both_admit_and_merge() {
    enable_lab_pow();
    let genesis = ChainState::new().tips[0];
    let ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;

    let miner_a = ChainState::new();
    let miner_b = ChainState::new();
    let sib_a = {
        let difficulty = miner_a.expected_difficulty_at(&[genesis], ts);
        let mut block = Block {
            height: 1,
            timestamp: ts,
            parents: vec![genesis],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 1,
            difficulty,
            version: hassan::default_block_version(),
            coinbase_entropy: 11,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        miner_a
            .bind_parent_commitments(&mut block)
            .expect("bind a");
        let (sk, pk) = generate_keypair();
        seal_block(&miner_a, &mut block, &sk, &pk);
        block
    };
    let sib_b = {
        let difficulty = miner_b.expected_difficulty_at(&[genesis], ts);
        let mut block = Block {
            height: 1,
            timestamp: ts,
            parents: vec![genesis],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 2,
            difficulty,
            version: hassan::default_block_version(),
            coinbase_entropy: 22,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        miner_b
            .bind_parent_commitments(&mut block)
            .expect("bind b");
        let (sk, pk) = generate_keypair();
        seal_block(&miner_b, &mut block, &sk, &pk);
        block
    };

    assert_ne!(sib_a.hash(), sib_b.hash(), "siblings must be distinct");
    assert_eq!(sib_a.difficulty, sib_b.difficulty);

    let mut hub = ChainState::new();
    hub.add_block(sib_a.clone()).expect("sibling a");
    hub.add_block(sib_b.clone()).expect("sibling b");
    assert_eq!(hub.tips.len(), 2, "both parallel tips stay live");
    assert_eq!(hub.dag.len(), 3, "genesis + two accepted siblings");

    // Merge citing both tips — blue score advances by mergeset, not 1:1 height.
    let merge_ts = ts.saturating_add(TARGET_BLOCK_TIME_MS);
    let merge = mine_on(&mut hub, merge_ts, 99);
    assert!(
        merge.parents.len() >= 2,
        "merge should cite both sibling tips"
    );
    hub.add_block(merge).expect("merge");
    assert_eq!(hub.tips.len(), 1);
    assert!(
        hub.selected_tip_blue_score() >= 3,
        "mergeset should credit parallel blues (got {})",
        hub.selected_tip_blue_score()
    );
}

#[test]
fn genesis_anchors_match() {
    let g = genesis_block();
    assert_eq!(g.hash(), hassan::genesis_hash());
}

#[test]
fn target_block_time_is_100ms() {
    assert_eq!(hassan::BLOCK_TIME_MS, 100);
    assert_eq!(TARGET_BLOCK_TIME_MS, 100);
}
