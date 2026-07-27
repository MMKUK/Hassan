//! Two-node P2P sync: mine on A, assert tip/balances match on B after gossip.

use hassan::p2p::Node;
use hassan::{generate_keypair, hash_to_address, seal_block, ChainState};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

fn wait_until<F: Fn() -> bool>(timeout: Duration, cond: F) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    cond()
}

#[test]
fn two_nodes_sync_tips_after_mining() {
    let a_state = Arc::new(RwLock::new(ChainState::new()));
    let b_state = Arc::new(RwLock::new(ChainState::new()));
    let (miner_sk, miner_pk) = generate_keypair();

    let node_a = Node::new(a_state.clone());
    let node_b = Node::new(b_state.clone());

    let addr_a = node_a.listen("127.0.0.1:0").expect("listen A");
    let addr_b = node_b.listen("127.0.0.1:0").expect("listen B");
    node_a.connect(&addr_b.to_string()).expect("A->B");
    node_b.connect(&addr_a.to_string()).expect("B->A");
    node_a.spawn_tip_announcer();
    node_b.spawn_tip_announcer();

    for i in 0..3u64 {
        let mut s = a_state.write().unwrap();
        let parents = s.tips.clone();
        let ts = hassan::GENESIS_TIMESTAMP_MS + (i + 1) * hassan::TARGET_BLOCK_TIME_MS;
        let difficulty = s.expected_difficulty_at(&parents, ts);
        let mut block = hassan::genesis_block();
        block.parents = parents;
        block.difficulty = difficulty;
        block.timestamp = ts;
        s.bind_parent_commitments(&mut block)
            .expect("selected parent");
        seal_block(&s, &mut block, &miner_sk, &miner_pk);
        s.add_block(block).expect("mine on A");
    }

    let tip_a = a_state.read().unwrap().tips[0];
    let ok = wait_until(Duration::from_secs(20), || {
        b_state.read().unwrap().dag.contains_key(&tip_a)
    });
    assert!(ok, "node B must sync A's tip via P2P");

    let score_a = a_state.read().unwrap().selected_tip_blue_score();
    let score_b = b_state.read().unwrap().selected_tip_blue_score();
    assert_eq!(score_a, score_b, "blue scores must match after sync");

    let miner = hash_to_address(&miner_pk);
    let utxo_a: u128 = a_state
        .read()
        .unwrap()
        .utxo
        .entries
        .values()
        .filter(|o| o.predicate.locked_address() == Some(miner.as_str()))
        .map(|o| o.value)
        .sum();
    let utxo_b: u128 = b_state
        .read()
        .unwrap()
        .utxo
        .entries
        .values()
        .filter(|o| o.predicate.locked_address() == Some(miner.as_str()))
        .map(|o| o.value)
        .sum();
    assert_eq!(
        utxo_a, utxo_b,
        "miner UTXO coinbase totals must match after deterministic replay"
    );
    assert!(utxo_a > 0, "subsidy should have been minted into UTXO");
}
