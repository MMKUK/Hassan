//! CI-meaningful adversarial / soak checks for P2P hardening.
//!
//! Covers: invalid-block ban weight, multi-peer tip divergence sync, and
//! static peer rate-limit budgets that must not regress to the old soft
//! ceilings without `HASSAN_RELAX_NET=1`.

use hassan::p2p::{Node, BAN_SCORE_THRESHOLD, INVALID_BLOCK_PENALTY, MAX_ORPHANS};
use hassan::{generate_keypair, seal_block, ChainState};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

fn enable_lab_pow() {
    // Integration tests link the non-`cfg(test)` library build — PoW is hard-era
    // unless this env is set (same requirement as local mining labs).
    std::env::set_var(hassan::BOOTSTRAP_EASY_ENV, "1");
}

fn wait_until<F: Fn() -> bool>(timeout: Duration, cond: F) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(40));
    }
    cond()
}

fn mine_on(state: &mut ChainState, sk: &[u8], pk: &[u8], step: u64) {
    let parents = state.tips.clone();
    let ts = hassan::GENESIS_TIMESTAMP_MS + step * hassan::TARGET_BLOCK_TIME_MS;
    let difficulty = state.expected_difficulty_at(&parents, ts);
    let mut block = hassan::genesis_block();
    block.parents = parents;
    block.difficulty = difficulty;
    block.timestamp = ts;
    state
        .bind_parent_commitments(&mut block)
        .expect("selected parent");
    seal_block(state, &mut block, sk, pk);
    state.add_block(block).expect("mine");
}

#[test]
fn ban_threshold_reachable_from_invalid_block_penalties() {
    assert!(MAX_ORPHANS >= 100);
    assert!(
        5 * INVALID_BLOCK_PENALTY >= BAN_SCORE_THRESHOLD,
        "five invalid blocks must reach ban threshold (got threshold {BAN_SCORE_THRESHOLD})"
    );
}

#[test]
fn body_and_tx_inflight_caps_are_finite() {
    use hassan::p2p::{
        MAX_HEADERS_PER_MSG, MAX_IN_FLIGHT_BODIES, MAX_IN_FLIGHT_TX_GETS, MAX_LOCATOR_HASHES,
        MAX_TX_PACKAGE,
    };
    assert!(MAX_IN_FLIGHT_BODIES >= 8 && MAX_IN_FLIGHT_BODIES <= 256);
    assert!(MAX_IN_FLIGHT_TX_GETS >= 8 && MAX_IN_FLIGHT_TX_GETS <= 256);
    assert_eq!(MAX_HEADERS_PER_MSG, 2_000);
    assert_eq!(MAX_LOCATOR_HASHES, 64);
    assert_eq!(MAX_TX_PACKAGE, hassan::MAX_MEMPOOL_PACKAGE_NONCES);
}

#[test]
fn three_nodes_converge_after_conflicting_tips() {
    enable_lab_pow();
    let (sk, pk) = generate_keypair();
    let a_state = Arc::new(RwLock::new(ChainState::new()));
    let b_state = Arc::new(RwLock::new(ChainState::new()));
    let c_state = Arc::new(RwLock::new(ChainState::new()));

    let node_a = Node::new(a_state.clone());
    let node_b = Node::new(b_state.clone());
    let node_c = Node::new(c_state.clone());

    let addr_a = node_a.listen("127.0.0.1:0").expect("listen A");
    let addr_b = node_b.listen("127.0.0.1:0").expect("listen B");
    let addr_c = node_c.listen("127.0.0.1:0").expect("listen C");

    node_a.connect(&addr_b.to_string()).unwrap();
    node_b.connect(&addr_a.to_string()).unwrap();
    node_b.connect(&addr_c.to_string()).unwrap();
    node_c.connect(&addr_b.to_string()).unwrap();
    node_a.spawn_tip_announcer();
    node_b.spawn_tip_announcer();
    node_c.spawn_tip_announcer();

    {
        let mut s = a_state.write().unwrap();
        mine_on(&mut s, &sk, &pk, 1);
        mine_on(&mut s, &sk, &pk, 2);
    }
    {
        let mut s = c_state.write().unwrap();
        mine_on(&mut s, &sk, &pk, 1);
        mine_on(&mut s, &sk, &pk, 2);
        mine_on(&mut s, &sk, &pk, 3); // C heavier
    }

    let tip_c = c_state.read().unwrap().tips[0];
    let ok = wait_until(Duration::from_secs(25), || {
        a_state.read().unwrap().dag.contains_key(&tip_c)
            && b_state.read().unwrap().dag.contains_key(&tip_c)
    });
    assert!(
        ok,
        "A and B must learn C's heavier tip via gossip (conflicting tips)"
    );
}

#[test]
fn default_net_policy_is_not_soft_lab_ceilings() {
    std::env::remove_var("HASSAN_RELAX_NET");
    std::env::remove_var("HASSAN_PUBLIC");
    let p = hassan::net_policy::NetPolicy::from_env();
    assert!(!p.public_mode);
    // Non-relax default budgets (see net_policy.rs): 4000 / 16 / 60.
    assert_eq!(p.peer_msg_limit, 4_000);
    assert_eq!(p.stark_verifies_per_window, 16);
    assert_eq!(p.api_write_limit_per_window, 60);
}
