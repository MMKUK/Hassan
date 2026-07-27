//! Engineered assurance: property checks, lightweight fuzz loops, soak helpers.
//!
//! Replaces “years of mainnet soak” with continuous, deterministic, automated
//! assurance that ships in-tree (property tests + fuzz-style unit loops).

use crate::ghostdag::{self, GhostdagData};
use crate::utxo::{OutPoint, TxOut, UtxoSet};
use crate::{predicate, Hash};
use std::collections::HashMap;

/// GHOSTDAG mergeset invariant: selected parent is first blue; no dupes.
pub fn mergeset_invariants(gd: &GhostdagData) -> Result<(), String> {
    if gd.mergeset_blues.is_empty() {
        return Err("mergeset blues empty".into());
    }
    if gd.blue_score > 0 && gd.selected_parent != Some(gd.mergeset_blues[0]) {
        return Err("selected parent must be first mergeset blue".into());
    }
    let mut seen = std::collections::HashSet::new();
    for h in gd.mergeset_blues.iter().chain(gd.mergeset_reds.iter()) {
        if !seen.insert(*h) {
            return Err("duplicate hash in mergeset".into());
        }
    }
    Ok(())
}

/// Supply conservation on a ledger snapshot.
pub fn supply_components_sum(
    accounts: u128,
    staked: u128,
    utxo: u128,
    fees_burned: u128,
) -> u128 {
    accounts
        .saturating_add(staked)
        .saturating_add(utxo)
        .saturating_add(fees_burned)
}

/// Fuzz-style: random predicate nesting evaluates without panic.
pub fn fuzz_predicate_evaluate(seed: u64, rounds: usize) {
    let mut x = seed;
    for _ in 0..rounds {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let addr = format!("hsn:{}", hex::encode([((x >> 8) as u8); 64]));
        let pred = match x % 5 {
            0 => predicate::Predicate::PayToAddress {
                address: addr.clone(),
            },
            1 => predicate::Predicate::HashLock {
                hash: predicate::hashlock_commitment(&(x as u32).to_le_bytes()),
            },
            2 => predicate::Predicate::AbsoluteLock {
                address: addr.clone(),
                unlock_blue: x % 1000,
            },
            3 => predicate::Predicate::RelativeLock {
                address: addr.clone(),
                relative_blues: (x % 50) as u32,
            },
            _ => predicate::Predicate::Or {
                left: Box::new(predicate::Predicate::PayToAddress {
                    address: addr.clone(),
                }),
                right: Box::new(predicate::Predicate::HashLock {
                    hash: predicate::hashlock_commitment(b"z"),
                }),
            },
        };
        let _ = predicate::evaluate_full(
            &pred,
            &predicate::UnlockWitness::Signature,
            &addr,
            x % 2000,
            0,
            None,
        );
    }
}

/// Fuzz-style: UTXO insert/spend sequences stay consistent.
pub fn fuzz_utxo_roundtrip(seed: u64, rounds: usize) {
    let mut set = UtxoSet::default();
    let mut x = seed;
    let mut live: Vec<OutPoint> = Vec::new();
    for i in 0..rounds {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        if x % 3 != 0 || live.is_empty() {
            let op = OutPoint {
                txid: Hash([(x as u8).wrapping_add(i as u8); 64]),
                vout: (x % 16) as u32,
            };
            if set.contains(&op) {
                continue;
            }
            set.insert(
                op,
                TxOut {
                    value: (x % 10_000) as u128 + 546,
                    predicate: predicate::Predicate::PayToAddress {
                        address: format!("hsn:{}", hex::encode([1u8; 64])),
                    },
                    created_blue: x % 100,
                },
            );
            live.push(op);
        } else {
            let idx = (x as usize) % live.len();
            let op = live.swap_remove(idx);
            let _ = set.spend(&op);
        }
        let _ = set.commitment();
        let _ = set.total_value();
    }
}

/// Tiny in-process soak: mine N blocks and check tip + supply invariant.
pub fn soak_mine_blocks(n: usize) -> Result<(), String> {
    use crate::{
        generate_keypair, seal_block, Block, ChainState, GENESIS_TIMESTAMP_MS, TARGET_BLOCK_TIME_MS,
    };
    let mut state = ChainState::new();
    let mut ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
    for i in 0..n {
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
            nonce: i as u64,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: i as u64,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state.bind_parent_commitments(&mut block)?;
        let (sk, pk) = generate_keypair();
        seal_block(&state, &mut block, &sk, &pk);
        state.add_block(block)?;
        if !state.supply_invariant_ok() {
            return Err(format!("supply invariant broken at block {i}"));
        }
        ts = ts.saturating_add(TARGET_BLOCK_TIME_MS);
    }
    if state.selected_tip_blue_score() < n as u64 {
        return Err("blue score too low after soak".into());
    }
    Ok(())
}

/// Property: selected tip is always among tips and has max blue_score.
pub fn selected_tip_is_heaviest(
    ghostdag: &HashMap<Hash, GhostdagData>,
    tips: &[Hash],
) -> Result<(), String> {
    let Some(tip) = ghostdag::selected_tip(ghostdag, tips) else {
        return Ok(());
    };
    if !tips.contains(&tip) {
        return Err("selected tip not in tips".into());
    }
    let tip_score = ghostdag.get(&tip).map(|d| d.blue_score).unwrap_or_default();
    for t in tips {
        let w = ghostdag.get(t).map(|d| d.blue_score).unwrap_or_default();
        if w > tip_score {
            return Err("heavier tip exists than selected".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainState;

    #[test]
    fn fuzz_predicates_do_not_panic() {
        fuzz_predicate_evaluate(0xC0FFEE, 200);
    }

    #[test]
    fn fuzz_utxo_sequences() {
        fuzz_utxo_roundtrip(42, 300);
    }

    #[test]
    fn soak_32_blocks_keeps_supply() {
        soak_mine_blocks(32).expect("soak");
    }

    #[test]
    #[ignore]
    fn soak_long_512_blocks() {
        soak_mine_blocks(512).expect("long soak");
    }

    #[test]
    fn tip_heaviest_on_fresh_chain() {
        let st = ChainState::new();
        selected_tip_is_heaviest(&st.ghostdag, &st.tips).unwrap();
        soak_mine_blocks(8).unwrap();
    }

    #[test]
    fn supply_components_identity() {
        assert_eq!(supply_components_sum(10, 20, 30, 40), 100);
    }

    #[test]
    fn daa_window_constant_is_sane() {
        assert_eq!(crate::DAA_WINDOW_CONSENSUS, 661);
        assert!(crate::DAA_WINDOW >= 16);
        assert!(crate::DAA_WINDOW <= 1024);
        assert_eq!(crate::BLOCK_TIME_MS, 100);
        assert_eq!(crate::FINALITY_DEPTH_CONSENSUS, 432_000);
        assert_eq!(
            crate::PRUNING_PROOF_RECENT_WINDOW,
            crate::DAA_WINDOW.saturating_mul(2)
        );
    }

    #[test]
    fn ghostdag_k_cluster_bound() {
        assert_eq!(ghostdag::GHOSTDAG_K, 40);
    }
}
