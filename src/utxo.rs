//! Hybrid UTXO value model for transparent spends.
//!
//! Spendable transparent value lives in outpoints. Registry / custody keep an
//! account overlay (credited via [`crate::predicate::Predicate::CreditAccount`]
//! outputs). Mergeset conflict resolution is the spent-outpoint set.

use crate::predicate::{Predicate, UnlockWitness};
use crate::Hash;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Reference to a created output: `(creating_tx_hash, output_index)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Hash,
    pub vout: u32,
}

impl OutPoint {
    /// Coinbase-style mint (`vout = u32::MAX`) keyed by a **nonce-independent**
    /// coinbase txid — must not depend on `block.hash()` / `state_root` or the
    /// post-mergeset commitment becomes circular with PoW.
    pub fn coinbase(coinbase_txid: Hash) -> Self {
        Self {
            txid: coinbase_txid,
            vout: u32::MAX,
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.vout == u32::MAX
    }
}

/// Deterministic coinbase txid from body identity fields (no nonce / state_root).
pub fn coinbase_txid(block: &crate::Block) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hassan-coinbase-txid-v22");
    hasher.update(&block.height.to_le_bytes());
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&(block.parents.len() as u64).to_le_bytes());
    for p in &block.parents {
        hasher.update(p.as_bytes());
    }
    hasher.update(block.miner.as_bytes());
    hasher.update(block.merkle_root.as_bytes());
    hasher.update(&block.coinbase_entropy.to_le_bytes());
    hasher.update(&(block.creator_pubkey.len() as u64).to_le_bytes());
    hasher.update(&block.creator_pubkey);
    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    Hash(out)
}

/// A created, unspent output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u128,
    pub predicate: Predicate,
    /// Blue score of the block that created this output (for CSV / maturity).
    #[serde(default)]
    pub created_blue: u64,
}

/// One spend of a previous outpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIn {
    pub previous: OutPoint,
    /// Relative lock (CSV-class): spendable only when
    /// `media_blue >= created_blue + relative_lock_blues`. `0` = none.
    #[serde(default)]
    pub relative_lock_blues: u32,
    #[serde(default)]
    pub witness: UnlockWitness,
}

/// Live UTXO set + spent nullifiers for conflict detection.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UtxoSet {
    pub entries: BTreeMap<OutPoint, TxOut>,
    /// Outpoints spent on the applied virtual (conflict nullifiers).
    #[serde(default)]
    pub spent: BTreeSet<OutPoint>,
}

impl UtxoSet {
    pub fn get(&self, op: &OutPoint) -> Option<&TxOut> {
        self.entries.get(op)
    }

    pub fn contains(&self, op: &OutPoint) -> bool {
        self.entries.contains_key(op)
    }

    pub fn is_spent(&self, op: &OutPoint) -> bool {
        self.spent.contains(op) || !self.entries.contains_key(op)
    }

    pub fn insert(&mut self, op: OutPoint, out: TxOut) {
        self.spent.remove(&op);
        self.entries.insert(op, out);
    }

    /// Spend `op`, returning the removed output. Fails if missing or already spent.
    pub fn spend(&mut self, op: &OutPoint) -> Result<TxOut, String> {
        if self.spent.contains(op) {
            return Err("Outpoint already spent".into());
        }
        let out = self
            .entries
            .remove(op)
            .ok_or_else(|| "Unknown outpoint".to_string())?;
        self.spent.insert(*op);
        Ok(out)
    }

    pub fn total_value(&self) -> u128 {
        self.entries.values().map(|o| o.value).sum()
    }

    /// Commitment over the live UTXO set (sorted outpoints).
    pub fn commitment(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hassan-utxo-set-v1");
        for (op, out) in &self.entries {
            hasher.update(op.txid.as_bytes());
            hasher.update(&op.vout.to_le_bytes());
            hasher.update(&out.value.to_le_bytes());
            hasher.update(&out.created_blue.to_le_bytes());
            hasher.update(&bincode::serialize(&out.predicate).unwrap_or_default());
        }
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);
        Hash(out)
    }
}

/// Blue-score maturity before a coinbase outpoint may be spent.
pub const COINBASE_MATURITY_BLUES: u64 = 100;

/// Minimum dust for newly created UTXO outputs (base units).
pub const UTXO_DUST: u128 = 546;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::Predicate;

    #[test]
    fn spend_removes_and_nullifies() {
        let mut set = UtxoSet::default();
        let op = OutPoint {
            txid: Hash::ZERO,
            vout: 0,
        };
        set.insert(
            op,
            TxOut {
                value: 1_000,
                predicate: Predicate::PayToAddress {
                    address: "hsn:aa".into(),
                },
                created_blue: 1,
            },
        );
        assert!(set.contains(&op));
        let out = set.spend(&op).unwrap();
        assert_eq!(out.value, 1_000);
        assert!(set.is_spent(&op));
        assert!(set.spend(&op).is_err());
    }

    #[test]
    fn commitment_changes_on_insert() {
        let mut set = UtxoSet::default();
        let a = set.commitment();
        set.insert(
            OutPoint {
                txid: Hash([1u8; 64]),
                vout: 0,
            },
            TxOut {
                value: 10,
                predicate: Predicate::PayToAddress {
                    address: "hsn:bb".into(),
                },
                created_blue: 0,
            },
        );
        assert_ne!(a, set.commitment());
    }
}
