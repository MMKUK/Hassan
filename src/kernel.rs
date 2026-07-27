//! Consensus kernel boundary — pure validation helpers without RPC/P2P.
//!
//! Callers (node, tests, light tools) share these checks so rule logic is not
//! only reachable through `ChainState::add_block`.

use crate::utxo_tx::UtxoTx;
use crate::{predicate, utxo, TransparentTx, HASH_SIZE, Hash};

/// Form + signature checks for a transparent account transfer (no state).
pub fn validate_transparent_form(tx: &TransparentTx, chain_id: u64) -> Result<(), String> {
    tx.validate_form()?;
    if tx.chain_id != chain_id {
        return Err("Wrong chain_id".into());
    }
    if !tx.verify() {
        return Err("Invalid signature".into());
    }
    if let Some(h) = &tx.hashlock {
        let commit = predicate::hashlock_commitment(&tx.hashlock_preimage);
        if &commit != h {
            return Err("Hashlock preimage mismatch".into());
        }
    }
    Ok(())
}

/// Form + signature checks for a UTXO transfer (no set mutation).
pub fn validate_utxo_form(tx: &UtxoTx, chain_id: u64) -> Result<(), String> {
    tx.validate_form()?;
    if tx.chain_id != chain_id {
        return Err("Wrong chain_id".into());
    }
    if !tx.verify() {
        return Err("Invalid signature".into());
    }
    Ok(())
}

/// Conserved value check for a UTXO tx against a read-only set snapshot.
pub fn utxo_value_conserved(set: &utxo::UtxoSet, tx: &UtxoTx) -> Result<(), String> {
    let mut input_sum = 0u128;
    for tin in &tx.inputs {
        let out = set
            .get(&tin.previous)
            .ok_or_else(|| "Unknown outpoint".to_string())?;
        input_sum = input_sum
            .checked_add(out.value)
            .ok_or("input overflow")?;
    }
    let mut output_sum = tx.fee;
    for out in &tx.outputs {
        output_sum = output_sum
            .checked_add(out.value)
            .ok_or("output overflow")?;
    }
    if input_sum != output_sum {
        return Err(format!("Value imbalance: {input_sum} != {output_sum}"));
    }
    Ok(())
}

/// Domain-separated digest for kernel rule versioning / assume-valid notes.
pub fn kernel_rules_id() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hassan-kernel-rules-v22");
    hasher.update(&HASH_SIZE.to_le_bytes());
    let mut out = [0u8; HASH_SIZE];
    hasher.finalize_xof().fill(&mut out);
    Hash(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_rules_id_is_stable() {
        assert_eq!(kernel_rules_id(), kernel_rules_id());
        assert_ne!(kernel_rules_id(), Hash::ZERO);
    }
}
