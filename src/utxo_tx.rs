//! Transparent UTXO transactions (hybrid ledger).
//!
//! Spendable value lives in [`crate::utxo::UtxoSet`]. Account balances remain
//! for registry/custody and optional [`Predicate::CreditAccount`] bridges.

use crate::abs_sig;
use crate::predicate::{evaluate_full, Predicate, UnlockWitness};
use crate::security;
use crate::utxo::{OutPoint, TxIn, TxOut, UtxoSet, COINBASE_MATURITY_BLUES, UTXO_DUST};
use crate::{hash_to_address, Hash, MIN_FEE_PER_BYTE, MIN_TX_FEE, PQ_PUBLIC_KEY_SIZE, PQ_SIGNATURE_SIZE};
use serde::{Deserialize, Serialize};

/// Enforce [`Predicate::ExactValue`] covenants against the spent output amount.
fn assert_exact_value_binds(pred: &Predicate, value: u128) -> Result<(), String> {
    match pred {
        Predicate::ExactValue { value: bound, inner } => {
            if *bound != value {
                return Err(format!(
                    "ExactValue: spent {value} != covenant bound {bound}"
                ));
            }
            assert_exact_value_binds(inner, value)
        }
        Predicate::And { left, right } | Predicate::Or { left, right } => {
            assert_exact_value_binds(left, value)?;
            assert_exact_value_binds(right, value)
        }
        _ => Ok(()),
    }
}

/// A signed UTXO spend: real outpoints in, predicates out, fee to miner coinbase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoTx {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    /// Absolute lock (CLTV-class): media blue score must be ≥ this (`0` = none).
    #[serde(default)]
    pub lock_blue_score: u64,
    pub fee: u128,
    pub chain_id: u64,
    pub from_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl UtxoTx {
    pub fn from_address(&self) -> String {
        hash_to_address(&self.from_pubkey)
    }

    pub fn relay_bytes(&self) -> usize {
        let mut priced = self.clone();
        if priced.signature.len() != PQ_SIGNATURE_SIZE {
            priced.signature = vec![0u8; PQ_SIGNATURE_SIZE];
        }
        bincode::serialize(&priced)
            .map(|b| b.len())
            .unwrap_or_else(|_| PQ_PUBLIC_KEY_SIZE.saturating_add(PQ_SIGNATURE_SIZE).saturating_add(256))
    }

    pub fn min_fee_required(&self) -> u128 {
        let by_size = (self.relay_bytes() as u128).saturating_mul(MIN_FEE_PER_BYTE);
        by_size.max(MIN_TX_FEE)
    }

    pub fn validate_form(&self) -> Result<(), String> {
        if self.inputs.is_empty() {
            return Err("UtxoTx requires at least one input".into());
        }
        if self.outputs.is_empty() {
            return Err("UtxoTx requires at least one output".into());
        }
        if self.outputs.len() > 64 {
            return Err("Too many outputs".into());
        }
        if self.inputs.len() > 64 {
            return Err("Too many inputs".into());
        }
        if self.from_pubkey.len() != PQ_PUBLIC_KEY_SIZE {
            return Err("Invalid from_pubkey length".into());
        }
        if self.fee < self.min_fee_required() {
            return Err(format!("Fee must be ≥ {}", self.min_fee_required()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for tin in &self.inputs {
            if !seen.insert(tin.previous) {
                return Err("Duplicate input outpoint".into());
            }
        }
        for out in &self.outputs {
            if out.value == 0 {
                return Err("Output value must be > 0".into());
            }
            if !out.predicate.is_account_credit() && out.value < UTXO_DUST {
                return Err(format!("Output below dust ({UTXO_DUST})"));
            }
            if let Some(addr) = out.predicate.locked_address() {
                if !security::is_valid_address(addr) {
                    return Err("Invalid output address".into());
                }
                // v27: new outputs must be canonical bech32m (legacy hex still
                // unlocks existing coins via dual-accept decode).
                if !crate::address::is_bech32m_address(addr) {
                    return Err("New UTXO outputs must use bech32m hsn1… addresses".into());
                }
            }
        }
        if self.signature.len() != PQ_SIGNATURE_SIZE && !self.signature.is_empty() {
            return Err("Invalid signature length".into());
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.lock_blue_score.to_le_bytes());
        buf.extend_from_slice(&self.fee.to_le_bytes());
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for tin in &self.inputs {
            buf.extend_from_slice(tin.previous.txid.as_bytes());
            buf.extend_from_slice(&tin.previous.vout.to_le_bytes());
            buf.extend_from_slice(&tin.relative_lock_blues.to_le_bytes());
            // Witness is NOT signed (hashlock preimage can be malleable by design
            // like script sig historically — txid binds signature separately).
        }
        buf.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for out in &self.outputs {
            buf.extend_from_slice(&out.value.to_le_bytes());
            buf.extend_from_slice(&bincode::serialize(&out.predicate).unwrap_or_default());
        }
        buf
    }

    pub fn sign(&mut self, signing_key_bytes: &[u8]) -> Result<(), String> {
        self.signature =
            abs_sig::sign_pq512(b"utxo-tx", &self.signing_bytes(), signing_key_bytes)?;
        Ok(())
    }

    pub fn verify(&self) -> bool {
        abs_sig::verify_pq512(
            b"utxo-tx",
            &self.signing_bytes(),
            &self.from_pubkey,
            &self.signature,
        )
    }

    /// Non-witness txid: signing material + signature (witness malleation cannot
    /// change this id — SegWit-class separation for PQ UTXO spends).
    pub fn txid(&self) -> Hash {
        let mut buf = self.signing_bytes();
        buf.extend_from_slice(&self.signature);
        Hash(abs_sig::digest512(b"utxo-txid", &buf))
    }

    /// Witness id: includes unlock witnesses (detects hashlock/preimage malleation).
    pub fn wtxid(&self) -> Hash {
        self.tx_hash()
    }

    pub fn tx_hash(&self) -> Hash {
        let mut buf = self.signing_bytes();
        buf.extend_from_slice(&self.signature);
        // Bind witnesses so hashlock spends are unique per reveal.
        for tin in &self.inputs {
            buf.extend_from_slice(&bincode::serialize(&tin.witness).unwrap_or_default());
        }
        Hash(abs_sig::digest512(b"utxo-tx-hash", &buf))
    }

    /// Build a simple single-input payment with optional change.
    pub fn payment(
        from_pubkey: Vec<u8>,
        funding: OutPoint,
        funding_value: u128,
        to: String,
        amount: u128,
        mut fee: u128,
        chain_id: u64,
        lock_blue_score: u64,
        relative_lock_blues: u32,
    ) -> Result<Self, String> {
        let change_addr = hash_to_address(&from_pubkey);
        // Probe density floor with a provisional body, then rebuild outputs.
        let mut probe = Self {
            inputs: vec![TxIn {
                previous: funding,
                relative_lock_blues,
                witness: UnlockWitness::Signature,
            }],
            outputs: vec![TxOut {
                value: amount,
                predicate: Predicate::PayToAddress {
                    address: to.clone(),
                },
                created_blue: 0,
            }],
            lock_blue_score,
            fee: fee.max(MIN_TX_FEE),
            chain_id,
            from_pubkey: from_pubkey.clone(),
            signature: vec![],
        };
        fee = fee.max(probe.min_fee_required());
        probe.fee = fee;
        // Keep caller fee when above the floor (RBF / priority); do not clamp down.

        let need = amount.checked_add(fee).ok_or("amount+fee overflow")?;
        if funding_value < need {
            return Err("Insufficient funding UTXO".into());
        }
        let change = funding_value - need;
        let mut outputs = vec![TxOut {
            value: amount,
            predicate: Predicate::PayToAddress { address: to },
            created_blue: 0,
        }];
        if change > 0 {
            if change < UTXO_DUST {
                return Err("Change below dust".into());
            }
            outputs.push(TxOut {
                value: change,
                predicate: Predicate::PayToAddress {
                    address: change_addr,
                },
                created_blue: 0,
            });
        }
        let mut tx = Self {
            inputs: vec![TxIn {
                previous: funding,
                relative_lock_blues,
                witness: UnlockWitness::Signature,
            }],
            outputs,
            lock_blue_score,
            fee,
            chain_id,
            from_pubkey,
            signature: vec![],
        };
        // Change output increases relay size → re-bump density floor once.
        let need_fee = tx.min_fee_required();
        if tx.fee < need_fee {
            let extra = need_fee - tx.fee;
            if let Some(last) = tx.outputs.last_mut() {
                if last.value > extra + UTXO_DUST {
                    last.value -= extra;
                    tx.fee = need_fee;
                } else {
                    return Err(format!("Fee must be ≥ {need_fee}"));
                }
            } else {
                return Err(format!("Fee must be ≥ {need_fee}"));
            }
        }
        Ok(tx)
    }
}

/// Apply a UTXO tx against `utxos` and optional account overlay.
/// `media_blue` is the validating tip's blue score (locktime / CSV / maturity).
/// On success, `fees_out` is increased by `tx.fee` (caller pays it to coinbase).
pub fn apply_utxo_tx(
    utxos: &mut UtxoSet,
    accounts: &mut std::collections::HashMap<String, crate::Account>,
    tx: &UtxoTx,
    media_blue: u64,
    fees_out: &mut u128,
) -> Result<(), String> {
    tx.validate_form()?;
    if !tx.verify() {
        return Err("Invalid UTXO signature".into());
    }
    if tx.lock_blue_score > 0 && media_blue < tx.lock_blue_score {
        return Err(format!(
            "Tx lock_blue_score {} not reached (media {media_blue})",
            tx.lock_blue_score
        ));
    }

    let signer = tx.from_address();
    let mut input_sum = 0u128;
    let mut spent_outs: Vec<(OutPoint, TxOut)> = Vec::with_capacity(tx.inputs.len());

    for tin in &tx.inputs {
        let out = utxos
            .get(&tin.previous)
            .cloned()
            .ok_or_else(|| "Unknown outpoint".to_string())?;
        if tin.previous.is_coinbase()
            && media_blue < out.created_blue.saturating_add(COINBASE_MATURITY_BLUES)
        {
            return Err("Coinbase immature".into());
        }
        if tin.relative_lock_blues > 0 {
            let unlock_at = out
                .created_blue
                .saturating_add(tin.relative_lock_blues as u64);
            if media_blue < unlock_at {
                return Err(format!(
                    "Relative lock: media {media_blue} < unlock {unlock_at}"
                ));
            }
        }
        evaluate_full(
            &out.predicate,
            &tin.witness,
            &signer,
            media_blue,
            out.created_blue,
            Some(tx.signing_bytes().as_slice()),
        )?;
        assert_exact_value_binds(&out.predicate, out.value)?;
        input_sum = input_sum
            .checked_add(out.value)
            .ok_or("input value overflow")?;
        spent_outs.push((tin.previous, out));
    }

    let mut output_sum = tx.fee;
    for out in &tx.outputs {
        output_sum = output_sum
            .checked_add(out.value)
            .ok_or("output value overflow")?;
    }
    if input_sum != output_sum {
        return Err(format!(
            "Value imbalance: inputs {input_sum} != outputs+fee {output_sum}"
        ));
    }

    // Mutate only after full checks.
    for (op, _) in &spent_outs {
        utxos.spend(op)?;
    }
    let txid = tx.tx_hash();
    for (i, out) in tx.outputs.iter().enumerate() {
        if out.predicate.is_account_credit() {
            let addr = out
                .predicate
                .locked_address()
                .ok_or("CreditAccount missing address")?
                .to_string();
            let acct = accounts.entry(addr).or_default();
            acct.balance = acct
                .balance
                .checked_add(out.value)
                .ok_or("account credit overflow")?;
            // No UTXO entry — value moved into overlay.
        } else {
            let mut created = out.clone();
            created.created_blue = media_blue;
            utxos.insert(
                OutPoint {
                    txid,
                    vout: i as u32,
                },
                created,
            );
        }
    }
    *fees_out = fees_out.saturating_add(tx.fee);
    Ok(())
}

/// Mint a coinbase **UTXO only** (no account overlay credit).
///
/// Issuance is UTXO-complete — matching [`crate::ChainState`]'s
/// block reward path. Do not double-credit accounts here.
pub fn mint_coinbase(
    utxos: &mut UtxoSet,
    block_hash: Hash,
    miner_address: &str,
    subsidy: u128,
    media_blue: u64,
) {
    if subsidy == 0 {
        return;
    }
    let op = OutPoint::coinbase(block_hash);
    utxos.insert(
        op,
        TxOut {
            value: subsidy,
            predicate: Predicate::PayToAddress {
                address: miner_address.to_string(),
            },
            created_blue: media_blue,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use crate::utxo::UtxoSet;
    use crate::CHAIN_ID;

    #[test]
    fn payment_and_apply_moves_value() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let to = {
            let (_, pk2) = generate_keypair();
            hash_to_address(&pk2)
        };
        let mut utxos = UtxoSet::default();
        let mut accounts = std::collections::HashMap::new();
        let fund_op = OutPoint {
            txid: Hash([9u8; 64]),
            vout: 0,
        };
        utxos.insert(
            fund_op,
            TxOut {
                value: 1_000_000,
                predicate: Predicate::PayToAddress {
                    address: from.clone(),
                },
                created_blue: 0,
            },
        );
        let mut tx = UtxoTx {
            inputs: vec![TxIn {
                previous: fund_op,
                relative_lock_blues: 0,
                witness: UnlockWitness::Signature,
            }],
            outputs: vec![
                TxOut {
                    value: 100_000,
                    predicate: Predicate::PayToAddress {
                        address: to.clone(),
                    },
                    created_blue: 0,
                },
                TxOut {
                    value: 1_000_000 - 100_000 - 50_000,
                    predicate: Predicate::PayToAddress { address: from },
                    created_blue: 0,
                },
            ],
            lock_blue_score: 0,
            fee: 50_000,
            chain_id: CHAIN_ID,
            from_pubkey: pk,
            signature: vec![],
        };
        // Ensure fee meets density floor.
        let need = tx.min_fee_required();
        if tx.fee < need {
            let bump = need - tx.fee;
            tx.fee = need;
            tx.outputs[1].value -= bump;
        }
        tx.sign(&sk).unwrap();
        let mut fees = 0u128;
        apply_utxo_tx(&mut utxos, &mut accounts, &tx, 10, &mut fees).unwrap();
        assert!(utxos.is_spent(&fund_op));
        assert!(fees > 0);
        let to_ops: Vec<_> = utxos
            .entries
            .iter()
            .filter(|(_, o)| o.predicate.locked_address() == Some(to.as_str()))
            .collect();
        assert_eq!(to_ops.len(), 1);
        assert_eq!(to_ops[0].1.value, 100_000);
    }

    #[test]
    fn absolute_lock_rejects_early() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut utxos = UtxoSet::default();
        let mut accounts = std::collections::HashMap::new();
        let fund_op = OutPoint {
            txid: Hash([3u8; 64]),
            vout: 0,
        };
        utxos.insert(
            fund_op,
            TxOut {
                value: 500_000,
                predicate: Predicate::PayToAddress { address: from },
                created_blue: 0,
            },
        );
        let (_, pk2) = generate_keypair();
        let to = hash_to_address(&pk2);
        let mut tx = UtxoTx {
            inputs: vec![TxIn {
                previous: fund_op,
                relative_lock_blues: 0,
                witness: UnlockWitness::Signature,
            }],
            outputs: vec![TxOut {
                value: 400_000,
                predicate: Predicate::PayToAddress { address: to },
                created_blue: 0,
            }],
            lock_blue_score: 100,
            fee: 100_000,
            chain_id: CHAIN_ID,
            from_pubkey: pk,
            signature: vec![],
        };
        let need = tx.min_fee_required();
        if tx.fee < need {
            tx.fee = need;
            if tx.outputs[0].value + tx.fee > 500_000 {
                tx.outputs[0].value = 500_000 - tx.fee;
            }
        }
        tx.sign(&sk).unwrap();
        let mut fees = 0u128;
        assert!(apply_utxo_tx(&mut utxos, &mut accounts, &tx, 50, &mut fees).is_err());
        apply_utxo_tx(&mut utxos, &mut accounts, &tx, 100, &mut fees).unwrap();
    }

    #[test]
    fn legacy_hex_output_rejected_on_new_utxo() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut utxos = UtxoSet::default();
        let fund_op = OutPoint {
            txid: Hash([8u8; 64]),
            vout: 0,
        };
        utxos.insert(
            fund_op,
            TxOut {
                value: 1_000_000,
                predicate: Predicate::PayToAddress { address: from },
                created_blue: 0,
            },
        );
        let legacy_to = format!("hsn:{}", hex::encode([0x22u8; 64]));
        let mut tx = UtxoTx {
            inputs: vec![TxIn {
                previous: fund_op,
                relative_lock_blues: 0,
                witness: UnlockWitness::Signature,
            }],
            outputs: vec![TxOut {
                value: 500_000,
                predicate: Predicate::PayToAddress {
                    address: legacy_to,
                },
                created_blue: 0,
            }],
            lock_blue_score: 0,
            fee: 10_000,
            chain_id: CHAIN_ID,
            from_pubkey: pk,
            signature: vec![],
        };
        tx.fee = tx.min_fee_required();
        tx.outputs[0].value = 1_000_000 - tx.fee;
        tx.sign(&sk).unwrap();
        let err = tx.validate_form().unwrap_err();
        assert!(err.contains("bech32m"), "{err}");
    }
}
