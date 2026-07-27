//! Hassan BDPE vault adapter — consensus-enforced UTXO escrow (VAULT).
//!
//! Phase 1 lock script:
//! ```text
//! Or(
//!   MultiSig { n: 2, addresses: [buyer, seller] },  // coop settle / refund
//!   AbsoluteLock { address: buyer, unlock_blue },   // timeout reclaim
//! )
//! ```
//!
//! Funds move only by spending the vault UTXO under those predicates.
//! No admin key. Registry escrow is a separate title/account overlay.

use crate::abs_sig;
use crate::predicate::{Predicate, UnlockWitness};
use crate::utxo::{OutPoint, TxIn, TxOut, UTXO_DUST};
use crate::utxo_tx::UtxoTx;
use crate::{hash_to_address, Hash, MIN_TX_FEE};
use tuep_escrow::{Clock, EscrowTerms, PayoutVector, SpendPath};

/// Build the Phase 1 vault predicate for buyer/seller + absolute blue timeout.
pub fn vault_predicate(buyer: &str, seller: &str, timeout_blue: u64) -> Predicate {
    Predicate::Or {
        left: Box::new(Predicate::MultiSig {
            n: 2,
            addresses: vec![buyer.to_string(), seller.to_string()],
        }),
        right: Box::new(Predicate::AbsoluteLock {
            address: buyer.to_string(),
            unlock_blue: timeout_blue,
        }),
    }
}

pub fn vault_predicate_from_terms(terms: &EscrowTerms) -> Predicate {
    vault_predicate(&terms.buyer, &terms.seller, terms.timeout_blue())
}

/// Detect a Phase 1 BDPE vault and return (buyer, seller, timeout_blue).
pub fn parse_vault_predicate(pred: &Predicate) -> Option<(String, String, u64)> {
    match pred {
        Predicate::Or { left, right } => match (left.as_ref(), right.as_ref()) {
            (
                Predicate::MultiSig { n: 2, addresses },
                Predicate::AbsoluteLock {
                    address: buyer,
                    unlock_blue,
                },
            ) if addresses.len() == 2 => {
                let a0 = &addresses[0];
                let a1 = &addresses[1];
                // Buyer is the AbsoluteLock party; order in MultiSig may vary.
                if crate::address::addresses_equivalent(a0, buyer) {
                    Some((buyer.clone(), a1.clone(), *unlock_blue))
                } else if crate::address::addresses_equivalent(a1, buyer) {
                    Some((buyer.clone(), a0.clone(), *unlock_blue))
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// Whether `pred` mentions `address` (MultiSig set or locked address).
pub fn predicate_involves_address(pred: &Predicate, address: &str) -> bool {
    match pred {
        Predicate::PayToAddress { address: a }
        | Predicate::AbsoluteLock { address: a, .. }
        | Predicate::RelativeLock { address: a, .. }
        | Predicate::AnnulAfter { address: a, .. }
        | Predicate::CreditAccount { address: a } => {
            crate::address::addresses_equivalent(a, address)
        }
        Predicate::MultiSig { addresses, .. } => addresses
            .iter()
            .any(|a| crate::address::addresses_equivalent(a, address)),
        Predicate::And { left, right } | Predicate::Or { left, right } => {
            predicate_involves_address(left, address) || predicate_involves_address(right, address)
        }
        Predicate::ExactValue { inner, .. } => predicate_involves_address(inner, address),
        Predicate::HashLock { .. } | Predicate::CommitData { .. } => false,
    }
}

/// Nested stack so [`Predicate::Or`] forwards a MultiSig-shaped witness.
///
/// `Or` peels one Stack layer; MultiSig then consumes `Stack([CosignerSig])`.
pub fn coop_witness(cosigner_pubkey: Vec<u8>, cosigner_signature: Vec<u8>) -> UnlockWitness {
    UnlockWitness::Stack(vec![UnlockWitness::Stack(vec![
        UnlockWitness::CosignerSig {
            pubkey: cosigner_pubkey,
            signature: cosigner_signature,
        },
    ])])
}

pub fn timeout_witness() -> UnlockWitness {
    UnlockWitness::Signature
}

fn payout_address(terms: &EscrowTerms, payout: PayoutVector) -> Result<String, String> {
    if !payout.phase1_allowed() {
        return Err("payout vector not allowed in Phase 1".into());
    }
    Ok(match payout {
        PayoutVector::ToSeller => terms.seller.clone(),
        PayoutVector::ToBuyer => terms.buyer.clone(),
    })
}

/// Fund vault: spend `funding` PayToAddress → BDPE vault output (+ change).
pub fn build_fund_tx(
    from_pubkey: Vec<u8>,
    funding: OutPoint,
    funding_value: u128,
    terms: &EscrowTerms,
    mut fee: u128,
    chain_id: u64,
) -> Result<UtxoTx, String> {
    terms.validate()?;
    let change_addr = hash_to_address(&from_pubkey);
    if !crate::address::addresses_equivalent(&change_addr, &terms.buyer) {
        return Err("only the buyer may fund the vault".into());
    }
    let vault = vault_predicate_from_terms(terms);
    let amount = terms.amount;

    let mut probe = UtxoTx {
        inputs: vec![TxIn {
            previous: funding,
            relative_lock_blues: 0,
            witness: UnlockWitness::Signature,
        }],
        outputs: vec![TxOut {
            value: amount,
            predicate: vault.clone(),
            created_blue: 0,
        }],
        lock_blue_score: 0,
        fee: fee.max(MIN_TX_FEE),
        chain_id,
        from_pubkey: from_pubkey.clone(),
        signature: vec![],
    };
    fee = fee.max(probe.min_fee_required());
    probe.fee = fee;
    fee = probe.min_fee_required();

    let need = amount.checked_add(fee).ok_or("amount+fee overflow")?;
    if funding_value < need {
        return Err("Insufficient funding UTXO".into());
    }
    let change = funding_value - need;
    let mut outputs = vec![TxOut {
        value: amount,
        predicate: vault,
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
    let mut tx = UtxoTx {
        inputs: vec![TxIn {
            previous: funding,
            relative_lock_blues: 0,
            witness: UnlockWitness::Signature,
        }],
        outputs,
        lock_blue_score: 0,
        fee,
        chain_id,
        from_pubkey,
        signature: vec![],
    };
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

/// Spend vault via coop 2-of-2 or timeout path to an allowed payout vector.
pub fn build_spend_tx(
    primary_pubkey: Vec<u8>,
    cosigner_pubkey: Option<Vec<u8>>,
    cosigner_secret: Option<&[u8]>,
    vault: OutPoint,
    vault_value: u128,
    terms: &EscrowTerms,
    path: SpendPath,
    media_blue: u64,
    mut fee: u128,
    chain_id: u64,
) -> Result<UtxoTx, String> {
    terms.validate()?;
    path.validate(terms, media_blue)?;
    let primary = hash_to_address(&primary_pubkey);

    let (payout, witness) = match path {
        SpendPath::Coop2of2 { payout } => {
            let cpk = cosigner_pubkey.ok_or("coop spend needs cosigner pubkey")?;
            let csk = cosigner_secret.ok_or("coop spend needs cosigner secret")?;
            let cosigner_addr = hash_to_address(&cpk);
            // Primary + cosigner must be exactly {buyer, seller}.
            let set_ok = (crate::address::addresses_equivalent(&primary, &terms.buyer)
                && crate::address::addresses_equivalent(&cosigner_addr, &terms.seller))
                || (crate::address::addresses_equivalent(&primary, &terms.seller)
                    && crate::address::addresses_equivalent(&cosigner_addr, &terms.buyer));
            if !set_ok {
                return Err("coop cosigners must be buyer and seller".into());
            }
            // Build unsigned body first for sighash, then attach cosigner sig.
            let to = payout_address(terms, payout)?;
            fee = fee.max(MIN_TX_FEE);
            let mut tx = provisional_spend(
                primary_pubkey.clone(),
                vault,
                vault_value,
                to,
                fee,
                chain_id,
                UnlockWitness::Signature, // placeholder — replaced after sighash
            )?;
            let sighash = tx.signing_bytes();
            let sig = abs_sig::sign_pq512(b"utxo-tx", &sighash, csk)?;
            tx.inputs[0].witness = coop_witness(cpk.clone(), sig);
            // Cosigner witness inflates relay bytes → re-bump density floor.
            let need = tx.min_fee_required();
            if tx.fee < need {
                let extra = need - tx.fee;
                if tx.outputs[0].value > extra + UTXO_DUST {
                    tx.outputs[0].value -= extra;
                    tx.fee = need;
                    // Payout amount changed → sighash changed → re-sign cosigner.
                    let sighash2 = tx.signing_bytes();
                    let sig2 = abs_sig::sign_pq512(b"utxo-tx", &sighash2, csk)?;
                    tx.inputs[0].witness = coop_witness(cpk, sig2);
                } else {
                    return Err(format!("Fee must be ≥ {need}"));
                }
            }
            return Ok(tx);
        }
        SpendPath::TimeoutBuyer => {
            if !crate::address::addresses_equivalent(&primary, &terms.buyer) {
                return Err("timeout claim must be signed by buyer".into());
            }
            (PayoutVector::ToBuyer, timeout_witness())
        }
    };

    let to = payout_address(terms, payout)?;
    provisional_spend(
        primary_pubkey,
        vault,
        vault_value,
        to,
        fee,
        chain_id,
        witness,
    )
}

fn provisional_spend(
    from_pubkey: Vec<u8>,
    vault: OutPoint,
    vault_value: u128,
    to: String,
    mut fee: u128,
    chain_id: u64,
    witness: UnlockWitness,
) -> Result<UtxoTx, String> {
    fee = fee.max(MIN_TX_FEE);
    let mut tx = UtxoTx {
        inputs: vec![TxIn {
            previous: vault,
            relative_lock_blues: 0,
            witness: witness.clone(),
        }],
        outputs: vec![TxOut {
            value: 1, // placeholder; set after fee
            predicate: Predicate::PayToAddress {
                address: to.clone(),
            },
            created_blue: 0,
        }],
        lock_blue_score: 0,
        fee,
        chain_id,
        from_pubkey,
        signature: vec![],
    };
    fee = tx.min_fee_required();
    if vault_value <= fee {
        return Err("vault value too small to cover fee".into());
    }
    let pay = vault_value - fee;
    if pay < UTXO_DUST {
        return Err("payout below dust".into());
    }
    tx.fee = fee;
    tx.outputs[0].value = pay;
    tx.inputs[0].witness = witness;
    // Re-bump if output size changed fee floor.
    let need = tx.min_fee_required();
    if need > tx.fee {
        let extra = need - tx.fee;
        if tx.outputs[0].value > extra + UTXO_DUST {
            tx.outputs[0].value -= extra;
            tx.fee = need;
        } else {
            return Err(format!("Fee must be ≥ {need}"));
        }
    }
    Ok(tx)
}

/// Terms helper for timeout clock.
pub fn terms_with_timeout(
    buyer: String,
    seller: String,
    amount: u128,
    timeout_blue: u64,
    memo: String,
    seed_hex: String,
) -> EscrowTerms {
    EscrowTerms {
        buyer,
        seller,
        amount,
        clock: Clock::absolute_blue(timeout_blue),
        memo,
        seed_hex,
    }
}

/// Hex outpoint helpers.
pub fn outpoint_from_hex(txid_hex: &str, vout: u32) -> Result<OutPoint, String> {
    let bytes = hex::decode(txid_hex).map_err(|_| "bad txid hex")?;
    let txid = Hash::try_from(bytes.as_slice()).map_err(|_| "txid must be 64 bytes")?;
    Ok(OutPoint { txid, vout })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use crate::utxo::UtxoSet;
    use crate::CHAIN_ID;
    use tuep_escrow::SpendPath;

    #[test]
    fn fund_coop_settle_moves_to_seller() {
        let (sk_b, pk_b) = generate_keypair();
        let (sk_s, pk_s) = generate_keypair();
        let buyer = hash_to_address(&pk_b);
        let seller = hash_to_address(&pk_s);
        let terms = terms_with_timeout(
            buyer.clone(),
            seller.clone(),
            100_000,
            50,
            "deal".into(),
            "01".into(),
        );

        let mut utxos = UtxoSet::default();
        let mut accounts = std::collections::HashMap::new();
        let fund_op = OutPoint {
            txid: Hash([9u8; 64]),
            vout: 0,
        };
        utxos.insert(
            fund_op,
            TxOut {
                value: 500_000,
                predicate: Predicate::PayToAddress {
                    address: buyer.clone(),
                },
                created_blue: 0,
            },
        );

        let mut fund = build_fund_tx(pk_b.clone(), fund_op, 500_000, &terms, 0, CHAIN_ID).unwrap();
        fund.sign(&sk_b).unwrap();
        let mut fees = 0u128;
        crate::utxo_tx::apply_utxo_tx(&mut utxos, &mut accounts, &fund, 10, &mut fees).unwrap();

        let vault_op = OutPoint {
            txid: fund.tx_hash(),
            vout: 0,
        };
        let vault_out = utxos.get(&vault_op).unwrap().clone();
        assert!(parse_vault_predicate(&vault_out.predicate).is_some());

        // Seller alone cannot settle (MultiSig needs cosigner; timeout not reached).
        let mut alone = provisional_spend(
            pk_s.clone(),
            vault_op,
            vault_out.value,
            seller.clone(),
            0,
            CHAIN_ID,
            UnlockWitness::Signature,
        )
        .unwrap();
        alone.sign(&sk_s).unwrap();
        let mut fees2 = 0u128;
        let err = crate::utxo_tx::apply_utxo_tx(
            &mut utxos.clone(),
            &mut accounts.clone(),
            &alone,
            10,
            &mut fees2,
        )
        .unwrap_err();
        assert!(
            err.contains("MultiSig") || err.contains("Or") || err.contains("cosigner"),
            "seller alone must fail: {err}"
        );

        let mut settle = build_spend_tx(
            pk_b.clone(),
            Some(pk_s.clone()),
            Some(&sk_s),
            vault_op,
            vault_out.value,
            &terms,
            SpendPath::Coop2of2 {
                payout: PayoutVector::ToSeller,
            },
            10,
            0,
            CHAIN_ID,
        )
        .unwrap();
        settle.sign(&sk_b).unwrap();
        let mut fees3 = 0u128;
        crate::utxo_tx::apply_utxo_tx(&mut utxos, &mut accounts, &settle, 10, &mut fees3).unwrap();

        let paid: u128 = utxos
            .entries
            .values()
            .filter(|o| o.predicate.locked_address() == Some(seller.as_str()))
            .map(|o| o.value)
            .sum();
        assert!(paid > 0);
    }

    #[test]
    fn timeout_buyer_reclaim() {
        let (sk_b, pk_b) = generate_keypair();
        let (_sk_s, pk_s) = generate_keypair();
        let buyer = hash_to_address(&pk_b);
        let seller = hash_to_address(&pk_s);
        let terms = terms_with_timeout(buyer.clone(), seller, 80_000, 20, "t".into(), "02".into());

        let mut utxos = UtxoSet::default();
        let mut accounts = std::collections::HashMap::new();
        let fund_op = OutPoint {
            txid: Hash([8u8; 64]),
            vout: 0,
        };
        utxos.insert(
            fund_op,
            TxOut {
                value: 200_000,
                predicate: Predicate::PayToAddress {
                    address: buyer.clone(),
                },
                created_blue: 0,
            },
        );
        let mut fund = build_fund_tx(pk_b.clone(), fund_op, 200_000, &terms, 0, CHAIN_ID).unwrap();
        fund.sign(&sk_b).unwrap();
        let mut fees = 0u128;
        crate::utxo_tx::apply_utxo_tx(&mut utxos, &mut accounts, &fund, 5, &mut fees).unwrap();
        let vault_op = OutPoint {
            txid: fund.tx_hash(),
            vout: 0,
        };
        let vault_val = utxos.get(&vault_op).unwrap().value;

        let early = build_spend_tx(
            pk_b.clone(),
            None,
            None,
            vault_op,
            vault_val,
            &terms,
            SpendPath::TimeoutBuyer,
            19,
            0,
            CHAIN_ID,
        );
        assert!(early.unwrap_err().contains("timeout"));

        let mut claim = build_spend_tx(
            pk_b.clone(),
            None,
            None,
            vault_op,
            vault_val,
            &terms,
            SpendPath::TimeoutBuyer,
            20,
            0,
            CHAIN_ID,
        )
        .unwrap();
        claim.sign(&sk_b).unwrap();
        let mut fees2 = 0u128;
        crate::utxo_tx::apply_utxo_tx(&mut utxos, &mut accounts, &claim, 20, &mut fees2).unwrap();
    }
}
