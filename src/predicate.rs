//! Minimal spend predicates / covenants for transparent UTXO outputs.
//!
//! Mini-VM richer than bare CSV: PayToAddress, HashLock, AbsoluteLock,
//! RelativeLock, And/Or trees, MultiSig-N-of-M (address set + ML-DSA cosigner
//! signatures), and CreditAccount (registry/custody bridge). Primary spender
//! ML-DSA is the enclosing tx signature; MultiSig cosigners must each supply a
//! real ML-DSA-87 signature over the same UTXO sighash.
//!
//! **HashLock** is anyone-can-spend-with-preimage (no owner-address check).
//! For owned HTLCs compose `And(HashLock, PayToAddress)`.

use crate::abs_sig;
use crate::address;
use crate::{Hash, PQ_PUBLIC_KEY_SIZE, PQ_SIGNATURE_SIZE};
use serde::{Deserialize, Serialize};

/// Spending condition committed in a [`crate::utxo::TxOut`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Predicate {
    /// Standard: unlock with ML-DSA-87 signature of the enclosing tx (signer
    /// pubkey must hash to `address`).
    PayToAddress { address: String },
    /// Preimage hashlock. **Anyone** who knows the preimage may unlock — the
    /// spender's address is not checked (HTLC-class). Compose with
    /// [`Predicate::PayToAddress`] under [`Predicate::And`] when ownership
    /// binding is required. The enclosing tx signature is the spender's key.
    HashLock { hash: Hash },
    /// Pay-to-address that additionally requires `media_blue >= unlock_blue`
    /// (CLTV-class absolute lock on the output).
    AbsoluteLock { address: String, unlock_blue: u64 },
    /// Relative lock baked into the output (CSV-class): spendable only when
    /// `media_blue >= created_blue + relative_blues`.
    RelativeLock { address: String, relative_blues: u32 },
    /// All sub-predicates must unlock (same witness stack consumed left→right
    /// via [`UnlockWitness::Stack`]).
    And { left: Box<Predicate>, right: Box<Predicate> },
    /// Either sub-predicate unlocks.
    Or { left: Box<Predicate>, right: Box<Predicate> },
    /// N-of-M: at least `n` distinct set members must authorize the spend.
    /// The enclosing tx ML-DSA counts for the primary `from_pubkey` if that
    /// address is in `addresses`. Every additional member must supply a
    /// [`UnlockWitness::CosignerSig`] verified over the UTXO sighash.
    /// Address-only tags ([`UnlockWitness::CosignerAddress`]) are rejected.
    MultiSig { n: u8, addresses: Vec<String> },
    /// Credit the account overlay and destroy the UTXO value (hybrid bridge).
    /// Not spendable as a UTXO afterward — value lives only in `accounts`.
    /// Do not double-credit accounts and UTXO for the same units.
    CreditAccount { address: String },
    /// Spendable only while `media_blue < expire_blue` (expiry covenant).
    AnnulAfter { address: String, expire_blue: u64 },
    /// Nested predicate that also binds exact output value (covenant amount).
    ExactValue {
        value: u128,
        inner: Box<Predicate>,
    },
    /// Require witness preimage whose Blake3 digest equals `commit` (data push).
    CommitData { commit: Hash },
}

impl Predicate {
    pub fn is_account_credit(&self) -> bool {
        match self {
            Predicate::CreditAccount { .. } => true,
            Predicate::And { left, right } | Predicate::Or { left, right } => {
                left.is_account_credit() || right.is_account_credit()
            }
            Predicate::ExactValue { inner, .. } => inner.is_account_credit(),
            _ => false,
        }
    }

    pub fn locked_address(&self) -> Option<&str> {
        match self {
            Predicate::PayToAddress { address }
            | Predicate::AbsoluteLock { address, .. }
            | Predicate::RelativeLock { address, .. }
            | Predicate::AnnulAfter { address, .. }
            | Predicate::CreditAccount { address } => Some(address.as_str()),
            Predicate::And { left, .. } | Predicate::Or { left, .. } => left.locked_address(),
            Predicate::ExactValue { inner, .. } => inner.locked_address(),
            Predicate::HashLock { .. }
            | Predicate::MultiSig { .. }
            | Predicate::CommitData { .. } => None,
        }
    }

    /// Max nesting depth (DoS bound for evaluation).
    pub fn depth(&self) -> usize {
        match self {
            Predicate::And { left, right } | Predicate::Or { left, right } => {
                1 + left.depth().max(right.depth())
            }
            Predicate::ExactValue { inner, .. } => 1 + inner.depth(),
            _ => 1,
        }
    }

    /// Whether evaluation needs the enclosing UTXO sighash (MultiSig cosigners).
    pub fn needs_sighash(&self) -> bool {
        match self {
            Predicate::MultiSig { .. } => true,
            Predicate::And { left, right } | Predicate::Or { left, right } => {
                left.needs_sighash() || right.needs_sighash()
            }
            Predicate::ExactValue { inner, .. } => inner.needs_sighash(),
            _ => false,
        }
    }
}

/// Witness data supplied by a [`crate::utxo::TxIn`] to unlock a predicate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockWitness {
    /// Empty — enclosing tx ML-DSA signature authorizes PayToAddress /
    /// AbsoluteLock / RelativeLock / MultiSig primary spends.
    #[default]
    Signature,
    /// Preimage for [`Predicate::HashLock`].
    Preimage(Vec<u8>),
    /// Stack of witnesses for And/Or/MultiSig.
    Stack(Vec<UnlockWitness>),
    /// Legacy address-only cosigner tag — **always rejected**. Kept in the
    /// enum so old forged witnesses deserialize and fail closed.
    CosignerAddress(String),
    /// Co-signer ML-DSA-87 over the enclosing UTXO tx sighash (`utxo-tx` domain).
    /// `pubkey` must hash to a MultiSig set member; `signature` must verify.
    CosignerSig { pubkey: Vec<u8>, signature: Vec<u8> },
}

const MAX_PRED_DEPTH: usize = 8;
const MAX_STACK: usize = 16;

/// Evaluate whether `witness` unlocks `predicate` under the given media blue
/// score, output `created_blue`, and signer address (from tx `from_pubkey`).
///
/// Predicates that do not need cosigner crypto may omit `sighash`. MultiSig
/// requires `sighash = Some(utxo_tx.signing_bytes())`.
pub fn evaluate(
    predicate: &Predicate,
    witness: &UnlockWitness,
    signer_address: &str,
    media_blue: u64,
) -> Result<(), String> {
    evaluate_full(predicate, witness, signer_address, media_blue, 0, None)
}

pub fn evaluate_full(
    predicate: &Predicate,
    witness: &UnlockWitness,
    signer_address: &str,
    media_blue: u64,
    created_blue: u64,
    sighash: Option<&[u8]>,
) -> Result<(), String> {
    if predicate.depth() > MAX_PRED_DEPTH {
        return Err("Predicate nesting too deep".into());
    }
    eval_inner(
        predicate,
        witness,
        signer_address,
        media_blue,
        created_blue,
        sighash,
    )
}

fn eval_inner(
    predicate: &Predicate,
    witness: &UnlockWitness,
    signer_address: &str,
    media_blue: u64,
    created_blue: u64,
    sighash: Option<&[u8]>,
) -> Result<(), String> {
    match predicate {
        Predicate::PayToAddress { address } => {
            if !address::addresses_equivalent(address, signer_address) {
                return Err("PayToAddress: signer does not own output".into());
            }
            if !matches!(witness, UnlockWitness::Signature | UnlockWitness::Stack(_)) {
                return Err("PayToAddress: expected signature witness".into());
            }
            Ok(())
        }
        Predicate::AbsoluteLock {
            address,
            unlock_blue,
        } => {
            if media_blue < *unlock_blue {
                return Err(format!(
                    "AbsoluteLock: media blue {media_blue} < unlock_blue {unlock_blue}"
                ));
            }
            if !address::addresses_equivalent(address, signer_address) {
                return Err("AbsoluteLock: signer does not own output".into());
            }
            Ok(())
        }
        Predicate::RelativeLock {
            address,
            relative_blues,
        } => {
            let need = created_blue.saturating_add(u64::from(*relative_blues));
            if media_blue < need {
                return Err(format!(
                    "RelativeLock: media blue {media_blue} < created+rel {need}"
                ));
            }
            if !address::addresses_equivalent(address, signer_address) {
                return Err("RelativeLock: signer does not own output".into());
            }
            Ok(())
        }
        Predicate::HashLock { hash } => match witness {
            UnlockWitness::Preimage(pre) => {
                if hashlock_commitment(pre) != *hash {
                    return Err("HashLock: preimage mismatch".into());
                }
                Ok(())
            }
            UnlockWitness::Stack(stack) if stack.len() == 1 => eval_inner(
                predicate,
                &stack[0],
                signer_address,
                media_blue,
                created_blue,
                sighash,
            ),
            _ => Err("HashLock: expected preimage witness".into()),
        },
        Predicate::And { left, right } => match witness {
            UnlockWitness::Stack(stack) if stack.len() >= 2 => {
                if stack.len() > MAX_STACK {
                    return Err("Witness stack too large".into());
                }
                eval_inner(
                    left,
                    &stack[0],
                    signer_address,
                    media_blue,
                    created_blue,
                    sighash,
                )?;
                eval_inner(
                    right,
                    &stack[1],
                    signer_address,
                    media_blue,
                    created_blue,
                    sighash,
                )?;
                Ok(())
            }
            _ => Err("And: expected Stack of 2 witnesses".into()),
        },
        Predicate::Or { left, right } => match witness {
            UnlockWitness::Stack(stack) if !stack.is_empty() => {
                let w = &stack[0];
                if eval_inner(left, w, signer_address, media_blue, created_blue, sighash).is_ok()
                    || eval_inner(right, w, signer_address, media_blue, created_blue, sighash)
                        .is_ok()
                {
                    Ok(())
                } else {
                    Err("Or: neither branch unlocked".into())
                }
            }
            w @ UnlockWitness::Signature | w @ UnlockWitness::Preimage(_) => {
                if eval_inner(left, w, signer_address, media_blue, created_blue, sighash).is_ok()
                    || eval_inner(right, w, signer_address, media_blue, created_blue, sighash)
                        .is_ok()
                {
                    Ok(())
                } else {
                    Err("Or: neither branch unlocked".into())
                }
            }
            _ => Err("Or: empty witness".into()),
        },
        Predicate::MultiSig { n, addresses } => {
            eval_multisig(*n, addresses, witness, signer_address, sighash)
        }
        Predicate::CreditAccount { .. } => Err("CreditAccount outputs are not spendable".into()),
        Predicate::AnnulAfter {
            address,
            expire_blue,
        } => {
            if media_blue >= *expire_blue {
                return Err(format!(
                    "AnnulAfter: media blue {media_blue} ≥ expire_blue {expire_blue}"
                ));
            }
            if !address::addresses_equivalent(address, signer_address) {
                return Err("AnnulAfter: signer does not own output".into());
            }
            Ok(())
        }
        Predicate::ExactValue { value: _, inner } => {
            // Value binding is checked by the enclosing UTXO apply path against
            // the spent output; here we only evaluate the nested unlock.
            eval_inner(
                inner,
                witness,
                signer_address,
                media_blue,
                created_blue,
                sighash,
            )
        }
        Predicate::CommitData { commit } => match witness {
            UnlockWitness::Preimage(pre) => {
                if hashlock_commitment(pre) != *commit {
                    return Err("CommitData: commitment mismatch".into());
                }
                Ok(())
            }
            UnlockWitness::Stack(stack) if stack.len() == 1 => eval_inner(
                predicate,
                &stack[0],
                signer_address,
                media_blue,
                created_blue,
                sighash,
            ),
            _ => Err("CommitData: expected preimage witness".into()),
        },
    }
}

fn eval_multisig(
    n: u8,
    addresses: &[String],
    witness: &UnlockWitness,
    signer_address: &str,
    sighash: Option<&[u8]>,
) -> Result<(), String> {
    if n == 0 || addresses.is_empty() || usize::from(n) > addresses.len() {
        return Err("MultiSig: invalid n-of-m".into());
    }
    if !addresses
        .iter()
        .any(|a| address::addresses_equivalent(a, signer_address))
    {
        return Err("MultiSig: primary signer not in set".into());
    }
    let msg = sighash.ok_or("MultiSig: missing sighash for cosigner verify")?;

    // Canonical keys for distinct-member counting (first matching set entry).
    let canon = |addr: &str| -> Option<String> {
        addresses
            .iter()
            .find(|a| address::addresses_equivalent(a, addr))
            .cloned()
    };

    let mut present = std::collections::BTreeSet::new();
    present.insert(
        canon(signer_address).ok_or("MultiSig: primary signer not in set")?,
    );

    let stack = match witness {
        UnlockWitness::Signature => &[][..],
        UnlockWitness::Stack(s) => {
            if s.len() > MAX_STACK {
                return Err("Witness stack too large".into());
            }
            s.as_slice()
        }
        UnlockWitness::CosignerAddress(_) => {
            return Err("MultiSig: CosignerAddress tags are not signatures".into());
        }
        UnlockWitness::CosignerSig { .. } | UnlockWitness::Preimage(_) => {
            return Err("MultiSig: expected Signature or Stack witness".into());
        }
    };

    for w in stack {
        match w {
            UnlockWitness::CosignerAddress(_) => {
                return Err("MultiSig: CosignerAddress tags are not signatures".into());
            }
            UnlockWitness::CosignerSig { pubkey, signature } => {
                if pubkey.len() != PQ_PUBLIC_KEY_SIZE {
                    return Err("MultiSig: cosigner pubkey length".into());
                }
                if signature.len() != PQ_SIGNATURE_SIZE {
                    return Err("MultiSig: cosigner signature length".into());
                }
                let addr = address::encode_hash(&crate::address_hash(pubkey));
                let key = canon(&addr).ok_or("MultiSig: cosigner not in set")?;
                if !abs_sig::verify_pq512(b"utxo-tx", msg, pubkey, signature) {
                    return Err("MultiSig: cosigner signature invalid".into());
                }
                present.insert(key);
            }
            UnlockWitness::Signature => {
                // Redundant primary marker — already counted.
            }
            UnlockWitness::Stack(_) | UnlockWitness::Preimage(_) => {
                return Err("MultiSig: unexpected nested witness".into());
            }
        }
    }

    if present.len() < usize::from(n) {
        return Err(format!(
            "MultiSig: need {n} cosigners, have {}",
            present.len()
        ));
    }
    Ok(())
}

/// Blake3-512 hashlock commitment for a preimage.
pub fn hashlock_commitment(preimage: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hassan-hashlock-v1");
    hasher.update(preimage);
    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    Hash(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use crate::hash_to_address;

    #[test]
    fn hashlock_roundtrip() {
        let pre = b"secret-preimage";
        let h = hashlock_commitment(pre);
        let pred = Predicate::HashLock { hash: h };
        evaluate(
            &pred,
            &UnlockWitness::Preimage(pre.to_vec()),
            "hsn:unused",
            0,
        )
        .unwrap();
        assert!(evaluate(
            &pred,
            &UnlockWitness::Preimage(b"wrong".to_vec()),
            "hsn:unused",
            0,
        )
        .is_err());
    }

    #[test]
    fn absolute_lock_enforced() {
        let pred = Predicate::AbsoluteLock {
            address: "hsn:abc".into(),
            unlock_blue: 50,
        };
        assert!(evaluate(&pred, &UnlockWitness::Signature, "hsn:abc", 49).is_err());
        evaluate(&pred, &UnlockWitness::Signature, "hsn:abc", 50).unwrap();
    }

    #[test]
    fn and_or_work() {
        let pay = Predicate::PayToAddress {
            address: "hsn:abc".into(),
        };
        let hl = Predicate::HashLock {
            hash: hashlock_commitment(b"x"),
        };
        let and = Predicate::And {
            left: Box::new(pay.clone()),
            right: Box::new(hl.clone()),
        };
        evaluate(
            &and,
            &UnlockWitness::Stack(vec![
                UnlockWitness::Signature,
                UnlockWitness::Preimage(b"x".to_vec()),
            ]),
            "hsn:abc",
            0,
        )
        .unwrap();

        let or = Predicate::Or {
            left: Box::new(hl),
            right: Box::new(pay),
        };
        evaluate(&or, &UnlockWitness::Signature, "hsn:abc", 0).unwrap();
    }

    #[test]
    fn multisig_rejects_address_only_cosigner_tags() {
        // Adversarial: today's pre-fix attack stuffed CosignerAddress tags
        // without co-signer private keys. That path must fail closed.
        let (sk_a, pk_a) = generate_keypair();
        let (_sk_b, pk_b) = generate_keypair();
        let addr_a = hash_to_address(&pk_a);
        let addr_b = hash_to_address(&pk_b);
        let ms = Predicate::MultiSig {
            n: 2,
            addresses: vec![addr_a.clone(), addr_b.clone()],
        };
        let sighash = b"utxo-sighash-probe";
        let forged = UnlockWitness::Stack(vec![UnlockWitness::CosignerAddress(addr_b.clone())]);
        let err = evaluate_full(&ms, &forged, &addr_a, 0, 0, Some(sighash))
            .expect_err("address-only cosigner tags must not unlock");
        assert!(
            err.contains("CosignerAddress") || err.contains("not signatures"),
            "unexpected err: {err}"
        );
        // Primary alone is insufficient for 2-of-2.
        assert!(evaluate_full(
            &ms,
            &UnlockWitness::Signature,
            &addr_a,
            0,
            0,
            Some(sighash)
        )
        .is_err());
        let _ = sk_a; // keep sk_a used for clarity of "has key A only"
    }

    #[test]
    fn multisig_requires_real_cosigner_ml_dsa() {
        let (sk_a, pk_a) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let addr_a = hash_to_address(&pk_a);
        let addr_b = hash_to_address(&pk_b);
        let ms = Predicate::MultiSig {
            n: 2,
            addresses: vec![addr_a.clone(), addr_b.clone()],
        };
        let sighash = b"utxo-sighash-for-multisig";
        let sig_b = abs_sig::sign_pq512(b"utxo-tx", sighash, &sk_b).unwrap();
        evaluate_full(
            &ms,
            &UnlockWitness::Stack(vec![UnlockWitness::CosignerSig {
                pubkey: pk_b.clone(),
                signature: sig_b,
            }]),
            &addr_a,
            0,
            0,
            Some(sighash),
        )
        .expect("valid cosigner ML-DSA must unlock 2-of-2");

        // Wrong key / bad signature rejected.
        let bad = abs_sig::sign_pq512(b"utxo-tx", b"other-message", &sk_b).unwrap();
        assert!(evaluate_full(
            &ms,
            &UnlockWitness::Stack(vec![UnlockWitness::CosignerSig {
                pubkey: pk_b,
                signature: bad,
            }]),
            &addr_a,
            0,
            0,
            Some(sighash),
        )
        .is_err());
        let _ = sk_a;
    }

    #[test]
    fn relative_lock_uses_created_blue() {
        let pred = Predicate::RelativeLock {
            address: "hsn:abc".into(),
            relative_blues: 10,
        };
        assert!(evaluate_full(&pred, &UnlockWitness::Signature, "hsn:abc", 9, 0, None).is_err());
        evaluate_full(&pred, &UnlockWitness::Signature, "hsn:abc", 10, 0, None).unwrap();
        evaluate_full(&pred, &UnlockWitness::Signature, "hsn:abc", 15, 5, None).unwrap();
    }

    #[test]
    fn annul_after_and_commit_data() {
        let pred = Predicate::AnnulAfter {
            address: "hsn:abc".into(),
            expire_blue: 100,
        };
        evaluate(&pred, &UnlockWitness::Signature, "hsn:abc", 99).unwrap();
        assert!(evaluate(&pred, &UnlockWitness::Signature, "hsn:abc", 100).is_err());

        let c = hashlock_commitment(b"payload");
        let cd = Predicate::CommitData { commit: c };
        evaluate(
            &cd,
            &UnlockWitness::Preimage(b"payload".to_vec()),
            "hsn:unused",
            0,
        )
        .unwrap();

        let nested = Predicate::ExactValue {
            value: 1_000,
            inner: Box::new(Predicate::PayToAddress {
                address: "hsn:abc".into(),
            }),
        };
        evaluate(&nested, &UnlockWitness::Signature, "hsn:abc", 0).unwrap();
        assert_eq!(nested.depth(), 2);
    }
}
