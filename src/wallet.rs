//! A wallet: post-quantum (ML-DSA-87) key management with **Absolute Binding
//! Signatures** — every wallet signature is a **number** plus an absolute
//! scheme type code (`87` = ML-DSA-87), over a Blake3-512 digest.

use crate::abs_sig::{AbsSignature, ABS_SCHEME_ML_DSA_87};
use crate::{
    generate_keypair, hash_to_address, Account, ChainState, TransparentTx, PQ_PUBLIC_KEY_SIZE,
    PQ_SECRET_KEY_SIZE,
};

/// A wallet: one ML-DSA-87 keypair and its derived address.
pub struct Wallet {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    address: String,
}

impl Wallet {
    /// Generate a fresh wallet with a new post-quantum keypair.
    pub fn generate() -> Self {
        let (secret_key, public_key) = generate_keypair();
        let address = hash_to_address(&public_key);
        Self {
            secret_key,
            public_key,
            address,
        }
    }

    /// Restore a wallet from an exported keypair.
    pub fn import(secret_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, String> {
        if secret_key.len() != PQ_SECRET_KEY_SIZE {
            return Err(format!("secret key must be {PQ_SECRET_KEY_SIZE} bytes"));
        }
        if public_key.len() != PQ_PUBLIC_KEY_SIZE {
            return Err(format!("public key must be {PQ_PUBLIC_KEY_SIZE} bytes"));
        }
        let probe = b"hassan-wallet-keypair-check";
        let abs = AbsSignature::sign(b"wallet-probe", probe, &secret_key, &public_key)?;
        if !abs.verify(b"wallet-probe", probe) {
            return Err("secret and public keys do not form a valid pair".into());
        }
        let address = hash_to_address(&public_key);
        Ok(Self {
            secret_key,
            public_key,
            address,
        })
    }

    pub fn export(&self) -> (Vec<u8>, Vec<u8>) {
        (self.secret_key.clone(), self.public_key.clone())
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Absolute signature scheme type code for this wallet (always 87).
    pub fn abs_scheme(&self) -> u32 {
        ABS_SCHEME_ML_DSA_87
    }

    /// Build and sign a transparent transfer (PQ-512 prehash + ML-DSA-87).
    ///
    /// v27: peer account transfers are consensus-disabled. Prefer
    /// [`Self::create_utxo_payment`]. This still builds a signed tx for tests /
    /// tooling; admission and apply will reject it on a live chain.
    pub fn create_transfer(
        &self,
        to: impl Into<String>,
        amount: u128,
        nonce: u64,
        chain_id: u64,
    ) -> Result<TransparentTx, String> {
        if !crate::ACCOUNT_PEER_TRANSFERS {
            return Err(
                "Account peer transfers disabled (v27); use create_utxo_payment".into(),
            );
        }
        self.create_transfer_with_fee(to, amount, 0, nonce, chain_id)
    }

    pub fn create_transfer_with_fee(
        &self,
        to: impl Into<String>,
        amount: u128,
        fee: u128,
        nonce: u64,
        chain_id: u64,
    ) -> Result<TransparentTx, String> {
        if !crate::ACCOUNT_PEER_TRANSFERS {
            return Err(
                "Account peer transfers disabled (v27); use create_utxo_payment".into(),
            );
        }
        let mut tx = TransparentTx::new_with_fee(
            self.public_key.clone(),
            to.into(),
            amount,
            fee,
            nonce,
            chain_id,
        );
        let need = tx.min_fee_required();
        if tx.fee < need {
            tx.fee = need;
        }
        tx.sign(&self.secret_key)?;
        Ok(tx)
    }

    /// Build and sign a UTXO payment (v27 primary peer-value path).
    pub fn create_utxo_payment(
        &self,
        funding: crate::utxo::OutPoint,
        funding_value: u128,
        to: impl Into<String>,
        amount: u128,
        fee: u128,
        chain_id: u64,
    ) -> Result<crate::utxo_tx::UtxoTx, String> {
        let mut tx = crate::utxo_tx::UtxoTx::payment(
            self.public_key.clone(),
            funding,
            funding_value,
            to.into(),
            amount,
            fee,
            chain_id,
            0,
            0,
        )?;
        tx.sign(&self.secret_key)?;
        Ok(tx)
    }

    /// Sign an arbitrary message and return an ABS (number + absolute type).
    pub fn sign_abs(&self, domain: &[u8], message: &[u8]) -> Result<AbsSignature, String> {
        AbsSignature::sign(domain, message, &self.secret_key, &self.public_key)
    }

    /// ABS view of a transfer this wallet created.
    pub fn transfer_abs_signature(&self, tx: &TransparentTx) -> AbsSignature {
        tx.abs_signature()
    }

    /// Account overlay balance (registry/custody). Does not include UTXO.
    pub fn account_balance(&self, state: &ChainState) -> u128 {
        state
            .accounts
            .get(&self.address)
            .map(|a: &Account| a.balance)
            .unwrap_or(0)
    }

    /// Sum of spendable UTXO locked to this wallet address.
    pub fn utxo_balance(&self, state: &ChainState) -> u128 {
        state
            .utxo
            .entries
            .values()
            .filter(|o| {
                o.predicate
                    .locked_address()
                    .map(|a| crate::address::addresses_equivalent(a, &self.address))
                    .unwrap_or(false)
            })
            .map(|o| o.value)
            .sum()
    }

    pub fn balance(&self, state: &ChainState) -> u128 {
        self.account_balance(state)
            .saturating_add(self.utxo_balance(state))
    }

    pub fn next_nonce(&self, state: &ChainState) -> u64 {
        state
            .accounts
            .get(&self.address)
            .map(|a: &Account| a.nonce)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_address, Hash, CHAIN_ID};

    #[test]
    fn generated_wallet_has_a_valid_address_and_signs_utxo() {
        let w = Wallet::generate();
        assert!(w.address().starts_with("hsn1"));
        assert_eq!(w.abs_scheme(), 87);
        assert!(
            w.create_transfer(test_address(1), 1000, 0, CHAIN_ID)
                .unwrap_err()
                .contains("disabled"),
            "v27: transparent peer transfers rejected"
        );
        let funding = crate::utxo::OutPoint {
            txid: Hash([7u8; 64]),
            vout: 0,
        };
        let tx = w
            .create_utxo_payment(funding, 1_000_000, test_address(1), 100_000, 0, CHAIN_ID)
            .unwrap();
        assert!(tx.verify());
    }

    #[test]
    fn utxo_balance_counts_locked_outputs() {
        let w = Wallet::generate();
        let mut state = ChainState::new();
        let op = crate::utxo::OutPoint {
            txid: Hash([3u8; 64]),
            vout: 0,
        };
        state.utxo.insert(
            op,
            crate::utxo::TxOut {
                value: 42_000,
                predicate: crate::predicate::Predicate::PayToAddress {
                    address: w.address().to_string(),
                },
                created_blue: 0,
            },
        );
        assert_eq!(w.utxo_balance(&state), 42_000);
        assert_eq!(w.balance(&state), 42_000);
    }

    #[test]
    fn export_import_round_trips_and_preserves_the_address() {
        let w = Wallet::generate();
        let (sk, pk) = w.export();
        let w2 = Wallet::import(sk, pk).unwrap();
        assert_eq!(w.address(), w2.address());
    }

    #[test]
    fn importing_wrong_sized_keys_is_rejected() {
        assert!(Wallet::import(vec![1, 2, 3], vec![4, 5, 6]).is_err());
    }

    #[test]
    fn importing_mismatched_keys_is_rejected() {
        let (sk, _) = crate::generate_keypair();
        let (_, pk2) = crate::generate_keypair();
        assert!(Wallet::import(sk, pk2).is_err());
    }
}
