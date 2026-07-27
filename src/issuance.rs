//! Issuance & settlement identity — banking language for block provenance.
//!
//! Every non-genesis block carries a notarized **Birth Certificate**: an
//! ML-DSA-87 signature over a **512-bit Settlement ID** (Blake3 XOF), after an
//! additional Blake3-512 domain prehash. Anyone, anywhere, can verify the
//! certificate against the issuer's public key.
use crate::{address_hash, Block, HASH_SIZE, PQ_PUBLIC_KEY_SIZE};
use blake3::Hasher as Blake3Hasher;
use serde::{Deserialize, Serialize};

/// Domain tag for the 512-bit settlement fingerprint.
pub const SETTLEMENT_DOMAIN: &[u8] = b"hassan-settlement-id-v1";

/// 512-bit (64-byte) settlement reference — Blake3 XOF over the block identity.
pub const SETTLEMENT_ID_SIZE: usize = HASH_SIZE;

/// Globally unique, 512-bit settlement reference for a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementId(pub [u8; SETTLEMENT_ID_SIZE]);

impl SettlementId {
    pub fn as_bytes(&self) -> &[u8; SETTLEMENT_ID_SIZE] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Notarized birth certificate: ML-DSA-87 signature over the 512-bit Settlement ID.
/// Verifiable offline by any party who has the issuer's public key — bank-grade
/// non-repudiation for block origination.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BirthCertificate {
    pub signature: Vec<u8>,
}

impl BirthCertificate {
    /// Issue a birth certificate: the issuer signs the Blake3-512 Settlement ID
    /// with ML-DSA-87 (already a 512-bit message).
    pub fn issue(settlement_id: &SettlementId, secret_key: &[u8]) -> Result<Self, String> {
        Ok(Self {
            // Settlement ID is already 512 bits; domain-separate once more for ABS.
            signature: crate::abs_sig::sign_pq512(
                b"birth-certificate",
                settlement_id.as_bytes(),
                secret_key,
            )?,
        })
    }

    /// Independent verification — same check a correspondent bank would run.
    pub fn verify(&self, settlement_id: &SettlementId, issuer_pubkey: &[u8]) -> bool {
        if issuer_pubkey.len() != PQ_PUBLIC_KEY_SIZE {
            return false;
        }
        crate::abs_sig::verify_pq512(
            b"birth-certificate",
            settlement_id.as_bytes(),
            issuer_pubkey,
            &self.signature,
        )
    }
}

impl Block {
    /// Absorb consensus identity fields into `hasher` (shared by PoW hash and
    /// the 512-bit Settlement ID).
    pub(crate) fn absorb_identity(&self, hasher: &mut Blake3Hasher) {
        hasher.update(crate::GENESIS_DOMAIN);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        for parent in &self.parents {
            hasher.update(parent.as_slice());
        }
        // Length-prefixed like `creator_pubkey` below: binds the interlink
        // *vector itself* (not just its contents) into the hash, so a forger
        // can't pad/truncate it without redoing the PoW search.
        hasher.update(&(self.interlinks.len() as u64).to_le_bytes());
        for link in &self.interlinks {
            hasher.update(link.as_slice());
        }
        hasher.update(self.merkle_root.as_slice());
        hasher.update(self.state_root.as_slice());
        hasher.update(self.miner.as_slice());
        hasher.update(&(self.creator_pubkey.len() as u64).to_le_bytes());
        hasher.update(&self.creator_pubkey);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.difficulty.to_le_bytes());
        hasher.update(&self.version.to_le_bytes());
    }

    /// 512-bit Settlement ID — the block's permanent reference number.
    pub fn settlement_id(&self) -> SettlementId {
        let mut hasher = Blake3Hasher::new();
        hasher.update(SETTLEMENT_DOMAIN);
        self.absorb_identity(&mut hasher);
        let mut out = [0u8; SETTLEMENT_ID_SIZE];
        hasher.finalize_xof().fill(&mut out);
        SettlementId(out)
    }

    /// Seal this block with a Birth Certificate after PoW fields are final.
    pub fn issue_birth_certificate(&mut self, secret_key: &[u8]) -> Result<(), String> {
        self.birth_certificate = BirthCertificate::issue(&self.settlement_id(), secret_key)?;
        Ok(())
    }

    /// Consensus check: issuer pubkey must match miner address, and the birth
    /// certificate must verify over the 512-bit Settlement ID. Genesis is exempt.
    pub fn verify_issuance(&self) -> Result<(), String> {
        if self.parents.is_empty() {
            return Ok(());
        }
        if self.creator_pubkey.len() != PQ_PUBLIC_KEY_SIZE {
            return Err("Missing or malformed issuer public key".into());
        }
        if self.miner != address_hash(&self.creator_pubkey) {
            return Err("miner / reward address does not match issuer public key".into());
        }
        if !self
            .birth_certificate
            .verify(&self.settlement_id(), &self.creator_pubkey)
        {
            return Err("Invalid birth certificate".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SETTLEMENT_ID_SIZE;
    use crate::{generate_keypair, genesis_block, seal_block, ChainState};

    #[test]
    fn settlement_id_is_512_bits_and_birth_cert_verifies() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let parents = state.tips.clone();
        let ts = crate::GENESIS_TIMESTAMP_MS + crate::TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let mut block = genesis_block();
        block.parents = parents;
        block.difficulty = difficulty;
        block.timestamp = ts;
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        seal_block(&state, &mut block, &sk, &pk);
        assert_eq!(block.settlement_id().0.len(), SETTLEMENT_ID_SIZE);
        assert!(block.verify_issuance().is_ok());
        assert!(state.add_block(block).is_ok());
    }

    #[test]
    fn tampered_birth_certificate_is_rejected() {
        let (sk, pk) = generate_keypair();
        let state = ChainState::new();
        let parents = state.tips.clone();
        let ts = crate::GENESIS_TIMESTAMP_MS + crate::TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let mut block = genesis_block();
        block.parents = parents;
        block.difficulty = difficulty;
        block.timestamp = ts;
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        seal_block(&state, &mut block, &sk, &pk);
        block.birth_certificate.signature[0] ^= 0xff;
        assert!(matches!(
            block.verify_issuance(),
            Err(e) if e.contains("birth certificate")
        ));
    }
}
