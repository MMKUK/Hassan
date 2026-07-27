//! Custody movements: **staking** and **cross-chain** exit/entry.
//!
//! Every custody event is bound to a block's **Birth Certificate** and
//! **512-bit Settlement ID**. A block (or titled asset / value) that leaves
//! for another chain or enters a stake lock must verify on exit; when it
//! returns, the entry proof must verify against the same issuance identity.

use crate::abs_sig::{digest512, sign_pq512, verify_pq512, DIGEST_512};
use crate::issuance::BirthCertificate;
use crate::{hash_to_address, Block, Hash, PQ_PUBLIC_KEY_SIZE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyKind {
    /// Value / title locked for staking yield.
    StakeLock,
    /// Stake matured / withdrawn back to free balance.
    StakeUnlock,
    /// Asset / value exiting Hassan toward a foreign chain.
    BridgeExit,
    /// Asset / value returning from a foreign chain onto Hassan.
    BridgeEnter,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyCertificate {
    pub kind: CustodyKind,
    /// Block hash this custody event anchors to.
    pub block_hash: Hash,
    /// 512-bit Settlement ID of the anchoring block.
    pub settlement_id: String,
    /// Birth certificate signature of the anchoring block (copied for offline verify).
    pub birth_certificate: Vec<u8>,
    pub issuer_pubkey: Vec<u8>,
    /// Destination or source chain id (0 = Hassan-local stake).
    pub foreign_chain_id: u64,
    pub amount: u128,
    pub title_id: Option<Hash>,
    pub owner: String,
    pub nonce: u64,
    pub chain_id: u64,
    /// ML-DSA-87 over Blake3-512 custody digest.
    pub signature: Vec<u8>,
    pub from_pubkey: Vec<u8>,
    /// Optional second, cryptographically unrelated signature (SLH-DSA
    /// hash-based scheme) over the same message — algorithm-diversity
    /// defense-in-depth. `None` means this certificate is single-signed
    /// (ML-DSA-87 only), which remains fully valid. See `src/dual_sig.rs`
    /// and `SECURITY.md` for why this isn't applied to every block.
    #[serde(default)]
    pub dual_signature: Option<crate::dual_sig::DualSignature>,
}

impl CustodyCertificate {
    fn message_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"hassan-custody-v1");
        buf.extend_from_slice(self.block_hash.as_slice());
        buf.extend_from_slice(self.settlement_id.as_bytes());
        buf.extend_from_slice(&self.birth_certificate);
        buf.extend_from_slice(&(self.foreign_chain_id).to_le_bytes());
        buf.extend_from_slice(&self.amount.to_le_bytes());
        if let Some(t) = &self.title_id {
            buf.extend_from_slice(t.as_slice());
        }
        buf.extend_from_slice(self.owner.as_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        let kind_tag: &[u8] = match self.kind {
            CustodyKind::StakeLock => b"stake-lock",
            CustodyKind::StakeUnlock => b"stake-unlock",
            CustodyKind::BridgeExit => b"bridge-exit",
            CustodyKind::BridgeEnter => b"bridge-enter",
        };
        buf.extend_from_slice(kind_tag);
        buf
    }

    pub fn sign(&mut self, secret_key: &[u8]) -> Result<(), String> {
        self.signature = sign_pq512(b"custody", &self.message_bytes(), secret_key)?;
        Ok(())
    }

    /// Additionally sign this certificate with a second, cryptographically
    /// unrelated hash-based scheme (SLH-DSA). Opt-in, additive — call after
    /// [`sign`]. See `src/dual_sig.rs` module docs for why this exists and
    /// why it's scoped to custody certificates rather than every block.
    pub fn sign_dual(&mut self, keypair: &crate::dual_sig::DualSigKeypair) -> Result<(), String> {
        let sig =
            crate::dual_sig::DualSignature::create(b"custody", &self.message_bytes(), keypair)?;
        self.dual_signature = Some(sig);
        Ok(())
    }

    /// Full verification:
    /// 1. Owner key matches address
    /// 2. ABS/PQ signature over custody message (512-bit prehash)
    /// 3. Optional second (SLH-DSA) signature, if present, must also verify
    /// 4. Anchoring block Birth Certificate verifies over Settlement ID
    pub fn verify(&self, settlement_id_bytes: &[u8; DIGEST_512]) -> Result<(), String> {
        if self.from_pubkey.len() != PQ_PUBLIC_KEY_SIZE {
            return Err("Invalid custody signer key".into());
        }
        if !crate::address::address_matches_pubkey(&self.owner, &self.from_pubkey) {
            return Err("Custody owner does not match signer".into());
        }
        if !verify_pq512(
            b"custody",
            &self.message_bytes(),
            &self.from_pubkey,
            &self.signature,
        ) {
            return Err("Invalid custody signature".into());
        }
        if let Some(dual) = &self.dual_signature {
            // A present-but-broken secondary signature is a harder failure
            // than a missing one: it means someone tampered with a
            // dual-signed certificate, not that dual-signing was skipped.
            if !dual.verify(b"custody", &self.message_bytes()) {
                return Err("Invalid secondary (SLH-DSA) custody signature".into());
            }
        }
        if hex::encode(settlement_id_bytes) != self.settlement_id {
            return Err("Settlement ID mismatch on custody certificate".into());
        }
        let birth = BirthCertificate {
            signature: self.birth_certificate.clone(),
        };
        // Reconstruct SettlementId type for birth verify
        let sid = crate::issuance::SettlementId(*settlement_id_bytes);
        if !birth.verify(&sid, &self.issuer_pubkey) {
            return Err("Birth Certificate failed on custody anchor — block not authentic".into());
        }
        Ok(())
    }
}

/// Bundles `issue_custody`'s parameters — grouped instead of nine positional
/// arguments so call sites stay readable and fields can't be transposed.
pub struct CustodyRequest<'a> {
    pub kind: CustodyKind,
    pub block: &'a Block,
    pub foreign_chain_id: u64,
    pub amount: u128,
    pub title_id: Option<Hash>,
    pub owner_sk: &'a [u8],
    pub owner_pk: &'a [u8],
    pub nonce: u64,
    pub chain_id: u64,
    /// Optional SLH-DSA keypair to additionally dual-sign this certificate
    /// with. `None` (the common case) leaves the certificate single-signed
    /// (ML-DSA-87), which is fully valid on its own.
    pub dual_sig_keypair: Option<&'a crate::dual_sig::DualSigKeypair>,
}

/// Build a custody certificate anchored to an already-sealed block.
pub fn issue_custody(req: CustodyRequest) -> Result<CustodyCertificate, String> {
    req.block.verify_issuance()?;
    let sid = req.block.settlement_id();
    let mut cert = CustodyCertificate {
        kind: req.kind,
        block_hash: req.block.hash(),
        settlement_id: sid.to_hex(),
        birth_certificate: req.block.birth_certificate.signature.clone(),
        issuer_pubkey: req.block.creator_pubkey.clone(),
        foreign_chain_id: req.foreign_chain_id,
        amount: req.amount,
        title_id: req.title_id,
        owner: hash_to_address(req.owner_pk),
        nonce: req.nonce,
        chain_id: req.chain_id,
        signature: vec![],
        from_pubkey: req.owner_pk.to_vec(),
        dual_signature: None,
    };
    cert.sign(req.owner_sk)?;
    if let Some(kp) = req.dual_sig_keypair {
        cert.sign_dual(kp)?;
    }
    cert.verify(sid.as_bytes())?;
    Ok(cert)
}

/// Verify a returning (bridge-enter) or unlock event against the original exit/lock.
pub fn verify_round_trip(
    exit_or_lock: &CustodyCertificate,
    enter_or_unlock: &CustodyCertificate,
) -> Result<(), String> {
    match (&exit_or_lock.kind, &enter_or_unlock.kind) {
        (CustodyKind::BridgeExit, CustodyKind::BridgeEnter)
        | (CustodyKind::StakeLock, CustodyKind::StakeUnlock) => {}
        _ => return Err("Custody pair kinds do not form an exit→entry or lock→unlock".into()),
    }
    if exit_or_lock.owner != enter_or_unlock.owner {
        return Err("Custody round-trip owner mismatch".into());
    }
    if exit_or_lock.amount != enter_or_unlock.amount {
        return Err("Custody round-trip amount mismatch".into());
    }
    if exit_or_lock.title_id != enter_or_unlock.title_id {
        return Err("Custody round-trip title mismatch".into());
    }
    if exit_or_lock.kind == CustodyKind::BridgeExit
        && exit_or_lock.foreign_chain_id != enter_or_unlock.foreign_chain_id
    {
        return Err("Bridge enter must cite the same foreign chain as exit".into());
    }
    // Both must carry valid birth-cert-bound anchors (settlement ids may differ
    // — exit and enter are different blocks — but each must be self-consistent).
    let exit_sid: [u8; DIGEST_512] = {
        let b = hex::decode(&exit_or_lock.settlement_id).map_err(|e| e.to_string())?;
        b.try_into()
            .map_err(|_| "bad exit settlement id".to_string())?
    };
    let enter_sid: [u8; DIGEST_512] = {
        let b = hex::decode(&enter_or_unlock.settlement_id).map_err(|e| e.to_string())?;
        b.try_into()
            .map_err(|_| "bad enter settlement id".to_string())?
    };
    exit_or_lock.verify(&exit_sid)?;
    enter_or_unlock.verify(&enter_sid)?;
    Ok(())
}

/// Hash a custody cert for AI / indexers (512-bit).
pub fn custody_fingerprint(cert: &CustodyCertificate) -> [u8; DIGEST_512] {
    digest512(b"custody-fp", &bincode::serialize(cert).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_keypair, genesis_block, seal_block, ChainState, CHAIN_ID};

    fn sealed_child() -> Block {
        let state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let parents = state.tips.clone();
        let ts = crate::GENESIS_TIMESTAMP_MS + crate::TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let mut block = genesis_block();
        block.parents = parents;
        block.difficulty = difficulty;
        block.state_root = state.merkle_root();
        block.timestamp = ts;
        seal_block(&state, &mut block, &sk, &pk);
        block
    }

    #[test]
    fn stake_lock_and_unlock_verify_with_birth_certificate() {
        let block_lock = sealed_child();
        let (sk, pk) = generate_keypair();
        let lock = issue_custody(CustodyRequest {
            kind: CustodyKind::StakeLock,
            block: &block_lock,
            foreign_chain_id: 0,
            amount: 1_000,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 0,
            chain_id: CHAIN_ID,
            dual_sig_keypair: None,
        })
        .unwrap();
        assert!(lock.verify(block_lock.settlement_id().as_bytes()).is_ok());

        let block_unlock = sealed_child();
        let unlock = issue_custody(CustodyRequest {
            kind: CustodyKind::StakeUnlock,
            block: &block_unlock,
            foreign_chain_id: 0,
            amount: 1_000,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 1,
            chain_id: CHAIN_ID,
            dual_sig_keypair: None,
        })
        .unwrap();
        verify_round_trip(&lock, &unlock).unwrap();
    }

    #[test]
    fn bridge_exit_and_enter_require_matching_foreign_chain() {
        let exit_block = sealed_child();
        let enter_block = sealed_child();
        let (sk, pk) = generate_keypair();
        let exit = issue_custody(CustodyRequest {
            kind: CustodyKind::BridgeExit,
            block: &exit_block,
            foreign_chain_id: 99,
            amount: 1000,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 0,
            chain_id: CHAIN_ID,
            dual_sig_keypair: None,
        })
        .unwrap();
        let enter = issue_custody(CustodyRequest {
            kind: CustodyKind::BridgeEnter,
            block: &enter_block,
            foreign_chain_id: 99,
            amount: 1000,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 1,
            chain_id: CHAIN_ID,
            dual_sig_keypair: None,
        })
        .unwrap();
        verify_round_trip(&exit, &enter).unwrap();
    }

    #[test]
    fn dual_signed_custody_cert_verifies_both_schemes() {
        let block = sealed_child();
        let (sk, pk) = generate_keypair();
        let dual_kp = crate::dual_sig::generate_keypair().expect("SLH-DSA keygen");
        let lock = issue_custody(CustodyRequest {
            kind: CustodyKind::StakeLock,
            block: &block,
            foreign_chain_id: 0,
            amount: 1000,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 0,
            chain_id: CHAIN_ID,
            dual_sig_keypair: Some(&dual_kp),
        })
        .unwrap();
        assert!(lock.dual_signature.is_some());
        assert!(lock.verify(block.settlement_id().as_bytes()).is_ok());

        let mut broken = lock.clone();
        if let Some(d) = broken.dual_signature.as_mut() {
            d.signature_hex = "00".repeat(crate::dual_sig::SIGNATURE_LEN);
        }
        assert!(
            broken.verify(block.settlement_id().as_bytes()).is_err(),
            "tampered secondary signature must fail verification"
        );
    }
}
