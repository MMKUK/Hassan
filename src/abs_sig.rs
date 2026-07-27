//! Absolute post-quantum signatures — every signed message is first reduced to a
//! **512-bit** Blake3 digest, then signed with **ML-DSA-87** (FIPS 204, highest
//! NIST Dilithium parameter set).
//!
//! Wallet / API surface exposes an **ABS** (Absolute Binding Signature):
//! - `scheme` — numeric absolute type code (never ambiguous)
//! - `digest512` — the 512-bit message digest (hex)
//! - `value` — signature bytes as a decimal **number** (big-endian integer)
//! - `value_hex` — same signature as hex for wire transport

use crate::{sign_message, verify_signature, PQ_PUBLIC_KEY_SIZE, PQ_SIGNATURE_SIZE};
use blake3::Hasher as Blake3Hasher;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Absolute signature scheme type codes (stable, numeric).
pub const ABS_SCHEME_ML_DSA_87: u32 = 87;
pub const ABS_SCHEME_NAME: &str = "ML-DSA-87";

/// 512-bit security digest size (aligned with `HASH_SIZE`).
pub const DIGEST_512: usize = crate::HASH_SIZE;

/// Domain-separated Blake3-512 of arbitrary message bytes.
pub fn digest512(domain: &[u8], message: &[u8]) -> [u8; DIGEST_512] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"hassan-pq-512-v1");
    hasher.update(domain);
    hasher.update(message);
    let mut out = [0u8; DIGEST_512];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Absolute Binding Signature — number + absolute type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbsSignature {
    /// Absolute scheme type code (87 = ML-DSA-87).
    pub scheme: u32,
    pub scheme_name: String,
    /// 512-bit message digest (hex).
    pub digest512: String,
    /// Signature interpreted as an unsigned big-endian integer (decimal string).
    pub value: String,
    /// Signature bytes (hex) — wire form.
    pub value_hex: String,
    /// Issuer / signer public key (hex).
    pub public_key: String,
}

impl AbsSignature {
    /// Sign `message` under `domain` after Blake3-512 prehash.
    pub fn sign(
        domain: &[u8],
        message: &[u8],
        secret_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, String> {
        let digest = digest512(domain, message);
        let sig = sign_message(secret_key, &digest)?;
        Ok(Self::from_parts(&digest, &sig, public_key))
    }

    pub fn from_parts(digest: &[u8; DIGEST_512], signature: &[u8], public_key: &[u8]) -> Self {
        let value = BigUint::from_bytes_be(signature).to_str_radix(10);
        Self {
            scheme: ABS_SCHEME_ML_DSA_87,
            scheme_name: ABS_SCHEME_NAME.into(),
            digest512: hex::encode(digest),
            value,
            value_hex: hex::encode(signature),
            public_key: hex::encode(public_key),
        }
    }

    /// Verify ABS: scheme must be ML-DSA-87, digest/signature lengths exact.
    pub fn verify(&self, domain: &[u8], message: &[u8]) -> bool {
        if self.scheme != ABS_SCHEME_ML_DSA_87 {
            return false;
        }
        let digest = digest512(domain, message);
        if hex::encode(digest) != self.digest512 {
            return false;
        }
        let pk = match hex::decode(&self.public_key) {
            Ok(b) if b.len() == PQ_PUBLIC_KEY_SIZE => b,
            _ => return false,
        };
        let sig = match hex::decode(&self.value_hex) {
            Ok(b) if b.len() == PQ_SIGNATURE_SIZE => b,
            _ => return false,
        };
        // Cross-check decimal number encodes the same bytes.
        if let Ok(n) = self.value.parse::<BigUint>() {
            let from_num = n.to_bytes_be();
            // BigUint drops leading zeros — pad to signature length.
            if from_num.len() > sig.len() {
                return false;
            }
            let mut padded = vec![0u8; sig.len() - from_num.len()];
            padded.extend_from_slice(&from_num);
            if padded != sig {
                return false;
            }
        } else {
            return false;
        }
        verify_signature(&pk, &digest, &sig)
    }
}

/// Sign any message with mandatory 512-bit prehash (used by consensus paths).
pub fn sign_pq512(domain: &[u8], message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    let digest = digest512(domain, message);
    sign_message(secret_key, &digest)
}

pub fn verify_pq512(domain: &[u8], message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    let digest = digest512(domain, message);
    verify_signature(public_key, &digest, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;

    #[test]
    fn abs_signature_round_trips_as_number_and_verifies() {
        let (sk, pk) = generate_keypair();
        let msg = b"transfer:100:to:alice";
        let abs = AbsSignature::sign(b"wallet-transfer", msg, &sk, &pk).unwrap();
        assert_eq!(abs.scheme, ABS_SCHEME_ML_DSA_87);
        assert!(!abs.value.is_empty());
        assert!(abs.value.chars().all(|c| c.is_ascii_digit()));
        assert!(abs.verify(b"wallet-transfer", msg));
        assert!(!abs.verify(b"wallet-transfer", b"tampered"));
    }
}
