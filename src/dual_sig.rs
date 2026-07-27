//! Secondary post-quantum signature scheme (SLH-DSA-SHAKE-256s, FIPS 205 —
//! the standardized descendant of SPHINCS+) for **algorithm diversity**.
//!
//! Every Birth Certificate and transfer already carries an ML-DSA-87
//! (FIPS 204, lattice-based) signature. That is a real, current
//! post-quantum guarantee on its own. This module adds a *second*,
//! cryptographically unrelated signature family: SLH-DSA is hash-based —
//! its security reduces only to the security of the underlying hash
//! function, not to any lattice-hardness assumption. If a novel attack ever
//! broke lattice-based schemes (the "eggs in one basket" risk of relying on
//! ML-DSA alone), a block dual-signed here would still be authenticated by
//! an unrelated cryptographic family.
//!
//! **Deliberate scope**: this is *not* applied to every block header.
//! SLH-DSA-SHAKE-256s signatures are large (~29.8 KB) — adding one to every
//! block on a 100ms block-time chain would cost ~25 GB/day in header
//! overhead alone, which would make the chain unusable. Dual-signing is
//! applied only to [`crate::custody::CustodyCertificate`] (stake lock/unlock,
//! bridge exit/enter): infrequent, high-value operations where ~30 KB of
//! extra assurance is a reasonable price, unlike a signature carried by
//! every block forever. See `SECURITY.md` for the full accounting of what
//! is and isn't implemented.

use fips205::slh_dsa_shake_256s::{self, PrivateKey, PublicKey};
use fips205::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};

pub const SCHEME_NAME: &str = "SLH-DSA-SHAKE-256s";
pub const PUBLIC_KEY_LEN: usize = slh_dsa_shake_256s::PK_LEN;
pub const SIGNATURE_LEN: usize = slh_dsa_shake_256s::SIG_LEN;

/// A generated SLH-DSA keypair, serialized as raw bytes for storage/transport.
#[derive(Clone)]
pub struct DualSigKeypair {
    pub public_key: Vec<u8>,
    secret_key: PrivateKey,
}

/// Generate a fresh SLH-DSA-SHAKE-256s keypair. Slow relative to ML-DSA-87
/// (hash-based schemes trade speed for the more conservative security
/// assumption) — call this rarely, e.g. once per validator identity, not
/// per block.
pub fn generate_keypair() -> Result<DualSigKeypair, String> {
    let (pk, sk) =
        slh_dsa_shake_256s::try_keygen().map_err(|e| format!("SLH-DSA keygen failed: {e}"))?;
    Ok(DualSigKeypair {
        public_key: pk.into_bytes().to_vec(),
        secret_key: sk,
    })
}

/// Sign `message` under `domain` (domain-separated the same way as
/// [`crate::abs_sig::sign_pq512`], via a Blake3-512 prehash) with the given
/// keypair's SLH-DSA secret key.
pub fn sign(domain: &[u8], message: &[u8], keypair: &DualSigKeypair) -> Result<Vec<u8>, String> {
    let digest = crate::abs_sig::digest512(domain, message);
    let sig = keypair
        .secret_key
        .try_sign(&digest, b"hassan-dual-sig-v1", true)
        .map_err(|e| format!("SLH-DSA sign failed: {e}"))?;
    Ok(sig.to_vec())
}

/// Verify an SLH-DSA signature produced by [`sign`].
pub fn verify(domain: &[u8], message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != PUBLIC_KEY_LEN || signature.len() != SIGNATURE_LEN {
        return false;
    }
    let Ok(pk_arr): Result<[u8; PUBLIC_KEY_LEN], _> = public_key.to_vec().try_into() else {
        return false;
    };
    let Ok(pk) = PublicKey::try_from_bytes(&pk_arr) else {
        return false;
    };
    let digest = crate::abs_sig::digest512(domain, message);
    let Ok(sig_arr): Result<[u8; SIGNATURE_LEN], _> = signature.to_vec().try_into() else {
        return false;
    };
    pk.verify(&digest, &sig_arr, b"hassan-dual-sig-v1")
}

/// Wire-friendly wrapper carrying both the public key and signature bytes,
/// mirroring [`crate::abs_sig::AbsSignature`]'s shape but for the secondary
/// scheme. `None` means "not dual-signed" — dual-signing is opt-in.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DualSignature {
    pub scheme: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

impl DualSignature {
    pub fn create(domain: &[u8], message: &[u8], keypair: &DualSigKeypair) -> Result<Self, String> {
        let signature = sign(domain, message, keypair)?;
        Ok(Self {
            scheme: SCHEME_NAME.into(),
            public_key_hex: hex::encode(&keypair.public_key),
            signature_hex: hex::encode(signature),
        })
    }

    pub fn verify(&self, domain: &[u8], message: &[u8]) -> bool {
        let Ok(pk) = hex::decode(&self.public_key_hex) else {
            return false;
        };
        let Ok(sig) = hex::decode(&self.signature_hex) else {
            return false;
        };
        verify(domain, message, &pk, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dual_signature_verifies_against_its_own_message_and_key() {
        let kp = generate_keypair().expect("keygen");
        let msg = b"stake-lock:1000:owner:hsn:abc";
        let sig = DualSignature::create(b"custody", msg, &kp).expect("sign");
        assert_eq!(sig.scheme, SCHEME_NAME);
        assert!(sig.verify(b"custody", msg));
    }

    #[test]
    fn a_dual_signature_is_rejected_under_a_tampered_message_or_domain() {
        let kp = generate_keypair().expect("keygen");
        let msg = b"stake-lock:1000:owner:hsn:abc";
        let sig = DualSignature::create(b"custody", msg, &kp).expect("sign");
        assert!(!sig.verify(b"custody", b"stake-lock:9999:owner:hsn:abc"));
        assert!(!sig.verify(b"other-domain", msg));
    }

    #[test]
    fn a_dual_signature_is_rejected_under_a_different_keypair() {
        let kp_a = generate_keypair().expect("keygen a");
        let kp_b = generate_keypair().expect("keygen b");
        let msg = b"bridge-exit:50:owner:hsn:xyz";
        let mut sig = DualSignature::create(b"custody", msg, &kp_a).expect("sign");
        sig.public_key_hex = hex::encode(&kp_b.public_key);
        assert!(!sig.verify(b"custody", msg));
    }
}
