//! ML-DSA-87 HD derivation (Blake3-XOF child keys from a master seed).
//!
//! Not BIP32 (secp-only); a PQ-native path: master seed → domain-separated
//! Blake3-512 XOF → ML-DSA-87 keypair per `(account, index)`.

use crate::{hash_to_address, PQ_SECRET_KEY_SIZE};
use blake3::Hasher;

pub const HD_DOMAIN: &[u8] = b"hassan-hd-mldsa87-v1";
pub const SEED_LEN: usize = 64;

/// Derive a 64-byte seed for ML-DSA keygen at path `m/account'/index'`.
/// The first 32 bytes feed `keygen_from_seed`.
pub fn derive_seed(master: &[u8], account: u32, index: u32) -> [u8; SEED_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(HD_DOMAIN);
    hasher.update(&(master.len() as u64).to_le_bytes());
    hasher.update(master);
    hasher.update(&account.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    let mut out = [0u8; SEED_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Derive `(secret, public, address)` for hardened path.
pub fn derive_keypair(
    master: &[u8],
    account: u32,
    index: u32,
) -> Result<(Vec<u8>, Vec<u8>, String), String> {
    if master.len() < 16 {
        return Err("master seed too short (need ≥16 bytes)".into());
    }
    let seed = derive_seed(master, account, index);
    let (sk, pk) = crate::generate_keypair_from_seed(&seed[..32])?;
    if sk.len() != PQ_SECRET_KEY_SIZE {
        return Err("HD derive produced wrong secret length".into());
    }
    let address = hash_to_address(&pk);
    Ok((sk, pk, address))
}

/// Stretch a passphrase into a master seed (Argon2id when available via wallet
/// file path; here Blake3-XOF for deterministic tests / CLI).
pub fn master_from_passphrase(passphrase: &str, salt: &[u8]) -> [u8; SEED_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(b"hassan-hd-master-from-pass-v1");
    hasher.update(salt);
    hasher.update(passphrase.as_bytes());
    let mut out = [0u8; SEED_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_index_sensitive() {
        let master = [7u8; 32];
        let (sk1, pk1, a1) = derive_keypair(&master, 0, 0).unwrap();
        let (sk2, pk2, a2) = derive_keypair(&master, 0, 0).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
        assert_eq!(a1, a2);
        let (_, _, a3) = derive_keypair(&master, 0, 1).unwrap();
        assert_ne!(a1, a3);
        let (_, _, a4) = derive_keypair(&master, 1, 0).unwrap();
        assert_ne!(a1, a4);
    }

    #[test]
    fn passphrase_master_stable() {
        let m1 = master_from_passphrase("test", b"salt");
        let m2 = master_from_passphrase("test", b"salt");
        assert_eq!(m1, m2);
        assert_ne!(m1, master_from_passphrase("test", b"other"));
    }
}
