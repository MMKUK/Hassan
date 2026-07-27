//! Bech32m addresses for Hassan (`hsn1…`).
//!
//! # Format
//! Canonical address = BIP-350 **bech32m** with HRP `hsn`, encoding the first
//! **32 bytes** of `Blake3-512("address" ‖ ML-DSA-87 pk)` (i.e. a 256-bit
//! fingerprint of the post-quantum public key — **not** the full key).
//!
//! Why 32 bytes (not BTC’s 20): ML-DSA keys are large; a 256-bit Blake3
//! truncation keeps a comfortable PQ collision margin while staying human-
//! readable. Length is longer than BTC `bc1…` P2WPKH but still compact vs
//! legacy `hsn:<128 hex>` (full 512-bit digest).
//!
//! # Dual-accept decode (v27)
//! Legacy `hsn:<128 hex>` remains accepted by [`is_valid_hassan_address`] and
//! [`addresses_equivalent`] so older strings continue to unlock outputs / match
//! pubkeys. **New UTXO outputs must be bech32m** (`hsn1…`) — enforced in
//! [`crate::utxo_tx::UtxoTx::validate_form`]. Wallet encode paths use bech32m.

use crate::{address_hash, Hash, HASH_SIZE};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
/// Payload size encoded in bech32m (bytes of the address digest prefix).
pub const ADDRESS_PAYLOAD_LEN: usize = 32;

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(*v);
        for (i, gen) in [0x3b6a_57b2u32, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
            .iter()
            .enumerate()
        {
            if (b >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.chars() {
        out.push((c as u8) >> 5);
    }
    out.push(0);
    for c in hrp.chars() {
        out.push((c as u8) & 31);
    }
    out
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv = (1u32 << to) - 1;
    for &value in data {
        if (u32::from(value) >> from) != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(value);
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(ret)
}

fn encode(hrp: &str, data: &[u8]) -> Option<String> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let checksum = polymod(&values) ^ BECH32M_CONST;
    let mut out = format!("{hrp}1");
    for d in data {
        out.push(CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        let c = ((checksum >> (5 * (5 - i))) & 31) as usize;
        out.push(CHARSET[c] as char);
    }
    Some(out)
}

fn decode(addr: &str) -> Option<(String, Vec<u8>)> {
    // Mixed case is invalid per BIP-173 / BIP-350.
    if addr.bytes().any(|b| b.is_ascii_uppercase()) && addr.bytes().any(|b| b.is_ascii_lowercase())
    {
        return None;
    }
    let addr = addr.to_ascii_lowercase();
    let (hrp, data) = addr.rsplit_once('1')?;
    if hrp.is_empty() || data.len() < 6 {
        return None;
    }
    let mut values = Vec::with_capacity(data.len());
    for c in data.bytes() {
        let v = CHARSET.iter().position(|&x| x == c)? as u8;
        values.push(v);
    }
    let mut check_vals = hrp_expand(hrp);
    check_vals.extend_from_slice(&values);
    if polymod(&check_vals) != BECH32M_CONST {
        return None;
    }
    let data_part = &values[..values.len() - 6];
    Some((hrp.to_string(), data_part.to_vec()))
}

/// Encode pubkey → canonical `hsn1…` bech32m address.
pub fn encode_address(pubkey: &[u8]) -> String {
    let h = address_hash(pubkey);
    encode_hash(&h)
}

/// Encode a full 512-bit address digest → `hsn1…` (first 32 bytes).
pub fn encode_hash(h: &Hash) -> String {
    let payload = &h.as_bytes()[..ADDRESS_PAYLOAD_LEN];
    let data = convert_bits(payload, 8, 5, true).expect("convert");
    encode("hsn", &data).expect("bech32m")
}

/// Legacy display / dual-accept form: `hsn:` + 128 hex chars (full digest).
pub fn encode_legacy_hex(h: &Hash) -> String {
    format!("hsn:{}", hex::encode(h.as_bytes()))
}

/// Decode `hsn1…` to the 32-byte payload (prefix of the address digest).
pub fn decode_address(addr: &str) -> Option<[u8; ADDRESS_PAYLOAD_LEN]> {
    let (hrp, data5) = decode(addr)?;
    if hrp != "hsn" {
        return None;
    }
    let bytes = convert_bits(&data5, 5, 8, false)?;
    if bytes.len() != ADDRESS_PAYLOAD_LEN {
        return None;
    }
    let mut out = [0u8; ADDRESS_PAYLOAD_LEN];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// 32-byte fingerprint shared by bech32m and legacy hex forms of the same key.
pub fn address_fingerprint(addr: &str) -> Option<[u8; ADDRESS_PAYLOAD_LEN]> {
    if let Some(fp) = decode_address(addr) {
        return Some(fp);
    }
    let hex_part = addr.strip_prefix("hsn:")?;
    if hex_part.len() != HASH_SIZE * 2 {
        return None;
    }
    let bytes = hex::decode(hex_part).ok()?;
    if bytes.len() != HASH_SIZE {
        return None;
    }
    let mut out = [0u8; ADDRESS_PAYLOAD_LEN];
    out.copy_from_slice(&bytes[..ADDRESS_PAYLOAD_LEN]);
    Some(out)
}

/// True when both strings name the same key fingerprint (exact or cross-format).
pub fn addresses_equivalent(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (address_fingerprint(a), address_fingerprint(b)) {
        (Some(fa), Some(fb)) => fa == fb,
        _ => false,
    }
}

/// True when `addr` is the bech32m or legacy encoding of `pubkey`.
pub fn address_matches_pubkey(addr: &str, pubkey: &[u8]) -> bool {
    let h = address_hash(pubkey);
    addresses_equivalent(addr, &encode_hash(&h))
        || addresses_equivalent(addr, &encode_legacy_hex(&h))
}

pub fn is_bech32m_address(addr: &str) -> bool {
    decode_address(addr).is_some()
}

/// Legacy hex or bech32m.
pub fn is_valid_hassan_address(addr: &str) -> bool {
    if is_bech32m_address(addr) {
        return true;
    }
    let Some(hex_part) = addr.strip_prefix("hsn:") else {
        return false;
    };
    if hex_part.len() != HASH_SIZE * 2 {
        return false;
    }
    hex::decode(hex_part)
        .ok()
        .filter(|b| b.len() == HASH_SIZE)
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;

    #[test]
    fn roundtrip_bech32m() {
        let (_, pk) = generate_keypair();
        let a = encode_address(&pk);
        assert!(a.starts_with("hsn1"));
        assert!(is_bech32m_address(&a));
        let payload = decode_address(&a).unwrap();
        assert_eq!(&payload, &address_hash(&pk).as_bytes()[..ADDRESS_PAYLOAD_LEN]);
    }

    #[test]
    fn same_pk_same_address() {
        let (_, pk) = generate_keypair();
        assert_eq!(encode_address(&pk), encode_address(&pk));
    }

    #[test]
    fn rejects_invalid_checksum() {
        let (_, pk) = generate_keypair();
        let a = encode_address(&pk);
        let mut chars: Vec<char> = a.chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'q' { 'p' } else { 'q' };
        let tampered: String = chars.into_iter().collect();
        assert!(!is_bech32m_address(&tampered));
        assert!(address_fingerprint(&tampered).is_none());
    }

    #[test]
    fn rejects_mixed_case() {
        let (_, pk) = generate_keypair();
        let a = encode_address(&pk);
        let mixed = format!("{}{}", &a[..4].to_uppercase(), &a[4..]);
        assert!(!is_bech32m_address(&mixed));
    }

    #[test]
    fn legacy_and_bech32m_are_equivalent() {
        let (_, pk) = generate_keypair();
        let h = address_hash(&pk);
        let bech = encode_hash(&h);
        let legacy = encode_legacy_hex(&h);
        assert!(addresses_equivalent(&bech, &legacy));
        assert!(address_matches_pubkey(&bech, &pk));
        assert!(address_matches_pubkey(&legacy, &pk));
        assert!(is_valid_hassan_address(&bech));
        assert!(is_valid_hassan_address(&legacy));
    }

    #[test]
    fn new_encode_is_bech32m_only() {
        let (_, pk) = generate_keypair();
        let a = encode_address(&pk);
        assert!(a.starts_with("hsn1"), "new outputs use bech32m");
        assert!(!a.starts_with("hsn:"));
        assert!(is_bech32m_address(&a));
    }
}
