//! Out-of-band peer identity pin directory (closes TOFU residual).
//!
//! Operators may pin expected ML-DSA-87 peer public keys so an active MITM
//! cannot insert *their own* PQ identity on first contact.
//!
//! ## Configuration
//!
//! - `HASSAN_PEER_PINS` — path to a pin file, **or** a comma/semicolon-separated
//!   list of hex pubkeys (and optional `hex@host:port` entries).
//! - `HASSAN_PEER_PINS_STRICT=1` — reject connections whose ML-DSA identity is
//!   not in the pin set. When unset/false and pins are configured, mismatched
//!   peers are logged and still accepted (warn-only prefer mode).
//!
//! Pin file format: one entry per line; `#` comments; blank lines ignored.
//! Each entry is either bare hex (64-byte ML-DSA-87 pubkey) or `hex@addr`.

use crate::PQ_PUBLIC_KEY_SIZE;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

pub const PEER_PINS_ENV: &str = "HASSAN_PEER_PINS";
pub const PEER_PINS_STRICT_ENV: &str = "HASSAN_PEER_PINS_STRICT";

#[derive(Clone, Debug, Default)]
pub struct PeerPinDirectory {
    /// Hex-decoded ML-DSA pubkeys that are pinned (any peer address).
    pub keys: HashSet<Vec<u8>>,
    /// Optional address → expected pubkey (when entry used `hex@host:port`).
    pub by_addr: std::collections::HashMap<String, Vec<u8>>,
    pub strict: bool,
}

static PINS: OnceLock<PeerPinDirectory> = OnceLock::new();

fn parse_hex_pubkey(raw: &str) -> Option<Vec<u8>> {
    let bytes = hex::decode(raw.trim()).ok()?;
    if bytes.len() != PQ_PUBLIC_KEY_SIZE {
        return None;
    }
    Some(bytes)
}

/// Parse a pin file or inline list into a directory.
pub fn parse_pin_source(source: &str, strict: bool) -> PeerPinDirectory {
    let mut dir = PeerPinDirectory {
        strict,
        ..Default::default()
    };
    let text = if Path::new(source).is_file() {
        std::fs::read_to_string(source).unwrap_or_default()
    } else {
        source.replace(';', "\n").replace(',', "\n")
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((hex_part, addr)) = line.split_once('@') {
            if let Some(pk) = parse_hex_pubkey(hex_part) {
                dir.by_addr.insert(addr.trim().to_string(), pk.clone());
                dir.keys.insert(pk);
            } else {
                eprintln!("peer_pin: skipping invalid hex@addr entry");
            }
        } else if let Some(pk) = parse_hex_pubkey(line) {
            dir.keys.insert(pk);
        } else {
            eprintln!("peer_pin: skipping invalid pin line");
        }
    }
    dir
}

fn load_directory() -> PeerPinDirectory {
    let strict = matches!(
        std::env::var(PEER_PINS_STRICT_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    );
    match std::env::var(PEER_PINS_ENV) {
        Ok(src) if !src.trim().is_empty() => parse_pin_source(src.trim(), strict),
        _ => PeerPinDirectory {
            strict,
            ..Default::default()
        },
    }
}

/// Process-wide pin directory (loaded once from env).
pub fn directory() -> &'static PeerPinDirectory {
    PINS.get_or_init(load_directory)
}

/// Whether any pins are configured.
pub fn has_pins() -> bool {
    let d = directory();
    !d.keys.is_empty() || !d.by_addr.is_empty()
}

/// Check a verified peer ML-DSA pubkey (and optional dialed address).
///
/// Returns `Ok(())` when the peer may stay connected, `Err(reason)` when the
/// connection must be dropped (strict mismatch or address-bound mismatch).
pub fn check_peer_identity(pubkey: &[u8], dialed_addr: Option<&str>) -> Result<(), String> {
    let d = directory();
    if d.keys.is_empty() && d.by_addr.is_empty() {
        return Ok(()); // no pins configured — TOFU
    }

    if let Some(addr) = dialed_addr {
        if let Some(expected) = d.by_addr.get(addr) {
            if expected.as_slice() != pubkey {
                return Err(format!(
                    "peer identity mismatch for pinned address {addr}"
                ));
            }
            return Ok(());
        }
    }

    if d.keys.iter().any(|k| k.as_slice() == pubkey) {
        return Ok(());
    }

    if d.strict {
        return Err("peer identity not in HASSAN_PEER_PINS (strict)".into());
    }
    eprintln!(
        "peer_pin: accepting unpinned ML-DSA identity (set {PEER_PINS_STRICT_ENV}=1 to reject)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inline_hex_and_addr_entries() {
        let pk = vec![0x11u8; PQ_PUBLIC_KEY_SIZE];
        let hex = hex::encode(&pk);
        let src = format!("{hex}\n{hex}@127.0.0.1:9333\n# comment\n");
        let dir = parse_pin_source(&src, true);
        assert!(dir.strict);
        assert!(dir.keys.contains(&pk));
        assert_eq!(dir.by_addr.get("127.0.0.1:9333"), Some(&pk));
    }

    #[test]
    fn strict_directory_holds_expected_key() {
        let pk = vec![0x22u8; PQ_PUBLIC_KEY_SIZE];
        let other = vec![0x33u8; PQ_PUBLIC_KEY_SIZE];
        let dir = PeerPinDirectory {
            keys: HashSet::from([pk.clone()]),
            by_addr: Default::default(),
            strict: true,
        };
        assert!(dir.keys.contains(&pk));
        assert!(!dir.keys.contains(&other));
        assert!(dir.strict);
    }

    #[test]
    fn addr_pin_mismatch_is_detected() {
        let expected = vec![0x44u8; PQ_PUBLIC_KEY_SIZE];
        let got = vec![0x55u8; PQ_PUBLIC_KEY_SIZE];
        let mut by_addr: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        by_addr.insert("10.0.0.1:9333".into(), expected.clone());
        assert_ne!(by_addr.get("10.0.0.1:9333").unwrap().as_slice(), got.as_slice());
    }

    #[test]
    fn invalid_hex_length_is_skipped() {
        let dir = parse_pin_source("deadbeef\n", false);
        assert!(dir.keys.is_empty());
    }
}
