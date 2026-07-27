//! Optional pinned bootstrap digests for IBD (assume-valid class).
//!
//! When `HASSAN_ASSUME_VALID=<64-byte-hex>` is set, a pruning-point / tip hash
//! matching the pin may skip deep historical STARK re-validation after the
//! multilevel pruning proof verifies. Empty / unset = no pin (full verify).
//!
//! Release builds may also ship a compile-time [`RELEASE_ASSUME_VALID`] pin
//! (empty by default until a release tags one).
//!
//! **What is skipped:** expensive winterfell STARK verify for the pinned hash
//! itself, and for strict ancestors of an already-imported pin. PoW, birth
//! certificate, merkle/state roots, and body rules still run.
//! **What is never skipped:** validation of blocks at/after the live tip that
//! are not under the pin.

use crate::Hash;
use std::sync::OnceLock;

/// Optional hardcoded release pin (empty = disabled). Operators can still
/// override / set via `HASSAN_ASSUME_VALID`.
pub const RELEASE_ASSUME_VALID: &[u8] = b"";

static PIN: OnceLock<Option<Hash>> = OnceLock::new();

/// Load the optional assume-valid hash from the environment (once), falling
/// back to [`RELEASE_ASSUME_VALID`] when set at compile time.
pub fn pinned_digest() -> Option<Hash> {
    PIN.get_or_init(|| {
        if let Ok(raw) = std::env::var("HASSAN_ASSUME_VALID") {
            let raw = raw.trim();
            if !raw.is_empty() {
                let Ok(bytes) = hex::decode(raw) else {
                    eprintln!("HASSAN_ASSUME_VALID: invalid hex — ignoring pin");
                    return None;
                };
                return match Hash::try_from(bytes.as_slice()) {
                    Ok(h) => Some(h),
                    Err(_) => {
                        eprintln!(
                            "HASSAN_ASSUME_VALID: need {} hex bytes — ignoring pin",
                            64 * 2
                        );
                        None
                    }
                };
            }
        }
        if RELEASE_ASSUME_VALID.is_empty() {
            None
        } else {
            Hash::try_from(RELEASE_ASSUME_VALID).ok()
        }
    })
    .clone()
}

/// True when `h` matches the configured pin (if any).
pub fn is_pinned(h: &Hash) -> bool {
    pinned_digest().map(|p| p == *h).unwrap_or(false)
}

/// Whether winterfell STARK verify may be skipped for `block_hash`.
///
/// `pin_is_ancestor`: caller reports whether `block_hash` is a strict ancestor
/// of the already-imported pin (reachability query against local DAG).
pub fn may_skip_stark_verify(block_hash: &Hash, pin_is_ancestor: impl FnOnce(&Hash) -> bool) -> bool {
    let Some(pin) = pinned_digest() else {
        return false;
    };
    if *block_hash == pin {
        return true;
    }
    pin_is_ancestor(&pin)
}

/// Log when a verified pruning point matches the assume-valid pin.
pub fn note_pruning_point_engaged(pp: &Hash) {
    if is_pinned(pp) {
        eprintln!(
            "assume_valid: pruning point {} matches pin — historical STARK verify may be skipped for pin ancestors; body floor active",
            &hex::encode(pp)[..16]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_pin_means_not_pinned() {
        // Do not mutate process env in parallel tests — just exercise API.
        let _ = pinned_digest();
        assert!(!is_pinned(&Hash::ZERO) || pinned_digest() == Some(Hash::ZERO));
    }

    #[test]
    fn release_pin_constant_is_empty_by_default() {
        assert!(RELEASE_ASSUME_VALID.is_empty());
    }

    #[test]
    fn may_skip_requires_pin() {
        // With default empty pin, never skip.
        if pinned_digest().is_none() {
            assert!(!may_skip_stark_verify(&Hash::ZERO, |_| true));
        }
    }
}
