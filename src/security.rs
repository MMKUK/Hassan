//! Real DoS protections for the API server: per-IP rate limiting with
//! temporary bans, a request-size cap, and shared input-validation helpers.
//!
//! This replaces what SECURITY.md previously (and incorrectly) claimed was
//! "completed in code" — none of it existed anywhere in the codebase. It
//! does now, and it's wired into `main.rs`'s request path.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Requests allowed per IP per rolling window.
pub const MAX_REQUESTS_PER_WINDOW: u32 = 120;
pub const WINDOW: Duration = Duration::from_secs(60);
/// Sustained abuse (this many requests inside one window) triggers a
/// temporary ban rather than just a rejected request.
pub const BAN_THRESHOLD: u32 = MAX_REQUESTS_PER_WINDOW * 3;
pub const BAN_DURATION: Duration = Duration::from_secs(300);
/// Hard cap on request size (headers + body). Requests larger than this are
/// rejected before the body is fully read.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Drop idle IP entries after this long with no traffic (bounds memory).
pub const IP_ENTRY_TTL: Duration = Duration::from_secs(600);

struct IpState {
    window_start: Instant,
    last_seen: Instant,
    count: u32,
    banned_until: Option<Instant>,
}

/// Per-IP sliding-window rate limiter with temporary bans for sustained abuse.
pub struct RateLimiter {
    state: Mutex<HashMap<IpAddr, IpState>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `Ok(())` if the request from `ip` should proceed, or
    /// `Err(reason)` if it should be rejected (rate-limited or banned).
    pub fn check(&self, ip: IpAddr) -> Result<(), String> {
        let mut map = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        // TTL prune idle entries so the map cannot grow without bound.
        map.retain(|_, s| {
            now.duration_since(s.last_seen) < IP_ENTRY_TTL
                || s.banned_until.map(|u| now < u).unwrap_or(false)
        });

        let entry = map.entry(ip).or_insert_with(|| IpState {
            window_start: now,
            last_seen: now,
            count: 0,
            banned_until: None,
        });
        entry.last_seen = now;

        if let Some(until) = entry.banned_until {
            if now < until {
                return Err(format!(
                    "IP temporarily banned ({}s remaining)",
                    (until - now).as_secs()
                ));
            }
            entry.banned_until = None;
            entry.count = 0;
            entry.window_start = now;
        }

        if now.duration_since(entry.window_start) >= WINDOW {
            entry.window_start = now;
            entry.count = 0;
        }

        entry.count += 1;

        if entry.count > BAN_THRESHOLD {
            entry.banned_until = Some(now + BAN_DURATION);
            return Err("Rate limit exceeded repeatedly; IP temporarily banned".into());
        }

        if entry.count > MAX_REQUESTS_PER_WINDOW {
            return Err(format!(
                "Rate limit exceeded: max {} requests / {}s",
                MAX_REQUESTS_PER_WINDOW,
                WINDOW.as_secs()
            ));
        }

        Ok(())
    }

    /// Number of tracked IPs — exposed for tests/metrics, not load-bearing.
    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// `hsn:<128 hex chars>` or bech32m `hsn1…` — matches wallet address formats.
pub fn is_valid_address(address: &str) -> bool {
    crate::address::is_valid_hassan_address(address)
}

/// A bare 64-byte (512-bit) hash as hex, with an optional `0x`.
pub fn is_valid_hash_hex(s: &str) -> bool {
    let s = s.strip_prefix("0x").unwrap_or(s);
    s.len() == crate::HASH_SIZE * 2 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Rejects zero and anything above total supply — a transfer can't
/// legitimately be either.
pub fn is_valid_amount(amount: u128, total_supply: u128) -> bool {
    amount > 0 && amount <= total_supply
}

/// Blue-score / height-like counters used in locktimes and API paths.
pub fn is_valid_blue_score(n: u64) -> bool {
    n < u64::MAX / 2
}

/// Nonce must be finite; account nonces are dense u64 counters.
pub fn is_valid_nonce(n: u64) -> bool {
    n < u64::MAX - 1_000
}

/// Fee must clear the protocol floor and stay below total supply.
pub fn is_valid_fee(fee: u128, total_supply: u128) -> bool {
    fee >= crate::MIN_TX_FEE && fee <= total_supply
}

/// Hex pubkey of expected PQ size.
pub fn is_valid_pubkey_hex(s: &str) -> bool {
    let s = s.strip_prefix("0x").unwrap_or(s);
    s.len() == crate::PQ_PUBLIC_KEY_SIZE * 2 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_within_the_window_limit_are_allowed() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            assert!(limiter.check(ip).is_ok());
        }
    }

    #[test]
    fn exceeding_the_window_limit_is_rejected() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.2".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            limiter.check(ip).unwrap();
        }
        assert!(limiter.check(ip).is_err());
    }

    #[test]
    fn sustained_abuse_triggers_a_ban_that_outlasts_a_single_rejection() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.3".parse().unwrap();
        for _ in 0..=BAN_THRESHOLD {
            let _ = limiter.check(ip);
        }
        assert!(limiter.check(ip).unwrap_err().contains("banned"));
    }

    #[test]
    fn distinct_ips_are_tracked_independently() {
        let limiter = RateLimiter::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.check(a).is_ok());
        assert!(limiter.check(b).is_ok());
        assert_eq!(limiter.tracked_ips(), 2);
    }

    #[test]
    fn address_validation_rejects_malformed_input() {
        assert!(is_valid_address(&format!("hsn:{}", "ab".repeat(64))));
        assert!(is_valid_address(&crate::address::encode_hash(&crate::Hash([0xab; 64]))));
        assert!(!is_valid_address(&format!("ghaz:{}", "ab".repeat(64)))); // legacy prefix no longer accepted
        assert!(!is_valid_address("not-an-address"));
        assert!(!is_valid_address("hsn:tooshort"));
        assert!(!is_valid_address(&format!("nogaz:{}", "ab".repeat(64))));
        assert!(!is_valid_address(&format!("hsn:{}", "zz".repeat(64)))); // non-hex
        assert!(!is_valid_address(&format!("hsn:{}", "ab".repeat(32)))); // old 256-bit length
    }

    #[test]
    fn hash_hex_validation_rejects_malformed_input() {
        assert!(is_valid_hash_hex(&"ab".repeat(64)));
        assert!(is_valid_hash_hex(&format!("0x{}", "ab".repeat(64))));
        assert!(!is_valid_hash_hex("short"));
        assert!(!is_valid_hash_hex(&"zz".repeat(64)));
        assert!(!is_valid_hash_hex(&"ab".repeat(32))); // old 256-bit length
    }

    #[test]
    fn amount_validation_rejects_zero_and_overflow() {
        assert!(!is_valid_amount(0, 1000));
        assert!(is_valid_amount(1, 1000));
        assert!(is_valid_amount(1000, 1000));
        assert!(!is_valid_amount(1001, 1000));
    }

    #[test]
    fn helper_validators_cover_fee_nonce_pubkey() {
        assert!(is_valid_blue_score(0));
        assert!(!is_valid_blue_score(u64::MAX));
        assert!(is_valid_nonce(0));
        assert!(is_valid_fee(crate::MIN_TX_FEE, crate::MAX_SUPPLY));
        assert!(!is_valid_fee(0, crate::MAX_SUPPLY));
        assert!(!is_valid_pubkey_hex("ab"));
        assert!(is_valid_pubkey_hex(&"ab".repeat(crate::PQ_PUBLIC_KEY_SIZE)));
    }
}
