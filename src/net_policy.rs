//! Operational hardening policy for **public deployment**.
//!
//! Consensus constants (`MIN_DIFFICULTY`, fees, genesis) are compile-time and
//! identical on every honest node. This module covers *operator* knobs that
//! do not fork the chain: API auth, dial filters, P2P rate budgets, STARK
//! verify budgets, and CORS.
//!
//! Enable with `HASSAN_PUBLIC=1`. See `PUBLIC.md`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Parsed once at process start from the environment.
#[derive(Clone, Debug)]
pub struct NetPolicy {
    /// Public-mode profile: stricter dials, tighter rates, API token required
    /// for writes, STARK verify budget enforced.
    pub public_mode: bool,
    /// Bearer token for state-changing HTTP routes (`HASSAN_API_TOKEN`).
    pub api_token: Option<String>,
    /// When true, gossip dials reject RFC1918 / loopback (still allow `.onion`).
    pub strict_dials: bool,
    /// Per-peer message limit inside the rate window.
    pub peer_msg_limit: u32,
    /// Max full STARK verifies a single peer may trigger per window.
    pub stark_verifies_per_window: u32,
    /// Window for STARK verify budget.
    pub stark_window: Duration,
    /// CORS allowlist (`HASSAN_CORS_ORIGIN`, comma-separated). Empty = omit ACAO
    /// (same-origin / non-browser clients only). `"*"` is rejected in public mode.
    pub cors_origins: Vec<String>,
    /// Write-route requests per IP per minute (stricter than general GET budget).
    pub api_write_limit_per_window: u32,
}

impl NetPolicy {
    pub fn from_env() -> Self {
        let public_mode = env_flag("HASSAN_PUBLIC");
        let allow_unauth = env_flag("HASSAN_ALLOW_UNAUTH_WRITES");
        let mut api_token = std::env::var("HASSAN_API_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // Public lock: no open writes, no soft lab budgets, persistent token required.
        if public_mode {
            if allow_unauth {
                eprintln!(
                    "FATAL: HASSAN_PUBLIC=1 refuses HASSAN_ALLOW_UNAUTH_WRITES=1"
                );
                std::process::exit(1);
            }
            if env_flag("HASSAN_RELAX_NET") {
                eprintln!("FATAL: HASSAN_PUBLIC=1 refuses HASSAN_RELAX_NET=1");
                std::process::exit(1);
            }
            if env_flag("HASSAN_BOOTSTRAP_EASY") {
                eprintln!(
                    "FATAL: HASSAN_PUBLIC=1 refuses HASSAN_BOOTSTRAP_EASY=1 \
                     (would soft-fork peers on the hard PoW floor)"
                );
                std::process::exit(1);
            }
            if api_token.is_none() {
                eprintln!(
                    "FATAL: HASSAN_PUBLIC=1 requires an explicit HASSAN_API_TOKEN \
                     (openssl rand -hex 32). Ephemeral tokens are not allowed."
                );
                std::process::exit(1);
            }
        }

        // Local / non-public: generate an ephemeral write token when unset so
        // malware / CSRF cannot hit writes without reading process stderr.
        if api_token.is_none() && !allow_unauth {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let tok = hex::encode(bytes);
            eprintln!(
                "HASSAN_API_TOKEN unset — ephemeral write token for this process:\n  {tok}\n\
                 Export HASSAN_API_TOKEN to persist, or HASSAN_ALLOW_UNAUTH_WRITES=1 for open writes."
            );
            api_token = Some(tok);
        }
        let strict_dials = public_mode || env_flag("HASSAN_STRICT_DIALS");
        // Non-public defaults sit closer to public budgets; HASSAN_RELAX_NET=1
        // restores the older soft lab ceilings (blocked when public).
        let relax = !public_mode && env_flag("HASSAN_RELAX_NET");
        let (peer_msg_limit, stark_verifies_per_window, api_write_limit_per_window) =
            if public_mode {
                (2_000, 8, 30)
            } else if relax {
                (20_000, 64, 120)
            } else {
                (4_000, 16, 60)
            };
        let cors_origins = std::env::var("HASSAN_CORS_ORIGIN")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            public_mode,
            api_token,
            strict_dials,
            peer_msg_limit,
            stark_verifies_per_window,
            stark_window: Duration::from_secs(10),
            cors_origins,
            api_write_limit_per_window,
        }
    }

    /// Public mode refuses wildcard CORS (drive-by browser abuse).
    pub fn cors_header_value(&self) -> Option<String> {
        if self.cors_origins.is_empty() {
            return None;
        }
        if self.public_mode && self.cors_origins.iter().any(|o| o == "*") {
            return None;
        }
        // Single origin is the common case; multi-origin needs request Origin match.
        if self.cors_origins.len() == 1 {
            return Some(self.cors_origins[0].clone());
        }
        None
    }

    pub fn cors_allows(&self, origin: &str) -> bool {
        if self.cors_origins.is_empty() {
            return false;
        }
        if self.public_mode && self.cors_origins.iter().any(|o| o == "*") {
            return false;
        }
        self.cors_origins.iter().any(|o| o == "*" || o == origin)
    }

    /// Write routes need a Bearer token whenever one is configured (default:
    /// always, via env or ephemeral generation). Only open when the operator
    /// set `HASSAN_ALLOW_UNAUTH_WRITES=1` and left the token unset.
    pub fn writes_require_token(&self) -> bool {
        self.api_token.is_some()
    }

    pub fn token_ok(&self, provided: Option<&str>) -> bool {
        match (&self.api_token, provided) {
            (None, _) => true, // open writes explicitly allowed
            (Some(expected), Some(got)) => constant_time_eq(expected.as_bytes(), got.as_bytes()),
            (Some(_), None) => false,
        }
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Per-peer sliding window counting expensive STARK verifications.
#[derive(Debug)]
pub struct StarkVerifyBudget {
    window_start_ms: AtomicU64,
    count: AtomicU32,
    limit: u32,
    window_ms: u64,
}

impl StarkVerifyBudget {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            window_start_ms: AtomicU64::new(0),
            count: AtomicU32::new(0),
            limit,
            window_ms: window.as_millis() as u64,
        }
    }

    /// Returns true if another full verify is allowed (and consumes one slot).
    pub fn try_consume(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let start = self.window_start_ms.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= self.window_ms {
            self.window_start_ms.store(now, Ordering::Relaxed);
            self.count.store(1, Ordering::Relaxed);
            return true;
        }
        let prev = self.count.fetch_add(1, Ordering::Relaxed);
        prev < self.limit
    }
}

/// Shared ban set for remote socket IPs (inbound reconnect resistance).
#[derive(Default)]
pub struct IpBanList {
    inner: std::sync::Mutex<std::collections::HashMap<IpAddr, Instant>>,
    ttl: Duration,
}

impl IpBanList {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
            ttl,
        }
    }

    pub fn ban(&self, ip: IpAddr) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.insert(ip, Instant::now() + self.ttl);
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.retain(|_, until| *until > now);
        g.contains_key(&ip)
    }
}

/// Process-wide policy + IP bans (set once from `main`).
static POLICY: std::sync::OnceLock<NetPolicy> = std::sync::OnceLock::new();
static IP_BANS: std::sync::OnceLock<Arc<IpBanList>> = std::sync::OnceLock::new();

pub fn init(policy: NetPolicy) {
    let _ = POLICY.set(policy);
    let _ = IP_BANS.set(Arc::new(IpBanList::new(Duration::from_secs(3600))));
}

pub fn policy() -> NetPolicy {
    POLICY.get().cloned().unwrap_or_else(NetPolicy::from_env)
}

pub fn ip_bans() -> Arc<IpBanList> {
    IP_BANS
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(IpBanList::new(Duration::from_secs(3600))))
}

/// Public-mode / strict dial filter: block private + loopback IPv4/IPv6.
pub fn is_publicly_dialable(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.is_empty() || addr.len() > 256 {
        return false;
    }
    let Some((host, port_str)) = addr.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return false;
    };
    if port == 0 {
        return false;
    }
    let host = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if host.ends_with(".onion") {
        return host.len() == 62
            && host
                .trim_end_matches(".onion")
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        // Hostnames allowed only when not in strict mode is handled by caller;
        // here we accept DNS names (resolved later).
        return !host.is_empty() && host.len() <= 253 && !host.contains(' ');
    };
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified() && !v6.is_loopback() && !v6.is_unicast_link_local()
            // Unique-local (fc00::/7) — treat as private.
            && (v6.segments()[0] & 0xfe00) != 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_dial_blocks_rfc1918_and_metadata() {
        assert!(!is_publicly_dialable("10.0.0.1:9333"));
        assert!(!is_publicly_dialable("192.168.1.1:9333"));
        assert!(!is_publicly_dialable("127.0.0.1:9333"));
        assert!(!is_publicly_dialable("169.254.169.254:80"));
        assert!(is_publicly_dialable("203.0.113.10:9333"));
    }

    #[test]
    fn token_compare_is_length_safe() {
        let p = NetPolicy {
            public_mode: true,
            api_token: Some("secret".into()),
            strict_dials: true,
            peer_msg_limit: 1,
            stark_verifies_per_window: 1,
            stark_window: Duration::from_secs(1),
            cors_origins: vec![],
            api_write_limit_per_window: 1,
        };
        assert!(p.token_ok(Some("secret")));
        assert!(!p.token_ok(Some("secre")));
        assert!(!p.token_ok(None));
    }
}
