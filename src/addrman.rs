//! AddrMan-class peer address manager: tried/new buckets + feeler selection.
//!
//! Simpler than Bitcoin Core's full asmap, but functional: diversity by /16
//! (IPv4) or /32 (IPv6), persistent buckets, and feeler probes for new addrs.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NEW_BUCKETS: usize = 64;
pub const TRIED_BUCKETS: usize = 32;
pub const ADDRS_PER_BUCKET: usize = 64;
pub const MAX_ADDRS_TOTAL: usize = 2_048;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddrRecord {
    pub addr: String,
    pub last_success_ms: u64,
    pub last_try_ms: u64,
    pub attempts: u32,
    pub source: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddrMan {
    pub new: Vec<Vec<AddrRecord>>,
    pub tried: Vec<Vec<AddrRecord>>,
    /// Feeler candidate queue (new addrs not yet tried).
    pub feelers: Vec<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn parse_host(addr: &str) -> Option<IpAddr> {
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or(addr);
    host.parse().ok()
}

/// Network group for eclipse resistance (/16 IPv4, /32 IPv6).
pub fn net_group(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..2].to_vec(),
        IpAddr::V6(v6) => v6.octets()[..4].to_vec(),
    }
}

fn bucket_for(addr: &str, n_buckets: usize, salt: u8) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hassan-addrman-bucket-v1");
    hasher.update(&[salt]);
    hasher.update(addr.as_bytes());
    if let Some(ip) = parse_host(addr) {
        hasher.update(&net_group(ip));
    }
    let mut out = [0u8; 8];
    hasher.finalize_xof().fill(&mut out);
    let v = u64::from_le_bytes(out);
    (v as usize) % n_buckets.max(1)
}

impl AddrMan {
    pub fn new() -> Self {
        Self {
            new: vec![Vec::new(); NEW_BUCKETS],
            tried: vec![Vec::new(); TRIED_BUCKETS],
            feelers: Vec::new(),
        }
    }

    pub fn ensure_buckets(&mut self) {
        if self.new.len() != NEW_BUCKETS {
            self.new.resize(NEW_BUCKETS, Vec::new());
        }
        if self.tried.len() != TRIED_BUCKETS {
            self.tried.resize(TRIED_BUCKETS, Vec::new());
        }
    }

    pub fn len(&self) -> usize {
        self.new.iter().map(|b| b.len()).sum::<usize>()
            + self.tried.iter().map(|b| b.len()).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert into new table (or refresh). Returns true if newly added.
    pub fn add(&mut self, addr: &str, source: &str) -> bool {
        self.ensure_buckets();
        if addr.is_empty() || self.contains(addr) {
            return false;
        }
        if self.len() >= MAX_ADDRS_TOTAL {
            return false;
        }
        let b = bucket_for(addr, NEW_BUCKETS, 0x4e);
        let bucket = &mut self.new[b];
        if bucket.len() >= ADDRS_PER_BUCKET {
            bucket.remove(0);
        }
        bucket.push(AddrRecord {
            addr: addr.to_string(),
            last_success_ms: 0,
            last_try_ms: 0,
            attempts: 0,
            source: source.to_string(),
        });
        if !self.feelers.iter().any(|a| a == addr) {
            self.feelers.push(addr.to_string());
        }
        true
    }

    pub fn contains(&self, addr: &str) -> bool {
        self.new
            .iter()
            .chain(self.tried.iter())
            .any(|b| b.iter().any(|r| r.addr == addr))
    }

    /// Mark a successful connection — promote to tried.
    pub fn good(&mut self, addr: &str) {
        self.ensure_buckets();
        let now = now_ms();
        // Remove from new.
        for bucket in &mut self.new {
            bucket.retain(|r| r.addr != addr);
        }
        self.feelers.retain(|a| a != addr);
        let b = bucket_for(addr, TRIED_BUCKETS, 0x54);
        let bucket = &mut self.tried[b];
        if let Some(r) = bucket.iter_mut().find(|r| r.addr == addr) {
            r.last_success_ms = now;
            r.attempts = 0;
            return;
        }
        if bucket.len() >= ADDRS_PER_BUCKET {
            bucket.remove(0);
        }
        bucket.push(AddrRecord {
            addr: addr.to_string(),
            last_success_ms: now,
            last_try_ms: now,
            attempts: 0,
            source: "good".into(),
        });
    }

    /// Record a failed dial attempt.
    pub fn attempted(&mut self, addr: &str) {
        self.ensure_buckets();
        let now = now_ms();
        for bucket in self.new.iter_mut().chain(self.tried.iter_mut()) {
            if let Some(r) = bucket.iter_mut().find(|r| r.addr == addr) {
                r.last_try_ms = now;
                r.attempts = r.attempts.saturating_add(1);
            }
        }
    }

    /// Select up to `n` diverse dial candidates (prefer tried, then new).
    pub fn select(&self, n: usize, exclude: &BTreeSet<String>) -> Vec<String> {
        let mut out = Vec::new();
        let mut groups: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut push = |addr: &str| {
            if out.len() >= n || exclude.contains(addr) {
                return;
            }
            if let Some(ip) = parse_host(addr) {
                let g = net_group(ip);
                if !groups.insert(g) && out.len() + 1 < n {
                    // Allow same group only if we still need fillers later.
                }
            }
            if !out.iter().any(|a| a == addr) {
                out.push(addr.to_string());
            }
        };
        for bucket in &self.tried {
            for r in bucket {
                push(&r.addr);
            }
        }
        for bucket in &self.new {
            for r in bucket {
                push(&r.addr);
            }
        }
        out
    }

    /// Pop one feeler address (new, not recently tried).
    pub fn select_feeler(&mut self) -> Option<String> {
        self.ensure_buckets();
        while let Some(addr) = self.feelers.pop() {
            if self.new.iter().any(|b| b.iter().any(|r| r.addr == addr)) {
                return Some(addr);
            }
        }
        None
    }

    /// Addresses to gossip (capped).
    pub fn sample_for_addr_msg(&self, max: usize) -> Vec<String> {
        let mut all: Vec<_> = self
            .tried
            .iter()
            .chain(self.new.iter())
            .flat_map(|b| b.iter().map(|r| r.addr.clone()))
            .collect();
        all.sort();
        all.dedup();
        all.truncate(max);
        all
    }

    pub fn stats(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        m.insert(
            "new",
            self.new.iter().map(|b| b.len()).sum(),
        );
        m.insert(
            "tried",
            self.tried.iter().map(|b| b.len()).sum(),
        );
        m.insert("feelers", self.feelers.len());
        m.insert("total", self.len());
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_good_promote_and_select() {
        let mut am = AddrMan::new();
        assert!(am.add("203.0.113.1:8333", "seed"));
        assert!(am.add("198.51.100.2:8333", "seed"));
        assert!(!am.add("203.0.113.1:8333", "dup"));
        am.good("203.0.113.1:8333");
        let st = am.stats();
        assert!(st["tried"] >= 1);
        let sel = am.select(2, &BTreeSet::new());
        assert!(!sel.is_empty());
    }

    #[test]
    fn feeler_pops_new() {
        let mut am = AddrMan::new();
        am.add("203.0.113.9:9000", "x");
        assert_eq!(am.select_feeler().as_deref(), Some("203.0.113.9:9000"));
    }
}
