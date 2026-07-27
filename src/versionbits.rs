//! Soft-upgrade signaling (BIP9/BIP8-class) over blue-score windows.
//!
//! Machinery is present; the deployment table is empty until a real rule fork
//! is wired to `DeploymentState::Active`. Do not treat API "Active" status as
//! a live consensus upgrade while [`DEPLOYMENTS`] is empty.

use crate::Hash;
use serde::{Deserialize, Serialize};

/// Bits available for soft deployments (low 8 of block `version`).
pub const VERSIONBITS_TOP_MASK: u32 = 0xE0_00_00_00;
pub const VERSIONBITS_TOP_BITS: u32 = 0x20_00_00_00;
pub const VERSIONBITS_NUM_BITS: u8 = 8;

/// Blue-score length of one signaling window.
pub const SIGNAL_WINDOW: u64 = 1_000;
/// Threshold: ≥ this many blocks in a window must signal to lock-in.
pub const SIGNAL_THRESHOLD: u64 = 750;
/// Windows after lock-in before the rule is active.
pub const LOCKIN_MIN_WINDOWS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentState {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub name: &'static str,
    pub bit: u8,
    /// Blue score at which signaling may begin.
    pub start_blue: u64,
    /// Blue score after which Failed if never LockedIn.
    pub timeout_blue: u64,
}

/// Built-in deployments. Empty until a consensus rule is actually gated on
/// `DeploymentState::Active` (observational scaffolding must not look live).
pub const DEPLOYMENTS: &[Deployment] = &[];

/// Compute miner-advertised version with TOP bits + optional signals.
pub fn miner_version(signals: &[u8]) -> u32 {
    let mut v = VERSIONBITS_TOP_BITS;
    for bit in signals {
        if *bit < VERSIONBITS_NUM_BITS {
            v |= 1u32 << bit;
        }
    }
    v
}

/// Whether `version` signals deployment bit `bit`.
pub fn signals(version: u32, bit: u8) -> bool {
    if bit >= VERSIONBITS_NUM_BITS {
        return false;
    }
    (version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS && (version & (1u32 << bit)) != 0
}

/// Track per-deployment state along a selected-chain walk of versions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VersionBitsState {
    /// Parallel to [`DEPLOYMENTS`].
    pub states: Vec<DeploymentState>,
    pub window_counts: Vec<u64>,
    pub window_start_blue: u64,
}

impl VersionBitsState {
    pub fn new() -> Self {
        Self {
            states: vec![DeploymentState::Defined; DEPLOYMENTS.len()],
            window_counts: vec![0; DEPLOYMENTS.len()],
            window_start_blue: 0,
        }
    }

    /// Feed one selected-chain block's `(blue_score, version)`.
    pub fn observe(&mut self, blue_score: u64, version: u32) {
        if self.states.is_empty() {
            *self = Self::new();
        }
        let window = blue_score / SIGNAL_WINDOW;
        let cur_window = self.window_start_blue / SIGNAL_WINDOW;
        if window > cur_window {
            // Close previous window → possible lock-in / fail.
            for (i, dep) in DEPLOYMENTS.iter().enumerate() {
                match self.states[i] {
                    DeploymentState::Started => {
                        if self.window_counts[i] >= SIGNAL_THRESHOLD {
                            self.states[i] = DeploymentState::LockedIn;
                        } else if blue_score >= dep.timeout_blue {
                            self.states[i] = DeploymentState::Failed;
                        }
                    }
                    DeploymentState::LockedIn => {
                        // After LOCKIN_MIN_WINDOWS of LockedIn, activate.
                        self.states[i] = DeploymentState::Active;
                    }
                    _ => {}
                }
                self.window_counts[i] = 0;
            }
            self.window_start_blue = window * SIGNAL_WINDOW;
        }

        for (i, dep) in DEPLOYMENTS.iter().enumerate() {
            if self.states[i] == DeploymentState::Defined && blue_score >= dep.start_blue {
                self.states[i] = DeploymentState::Started;
            }
            if matches!(
                self.states[i],
                DeploymentState::Started | DeploymentState::LockedIn
            ) && signals(version, dep.bit)
            {
                self.window_counts[i] = self.window_counts[i].saturating_add(1);
            }
            if self.states[i] == DeploymentState::Started && blue_score >= dep.timeout_blue {
                self.states[i] = DeploymentState::Failed;
            }
        }
    }

    pub fn is_active(&self, name: &str) -> bool {
        DEPLOYMENTS
            .iter()
            .enumerate()
            .find(|(_, d)| d.name == name)
            .map(|(i, _)| self.states.get(i) == Some(&DeploymentState::Active))
            .unwrap_or(false)
    }

    pub fn status_json(&self) -> serde_json::Value {
        let items: Vec<_> = DEPLOYMENTS
            .iter()
            .enumerate()
            .map(|(i, d)| {
                serde_json::json!({
                    "name": d.name,
                    "bit": d.bit,
                    "state": format!("{:?}", self.states.get(i).copied().unwrap_or(DeploymentState::Defined)),
                    "window_signals": self.window_counts.get(i).copied().unwrap_or(0),
                })
            })
            .collect();
        serde_json::json!({
            "window": SIGNAL_WINDOW,
            "threshold": SIGNAL_THRESHOLD,
            "deployments": items,
        })
    }
}

/// Digest of deployment table (for status / assume-valid notes).
pub fn deployments_id() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hassan-versionbits-v21");
    for d in DEPLOYMENTS {
        hasher.update(d.name.as_bytes());
        hasher.update(&[d.bit]);
        hasher.update(&d.start_blue.to_le_bytes());
    }
    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    Hash(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_require_top_bits() {
        assert!(!signals(1 << 0, 0));
        assert!(signals(VERSIONBITS_TOP_BITS | 1, 0));
        assert!(!signals(VERSIONBITS_TOP_BITS | 1, 1));
    }

    #[test]
    fn lock_in_after_threshold() {
        // Deployments table is empty until a real rule fork ships; machinery
        // still tracks an empty state without panicking.
        let mut st = VersionBitsState::new();
        assert!(DEPLOYMENTS.is_empty());
        assert!(st.states.is_empty());
        for i in 0..(SIGNAL_WINDOW * 2) {
            st.observe(i, miner_version(&[0]));
        }
        assert!(!st.is_active("package_relay"));
        let j = st.status_json();
        assert_eq!(j["deployments"].as_array().unwrap().len(), 0);
    }
}
