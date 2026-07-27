//! TUEP escrow LAW — Bank-Decoupled Payment Escrow (BDPE) Phase 1.
//!
//! Pure types + clocks + allowed payout vectors + typed events + state machine.
//! No chain adapters, no admin unlock key, no status-only "Locked".
//!
//! Phase 1: cooperative 2-of-2 + hard timeout reclaim. Arbiter / dispute are
//! Phase 2 stubs (transitions rejected).

use serde::{Deserialize, Serialize};

/// Protocol tag absorbed into escrow id derivation.
pub const BDPE_DOMAIN: &[u8] = b"tuep-bdpe-v1";

/// Escrow lifecycle (on-chain meaning only after [`EscrowPhase::Funded`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowPhase {
    /// Local terms agreed; no value locked yet.
    Offered,
    /// Value locked by vault predicate / consensus.
    Funded,
    /// Coop 2-of-2 paid the seller vector.
    Settled,
    /// Coop 2-of-2 returned funds to the buyer.
    Refunded,
    /// Buyer reclaimed after absolute timeout.
    TimedOut,
    /// Phase 2 stub — not reachable in Phase 1.
    Disputed,
}

impl EscrowPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            EscrowPhase::Offered => "offered",
            EscrowPhase::Funded => "funded",
            EscrowPhase::Settled => "settled",
            EscrowPhase::Refunded => "refunded",
            EscrowPhase::TimedOut => "timed_out",
            EscrowPhase::Disputed => "disputed",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            EscrowPhase::Settled | EscrowPhase::Refunded | EscrowPhase::TimedOut
        )
    }

    pub fn is_locked(self) -> bool {
        self == EscrowPhase::Funded
    }
}

/// Party roles in a BDPE deal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Party {
    Buyer,
    Seller,
    /// Phase 2 — not used for Phase 1 authorization.
    Arbiter,
}

/// Absolute clock: vault unlocks for buyer reclaim when media blue ≥ this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Clock {
    AbsoluteBlue { unlock_blue: u64 },
}

impl Clock {
    pub fn absolute_blue(unlock_blue: u64) -> Self {
        Clock::AbsoluteBlue { unlock_blue }
    }

    pub fn unlock_blue(self) -> u64 {
        match self {
            Clock::AbsoluteBlue { unlock_blue } => unlock_blue,
        }
    }

    pub fn reached(self, media_blue: u64) -> bool {
        media_blue >= self.unlock_blue()
    }
}

/// Allowed Phase 1 payout destinations (exact vectors only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutVector {
    /// Full vault value (minus fee) to seller.
    ToSeller,
    /// Full vault value (minus fee) to buyer (coop refund or timeout).
    ToBuyer,
}

impl PayoutVector {
    pub fn as_str(self) -> &'static str {
        match self {
            PayoutVector::ToSeller => "to_seller",
            PayoutVector::ToBuyer => "to_buyer",
        }
    }

    /// Phase 1 allow-list. Anything else is rejected.
    pub fn phase1_allowed(self) -> bool {
        matches!(self, PayoutVector::ToSeller | PayoutVector::ToBuyer)
    }
}

/// Typed escrow events — never a free-form `action: String`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EscrowEvent {
    Opened {
        escrow_id: String,
        buyer: String,
        seller: String,
        amount: u128,
        timeout_blue: u64,
        memo: String,
    },
    Funded {
        escrow_id: String,
        outpoint_txid: String,
        outpoint_vout: u32,
        amount: u128,
        media_blue: u64,
    },
    CoopSettled {
        escrow_id: String,
        payout: PayoutVector,
        to: String,
        amount: u128,
        spend_txid: String,
    },
    CoopRefunded {
        escrow_id: String,
        payout: PayoutVector,
        to: String,
        amount: u128,
        spend_txid: String,
    },
    TimeoutClaimed {
        escrow_id: String,
        payout: PayoutVector,
        to: String,
        amount: u128,
        spend_txid: String,
        media_blue: u64,
    },
    /// Phase 2 stub event — state machine rejects transitions into Disputed.
    DisputeOpened {
        escrow_id: String,
        by: Party,
    },
}

impl EscrowEvent {
    pub fn escrow_id(&self) -> &str {
        match self {
            EscrowEvent::Opened { escrow_id, .. }
            | EscrowEvent::Funded { escrow_id, .. }
            | EscrowEvent::CoopSettled { escrow_id, .. }
            | EscrowEvent::CoopRefunded { escrow_id, .. }
            | EscrowEvent::TimeoutClaimed { escrow_id, .. }
            | EscrowEvent::DisputeOpened { escrow_id, .. } => escrow_id.as_str(),
        }
    }
}

/// Immutable deal terms (LAW).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowTerms {
    pub buyer: String,
    pub seller: String,
    pub amount: u128,
    pub clock: Clock,
    pub memo: String,
    /// Deterministic seed (hex) contributed at open.
    pub seed_hex: String,
}

impl EscrowTerms {
    pub fn timeout_blue(&self) -> u64 {
        self.clock.unlock_blue()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.buyer.is_empty() || self.seller.is_empty() {
            return Err("buyer and seller required".into());
        }
        if self.buyer == self.seller {
            return Err("buyer and seller must differ".into());
        }
        if self.amount == 0 {
            return Err("amount must be positive".into());
        }
        if self.seed_hex.is_empty() {
            return Err("seed required".into());
        }
        Ok(())
    }

    /// Derive a stable escrow id from opener + terms (Blake3-512 hex).
    pub fn derive_id(&self, opener: &str) -> String {
        let mut h = blake3::Hasher::new();
        h.update(BDPE_DOMAIN);
        h.update(opener.as_bytes());
        h.update(self.buyer.as_bytes());
        h.update(self.seller.as_bytes());
        h.update(&self.amount.to_le_bytes());
        h.update(&self.timeout_blue().to_le_bytes());
        h.update(self.memo.as_bytes());
        h.update(self.seed_hex.as_bytes());
        let mut out = [0u8; 64];
        h.finalize_xof().fill(&mut out);
        hex::encode(out)
    }
}

/// On-chain vault reference after funding (UTXO outpoint).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultOutpoint {
    pub txid_hex: String,
    pub vout: u32,
}

/// Live escrow record + history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowRecord {
    pub escrow_id: String,
    pub opener: String,
    pub terms: EscrowTerms,
    pub phase: EscrowPhase,
    pub vault: Option<VaultOutpoint>,
    pub history: Vec<EscrowEvent>,
}

impl EscrowRecord {
    pub fn open(opener: impl Into<String>, terms: EscrowTerms) -> Result<Self, String> {
        terms.validate()?;
        let opener = opener.into();
        let escrow_id = terms.derive_id(&opener);
        let ev = EscrowEvent::Opened {
            escrow_id: escrow_id.clone(),
            buyer: terms.buyer.clone(),
            seller: terms.seller.clone(),
            amount: terms.amount,
            timeout_blue: terms.timeout_blue(),
            memo: terms.memo.clone(),
        };
        Ok(Self {
            escrow_id,
            opener,
            terms,
            phase: EscrowPhase::Offered,
            vault: None,
            history: vec![ev],
        })
    }

    pub fn apply(&mut self, event: EscrowEvent) -> Result<(), String> {
        if event.escrow_id() != self.escrow_id {
            return Err("event escrow_id mismatch".into());
        }
        let next = transition(self.phase, &event, &self.terms)?;
        match &event {
            EscrowEvent::Funded {
                outpoint_txid,
                outpoint_vout,
                amount,
                ..
            } => {
                if *amount != self.terms.amount {
                    return Err("fund amount must equal terms.amount".into());
                }
                self.vault = Some(VaultOutpoint {
                    txid_hex: outpoint_txid.clone(),
                    vout: *outpoint_vout,
                });
            }
            EscrowEvent::CoopSettled { payout, to, .. }
            | EscrowEvent::CoopRefunded { payout, to, .. }
            | EscrowEvent::TimeoutClaimed { payout, to, .. } => {
                assert_payout(*payout, to, &self.terms)?;
            }
            EscrowEvent::DisputeOpened { .. } => {
                return Err("Phase 1: dispute not enabled".into());
            }
            EscrowEvent::Opened { .. } => {
                return Err("already opened".into());
            }
        }
        self.phase = next;
        self.history.push(event);
        Ok(())
    }
}

fn assert_payout(payout: PayoutVector, to: &str, terms: &EscrowTerms) -> Result<(), String> {
    if !payout.phase1_allowed() {
        return Err("payout vector not allowed in Phase 1".into());
    }
    match payout {
        PayoutVector::ToSeller => {
            if to != terms.seller {
                return Err("ToSeller payout must target seller address".into());
            }
        }
        PayoutVector::ToBuyer => {
            if to != terms.buyer {
                return Err("ToBuyer payout must target buyer address".into());
            }
        }
    }
    Ok(())
}

/// Pure state-machine transition table.
pub fn transition(
    phase: EscrowPhase,
    event: &EscrowEvent,
    terms: &EscrowTerms,
) -> Result<EscrowPhase, String> {
    if let EscrowEvent::DisputeOpened { .. } = event {
        return Err("Phase 1: dispute not enabled".into());
    }
    if phase.is_terminal() {
        return Err(format!("escrow already closed ({})", phase.as_str()));
    }
    match (phase, event) {
        (EscrowPhase::Offered, EscrowEvent::Funded { amount, .. }) => {
            if *amount != terms.amount {
                return Err("fund amount mismatch".into());
            }
            Ok(EscrowPhase::Funded)
        }
        (EscrowPhase::Funded, EscrowEvent::CoopSettled { payout, to, .. }) => {
            if *payout != PayoutVector::ToSeller {
                return Err("coop settle requires ToSeller vector".into());
            }
            if to != &terms.seller {
                return Err("settle must pay seller".into());
            }
            Ok(EscrowPhase::Settled)
        }
        (EscrowPhase::Funded, EscrowEvent::CoopRefunded { payout, to, .. }) => {
            if *payout != PayoutVector::ToBuyer {
                return Err("coop refund requires ToBuyer vector".into());
            }
            if to != &terms.buyer {
                return Err("refund must pay buyer".into());
            }
            Ok(EscrowPhase::Refunded)
        }
        (
            EscrowPhase::Funded,
            EscrowEvent::TimeoutClaimed {
                payout,
                to,
                media_blue,
                ..
            },
        ) => {
            if *payout != PayoutVector::ToBuyer {
                return Err("timeout claim requires ToBuyer vector".into());
            }
            if to != &terms.buyer {
                return Err("timeout claim must pay buyer".into());
            }
            if !terms.clock.reached(*media_blue) {
                return Err("timeout clock not reached".into());
            }
            Ok(EscrowPhase::TimedOut)
        }
        (p, e) => Err(format!(
            "illegal transition from {} via {:?}",
            p.as_str(),
            std::mem::discriminant(e)
        )),
    }
}

/// Authorization check for a spend path (LAW-level; chain adapter enforces crypto).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendPath {
    /// Buyer + seller both authorize (2-of-2).
    Coop2of2 { payout: PayoutVector },
    /// Buyer alone after absolute timeout.
    TimeoutBuyer,
}

impl SpendPath {
    pub fn validate(self, terms: &EscrowTerms, media_blue: u64) -> Result<(), String> {
        match self {
            SpendPath::Coop2of2 { payout } => {
                if !payout.phase1_allowed() {
                    return Err("payout not allowed".into());
                }
                Ok(())
            }
            SpendPath::TimeoutBuyer => {
                if !terms.clock.reached(media_blue) {
                    return Err("timeout not reached".into());
                }
                Ok(())
            }
        }
    }
}

/// Reject seller-alone settle at the LAW layer (no such SpendPath exists).
pub fn reject_unilateral_seller_settle() -> Result<(), String> {
    Err("unilateral seller settle forbidden — need Coop2of2 or timeout buyer reclaim".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_terms() -> EscrowTerms {
        EscrowTerms {
            buyer: "hsn1buyer".into(),
            seller: "hsn1seller".into(),
            amount: 1_000_000,
            clock: Clock::absolute_blue(100),
            memo: "probe".into(),
            seed_hex: "aa".into(),
        }
    }

    #[test]
    fn open_fund_coop_settle() {
        let mut rec = EscrowRecord::open("hsn1buyer", sample_terms()).unwrap();
        assert_eq!(rec.phase, EscrowPhase::Offered);
        rec.apply(EscrowEvent::Funded {
            escrow_id: rec.escrow_id.clone(),
            outpoint_txid: "00".repeat(64),
            outpoint_vout: 0,
            amount: 1_000_000,
            media_blue: 10,
        })
        .unwrap();
        assert!(rec.phase.is_locked());
        rec.apply(EscrowEvent::CoopSettled {
            escrow_id: rec.escrow_id.clone(),
            payout: PayoutVector::ToSeller,
            to: "hsn1seller".into(),
            amount: 1_000_000,
            spend_txid: "11".repeat(64),
        })
        .unwrap();
        assert_eq!(rec.phase, EscrowPhase::Settled);
    }

    #[test]
    fn timeout_requires_clock() {
        let mut rec = EscrowRecord::open("hsn1buyer", sample_terms()).unwrap();
        rec.apply(EscrowEvent::Funded {
            escrow_id: rec.escrow_id.clone(),
            outpoint_txid: "00".repeat(64),
            outpoint_vout: 0,
            amount: 1_000_000,
            media_blue: 1,
        })
        .unwrap();
        let early = rec.apply(EscrowEvent::TimeoutClaimed {
            escrow_id: rec.escrow_id.clone(),
            payout: PayoutVector::ToBuyer,
            to: "hsn1buyer".into(),
            amount: 1_000_000,
            spend_txid: "22".repeat(64),
            media_blue: 99,
        });
        assert!(early.unwrap_err().contains("timeout"));
        rec.apply(EscrowEvent::TimeoutClaimed {
            escrow_id: rec.escrow_id.clone(),
            payout: PayoutVector::ToBuyer,
            to: "hsn1buyer".into(),
            amount: 1_000_000,
            spend_txid: "22".repeat(64),
            media_blue: 100,
        })
        .unwrap();
        assert_eq!(rec.phase, EscrowPhase::TimedOut);
    }

    #[test]
    fn reject_settle_to_wrong_party() {
        let mut rec = EscrowRecord::open("hsn1buyer", sample_terms()).unwrap();
        rec.apply(EscrowEvent::Funded {
            escrow_id: rec.escrow_id.clone(),
            outpoint_txid: "00".repeat(64),
            outpoint_vout: 0,
            amount: 1_000_000,
            media_blue: 1,
        })
        .unwrap();
        let err = rec
            .apply(EscrowEvent::CoopSettled {
                escrow_id: rec.escrow_id.clone(),
                payout: PayoutVector::ToSeller,
                to: "hsn1buyer".into(), // wrong
                amount: 1_000_000,
                spend_txid: "33".repeat(64),
            })
            .unwrap_err();
        assert!(err.contains("seller") || err.contains("settle"));
    }

    #[test]
    fn dispute_stub_rejected() {
        let mut rec = EscrowRecord::open("hsn1buyer", sample_terms()).unwrap();
        rec.apply(EscrowEvent::Funded {
            escrow_id: rec.escrow_id.clone(),
            outpoint_txid: "00".repeat(64),
            outpoint_vout: 0,
            amount: 1_000_000,
            media_blue: 1,
        })
        .unwrap();
        assert!(rec
            .apply(EscrowEvent::DisputeOpened {
                escrow_id: rec.escrow_id.clone(),
                by: Party::Buyer,
            })
            .unwrap_err()
            .contains("Phase 1"));
    }

    #[test]
    fn unilateral_seller_path_does_not_exist() {
        assert!(reject_unilateral_seller_settle().is_err());
        let terms = sample_terms();
        SpendPath::TimeoutBuyer.validate(&terms, 50).unwrap_err();
        SpendPath::Coop2of2 {
            payout: PayoutVector::ToSeller,
        }
        .validate(&terms, 0)
        .unwrap();
    }
}
