//! Transparent title registry & escrow overlay.
//!
//! Every titled asset (vehicle, loan note, stake position, generic property)
//! has a public **chain of title**: who it was issued to, every subsequent
//! owner, and who holds it now. Registry escrow holds account-overlay value
//! (and optionally a title). Peer UTXO value uses BDPE vaults (`crate::bdpe`);
//! this module must not allow unilateral seller self-pay.

use crate::{abs_sig, hash_to_address, Account, Block, ChainState, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Asset class — what the title represents in commercial terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetClass {
    /// Motor vehicle / equipment title.
    Vehicle,
    /// Loan / credit note (who owes whom).
    Loan,
    /// Staked / pledged position.
    Stake,
    /// Real property claim.
    RealEstate,
    /// Catch-all titled property.
    Generic,
}

impl AssetClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetClass::Vehicle => "vehicle",
            AssetClass::Loan => "loan",
            AssetClass::Stake => "stake",
            AssetClass::RealEstate => "real_estate",
            AssetClass::Generic => "generic",
        }
    }
}

/// One entry in the public chain of title (ownership history).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TitleEvent {
    pub timestamp: u64,
    pub block_height: u64,
    pub settlement_id: String,
    pub event: String,
    pub from: Option<String>,
    pub to: String,
    pub memo: String,
}

/// A titled asset with full ownership history — transparent as glass.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TitleDeed {
    pub title_id: Hash,
    pub asset_class: AssetClass,
    pub description: String,
    pub current_owner: String,
    pub issued_at: u64,
    pub history: Vec<TitleEvent>,
    /// Optional active escrow locking this title.
    pub escrow_id: Option<Hash>,
    /// Optional lien / pledge holder (e.g. lender on a vehicle loan).
    pub lienholder: Option<String>,
}

impl TitleDeed {
    pub fn title_id_hex(&self) -> String {
        hex::encode(self.title_id)
    }
}

/// Escrow status — clearing-house lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowStatus {
    /// Opened; awaiting funding.
    Open,
    /// Buyer has deposited the agreed amount.
    Funded,
    /// Funds (and optional title) released to seller.
    Released,
    /// Funds returned to buyer.
    Refunded,
    /// Frozen pending arbiter decision.
    Disputed,
}

/// Registry escrow: account-overlay value held until conditions clear.
///
/// Phase 1 authorization (v30+):
/// - Release → **buyer only** (seller cannot self-pay; arbiter alone cannot move funds)
/// - Refund (funded) → **seller only**; Open cancel → buyer
/// - TimeoutClaim → buyer after `timeout_blue` when funded
///
/// Arbiter is recorded for Phase-2 cosigner awards; unilateral arbiter spend is
/// rejected (honeypot closed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowAccount {
    pub escrow_id: Hash,
    pub buyer: String,
    pub seller: String,
    pub arbiter: Option<String>,
    pub amount: u128,
    pub funded: u128,
    pub status: EscrowStatus,
    pub title_id: Option<Hash>,
    pub opened_at: u64,
    pub memo: String,
    /// Absolute blue-score after which buyer may timeout-claim (`0` = none).
    #[serde(default, alias = "timeout_height")]
    pub timeout_blue: u64,
}

impl EscrowAccount {
    pub fn escrow_id_hex(&self) -> String {
        hex::encode(self.escrow_id)
    }
}

/// On-block registry operations — all public, all signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RegistryOp {
    /// Issue a new title to an owner (originator must sign).
    IssueTitle {
        from_pubkey: Vec<u8>,
        owner: String,
        asset_class: AssetClass,
        description: String,
        title_seed: Hash,
        nonce: u64,
        chain_id: u64,
        signature: Vec<u8>,
    },
    /// Transfer title (sale / assignment). Current owner signs.
    TransferTitle {
        from_pubkey: Vec<u8>,
        title_id: Hash,
        to: String,
        memo: String,
        nonce: u64,
        chain_id: u64,
        signature: Vec<u8>,
    },
    /// Open an escrow between buyer and seller.
    OpenEscrow {
        from_pubkey: Vec<u8>,
        buyer: String,
        seller: String,
        arbiter: Option<String>,
        amount: u128,
        title_id: Option<Hash>,
        memo: String,
        escrow_seed: Hash,
        /// Buyer may timeout-claim at/after this blue-score (`0` = disabled).
        #[serde(alias = "timeout_height")]
        timeout_blue: u64,
        nonce: u64,
        chain_id: u64,
        signature: Vec<u8>,
    },
    /// Buyer funds the escrow from their transparent balance.
    FundEscrow {
        from_pubkey: Vec<u8>,
        escrow_id: Hash,
        amount: u128,
        nonce: u64,
        chain_id: u64,
        signature: Vec<u8>,
    },
    /// Release escrow to seller — **buyer only** (arbiter cannot act alone).
    ReleaseEscrow {
        from_pubkey: Vec<u8>,
        escrow_id: Hash,
        nonce: u64,
        chain_id: u64,
        signature: Vec<u8>,
    },
    /// Refund escrow to buyer.
    RefundEscrow {
        from_pubkey: Vec<u8>,
        escrow_id: Hash,
        nonce: u64,
        chain_id: u64,
        signature: Vec<u8>,
    },
    /// Buyer timeout-claim after `timeout_blue` when escrow is funded.
    TimeoutClaimEscrow {
        from_pubkey: Vec<u8>,
        escrow_id: Hash,
        nonce: u64,
        chain_id: u64,
        signature: Vec<u8>,
    },
}

impl RegistryOp {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            RegistryOp::IssueTitle {
                owner,
                asset_class,
                description,
                title_seed,
                nonce,
                chain_id,
                ..
            } => {
                buf.extend_from_slice(b"issue-title-v1");
                buf.extend_from_slice(owner.as_bytes());
                buf.extend_from_slice(asset_class.as_str().as_bytes());
                buf.extend_from_slice(description.as_bytes());
                buf.extend_from_slice(title_seed.as_slice());
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&chain_id.to_le_bytes());
            }
            RegistryOp::TransferTitle {
                title_id,
                to,
                memo,
                nonce,
                chain_id,
                ..
            } => {
                buf.extend_from_slice(b"transfer-title-v1");
                buf.extend_from_slice(title_id.as_slice());
                buf.extend_from_slice(to.as_bytes());
                buf.extend_from_slice(memo.as_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&chain_id.to_le_bytes());
            }
            RegistryOp::OpenEscrow {
                buyer,
                seller,
                arbiter,
                amount,
                title_id,
                memo,
                escrow_seed,
                timeout_blue,
                nonce,
                chain_id,
                ..
            } => {
                buf.extend_from_slice(b"open-escrow-v3");
                buf.extend_from_slice(buyer.as_bytes());
                buf.extend_from_slice(seller.as_bytes());
                if let Some(a) = arbiter {
                    buf.extend_from_slice(a.as_bytes());
                }
                buf.extend_from_slice(&amount.to_le_bytes());
                if let Some(t) = title_id {
                    buf.extend_from_slice(t.as_slice());
                }
                buf.extend_from_slice(memo.as_bytes());
                buf.extend_from_slice(escrow_seed.as_slice());
                buf.extend_from_slice(&timeout_blue.to_le_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&chain_id.to_le_bytes());
            }
            RegistryOp::FundEscrow {
                escrow_id,
                amount,
                nonce,
                chain_id,
                ..
            } => {
                buf.extend_from_slice(b"fund-escrow-v1");
                buf.extend_from_slice(escrow_id.as_slice());
                buf.extend_from_slice(&amount.to_le_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&chain_id.to_le_bytes());
            }
            RegistryOp::ReleaseEscrow {
                escrow_id,
                nonce,
                chain_id,
                ..
            }
            | RegistryOp::RefundEscrow {
                escrow_id,
                nonce,
                chain_id,
                ..
            }
            | RegistryOp::TimeoutClaimEscrow {
                escrow_id,
                nonce,
                chain_id,
                ..
            } => {
                let tag = match self {
                    RegistryOp::ReleaseEscrow { .. } => b"release-escrow-v1" as &[u8],
                    RegistryOp::TimeoutClaimEscrow { .. } => b"timeout-claim-escrow-v1",
                    _ => b"refund-escrow-v1",
                };
                buf.extend_from_slice(tag);
                buf.extend_from_slice(escrow_id.as_slice());
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.extend_from_slice(&chain_id.to_le_bytes());
            }
        }
        buf
    }

    pub fn sign(&mut self, secret_key: &[u8]) -> Result<(), String> {
        let sig = abs_sig::sign_pq512(b"registry-op", &self.signing_bytes(), secret_key)?;
        match self {
            RegistryOp::IssueTitle { signature, .. }
            | RegistryOp::TransferTitle { signature, .. }
            | RegistryOp::OpenEscrow { signature, .. }
            | RegistryOp::FundEscrow { signature, .. }
            | RegistryOp::ReleaseEscrow { signature, .. }
            | RegistryOp::RefundEscrow { signature, .. }
            | RegistryOp::TimeoutClaimEscrow { signature, .. } => *signature = sig,
        }
        Ok(())
    }

    pub fn verify(&self) -> bool {
        let (pk, sig) = match self {
            RegistryOp::IssueTitle {
                from_pubkey,
                signature,
                ..
            }
            | RegistryOp::TransferTitle {
                from_pubkey,
                signature,
                ..
            }
            | RegistryOp::OpenEscrow {
                from_pubkey,
                signature,
                ..
            }
            | RegistryOp::FundEscrow {
                from_pubkey,
                signature,
                ..
            }
            | RegistryOp::ReleaseEscrow {
                from_pubkey,
                signature,
                ..
            }
            | RegistryOp::RefundEscrow {
                from_pubkey,
                signature,
                ..
            }
            | RegistryOp::TimeoutClaimEscrow {
                from_pubkey,
                signature,
                ..
            } => (from_pubkey, signature),
        };
        abs_sig::verify_pq512(b"registry-op", &self.signing_bytes(), pk, sig)
    }

    pub fn op_hash(&self) -> Hash {
        Hash(crate::abs_sig::digest512(
            b"hassan-registry-op-v1",
            &bincode::serialize(self).unwrap_or_default(),
        ))
    }

    pub fn signer_address(&self) -> String {
        match self {
            RegistryOp::IssueTitle { from_pubkey, .. }
            | RegistryOp::TransferTitle { from_pubkey, .. }
            | RegistryOp::OpenEscrow { from_pubkey, .. }
            | RegistryOp::FundEscrow { from_pubkey, .. }
            | RegistryOp::ReleaseEscrow { from_pubkey, .. }
            | RegistryOp::RefundEscrow { from_pubkey, .. }
            | RegistryOp::TimeoutClaimEscrow { from_pubkey, .. } => hash_to_address(from_pubkey),
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            RegistryOp::IssueTitle { chain_id, .. }
            | RegistryOp::TransferTitle { chain_id, .. }
            | RegistryOp::OpenEscrow { chain_id, .. }
            | RegistryOp::FundEscrow { chain_id, .. }
            | RegistryOp::ReleaseEscrow { chain_id, .. }
            | RegistryOp::RefundEscrow { chain_id, .. }
            | RegistryOp::TimeoutClaimEscrow { chain_id, .. } => *chain_id,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            RegistryOp::IssueTitle { nonce, .. }
            | RegistryOp::TransferTitle { nonce, .. }
            | RegistryOp::OpenEscrow { nonce, .. }
            | RegistryOp::FundEscrow { nonce, .. }
            | RegistryOp::ReleaseEscrow { nonce, .. }
            | RegistryOp::RefundEscrow { nonce, .. }
            | RegistryOp::TimeoutClaimEscrow { nonce, .. } => *nonce,
        }
    }
}

/// Derive a deterministic title id from issuer + seed (512-bit).
pub fn derive_title_id(issuer: &str, seed: &Hash) -> Hash {
    let mut buf = Vec::new();
    buf.extend_from_slice(issuer.as_bytes());
    buf.extend_from_slice(seed.as_slice());
    Hash(crate::abs_sig::digest512(b"hassan-title-id-v1", &buf))
}

pub fn derive_escrow_id(opener: &str, seed: &Hash) -> Hash {
    let mut buf = Vec::new();
    buf.extend_from_slice(opener.as_bytes());
    buf.extend_from_slice(seed.as_slice());
    Hash(crate::abs_sig::digest512(b"hassan-escrow-id-v1", &buf))
}

/// In-memory registry state (persisted inside `Ledger` / `ChainState`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RegistryState {
    pub titles: HashMap<Hash, TitleDeed>,
    pub escrows: HashMap<Hash, EscrowAccount>,
}

impl RegistryState {
    pub fn apply_op(
        &mut self,
        accounts: &mut HashMap<String, Account>,
        op: &RegistryOp,
        block: &Block,
        settlement_id_hex: &str,
        blue_score: u64,
    ) -> Result<(), String> {
        if !op.verify() {
            return Err("Invalid registry signature".into());
        }
        let signer = op.signer_address();
        // Advance signer nonce like transparent transfers.
        {
            let acct = accounts.entry(signer.clone()).or_insert(Account {
                balance: 0,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            });
            if op.nonce() != acct.nonce {
                return Err("Stale or future nonce on registry op".into());
            }
            acct.nonce = acct.nonce.saturating_add(1);
        }

        match op {
            RegistryOp::IssueTitle {
                owner,
                asset_class,
                description,
                title_seed,
                ..
            } => {
                let title_id = derive_title_id(&signer, title_seed);
                if self.titles.contains_key(&title_id) {
                    return Err("Title already issued".into());
                }
                let deed = TitleDeed {
                    title_id,
                    asset_class: asset_class.clone(),
                    description: description.clone(),
                    current_owner: owner.clone(),
                    issued_at: block.timestamp,
                    history: vec![TitleEvent {
                        timestamp: block.timestamp,
                        block_height: block.height,
                        settlement_id: settlement_id_hex.to_string(),
                        event: "issued".into(),
                        from: None,
                        to: owner.clone(),
                        memo: "original issuance".into(),
                    }],
                    escrow_id: None,
                    lienholder: None,
                };
                self.titles.insert(title_id, deed);
            }
            RegistryOp::TransferTitle {
                title_id, to, memo, ..
            } => {
                let deed = self.titles.get_mut(title_id).ok_or("Title not found")?;
                if deed.current_owner != signer {
                    return Err("Only the current owner can transfer title".into());
                }
                if deed.escrow_id.is_some() {
                    return Err("Title is locked in escrow".into());
                }
                let from = deed.current_owner.clone();
                deed.current_owner = to.clone();
                deed.history.push(TitleEvent {
                    timestamp: block.timestamp,
                    block_height: block.height,
                    settlement_id: settlement_id_hex.to_string(),
                    event: "transferred".into(),
                    from: Some(from),
                    to: to.clone(),
                    memo: memo.clone(),
                });
            }
            RegistryOp::OpenEscrow {
                buyer,
                seller,
                arbiter,
                amount,
                title_id,
                memo,
                escrow_seed,
                timeout_blue,
                ..
            } => {
                if *amount == 0 {
                    return Err("Escrow amount must be positive".into());
                }
                if let Some(tid) = title_id {
                    let deed = self
                        .titles
                        .get_mut(tid)
                        .ok_or("Title not found for escrow")?;
                    if deed.current_owner != *seller {
                        return Err("Escrow title must be owned by seller".into());
                    }
                    if deed.escrow_id.is_some() {
                        return Err("Title already in escrow".into());
                    }
                }
                let escrow_id = derive_escrow_id(&signer, escrow_seed);
                if self.escrows.contains_key(&escrow_id) {
                    return Err("Escrow already exists".into());
                }
                if let Some(tid) = title_id {
                    if let Some(deed) = self.titles.get_mut(tid) {
                        deed.escrow_id = Some(escrow_id);
                    }
                }
                self.escrows.insert(
                    escrow_id,
                    EscrowAccount {
                        escrow_id,
                        buyer: buyer.clone(),
                        seller: seller.clone(),
                        arbiter: arbiter.clone(),
                        amount: *amount,
                        funded: 0,
                        status: EscrowStatus::Open,
                        title_id: *title_id,
                        opened_at: block.timestamp,
                        memo: memo.clone(),
                        timeout_blue: *timeout_blue,
                    },
                );
            }
            RegistryOp::FundEscrow {
                escrow_id, amount, ..
            } => {
                let esc = self.escrows.get_mut(escrow_id).ok_or("Escrow not found")?;
                if signer != esc.buyer {
                    return Err("Only the buyer can fund escrow".into());
                }
                if esc.status != EscrowStatus::Open && esc.status != EscrowStatus::Funded {
                    return Err("Escrow is not open for funding".into());
                }
                let buyer_acct = accounts.get_mut(&signer).ok_or("Buyer account missing")?;
                if buyer_acct.balance < *amount {
                    return Err("Insufficient balance to fund escrow".into());
                }
                buyer_acct.balance -= *amount;
                esc.funded = esc.funded.saturating_add(*amount);
                if esc.funded >= esc.amount {
                    esc.status = EscrowStatus::Funded;
                }
            }
            RegistryOp::ReleaseEscrow { escrow_id, .. } => {
                let esc = self.escrows.get_mut(escrow_id).ok_or("Escrow not found")?;
                // Buyer only — seller self-pay and unilateral arbiter both rejected.
                if signer != esc.buyer {
                    return Err(
                        "Not authorized to release escrow (buyer must sign; arbiter cannot act alone)"
                            .into(),
                    );
                }
                if esc.status != EscrowStatus::Funded {
                    return Err("Escrow must be fully funded before release".into());
                }
                let pay = esc.funded;
                let seller = esc.seller.clone();
                let title_id = esc.title_id;
                let buyer = esc.buyer.clone();
                esc.funded = 0;
                esc.status = EscrowStatus::Released;
                let seller_acct = accounts.entry(seller.clone()).or_insert(Account {
                    balance: 0,
                    nonce: 0,
                    last_spend_blue: 0,
                    code_hash: None,
                    storage_root: Hash::ZERO,
                });
                seller_acct.balance = seller_acct.balance.saturating_add(pay);
                if let Some(tid) = title_id {
                    if let Some(deed) = self.titles.get_mut(&tid) {
                        deed.escrow_id = None;
                        let from = deed.current_owner.clone();
                        deed.current_owner = buyer.clone();
                        deed.history.push(TitleEvent {
                            timestamp: block.timestamp,
                            block_height: block.height,
                            settlement_id: settlement_id_hex.to_string(),
                            event: "escrow_released".into(),
                            from: Some(from),
                            to: buyer,
                            memo: "title cleared through escrow".into(),
                        });
                    }
                }
            }
            RegistryOp::RefundEscrow { escrow_id, .. } => {
                let esc = self.escrows.get_mut(escrow_id).ok_or("Escrow not found")?;
                let authorized = match esc.status {
                    EscrowStatus::Open => signer == esc.buyer,
                    EscrowStatus::Funded => signer == esc.seller,
                    _ => false,
                };
                if !authorized {
                    return Err(
                        "Not authorized to refund escrow (Open→buyer; Funded→seller; no unilateral arbiter)"
                            .into(),
                    );
                }
                if esc.status == EscrowStatus::Released || esc.status == EscrowStatus::Refunded {
                    return Err("Escrow already closed".into());
                }
                let refund = esc.funded;
                let buyer = esc.buyer.clone();
                let title_id = esc.title_id;
                esc.funded = 0;
                esc.status = EscrowStatus::Refunded;
                if refund > 0 {
                    let buyer_acct = accounts.entry(buyer).or_insert(Account {
                        balance: 0,
                        nonce: 0,
                        last_spend_blue: 0,
                        code_hash: None,
                        storage_root: Hash::ZERO,
                    });
                    buyer_acct.balance = buyer_acct.balance.saturating_add(refund);
                }
                if let Some(tid) = title_id {
                    if let Some(deed) = self.titles.get_mut(&tid) {
                        deed.escrow_id = None;
                    }
                }
            }
            RegistryOp::TimeoutClaimEscrow { escrow_id, .. } => {
                let esc = self.escrows.get_mut(escrow_id).ok_or("Escrow not found")?;
                if signer != esc.buyer {
                    return Err("Only the buyer can timeout-claim escrow".into());
                }
                if esc.status != EscrowStatus::Funded {
                    return Err("Escrow must be funded for timeout claim".into());
                }
                if esc.timeout_blue == 0 {
                    return Err("Escrow has no timeout path".into());
                }
                if blue_score < esc.timeout_blue {
                    return Err(format!(
                        "Timeout not reached: blue_score {blue_score} < {}",
                        esc.timeout_blue
                    ));
                }
                let refund = esc.funded;
                let buyer = esc.buyer.clone();
                let title_id = esc.title_id;
                esc.funded = 0;
                esc.status = EscrowStatus::Refunded;
                if refund > 0 {
                    let buyer_acct = accounts.entry(buyer).or_insert(Account {
                        balance: 0,
                        nonce: 0,
                        last_spend_blue: 0,
                        code_hash: None,
                        storage_root: Hash::ZERO,
                    });
                    buyer_acct.balance = buyer_acct.balance.saturating_add(refund);
                }
                if let Some(tid) = title_id {
                    if let Some(deed) = self.titles.get_mut(&tid) {
                        deed.escrow_id = None;
                    }
                }
            }
        }
        Ok(())
    }
}

impl ChainState {
    /// Validate registry op form (signature + chain id) without mutating state.
    pub fn validate_registry_ops(&self, block: &Block) -> Result<(), String> {
        for op in &block.registry_ops {
            if op.chain_id() != self.chain_id {
                return Err("Wrong chain_id on registry op".into());
            }
            if !op.verify() {
                return Err("Invalid registry signature".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_keypair, hash_to_address, ChainState, HASH_SIZE};

    #[test]
    fn issue_and_transfer_title_records_full_chain_of_title() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let owner = hash_to_address(&pk);
        let mut issue = RegistryOp::IssueTitle {
            from_pubkey: pk.clone(),
            owner: owner.clone(),
            asset_class: AssetClass::Vehicle,
            description: "2024 Sedan VIN-TEST".into(),
            title_seed: Hash([7u8; HASH_SIZE]),
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        issue.sign(&sk).unwrap();
        state.admit_registry_to_mempool(issue.clone()).unwrap();

        // Apply via ledger helper (simulate inclusion).
        let block = crate::genesis_block();
        let settlement = "settlement-test";
        state
            .registry
            .apply_op(&mut state.accounts, &issue, &block, settlement, 0)
            .unwrap();
        assert_eq!(state.registry.titles.len(), 1);
        let title_id = derive_title_id(&owner, &Hash([7u8; HASH_SIZE]));
        let deed = state.registry.titles.get(&title_id).unwrap();
        assert_eq!(deed.current_owner, owner);
        assert_eq!(deed.history.len(), 1);

        let (sk2, pk2) = generate_keypair();
        let buyer = hash_to_address(&pk2);
        // Advance issuer nonce already done by apply_op; transfer from owner.
        let mut xfer = RegistryOp::TransferTitle {
            from_pubkey: pk.clone(),
            title_id,
            to: buyer.clone(),
            memo: "sale".into(),
            nonce: 1,
            chain_id: state.chain_id,
            signature: vec![],
        };
        xfer.sign(&sk).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &xfer, &block, settlement, 0)
            .unwrap();
        let deed = state.registry.titles.get(&title_id).unwrap();
        assert_eq!(deed.current_owner, buyer);
        assert_eq!(deed.history.len(), 2);
        assert_eq!(deed.history[1].from.as_deref(), Some(owner.as_str()));
        let _ = (sk2, pk2);
    }

    #[test]
    fn escrow_fund_and_release_transfers_title_and_cash() {
        let mut state = ChainState::new();
        let (sk_seller, pk_seller) = generate_keypair();
        let (sk_buyer, pk_buyer) = generate_keypair();
        let seller = hash_to_address(&pk_seller);
        let buyer = hash_to_address(&pk_buyer);

        state.accounts.insert(
            buyer.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );

        let mut issue = RegistryOp::IssueTitle {
            from_pubkey: pk_seller.clone(),
            owner: seller.clone(),
            asset_class: AssetClass::Loan,
            description: "Note #1".into(),
            title_seed: Hash([9u8; HASH_SIZE]),
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        issue.sign(&sk_seller).unwrap();
        let block = crate::genesis_block();
        state
            .registry
            .apply_op(&mut state.accounts, &issue, &block, "s", 0)
            .unwrap();
        let title_id = derive_title_id(&seller, &Hash([9u8; HASH_SIZE]));

        let mut open = RegistryOp::OpenEscrow {
            from_pubkey: pk_seller.clone(),
            buyer: buyer.clone(),
            seller: seller.clone(),
            arbiter: None,
            amount: 1000,
            title_id: Some(title_id),
            memo: "purchase".into(),
            escrow_seed: Hash([3u8; HASH_SIZE]),
            timeout_blue: 0,
            nonce: 1,
            chain_id: state.chain_id,
            signature: vec![],
        };
        open.sign(&sk_seller).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &open, &block, "s", 0)
            .unwrap();
        let escrow_id = derive_escrow_id(&seller, &Hash([3u8; HASH_SIZE]));

        let mut fund = RegistryOp::FundEscrow {
            from_pubkey: pk_buyer.clone(),
            escrow_id,
            amount: 1000,
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        fund.sign(&sk_buyer).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &fund, &block, "s", 0)
            .unwrap();
        assert_eq!(state.accounts.get(&buyer).unwrap().balance, 1_000_000 - 1000);

        let mut release = RegistryOp::ReleaseEscrow {
            from_pubkey: pk_buyer.clone(),
            escrow_id,
            nonce: 1,
            chain_id: state.chain_id,
            signature: vec![],
        };
        release.sign(&sk_buyer).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &release, &block, "s", 0)
            .unwrap();
        assert_eq!(state.accounts.get(&seller).unwrap().balance, 1000);
        assert_eq!(
            state.registry.titles.get(&title_id).unwrap().current_owner,
            buyer
        );
    }

    #[test]
    fn seller_cannot_unilaterally_release_escrow() {
        let mut state = ChainState::new();
        let (sk_seller, pk_seller) = generate_keypair();
        let (sk_buyer, pk_buyer) = generate_keypair();
        let seller = hash_to_address(&pk_seller);
        let buyer = hash_to_address(&pk_buyer);
        state.accounts.insert(
            buyer.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let block = crate::genesis_block();
        let mut open = RegistryOp::OpenEscrow {
            from_pubkey: pk_seller.clone(),
            buyer: buyer.clone(),
            seller: seller.clone(),
            arbiter: None,
            amount: 500,
            title_id: None,
            memo: "cash".into(),
            escrow_seed: Hash([4u8; HASH_SIZE]),
            timeout_blue: 10,
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        open.sign(&sk_seller).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &open, &block, "s", 0)
            .unwrap();
        let escrow_id = derive_escrow_id(&seller, &Hash([4u8; HASH_SIZE]));
        let mut fund = RegistryOp::FundEscrow {
            from_pubkey: pk_buyer.clone(),
            escrow_id,
            amount: 500,
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        fund.sign(&sk_buyer).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &fund, &block, "s", 0)
            .unwrap();

        let mut seller_release = RegistryOp::ReleaseEscrow {
            from_pubkey: pk_seller.clone(),
            escrow_id,
            nonce: 1,
            chain_id: state.chain_id,
            signature: vec![],
        };
        seller_release.sign(&sk_seller).unwrap();
        let err = state
            .registry
            .apply_op(&mut state.accounts, &seller_release, &block, "s", 0)
            .unwrap_err();
        assert!(
            err.contains("self-pay") || err.contains("Not authorized"),
            "unexpected: {err}"
        );

        // Buyer timeout-claim before blue_score fails; at/after timeout_blue succeeds.
        let mut early = RegistryOp::TimeoutClaimEscrow {
            from_pubkey: pk_buyer.clone(),
            escrow_id,
            nonce: 1,
            chain_id: state.chain_id,
            signature: vec![],
        };
        early.sign(&sk_buyer).unwrap();
        assert!(state
            .registry
            .apply_op(&mut state.accounts, &early, &block, "s", 0)
            .unwrap_err()
            .contains("Timeout"));

        let mut claim = RegistryOp::TimeoutClaimEscrow {
            from_pubkey: pk_buyer.clone(),
            escrow_id,
            nonce: 2,
            chain_id: state.chain_id,
            signature: vec![],
        };
        claim.sign(&sk_buyer).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &claim, &block, "s", 10)
            .unwrap();
        assert_eq!(
            state.registry.escrows.get(&escrow_id).unwrap().status,
            EscrowStatus::Refunded
        );
    }

    #[test]
    fn arbiter_alone_cannot_release_or_refund_funded_escrow() {
        let mut state = ChainState::new();
        let (sk_seller, pk_seller) = generate_keypair();
        let (sk_buyer, pk_buyer) = generate_keypair();
        let (sk_arb, pk_arb) = generate_keypair();
        let seller = hash_to_address(&pk_seller);
        let buyer = hash_to_address(&pk_buyer);
        let arbiter = hash_to_address(&pk_arb);
        state.accounts.insert(
            buyer.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let block = crate::genesis_block();
        let mut open = RegistryOp::OpenEscrow {
            from_pubkey: pk_seller.clone(),
            buyer: buyer.clone(),
            seller: seller.clone(),
            arbiter: Some(arbiter),
            amount: 500,
            title_id: None,
            memo: "arb".into(),
            escrow_seed: Hash([9u8; HASH_SIZE]),
            timeout_blue: 0,
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        open.sign(&sk_seller).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &open, &block, "s", 0)
            .unwrap();
        let escrow_id = derive_escrow_id(&seller, &Hash([9u8; HASH_SIZE]));
        let mut fund = RegistryOp::FundEscrow {
            from_pubkey: pk_buyer.clone(),
            escrow_id,
            amount: 500,
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        fund.sign(&sk_buyer).unwrap();
        state
            .registry
            .apply_op(&mut state.accounts, &fund, &block, "s", 0)
            .unwrap();

        let mut arb_release = RegistryOp::ReleaseEscrow {
            from_pubkey: pk_arb.clone(),
            escrow_id,
            nonce: 0,
            chain_id: state.chain_id,
            signature: vec![],
        };
        arb_release.sign(&sk_arb).unwrap();
        let err = state
            .registry
            .apply_op(&mut state.accounts, &arb_release, &block, "s", 0)
            .unwrap_err();
        assert!(
            err.contains("arbiter") || err.contains("Not authorized"),
            "unexpected: {err}"
        );

        let mut arb_refund = RegistryOp::RefundEscrow {
            from_pubkey: pk_arb.clone(),
            escrow_id,
            nonce: 1,
            chain_id: state.chain_id,
            signature: vec![],
        };
        arb_refund.sign(&sk_arb).unwrap();
        let err2 = state
            .registry
            .apply_op(&mut state.accounts, &arb_refund, &block, "s", 0)
            .unwrap_err();
        assert!(
            err2.contains("arbiter") || err2.contains("Not authorized"),
            "unexpected: {err2}"
        );
    }
}
