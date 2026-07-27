//! Economic Entity model — supply-chain / forensic-accounting framing of a
//! block and its transfers, on top of Hassan's existing consensus data.
//!
//! Every block is treated as a full economic instrument rather than a bare
//! data container: `E = (H, T, P, C, L, F)` — Header, Transactions,
//! Provenance, Custody, Lineage, Finality. This module adds **no new
//! consensus state**; every field below is derived, read-only, from data
//! that already exists in [`ChainState`] (the header, GHOSTDAG data, the
//! [`crate::issuance`] module, and account balances). It exists to expose
//! that data through one coherent economic vocabulary instead of ad-hoc API
//! fields.
//!
//! [`CostBasis`] is the one deliberate exception: on-chain data alone cannot
//! know a miner's real electricity price, hardware amortization schedule, or
//! cost of capital, so it is an **illustrative estimate** driven by
//! configurable assumption constants (see `genesis::economics`), never an
//! audited fact. Every `CostBasis` carries `is_estimate: true` for exactly
//! this reason — treat it like a mining-profitability calculator, not a
//! financial statement.
//!
//! Custodian roles are limited to ones that actually exist in Hassan's
//! architecture today (issuer, validator, archive custodian, beneficial
//! owner). Institutional-finance roles like "Exchange" or "Clearing House"
//! describe market structure this single-issuer PoW chain doesn't have yet,
//! so they're intentionally left unmodeled rather than faked.

use crate::{address_hash, hash512, now_ms, Block, ChainState, Hash, TransparentTx};
use serde::Serialize;

/// A role a party plays with respect to a block, restricted to roles that
/// exist in Hassan's current code (see module docs).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "role")]
pub enum Custodian {
    /// The miner who found the block and issued its Birth Certificate.
    PrimaryIssuer { address: Option<String> },
    /// Every full node re-derives GHOSTDAG coloring and re-verifies the Birth
    /// Certificate for every block it accepts. No separate reward exists for
    /// this today, but it is a real, load-bearing custodial role.
    Validator { description: &'static str },
    /// A node retaining full history (started with `HASSAN_ARCHIVAL=1`)
    /// instead of pruning it, so it can serve cold-start sync / pruning
    /// proofs to new peers.
    ArchiveCustodian { is_local_node_archival: bool },
    /// Current holder of record of the block's issuance (its subsidy).
    /// Coins are fungible once spent, so this is the *recipient of record*,
    /// not a guarantee those exact coins are still untouched.
    BeneficialOwner {
        address: Option<String>,
        current_balance: String,
    },
}

/// Immutable origin document for a block — a certificate of origin.
#[derive(Clone, Debug, Serialize)]
pub struct ProvenanceRecord {
    pub settlement_id: String,
    pub instrument_type: &'static str,
    pub issuing_authority: Option<String>,
    pub jurisdiction: String,
    pub issuance_signature: String,
    pub issuance_verified: bool,
    pub issued_at_ms: u64,
}

/// Full record of every economic agent that has handled the block, mirroring
/// institutional custody chains.
#[derive(Clone, Debug, Serialize)]
pub struct CustodyChain {
    pub primary_issuer: Custodian,
    pub validator: Custodian,
    pub archive_custodian: Custodian,
    pub beneficial_owner: Custodian,
}

/// Ancestors, siblings ("economic siblings" — parallel blocks GHOSTDAG keeps
/// instead of discarding as orphans), and descendants ("economic offspring").
#[derive(Clone, Debug, Serialize)]
pub struct LineageGraph {
    pub ancestors: Vec<String>,
    pub selected_parent: Option<String>,
    pub economic_offspring: Vec<String>,
    pub economic_siblings: Vec<String>,
    pub blue_mergeset_size: Option<usize>,
    pub red_mergeset_size: Option<usize>,
}

/// Irreversible settlement state: whether every claim in this block is
/// resolved and its provenance sealed beyond practical reorg risk.
#[derive(Clone, Debug, Serialize)]
pub struct EconomicFinality {
    pub blue_score: Option<u64>,
    pub is_on_selected_chain: bool,
    pub is_economically_final: bool,
    pub confirmations: Option<u64>,
    pub finality_depth: u64,
}

/// A single chained verification event. `entry_hash` commits to the entry's
/// own content *and* the previous entry's hash, so tampering with, removing,
/// or reordering any entry changes every hash after it — the same
/// tamper-evidence property as a blockchain applied to one block's own audit
/// history.
#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    pub sequence: u32,
    pub event: &'static str,
    pub detail: String,
    pub prev_entry_hash: String,
    pub entry_hash: String,
}

/// Chronological, hash-chained record of every verification event a node
/// performs while accepting a block: PoW check, Birth Certificate check,
/// GHOSTDAG coloring, and (once reached) economic finality.
///
/// Unlike a server-side audit log, this trail is **deterministically
/// recomputed** from the block's own consensus data (header, GHOSTDAG data,
/// chain position) rather than recorded and stored as mutable server state.
/// That is what makes it independently auditable: any two honest nodes with
/// the same valid chain state compute byte-identical entries and hashes
/// without trusting each other or a central log. There is nothing here to
/// tamper with, because there is nothing here that isn't re-derived from
/// already-verified consensus facts every time it's requested.
#[derive(Clone, Debug, Serialize)]
pub struct AuditTrail {
    pub entries: Vec<AuditEntry>,
    /// Hash of the final entry — a single 512-bit fingerprint of the whole
    /// trail, suitable for quick equality checks between two nodes.
    pub trail_hash: String,
}

impl AuditTrail {
    fn push(entries: &mut Vec<AuditEntry>, event: &'static str, detail: String) {
        let sequence = entries.len() as u32;
        let prev_entry_hash = entries
            .last()
            .map(|e: &AuditEntry| e.entry_hash.clone())
            .unwrap_or_else(|| hex::encode(Hash::ZERO));
        let mut buf = Vec::new();
        buf.extend_from_slice(prev_entry_hash.as_bytes());
        buf.extend_from_slice(&sequence.to_be_bytes());
        buf.extend_from_slice(event.as_bytes());
        buf.extend_from_slice(detail.as_bytes());
        let entry_hash = hex::encode(hash512(&buf));
        entries.push(AuditEntry {
            sequence,
            event,
            detail,
            prev_entry_hash,
            entry_hash,
        });
    }

    fn build(
        b: &Block,
        is_genesis: bool,
        provenance: &ProvenanceRecord,
        lineage: &LineageGraph,
        finality: &EconomicFinality,
    ) -> Self {
        let mut entries = Vec::new();

        Self::push(
            &mut entries,
            "block_received",
            format!("settlement_id={}", provenance.settlement_id),
        );

        if is_genesis {
            Self::push(
                &mut entries,
                "proof_of_work_exempt",
                "genesis instrument is defined into existence, not mined".to_string(),
            );
        } else {
            Self::push(
                &mut entries,
                "proof_of_work_verified",
                format!("difficulty={} target_met=true", b.difficulty),
            );
        }

        Self::push(
            &mut entries,
            "birth_certificate_verified",
            format!(
                "scheme=ML-DSA-87 verified={} issuer={}",
                provenance.issuance_verified,
                provenance
                    .issuing_authority
                    .as_deref()
                    .unwrap_or("none (genesis)")
            ),
        );

        Self::push(
            &mut entries,
            "ghostdag_coloring_computed",
            format!(
                "blue_score={} blue_mergeset={} red_mergeset={} ancestors={} siblings_preserved={}",
                finality
                    .blue_score
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                lineage.blue_mergeset_size.unwrap_or(0),
                lineage.red_mergeset_size.unwrap_or(0),
                lineage.ancestors.len(),
                lineage.economic_siblings.len(),
            ),
        );

        Self::push(
            &mut entries,
            "chain_membership_evaluated",
            format!(
                "is_on_selected_chain={} confirmations={}",
                finality.is_on_selected_chain,
                finality
                    .confirmations
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
            ),
        );

        if finality.is_economically_final {
            Self::push(
                &mut entries,
                "economic_finality_reached",
                format!("finality_depth={}", finality.finality_depth),
            );
        }

        let trail_hash = entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| hex::encode(Hash::ZERO));
        Self {
            entries,
            trail_hash,
        }
    }
}

/// Illustrative issuance cost estimate: energy + hardware depreciation +
/// opportunity cost of capital, derived from the block's PoW difficulty and
/// configurable assumption constants. **Not** measured real-world data — see
/// module docs.
#[derive(Clone, Debug, Serialize)]
pub struct CostBasis {
    pub difficulty: u64,
    pub estimated_hashes: String,
    pub estimated_energy_joules: f64,
    pub estimated_energy_cost_usd: f64,
    pub estimated_hardware_depreciation_usd: f64,
    pub estimated_capital_opportunity_cost_usd: f64,
    pub estimated_total_cost_usd: f64,
    pub is_estimate: bool,
    pub methodology: &'static str,
}

impl CostBasis {
    /// Estimate the issuance cost of a block mined at `difficulty`, using the
    /// assumption constants in [`crate::genesis`]. `difficulty` is used
    /// directly as the expected hash-attempt count, matching this codebase's
    /// existing convention that `target = MAX_TARGET / difficulty` (see
    /// `pow_target`), i.e. a difficulty-`D` block costs ~`D` hash attempts in
    /// expectation.
    pub fn estimate(difficulty: u64) -> Self {
        use crate::genesis::economics::*;
        let estimated_hashes = difficulty as f64;
        let energy_joules = estimated_hashes * ASSUMED_JOULES_PER_HASH;
        let energy_kwh = energy_joules / 3_600_000.0;
        let energy_cost_usd = energy_kwh * ASSUMED_ENERGY_PRICE_USD_PER_KWH;
        let hardware_depreciation_usd =
            ASSUMED_HARDWARE_COST_USD / ASSUMED_HARDWARE_AMORTIZATION_BLOCKS;
        let capital_opportunity_cost_usd =
            (ASSUMED_HARDWARE_COST_USD * ASSUMED_CAPITAL_ANNUAL_RATE) / blocks_per_year();
        let total = energy_cost_usd + hardware_depreciation_usd + capital_opportunity_cost_usd;
        Self {
            difficulty,
            estimated_hashes: (difficulty as u128).to_string(),
            estimated_energy_joules: energy_joules,
            estimated_energy_cost_usd: energy_cost_usd,
            estimated_hardware_depreciation_usd: hardware_depreciation_usd,
            estimated_capital_opportunity_cost_usd: capital_opportunity_cost_usd,
            estimated_total_cost_usd: total,
            is_estimate: true,
            methodology: "difficulty (~hash attempts) \u{d7} assumed J/hash \u{d7} assumed energy \
                price, plus straight-line hardware depreciation and cost-of-capital spread over \
                one assumed amortization period. Assumptions are published constants, not \
                measured market data — see genesis.toml [economics].",
        }
    }
}

/// Cost/reward framing of ledger verification: the mempool fee market as a
/// market-clearing spread for settlement priority, analogous to a
/// market-maker's bid/ask spread.
#[derive(Clone, Debug, Serialize)]
pub struct VerificationEconomics {
    pub protocol_min_fee: String,
    pub current_min_relay_fee: String,
    pub low_fee_estimate: String,
    pub medium_fee_estimate: String,
    pub high_fee_estimate: String,
    pub verification_spread: String,
    pub mempool_txs: usize,
    pub package_count: usize,
    pub best_package_fee: String,
}

impl VerificationEconomics {
    pub fn snapshot(state: &ChainState) -> Self {
        let est = state.estimate_fee();
        Self {
            protocol_min_fee: crate::MIN_TX_FEE.to_string(),
            current_min_relay_fee: state.current_min_relay_fee().to_string(),
            low_fee_estimate: est.low.to_string(),
            medium_fee_estimate: est.medium.to_string(),
            high_fee_estimate: est.high.to_string(),
            verification_spread: est.high.saturating_sub(est.low).to_string(),
            mempool_txs: est.mempool_txs,
            package_count: est.package_count,
            best_package_fee: est.best_package_fee.to_string(),
        }
    }
}

/// The formal economic-entity tuple for a block:
/// `E = (H, T, P, C, L, F)` — Header, Transactions, Provenance, Custody,
/// Lineage, Finality — plus an illustrative cost basis and a snapshot of the
/// current verification-economics (fee market) context.
#[derive(Clone, Debug, Serialize)]
pub struct EconomicEntity {
    pub header_hash: String,
    pub height: Option<u64>,
    pub transaction_count: usize,
    pub provenance: ProvenanceRecord,
    pub custody: CustodyChain,
    pub lineage: LineageGraph,
    pub finality: EconomicFinality,
    pub audit_trail: AuditTrail,
    pub cost_basis: CostBasis,
    pub verification_economics: VerificationEconomics,
}

fn issuer_address(b: &Block) -> Option<String> {
    if b.creator_pubkey.is_empty() {
        return None;
    }
    Some(format!(
        "hsn:{}",
        hex::encode(address_hash(&b.creator_pubkey))
    ))
}

impl EconomicEntity {
    pub fn for_block(state: &ChainState, hash: &Hash) -> Option<Self> {
        let b = state.dag.get(hash)?;
        let gd = state.ghostdag.get(hash);
        let height = state
            .main_chain
            .iter()
            .position(|h| h == hash)
            .map(|i| state.pruned_selected_blocks + i as u64);
        let is_genesis = b.parents.is_empty();
        let issuer = issuer_address(b);
        let miner_addr = format!("hsn:{}", hex::encode(b.miner));
        let balance = state
            .accounts
            .get(&miner_addr)
            .map(|a| a.balance)
            .unwrap_or(0);

        let provenance = ProvenanceRecord {
            settlement_id: b.settlement_id().to_hex(),
            instrument_type: if is_genesis {
                "Genesis Instrument"
            } else {
                "PoW Block"
            },
            issuing_authority: issuer.clone(),
            jurisdiction: format!("Hassan Protocol, chain_id {}", state.chain_id),
            issuance_signature: hex::encode(&b.birth_certificate.signature),
            issuance_verified: b.verify_issuance().is_ok(),
            issued_at_ms: b.timestamp,
        };

        let custody = CustodyChain {
            primary_issuer: Custodian::PrimaryIssuer {
                address: Some(miner_addr.clone()),
            },
            validator: Custodian::Validator {
                description: "Every full node re-verifies this block's Birth Certificate and \
                    GHOSTDAG coloring before accepting it.",
            },
            archive_custodian: Custodian::ArchiveCustodian {
                is_local_node_archival: state.archival,
            },
            beneficial_owner: Custodian::BeneficialOwner {
                address: Some(miner_addr),
                current_balance: balance.to_string(),
            },
        };

        let children: Vec<String> = state
            .dag
            .iter()
            .filter(|(_, child)| child.parents.iter().any(|p| p == hash))
            .map(|(h, _)| hex::encode(h))
            .collect();
        let siblings: Vec<String> = state
            .tips
            .iter()
            .filter(|t| *t != hash)
            .filter(|t| {
                state
                    .dag
                    .get(*t)
                    .map(|tb| tb.parents.iter().any(|p| b.parents.contains(p)))
                    .unwrap_or(false)
            })
            .map(hex::encode)
            .collect();
        let lineage = LineageGraph {
            ancestors: b.parents.iter().map(hex::encode).collect(),
            selected_parent: gd.and_then(|d| d.selected_parent).map(hex::encode),
            economic_offspring: children,
            economic_siblings: siblings,
            blue_mergeset_size: gd.map(|d| d.mergeset_blues.len()),
            red_mergeset_size: gd.map(|d| d.mergeset_reds.len()),
        };

        let blue_score = gd.map(|d| d.blue_score);
        let tip_blue_score = state.selected_tip_blue_score();
        let is_on_selected_chain = state.main_chain.contains(hash);
        let confirmations = blue_score.map(|s| tip_blue_score.saturating_sub(s));
        let finality = EconomicFinality {
            blue_score,
            is_on_selected_chain,
            is_economically_final: is_on_selected_chain
                && confirmations
                    .map(|c| c >= crate::FINALITY_DEPTH)
                    .unwrap_or(false),
            confirmations,
            finality_depth: crate::FINALITY_DEPTH,
        };

        let audit_trail = AuditTrail::build(b, is_genesis, &provenance, &lineage, &finality);

        Some(Self {
            header_hash: hex::encode(hash),
            height,
            transaction_count: b.transparent_txs.len() + b.registry_ops.len(),
            provenance,
            custody,
            lineage,
            finality,
            audit_trail,
            cost_basis: CostBasis::estimate(b.difficulty),
            verification_economics: VerificationEconomics::snapshot(state),
        })
    }
}

/// Complete life history of a block — origin, transformations, current
/// state — as a short human-readable narrative built from the same data as
/// [`EconomicEntity`].
#[derive(Clone, Debug, Serialize)]
pub struct EconomicBiography {
    pub header_hash: String,
    pub origin: String,
    pub transformations: Vec<String>,
    pub current_state: String,
}

impl EconomicBiography {
    pub fn for_block(state: &ChainState, hash: &Hash) -> Option<Self> {
        let entity = EconomicEntity::for_block(state, hash)?;
        let b = state.dag.get(hash)?;
        let is_genesis = b.parents.is_empty();

        let origin =
            if is_genesis {
                format!(
                "Instrument created at genesis (t={}ms), issuing authority '{}', jurisdiction {}.",
                entity.provenance.issued_at_ms, crate::FOUNDER, entity.provenance.jurisdiction
            )
            } else {
                format!(
                    "Issued at t={}ms by {} via proof-of-work at difficulty {}, notarized with a \
                 Birth Certificate over Settlement ID {}.",
                    entity.provenance.issued_at_ms,
                    entity
                        .provenance
                        .issuing_authority
                        .as_deref()
                        .unwrap_or("unknown issuer"),
                    entity.cost_basis.difficulty,
                    &entity.provenance.settlement_id[..16],
                )
            };

        let mut transformations = Vec::new();
        if !entity.lineage.economic_offspring.is_empty() {
            transformations.push(format!(
                "Extended by {} descendant block(s) in the DAG.",
                entity.lineage.economic_offspring.len()
            ));
        }
        if !entity.lineage.economic_siblings.is_empty() {
            transformations.push(format!(
                "{} economic sibling(s) preserved (blue/red GHOSTDAG mergeset) rather than \
                 discarded as orphans.",
                entity.lineage.economic_siblings.len()
            ));
        }
        if let Some(c) = entity.finality.confirmations {
            transformations.push(format!(
                "Accrued {} confirmation(s) (blue-score distance from the selected tip).",
                c
            ));
        }
        if entity.finality.is_economically_final {
            transformations.push(
                "Reached economic finality: beyond the reorg window, all claims settled."
                    .to_string(),
            );
        }

        let current_state = if entity.finality.is_on_selected_chain {
            format!(
                "Currently on the selected chain{}.",
                if entity.finality.is_economically_final {
                    ", economically final"
                } else {
                    ", awaiting finality"
                }
            )
        } else {
            "Currently a non-selected (red) DAG block — still valid, but not on the main chain."
                .to_string()
        };

        Some(Self {
            header_hash: entity.header_hash,
            origin,
            transformations,
            current_state,
        })
    }
}

/// Confirmed-vs-pending status of a transfer.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status")]
pub enum TransactionLineage {
    Pending,
    Confirmed {
        containing_block: String,
        height: Option<u64>,
    },
}

/// Mempool-to-block propagation timing for a transfer ("journey history").
#[derive(Clone, Debug, Serialize)]
pub struct TransactionJourney {
    pub first_seen_ms: Option<u64>,
    pub confirmed_at_ms: Option<u64>,
    pub mempool_dwell_ms: Option<u64>,
}

/// Economic-entity view of a single transfer: birth (signature + nonce),
/// lineage (which block, if any, settled it), custody (sender/receiver as
/// economic agents), and journey (mempool dwell time).
#[derive(Clone, Debug, Serialize)]
pub struct TransactionEconomicEntity {
    pub tx_hash: String,
    pub signed_by: String,
    pub nonce: u64,
    pub lineage: TransactionLineage,
    pub remitting_agent: String,
    pub beneficiary_agent: String,
    pub amount: String,
    pub fee: String,
    pub journey: TransactionJourney,
}

/// Locate a confirmed transfer by hash on the selected chain.
pub fn find_confirmed_transfer<'a>(
    state: &'a ChainState,
    tx_hash: &Hash,
) -> Option<(&'a Block, u64, &'a TransparentTx)> {
    for (i, h) in state.main_chain.iter().enumerate() {
        if let Some(b) = state.dag.get(h) {
            if let Some(tx) = b.transparent_txs.iter().find(|t| &t.tx_hash() == tx_hash) {
                return Some((b, state.pruned_selected_blocks + i as u64, tx));
            }
        }
    }
    None
}

impl TransactionEconomicEntity {
    pub fn for_tx(state: &ChainState, tx_hash: &Hash) -> Option<Self> {
        let first_seen_ms = state.tx_first_seen_ms.get(tx_hash).copied();

        if let Some(tx) = state
            .transparent_mempool
            .iter()
            .find(|t| &t.tx_hash() == tx_hash)
        {
            return Some(Self {
                tx_hash: hex::encode(tx_hash),
                signed_by: tx.from.clone(),
                nonce: tx.nonce,
                lineage: TransactionLineage::Pending,
                remitting_agent: tx.from.clone(),
                beneficiary_agent: tx.to.clone(),
                amount: tx.amount.to_string(),
                fee: tx.fee.to_string(),
                journey: TransactionJourney {
                    first_seen_ms,
                    confirmed_at_ms: None,
                    mempool_dwell_ms: None,
                },
            });
        }

        let (block, height, tx) = find_confirmed_transfer(state, tx_hash)?;
        let confirmed_at_ms = Some(block.timestamp);
        let mempool_dwell_ms = match (first_seen_ms, confirmed_at_ms) {
            (Some(seen), Some(conf)) => Some(conf.saturating_sub(seen)),
            _ => None,
        };
        Some(Self {
            tx_hash: hex::encode(tx_hash),
            signed_by: tx.from.clone(),
            nonce: tx.nonce,
            lineage: TransactionLineage::Confirmed {
                containing_block: hex::encode(block.hash()),
                height: Some(height),
            },
            remitting_agent: tx.from.clone(),
            beneficiary_agent: tx.to.clone(),
            amount: tx.amount.to_string(),
            fee: tx.fee.to_string(),
            journey: TransactionJourney {
                first_seen_ms,
                confirmed_at_ms,
                mempool_dwell_ms,
            },
        })
    }
}

/// Record a transfer's mempool admission time (and tip blue score) for later
/// journey/dwell-time reporting and confirmation-target fee history.
/// Best-effort, in-memory only, bounded — this is an economics/explorer
/// convenience, not consensus state (never persisted, never affects validation).
pub fn record_first_seen(state: &mut ChainState, tx_hash: Hash) {
    const MAX_TRACKED: usize = crate::MAX_MEMPOOL_SIZE * 2;
    if state.tx_first_seen_ms.len() >= MAX_TRACKED && !state.tx_first_seen_ms.contains_key(&tx_hash)
    {
        // Drop an arbitrary entry rather than grow unbounded; this is
        // best-effort telemetry, not a correctness-critical index.
        if let Some(k) = state.tx_first_seen_ms.keys().next().copied() {
            state.tx_first_seen_ms.remove(&k);
            state.tx_first_seen_blue.remove(&k);
        }
    }
    state.tx_first_seen_ms.entry(tx_hash).or_insert_with(now_ms);
    let tip_blue = state.selected_tip_blue_score();
    state.tx_first_seen_blue.entry(tx_hash).or_insert(tip_blue);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_keypair, hash_to_address, test_address, Account, TransparentTx};

    #[test]
    fn genesis_has_a_provenance_record_and_no_issuer() {
        let state = ChainState::new();
        let genesis_hash = state.tips[0];
        let entity =
            EconomicEntity::for_block(&state, &genesis_hash).expect("genesis is a real block");
        assert_eq!(entity.provenance.instrument_type, "Genesis Instrument");
        assert!(
            entity.provenance.issuing_authority.is_none(),
            "genesis has no miner issuer"
        );
        assert_eq!(
            entity.lineage.ancestors.len(),
            0,
            "genesis has no ancestors"
        );
        assert!(entity.finality.is_on_selected_chain);
    }

    #[test]
    fn cost_basis_is_a_labeled_estimate_that_scales_with_difficulty() {
        let low = CostBasis::estimate(1_000);
        let high = CostBasis::estimate(1_000_000);
        assert!(
            low.is_estimate,
            "must always be labeled as an estimate, never as fact"
        );
        assert!(
            high.estimated_total_cost_usd > low.estimated_total_cost_usd,
            "harder blocks must cost more in the estimate"
        );
        assert!(
            low.estimated_total_cost_usd > 0.0,
            "even an easy block has non-zero hardware/capital cost"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn pending_transfer_has_a_journey_first_seen_timestamp_and_no_confirmation() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );

        let mut tx = TransparentTx::new(pk, test_address(0xc), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();
        let tx_hash = tx.tx_hash();
        state
            .admit_transparent_to_mempool(tx)
            .expect("valid transfer admitted");

        let entity = TransactionEconomicEntity::for_tx(&state, &tx_hash)
            .expect("pending transfer is findable");
        assert!(matches!(entity.lineage, TransactionLineage::Pending));
        assert!(
            entity.journey.first_seen_ms.is_some(),
            "admission must be timestamped"
        );
        assert!(entity.journey.confirmed_at_ms.is_none());
        assert!(entity.journey.mempool_dwell_ms.is_none());
    }

    #[test]
    fn unknown_transfer_hash_resolves_to_nothing() {
        let state = ChainState::new();
        let bogus = Hash([0xab; crate::HASH_SIZE]);
        assert!(TransactionEconomicEntity::for_tx(&state, &bogus).is_none());
    }

    #[test]
    fn audit_trail_is_hash_chained_and_deterministic() {
        let state = ChainState::new();
        let genesis_hash = state.tips[0];
        let a = EconomicEntity::for_block(&state, &genesis_hash)
            .unwrap()
            .audit_trail;
        let b = EconomicEntity::for_block(&state, &genesis_hash)
            .unwrap()
            .audit_trail;

        assert_eq!(
            a.trail_hash, b.trail_hash,
            "same block must always produce the same trail (audit independence)"
        );
        assert!(
            a.entries.len() >= 4,
            "genesis should have at least received/pow-exempt/certificate/coloring entries"
        );
        assert_eq!(
            a.entries[0].prev_entry_hash,
            hex::encode(Hash::ZERO),
            "first entry chains from zero"
        );
        for pair in a.entries.windows(2) {
            assert_eq!(
                pair[1].prev_entry_hash, pair[0].entry_hash,
                "each entry must chain to the previous entry's hash"
            );
        }
        assert_eq!(a.trail_hash, a.entries.last().unwrap().entry_hash);
    }

    #[test]
    fn a_mined_block_has_a_different_trail_hash_than_genesis() {
        let mut state = ChainState::new();
        let genesis_hash = state.tips[0];
        let genesis_trail = EconomicEntity::for_block(&state, &genesis_hash)
            .unwrap()
            .audit_trail;
        assert!(
            genesis_trail
                .entries
                .iter()
                .any(|e| e.event == "proof_of_work_exempt"),
            "genesis must record itself as PoW-exempt, not falsely claim a PoW check happened"
        );

        let parents = state.tips.clone();
        let t = crate::now_ms();
        let difficulty = state.expected_difficulty_at(&parents, t);
        let mut block = Block {
            height: 0,
            timestamp: t,
            parents,
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = crate::test_miner_keys();
        crate::seal_block(&state, &mut block, sk, pk);
        let mined_hash = block.hash();
        state.add_block(block).expect("mined block must be valid");

        let mined_trail = EconomicEntity::for_block(&state, &mined_hash)
            .unwrap()
            .audit_trail;
        assert!(
            mined_trail
                .entries
                .iter()
                .any(|e| e.event == "proof_of_work_verified"),
            "a real mined block must record a real PoW check, not the genesis exemption"
        );
        assert_ne!(
            genesis_trail.trail_hash, mined_trail.trail_hash,
            "different blocks with different verification facts must not collide"
        );
    }
}
