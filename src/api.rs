use crate::{ChainState, Hash, TransparentTx, HASH_SIZE};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

pub struct ApiServer {
    state: Arc<RwLock<ChainState>>,
}

/// A transparent transfer submission. The transfer is signed client-side (the
/// node never sees a private key); `from_pubkey` is the hex-encoded ML-DSA-87
/// public key and `signature` the hex-encoded ML-DSA-87 signature over the
/// transfer's canonical bytes.
#[derive(Serialize, Deserialize)]
pub struct TxSubmitRequest {
    pub from_pubkey: String,
    pub to: String,
    pub amount: u128,
    /// Optional burned fee; defaults to [`crate::MIN_TX_FEE`].
    #[serde(default = "default_fee")]
    pub fee: u128,
    pub nonce: u64,
    pub chain_id: u64,
    pub signature: String,
}

fn default_fee() -> u128 {
    crate::MIN_TX_FEE
}

#[derive(Serialize, Deserialize)]
pub struct TxSubmitResponse {
    pub tx_hash: String,
    pub status: String,
}

impl ApiServer {
    pub fn new(state: Arc<RwLock<ChainState>>) -> Self {
        Self { state }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, ChainState> {
        self.state.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, ChainState> {
        self.state.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Resolve a block by absolute height (decimal) or full 64-char hex hash.
    fn resolve_block<'a>(s: &'a ChainState, id: &str) -> Option<(Hash, &'a crate::Block)> {
        if let Ok(height) = id.parse::<u64>() {
            let local = height.checked_sub(s.pruned_selected_blocks)? as usize;
            let h = s.main_chain.get(local)?;
            let b = s.dag.get(h)?;
            return Some((*h, b));
        }
        if id.len() == HASH_SIZE * 2 {
            if let Ok(bytes) = hex::decode(id) {
                if let Ok(h) = <Hash>::try_from(bytes.as_slice()) {
                    if let Some(b) = s.dag.get(&h) {
                        return Some((h, b));
                    }
                }
            }
        }
        None
    }

    pub fn status(&self) -> serde_json::Value {
        let s = self.read();
        let tip = s.main_chain.last().copied();
        let tip_block = tip.and_then(|h| s.dag.get(&h));
        let net = crate::p2p::network_status();
        let mut out = serde_json::Map::new();
        let put = |m: &mut serde_json::Map<String, serde_json::Value>, k: &str, v: serde_json::Value| {
            m.insert(k.into(), v);
        };
        put(&mut out, "height", serde_json::json!(s.tip_height()));
        put(&mut out, "blue_score", serde_json::json!(s.selected_tip_blue_score()));
        put(&mut out, "dag_blocks", serde_json::json!(s.dag.len()));
        put(&mut out, "tips", serde_json::json!(s.tips.len()));
        put(&mut out, "difficulty", serde_json::json!(s.difficulty));
        put(
            &mut out,
            "target_block_time_ms",
            serde_json::json!(crate::TARGET_BLOCK_TIME_MS),
        );
        put(
            &mut out,
            "mempool",
            serde_json::json!(
                s.transparent_mempool.len()
                    + s.utxo_mempool.len()
                    + s.registry_mempool.len()
                    + s.custody_mempool.len()
            ),
        );
        put(
            &mut out,
            "mempool_transparent",
            serde_json::json!(s.transparent_mempool.len()),
        );
        put(
            &mut out,
            "mempool_utxo",
            serde_json::json!(s.utxo_mempool.len()),
        );
        put(
            &mut out,
            "mempool_registry",
            serde_json::json!(s.registry_mempool.len()),
        );
        put(
            &mut out,
            "mempool_custody",
            serde_json::json!(s.custody_mempool.len()),
        );
        put(
            &mut out,
            "finality_depth",
            serde_json::json!(crate::FINALITY_DEPTH),
        );
        put(
            &mut out,
            "pruning_depth",
            serde_json::json!(crate::PRUNING_DEPTH),
        );
        put(
            &mut out,
            "min_relay_fee",
            serde_json::json!(s.current_min_relay_fee().to_string()),
        );
        put(&mut out, "titles", serde_json::json!(s.registry.titles.len()));
        put(&mut out, "escrows", serde_json::json!(s.registry.escrows.len()));
        put(
            &mut out,
            "pruning_point",
            serde_json::json!(s.pruning_point.map(hex::encode)),
        );
        put(
            &mut out,
            "state_root",
            serde_json::json!(tip_block.map(|b| hex::encode(b.state_root))),
        );
        put(
            &mut out,
            "utxo_commitment",
            serde_json::json!(hex::encode(s.utxo.commitment())),
        );
        put(&mut out, "utxo_set_size", serde_json::json!(s.utxo.entries.len()));
        put(&mut out, "supply_ok", serde_json::json!(s.supply_invariant_ok()));
        put(
            &mut out,
            "circulating_supply",
            serde_json::json!(s.minted_supply.to_string()),
        );
        put(
            &mut out,
            "max_supply",
            serde_json::json!(crate::MAX_SUPPLY.to_string()),
        );
        put(
            &mut out,
            "max_supply_coins",
            serde_json::json!(crate::MAX_SUPPLY_COINS),
        );
        put(&mut out, "coin_decimals", serde_json::json!(8));
        put(
            &mut out,
            "block_reward",
            serde_json::json!(crate::BLOCK_REWARD.to_string()),
        );
        put(
            &mut out,
            "bootstrap_era_end",
            serde_json::json!(crate::BOOTSTRAP_ERA_END.to_string()),
        );
        put(
            &mut out,
            "hard_era_min_difficulty",
            serde_json::json!(crate::HARD_ERA_MIN_DIFFICULTY),
        );
        put(
            &mut out,
            "era_min_difficulty",
            serde_json::json!(crate::era_min_difficulty(s.minted_supply, crate::now_ms())),
        );
        put(&mut out, "min_difficulty", serde_json::json!(crate::MIN_DIFFICULTY));
        put(
            &mut out,
            "total_supply",
            serde_json::json!(s.minted_supply.to_string()),
        );
        put(
            &mut out,
            "fees_burned",
            serde_json::json!(s.fees_burned.to_string()),
        );
        put(
            &mut out,
            "fee_policy",
            serde_json::json!("v26+ fees pay miner coinbase (subsidy+fees); fees_burned is legacy and 0 on fresh chains"),
        );
        put(
            &mut out,
            "stark_kind",
            serde_json::json!("sequential_work_companion"),
        );
        put(
            &mut out,
            "stark_is_validity_zk",
            serde_json::json!(false),
        );
        put(
            &mut out,
            "stark_notes",
            serde_json::json!(
                "Per-block STARK proves SEQUENTIAL_STEPS of a fixed AIR from the block-hash seed — a VDF-style companion to PoW, not a validity ZK of txs/state transitions and not privacy ZK."
            ),
        );
        put(
            &mut out,
            "assume_valid",
            serde_json::json!(crate::assume_valid::pinned_digest().map(|h| hex::encode(h))),
        );
        put(&mut out, "staked_accounts", serde_json::json!(s.staked.len()));
        put(&mut out, "chain_id", serde_json::json!(s.chain_id));
        put(
            &mut out,
            "chain_hash",
            serde_json::json!(crate::chain_hash_hex()),
        );
        put(
            &mut out,
            "genesis_domain",
            serde_json::json!(String::from_utf8_lossy(crate::GENESIS_DOMAIN).to_string()),
        );
        put(&mut out, "founder", serde_json::json!(crate::FOUNDER));
        put(&mut out, "slogan", serde_json::json!(crate::SLOGAN));
        put(&mut out, "settlement_bits", serde_json::json!(512));
        put(&mut out, "signature_scheme", serde_json::json!("ML-DSA-87"));
        put(&mut out, "pow_algo", serde_json::json!("blake3-512"));
        put(
            &mut out,
            "pow_notes",
            serde_json::json!(
                "Blake3-512 XOF PoW; target_block_time_ms=100. Bootstrap floor 7000 until 1M HSN minted, then hard 2^24. Optional HASSAN_BOOTSTRAP_EASY=1 keeps bootstrap floor after 1M (peers must match). Parallel GHOSTDAG tips: more honest hashrate raises aggregate accepted blocks/sec. Solo miner, stratum (HASSAN_STRATUM_PASSWORD), /api/v1/mining/light."
            ),
        );
        put(&mut out, "pq_digest_bits", serde_json::json!(512));
        put(&mut out, "abs_scheme", serde_json::json!(87));
        put(&mut out, "peers", serde_json::json!(net.peer_count));
        put(&mut out, "p2p_listening", serde_json::json!(net.listening));
        put(&mut out, "p2p_listen_addr", serde_json::json!(net.listen_addr));
        put(&mut out, "archival", serde_json::json!(s.archival));
        put(
            &mut out,
            "kernel_rules",
            serde_json::json!(hex::encode(crate::kernel::kernel_rules_id())),
        );
        put(
            &mut out,
            "crate_version",
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        );
        serde_json::Value::Object(out)
    }

    pub fn latest_blocks(&self, n: usize) -> Vec<serde_json::Value> {
        let s = self.read();
        let base = s.pruned_selected_blocks as usize;
        s.main_chain
            .iter()
            .enumerate()
            .rev()
            .take(n)
            .filter_map(|(i, h)| {
                s.dag.get(h).map(|b| serde_json::json!({
                "hash": hex::encode(h),
                "height": base + i,
                "blue_score": s.ghostdag.get(h).map(|d| d.blue_score),
                "transfers": b.transparent_txs.len(),
                "utxo_txs": b.utxo_txs.len(),
                "registry_ops": b.registry_ops.len(),
                "tx_count": b.transparent_txs.len() + b.utxo_txs.len() + b.registry_ops.len(),
                "timestamp": b.timestamp,
                "miner": crate::address::encode_hash(&b.miner),
                "settlement_id": b.settlement_id().to_hex(),
                "birth_ok": b.verify_issuance().is_ok(),
                "parents": b.parents.iter().map(|p| hex::encode(&p[..5])).collect::<Vec<_>>(),
                "id": hex::encode(&h[..5]),
            }))
            })
            .collect()
    }

    pub fn get_block(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (hash, b) = Self::resolve_block(&s, id)?;
        let height = if let Ok(h) = id.parse::<u64>() {
            h
        } else {
            s.main_chain
                .iter()
                .position(|h| h == &hash)
                .map(|i| s.pruned_selected_blocks + i as u64)
                .unwrap_or(b.height)
        };
        let birth_ok = b.verify_issuance().is_ok();
        let tip_blue = s.selected_tip_blue_score();
        let blue = s.ghostdag.get(&hash).map(|d| d.blue_score);
        let confirmations = blue.map(|bs| tip_blue.saturating_sub(bs));
        let on_selected = s.main_chain.iter().any(|h| h == &hash);
        let is_final = confirmations
            .map(|c| c >= crate::FINALITY_DEPTH)
            .unwrap_or(false);
        Some(serde_json::json!({
            "hash": hex::encode(hash),
            "height": height,
            "blue_score": blue,
            "confirmations": confirmations,
            "finality_depth": crate::FINALITY_DEPTH,
            "is_final": is_final,
            "on_selected_chain": on_selected,
            "timestamp": b.timestamp,
            "parents": b.parents.iter().map(hex::encode).collect::<Vec<_>>(),
            "difficulty": b.difficulty,
            "transfers": b.transparent_txs.iter().map(|tx| {
                serde_json::json!({
                    "tx_hash": hex::encode(tx.tx_hash()),
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "nonce": tx.nonce,
                })
            }).collect::<Vec<_>>(),
            "utxo_transactions": b.utxo_txs.iter().map(|tx| {
                serde_json::json!({
                    "txid": hex::encode(tx.txid()),
                    "wtxid": hex::encode(tx.wtxid()),
                    "fee": tx.fee.to_string(),
                    "inputs": tx.inputs.len(),
                    "outputs": tx.outputs.len(),
                    "from": tx.from_address(),
                })
            }).collect::<Vec<_>>(),
            "registry_ops": b.registry_ops.len(),
            "miner": crate::address::encode_hash(&b.miner),
            "issuer": if b.creator_pubkey.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(crate::hash_to_address(&b.creator_pubkey))
            },
            "issuer_pubkey": hex::encode(&b.creator_pubkey),
            "settlement_id": b.settlement_id().to_hex(),
            "settlement_bits": 512,
            "birth_ok": birth_ok,
            "birth_certificate": hex::encode(&b.birth_certificate.signature),
            "nonce": b.nonce,
            "state_root": hex::encode(b.state_root),
            "merkle_root": hex::encode(b.merkle_root),
            "utxo_txs": b.utxo_txs.len(),
            "custody_ops": b.custody_ops.len(),
            "version": b.version,
            "interlinks": b.interlinks.iter().map(hex::encode).collect::<Vec<_>>(),
            "body_pruned": s.is_body_pruned(&hash),
        }))
    }

    /// Issuance packet: 512-bit Settlement ID + Birth Certificate (bank-grade notarization).
    pub fn get_block_issuance(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (hash, b) = Self::resolve_block(&s, id)?;
        let birth_ok = b.verify_issuance().is_ok();
        Some(serde_json::json!({
            "hash": hex::encode(hash),
            "settlement_id": b.settlement_id().to_hex(),
            "settlement_bits": 512,
            "issuer_pubkey": hex::encode(&b.creator_pubkey),
            "issuer": if b.creator_pubkey.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(crate::hash_to_address(&b.creator_pubkey))
            },
            "birth_certificate": hex::encode(&b.birth_certificate.signature),
            "birth_ok": birth_ok,
            "signature_scheme": "ML-DSA-87",
            "pq_digest_bits": 512,
            "verifiable_everywhere": birth_ok,
        }))
    }

    /// The full Economic Entity view of a block: `E = (H,T,P,C,L,F)` —
    /// Header, Transactions, Provenance, Custody, Lineage, Finality — plus
    /// an illustrative Cost Basis and a Verification Economics snapshot.
    /// See [`crate::economics`].
    pub fn get_block_economic_entity(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (hash, _) = Self::resolve_block(&s, id)?;
        let entity = crate::economics::EconomicEntity::for_block(&s, &hash)?;
        serde_json::to_value(entity).ok()
    }

    /// A block's complete economic life history (origin, transformations,
    /// current state) as a short narrative. See [`crate::economics`].
    pub fn get_block_economic_biography(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (hash, _) = Self::resolve_block(&s, id)?;
        let bio = crate::economics::EconomicBiography::for_block(&s, &hash)?;
        serde_json::to_value(bio).ok()
    }

    /// Economic Entity view of a single transfer: birth, lineage, custody,
    /// and journey (mempool dwell time). Accepts either a pending or a
    /// confirmed transfer's hash.
    pub fn get_tx_economic_entity(&self, tx_hash_hex: &str) -> Option<serde_json::Value> {
        let bytes = hex::decode(tx_hash_hex).ok()?;
        let hash = Hash::try_from(bytes.as_slice()).ok()?;
        let s = self.read();
        let entity = crate::economics::TransactionEconomicEntity::for_tx(&s, &hash)?;
        serde_json::to_value(entity).ok()
    }

    /// Chain of title for a block's DAG ancestry (parents / children / selected parent).
    pub fn get_block_family(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (hash, b) = Self::resolve_block(&s, id)?;
        let gd = s.ghostdag.get(&hash);
        let selected_parent = gd.and_then(|d| d.selected_parent).map(hex::encode);
        let children: Vec<String> = s
            .dag
            .iter()
            .filter(|(_, child)| child.parents.iter().any(|p| p == &hash))
            .map(|(h, _)| hex::encode(h))
            .collect();
        let siblings: Vec<String> = s
            .tips
            .iter()
            .filter(|t| **t != hash)
            .filter(|t| {
                s.dag
                    .get(*t)
                    .map(|tb| tb.parents.iter().any(|p| b.parents.contains(p)))
                    .unwrap_or(false)
            })
            .map(hex::encode)
            .collect();
        Some(serde_json::json!({
            "hash": hex::encode(hash),
            "parents": b.parents.iter().map(hex::encode).collect::<Vec<_>>(),
            "selected_parent": selected_parent,
            "children": children,
            "sibling_tips": siblings,
            "settlement_id": b.settlement_id().to_hex(),
            "issuer": crate::address::encode_hash(&b.miner),
            "birth_ok": b.verify_issuance().is_ok(),
            "blue_score": gd.map(|d| d.blue_score),
            "blue_mergeset_size": gd.map(|d| d.mergeset_blues.len()),
            "red_mergeset_size": gd.map(|d| d.mergeset_reds.len()),
            "is_chain_block": s.main_chain.contains(&hash),
        }))
    }

    /// Public title deed + full ownership history (chain of title).
    pub fn get_title(&self, title_id_hex: &str) -> Option<serde_json::Value> {
        let bytes = hex::decode(title_id_hex).ok()?;
        let id = Hash::try_from(bytes.as_slice()).ok()?;
        let s = self.read();
        let deed = s.registry.titles.get(&id)?;
        Some(serde_json::json!({
            "title_id": deed.title_id_hex(),
            "asset_class": deed.asset_class.as_str(),
            "description": deed.description,
            "current_owner": deed.current_owner,
            "issued_at": deed.issued_at,
            "lienholder": deed.lienholder,
            "escrow_id": deed.escrow_id.map(hex::encode),
            "chain_of_title": deed.history,
            "owners": {
                "current": deed.current_owner,
                "prior": deed.history.iter().filter_map(|e| e.from.clone()).collect::<Vec<_>>(),
            },
        }))
    }

    pub fn list_titles(&self, limit: usize) -> Vec<serde_json::Value> {
        let s = self.read();
        s.registry
            .titles
            .values()
            .take(limit)
            .map(|d| {
                serde_json::json!({
                    "title_id": d.title_id_hex(),
                    "asset_class": d.asset_class.as_str(),
                    "description": d.description,
                    "current_owner": d.current_owner,
                    "events": d.history.len(),
                    "in_escrow": d.escrow_id.is_some(),
                })
            })
            .collect()
    }

    pub fn get_escrow(&self, escrow_id_hex: &str) -> Option<serde_json::Value> {
        let bytes = hex::decode(escrow_id_hex).ok()?;
        let id = Hash::try_from(bytes.as_slice()).ok()?;
        let s = self.read();
        let e = s.registry.escrows.get(&id)?;
        Some(serde_json::json!({
            "escrow_id": e.escrow_id_hex(),
            "buyer": e.buyer,
            "seller": e.seller,
            "arbiter": e.arbiter,
            "amount": e.amount.to_string(),
            "funded": e.funded.to_string(),
            "status": format!("{:?}", e.status).to_lowercase(),
            "title_id": e.title_id.map(hex::encode),
            "opened_at": e.opened_at,
            "timeout_blue": e.timeout_blue,
            "timeout_height": e.timeout_blue, // alias for explorers
            "memo": e.memo,
        }))
    }

    pub fn list_escrows(&self, limit: usize) -> Vec<serde_json::Value> {
        let s = self.read();
        s.registry
            .escrows
            .values()
            .take(limit)
            .map(|e| {
                serde_json::json!({
                    "escrow_id": e.escrow_id_hex(),
                    "buyer": e.buyer,
                    "seller": e.seller,
                    "amount": e.amount.to_string(),
                    "funded": e.funded.to_string(),
                    "status": format!("{:?}", e.status).to_lowercase(),
                    "timeout_blue": e.timeout_blue,
                    "timeout_height": e.timeout_blue,
                })
            })
            .collect()
    }

    /// Titles currently owned by an address (public ownership lookup).
    pub fn titles_for_owner(&self, address: &str) -> Vec<serde_json::Value> {
        let s = self.read();
        s.registry
            .titles
            .values()
            .filter(|d| d.current_owner == address)
            .map(|d| {
                serde_json::json!({
                    "title_id": d.title_id_hex(),
                    "asset_class": d.asset_class.as_str(),
                    "description": d.description,
                    "events": d.history.len(),
                })
            })
            .collect()
    }

    pub fn mining_stats(&self) -> serde_json::Value {
        let s = self.read();
        let era_floor = crate::era_min_difficulty(s.minted_supply, crate::now_ms());
        serde_json::json!({
            "difficulty": s.difficulty,
            "era_min_difficulty": era_floor,
            "min_difficulty": crate::MIN_DIFFICULTY,
            "hard_era_min_difficulty": crate::HARD_ERA_MIN_DIFFICULTY,
            "bootstrap_era_end": crate::BOOTSTRAP_ERA_END.to_string(),
            "pow_algo": "blake3-512",
            "target_block_time_ms": crate::TARGET_BLOCK_TIME_MS,
            "block_reward": s.block_reward.to_string(),
            "fees_burned": s.fees_burned.to_string(),
            "treasury": s.treasury.to_string(),
            "default_share_difficulty": crate::stratum::DEFAULT_SHARE_DIFFICULTY,
            "light_mine": "/api/v1/mining/light",
            "template": "/api/v1/mining/template",
            "stratum": "/api/v1/stratum",
        })
    }

    /// Network / P2P snapshot for the explorer (updated by the P2P stack).
    pub fn network(&self) -> serde_json::Value {
        let net = crate::p2p::network_status();
        let s = self.read();
        serde_json::json!({
            "peer_count": net.peer_count,
            "listening": net.listening,
            "listen_addr": net.listen_addr,
            "banned_count": net.banned_count,
            "known_addrs": net.known_addrs,
            "tips": s.tips.iter().map(hex::encode).collect::<Vec<_>>(),
            "dag_blocks": s.dag.len(),
            "height": s.tip_height(),
            "chain_id": s.chain_id,
            "chain_hash": crate::chain_hash_hex(),
            "genesis_domain": String::from_utf8_lossy(crate::GENESIS_DOMAIN),
        })
    }

    /// Custody / stake locks currently recorded in consensus state.
    pub fn list_custody(&self) -> serde_json::Value {
        let s = self.read();
        let staked: Vec<_> = s
            .staked
            .iter()
            .map(|(addr, amt)| {
                serde_json::json!({
                    "owner": addr,
                    "amount": amt.to_string(),
                })
            })
            .collect();
        serde_json::json!({
            "staked": staked,
            "custody_mempool": s.custody_mempool.len(),
        })
    }

    /// Bounded Blake3-512 nonce search for laptop/mobile miners.
    ///
    /// Searches up to `max_hashes` (clamped) share-style digests at
    /// `share_difficulty` (default: stratum default). Does **not** produce a
    /// full sealed block — use the node's solo miner or submit a template
    /// solution via stratum/pool handoff for network blocks. Practical for
    /// verifying local hashrate and stratum share difficulty on CPU/mobile.
    pub fn light_mine(&self, max_hashes: u64, share_difficulty: Option<u64>) -> serde_json::Value {
        let max_hashes = max_hashes.clamp(1, 25_000);
        let share_diff = share_difficulty
            .unwrap_or(crate::stratum::DEFAULT_SHARE_DIFFICULTY)
            .clamp(
                crate::stratum::MIN_SHARE_DIFFICULTY,
                crate::stratum::MAX_SHARE_DIFFICULTY,
            );
        let s = self.read();
        let parents = s.tips.clone();
        let ts = crate::now_ms();
        let network_diff = s.expected_difficulty_at(&parents, ts);
        let target = crate::pow_target(share_diff);
        let mut hasher0 = blake3::Hasher::new();
        hasher0.update(b"hassan-light-mine-v1");
        for p in &parents {
            hasher0.update(p.as_bytes());
        }
        hasher0.update(&network_diff.to_le_bytes());
        hasher0.update(&ts.to_le_bytes());
        let mut template = [0u8; crate::HASH_SIZE];
        hasher0.finalize_xof().fill(&mut template);

        let start = std::time::Instant::now();
        let mut found: Option<(u64, String)> = None;
        for nonce in 0..max_hashes {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"hassan-stratum-share-v1");
            hasher.update(&template);
            hasher.update(&nonce.to_le_bytes());
            let mut out = [0u8; crate::HASH_SIZE];
            hasher.finalize_xof().fill(&mut out);
            if crate::hash_meets_target(&crate::Hash(out), &target) {
                found = Some((nonce, hex::encode(out)));
                break;
            }
        }
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let tried = found.as_ref().map(|(n, _)| n + 1).unwrap_or(max_hashes);
        let hps = if elapsed_ms > 0 {
            tried.saturating_mul(1000) / elapsed_ms.max(1)
        } else {
            tried
        };
        serde_json::json!({
            "pow_algo": "blake3-512",
            "share_difficulty": share_diff,
            "network_difficulty": network_diff,
            "era_min_difficulty": crate::era_min_difficulty(s.minted_supply, ts),
            "max_hashes": max_hashes,
            "hashes_tried": tried,
            "elapsed_ms": elapsed_ms,
            "hashes_per_sec": hps,
            "found": found.is_some(),
            "nonce": found.as_ref().map(|(n, _)| n),
            "share_hash": found.as_ref().map(|(_, h)| h.clone()),
            "template": hex::encode(template),
            "parents": parents.iter().map(hex::encode).collect::<Vec<_>>(),
            "note": "Light mine searches share difficulty for CPU/laptop/mobile. Full blocks require birth certificates from a registered miner key (solo miner / pool).",
        })
    }

    pub fn submit_tx(&self, req: TxSubmitRequest) -> Result<TxSubmitResponse, String> {
        if !crate::ACCOUNT_PEER_TRANSFERS {
            return Err(
                "Account peer transfers disabled (v27); submit a UTXO spend via /api/v1/utxo/submit"
                    .into(),
            );
        }
        let from_pubkey = hex::decode(&req.from_pubkey).map_err(|_| "Invalid from_pubkey hex")?;
        let signature = hex::decode(&req.signature).map_err(|_| "Invalid signature hex")?;

        let mut tx = TransparentTx::new_with_fee(
            from_pubkey,
            req.to,
            req.amount,
            req.fee,
            req.nonce,
            req.chain_id,
        );
        tx.signature = signature;

        let tx_hash = tx.tx_hash();
        let mut state = self.write();
        state.admit_transparent_to_mempool(tx)?;

        Ok(TxSubmitResponse {
            tx_hash: hex::encode(tx_hash),
            status: "pending".into(),
        })
    }

    /// Compares the classic linear pruning-point proof against the succinct
    /// multi-level (superblock/interlink) one on THIS node's actual current
    /// chain — a live demonstration of the compression `superproof` buys,
    /// not just a synthetic benchmark. `None` fields mean this node can't
    /// serve a proof yet (no pruning point, or not archival).
    pub fn pruning_proof_stats(&self) -> serde_json::Value {
        let s = self.read();
        let linear = s.build_pruning_proof();
        let multilevel = s.build_multilevel_pruning_proof(crate::PRUNING_PROOF_RECENT_WINDOW);
        let linear_headers = linear.as_ref().map(|p| p.headers.len());
        let multilevel_summary = multilevel
            .as_ref()
            .and_then(|p| crate::superproof::verify_multilevel_pruning_proof(p).ok());
        serde_json::json!({
            "archival": s.archival,
            "pruning_point": s.pruning_point.map(hex::encode),
            "linear_proof_headers": linear_headers,
            "multilevel_proof_headers": multilevel_summary.as_ref().map(|sm| sm.header_count),
            "multilevel_recent_headers": multilevel.as_ref().map(|p| p.recent_headers.len()),
            "multilevel_hops": multilevel.as_ref().map(|p| p.hops.len()),
            "compression_ratio": match (linear_headers, multilevel_summary.as_ref()) {
                (Some(l), Some(sm)) if sm.header_count > 0 => {
                    Some(format!("{:.1}x", l as f64 / sm.header_count as f64))
                }
                _ => None,
            },
            "verified_work": multilevel_summary.as_ref().map(|sm| sm.verified_work.to_string()),
            "estimated_total_work": multilevel_summary.as_ref().map(|sm| sm.estimated_total_work.to_string()),
        })
    }

    /// Verification Economics: the fee market reframed as the cost/reward
    /// spread for ledger verification (bid/ask-style spread for settlement
    /// priority). Same underlying data as [`Self::fee_estimate`].
    pub fn verification_economics(&self) -> serde_json::Value {
        let s = self.read();
        serde_json::to_value(crate::economics::VerificationEconomics::snapshot(&s))
            .unwrap_or(serde_json::json!({}))
    }

    /// Fee-market snapshot: confirmation-target estimates (high≈6 / medium≈20 /
    /// low≈100 blues) via history success-walk when available (mempool waiters
    /// past the target count as failures), else mempool percentiles, floored at
    /// the current relay minimum with monotonic tiers. See [`crate::ChainState::estimate_fee`].
    pub fn fee_estimate(&self) -> serde_json::Value {
        let s = self.read();
        let est = s.estimate_fee();
        serde_json::json!({
            "low": est.low.to_string(),
            "medium": est.medium.to_string(),
            "high": est.high.to_string(),
            "high_target_blues": est.high_target_blues,
            "medium_target_blues": est.medium_target_blues,
            "low_target_blues": est.low_target_blues,
            "min_relay_fee": s.current_min_relay_fee().to_string(),
            "protocol_min_fee": crate::MIN_TX_FEE.to_string(),
            "mempool_txs": est.mempool_txs,
            "mempool_utxo": s.utxo_mempool.len(),
            "package_count": est.package_count,
            "best_package_fee": est.best_package_fee.to_string(),
            "fee_history_blocks": s.fee_history.samples.len(),
        })
    }

    /// getblocktemplate-equivalent: parents, difficulty, commitments, selected txs.
    pub fn get_block_template(&self) -> serde_json::Value {
        let s = self.read();
        let mut parents = s.tips.clone();
        parents.sort_by(|a, b| {
            let sa = s.ghostdag.get(a).map(|d| d.blue_score).unwrap_or(0);
            let sb = s.ghostdag.get(b).map(|d| d.blue_score).unwrap_or(0);
            sb.cmp(&sa).then_with(|| b.cmp(a))
        });
        parents.truncate(crate::MAX_BLOCK_PARENTS);
        let timestamp = crate::now_ms();
        let difficulty = s.expected_difficulty_at(&parents, timestamp);
        let txs = s.select_valid_block_txs(&s.transparent_mempool);
        let utxo_txs = s.select_valid_utxo_txs(&s.utxo_mempool);
        let sp = crate::ghostdag::select_parent(&s.ghostdag, &parents);
        let state_hint = sp.map(|h| hex::encode(s.merkle_root_at(&h)));
        serde_json::json!({
            "version": crate::STATE_FORMAT_VERSION,
            "chain_id": s.chain_id,
            "chain_hash": crate::chain_hash_hex(),
            "genesis_domain": String::from_utf8_lossy(crate::GENESIS_DOMAIN),
            "height": s.tip_height().saturating_add(1),
            "blue_score_hint": s.selected_tip_blue_score().saturating_add(1),
            "timestamp": timestamp,
            "difficulty": difficulty,
            "parents": parents.iter().map(hex::encode).collect::<Vec<_>>(),
            "selected_parent": sp.map(hex::encode),
            "state_root_hint": state_hint,
            "past_median_time": sp.map(|h| s.past_median_time(&h)),
            "transactions": txs.iter().map(|tx| {
                serde_json::json!({
                    "tx_hash": hex::encode(tx.tx_hash()),
                    "fee": tx.fee.to_string(),
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "nonce": tx.nonce,
                    "lock_blue_score": tx.lock_blue_score,
                    "relative_lock_blues": tx.relative_lock_blues,
                })
            }).collect::<Vec<_>>(),
            "utxo_transactions": utxo_txs.iter().map(|tx| {
                serde_json::json!({
                    "txid": hex::encode(tx.txid()),
                    "wtxid": hex::encode(tx.wtxid()),
                    "fee": tx.fee.to_string(),
                    "inputs": tx.inputs.len(),
                    "outputs": tx.outputs.len(),
                    "from": tx.from_address(),
                    "relay_bytes": tx.relay_bytes(),
                })
            }).collect::<Vec<_>>(),
            "min_relay_fee": s.current_min_relay_fee().to_string(),
            "kernel_rules_id": hex::encode(crate::kernel::kernel_rules_id()),
            "utxo_set_size": s.utxo.entries.len(),
            "utxo_commitment": hex::encode(s.utxo.commitment()),
        })
    }

    /// Supply audit: minted vs account+utxo overlays (hybrid).
    pub fn get_supply(&self) -> serde_json::Value {
        let s = self.read();
        let account_sum: u128 = s.accounts.values().map(|a| a.balance).sum();
        let utxo_sum = s.utxo.total_value();
        let staked_sum: u128 = s.staked.values().copied().sum();
        serde_json::json!({
            "minted_supply": s.minted_supply.to_string(),
            "max_supply": crate::MAX_SUPPLY.to_string(),
            "account_balances": account_sum.to_string(),
            "utxo_value": utxo_sum.to_string(),
            "staked": staked_sum.to_string(),
            "fees_burned": s.fees_burned.to_string(),
            "fee_policy": "v26+ fees pay miner coinbase; fees_burned legacy (0 on fresh)",
            "cumulative_issuance_at_tip": crate::cumulative_issuance(s.selected_tip_blue_score()).to_string(),
            "hybrid_ledger_note": "v27: peer value is UTXO-only (ACCOUNT_PEER_TRANSFERS=false). Accounts remain for registry/custody; fund via CreditAccount; bridge_account_to_utxo returns overlay→UTXO. supply_invariant_ok must hold.",
            "account_peer_transfers": crate::ACCOUNT_PEER_TRANSFERS,
        })
    }

    pub fn mempool_txs(&self) -> Vec<serde_json::Value> {
        let s = self.read();
        let mut out: Vec<serde_json::Value> = s
            .transparent_mempool
            .iter()
            .map(|tx| {
                let tip = s.account_nonce(&tx.from);
                let ancestors: u64 = if tx.nonce >= tip {
                    tx.nonce - tip + 1
                } else {
                    0
                };
                let pkg_fee: u128 = s
                    .transparent_mempool
                    .iter()
                    .filter(|t| t.from == tx.from && t.nonce >= tip && t.nonce <= tx.nonce)
                    .map(|t| t.fee)
                    .sum();
                serde_json::json!({
                    "type": "transparent",
                    "tx_hash": hex::encode(tx.tx_hash()),
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "nonce": tx.nonce,
                    "relay_bytes": tx.relay_bytes(),
                    "ancestor_count": ancestors,
                    "ancestor_fees": pkg_fee.to_string(),
                    "feerate": if tx.relay_bytes() > 0 {
                        tx.fee / tx.relay_bytes() as u128
                    } else {
                        0
                    }.to_string(),
                })
            })
            .collect();
        for tx in &s.utxo_mempool {
            let bytes = tx.relay_bytes().max(1);
            out.push(serde_json::json!({
                "type": "utxo",
                "txid": hex::encode(tx.txid()),
                "wtxid": hex::encode(tx.wtxid()),
                "from": tx.from_address(),
                "fee": tx.fee.to_string(),
                "inputs": tx.inputs.len(),
                "outputs": tx.outputs.len(),
                "relay_bytes": bytes,
                "feerate": (tx.fee / bytes as u128).to_string(),
            }));
        }
        out
    }

    /// GHOSTDAG metadata for a block.
    pub fn ghostdag_info(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (h, _) = Self::resolve_block(&s, id)?;
        let gd = s.ghostdag.get(&h)?;
        Some(serde_json::json!({
            "hash": hex::encode(h),
            "blue_score": gd.blue_score,
            "selected_parent": gd.selected_parent.map(hex::encode),
            "mergeset_blues": gd.mergeset_blues.iter().map(hex::encode).collect::<Vec<_>>(),
            "mergeset_reds": gd.mergeset_reds.iter().map(hex::encode).collect::<Vec<_>>(),
            "is_blue_on_selected": s.main_chain.contains(&h),
        }))
    }

    /// Soft-upgrade version bits status.
    pub fn version_bits(&self) -> serde_json::Value {
        self.read().version_bits_status().status_json()
    }

    /// UTXOs locked to an address (PayToAddress / AbsoluteLock / RelativeLock)
    /// plus MultiSig / BDPE vaults that mention the address.
    /// Accepts bech32m or legacy hex; matches either encoding of the same key.
    pub fn list_utxos(&self, address: &str) -> serde_json::Value {
        let s = self.read();
        let mut outs = Vec::new();
        for (op, out) in &s.utxo.entries {
            let involved = out
                .predicate
                .locked_address()
                .is_some_and(|a| crate::address::addresses_equivalent(a, address))
                || crate::bdpe::predicate_involves_address(&out.predicate, address);
            if involved {
                let vault = crate::bdpe::parse_vault_predicate(&out.predicate);
                outs.push(serde_json::json!({
                    "txid": hex::encode(op.txid),
                    "vout": op.vout,
                    "value": out.value.to_string(),
                    "created_blue": out.created_blue,
                    "coinbase": op.is_coinbase(),
                    "predicate": format!("{:?}", out.predicate),
                    "bdpe_vault": vault.as_ref().map(|(b, sell, t)| serde_json::json!({
                        "buyer": b,
                        "seller": sell,
                        "timeout_blue": t,
                    })),
                }));
            }
        }
        serde_json::json!({ "address": address, "utxos": outs })
    }

    /// List live BDPE vault UTXOs (optionally filtered by party address).
    pub fn list_bdpe_vaults(&self, address: Option<&str>, limit: usize) -> Vec<serde_json::Value> {
        let s = self.read();
        let mut out = Vec::new();
        for (op, u) in &s.utxo.entries {
            let Some((buyer, seller, timeout_blue)) =
                crate::bdpe::parse_vault_predicate(&u.predicate)
            else {
                continue;
            };
            if let Some(addr) = address {
                if !crate::address::addresses_equivalent(&buyer, addr)
                    && !crate::address::addresses_equivalent(&seller, addr)
                {
                    continue;
                }
            }
            out.push(serde_json::json!({
                "txid": hex::encode(op.txid),
                "vout": op.vout,
                "value": u.value.to_string(),
                "created_blue": u.created_blue,
                "buyer": buyer,
                "seller": seller,
                "timeout_blue": timeout_blue,
                "media_blue": s.selected_tip_blue_score(),
                "timeout_reached": s.selected_tip_blue_score() >= timeout_blue,
                "status": if s.selected_tip_blue_score() >= timeout_blue {
                    "claimable"
                } else {
                    "funded"
                },
            }));
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    /// Admit a signed UTXO spend (BDPE fund/settle/refund/timeout + payments).
    pub fn submit_utxo_tx(&self, tx: crate::utxo_tx::UtxoTx) -> Result<serde_json::Value, String> {
        let txid = hex::encode(tx.txid());
        let wtxid = hex::encode(tx.wtxid());
        let mut s = self.write();
        s.admit_utxo_to_mempool(tx)?;
        Ok(serde_json::json!({
            "status": "accepted",
            "txid": txid,
            "wtxid": wtxid,
        }))
    }

    /// Light-client tip + selected-chain tail + interlink skips + UTXO commit.
    pub fn light_tip(&self, n: usize) -> serde_json::Value {
        let s = self.read();
        let tip = s.main_chain.last().copied();
        let tip_block = tip.and_then(|h| s.dag.get(&h));
        let chain: Vec<_> = s
            .main_chain
            .iter()
            .rev()
            .take(n)
            .map(|h| {
                let gd = s.ghostdag.get(h);
                let b = s.dag.get(h);
                serde_json::json!({
                    "hash": hex::encode(h),
                    "blue_score": gd.map(|d| d.blue_score),
                    "selected_parent": gd.and_then(|d| d.selected_parent.map(hex::encode)),
                    "mergeset_blues": gd.map(|d| d.mergeset_blues.len()).unwrap_or(0),
                    "mergeset_reds": gd.map(|d| d.mergeset_reds.len()).unwrap_or(0),
                    "state_root": b.map(|blk| hex::encode(blk.state_root)),
                    "interlinks": b.map(|blk| {
                        blk.interlinks.iter().map(hex::encode).collect::<Vec<_>>()
                    }).unwrap_or_default(),
                })
            })
            .collect();
        let pp = s.pruning_point.map(hex::encode);
        serde_json::json!({
            "tip": tip.map(hex::encode),
            "blue_score": s.selected_tip_blue_score(),
            "selected_chain_tail": chain,
            "utxo_commitment": hex::encode(s.utxo.commitment()),
            "state_root": tip_block.map(|b| hex::encode(b.state_root)),
            "pruning_point": pp,
            "supply_ok": s.supply_invariant_ok(),
            "kernel_rules": hex::encode(crate::kernel::kernel_rules_id()),
        })
    }

    /// Server-Sent Events snapshot (poll-friendly tip+mempool pulse).
    pub fn events_snapshot(&self) -> serde_json::Value {
        let s = self.read();
        serde_json::json!({
            "type": "tip",
            "height": s.tip_height(),
            "blue_score": s.selected_tip_blue_score(),
            "tip": s.main_chain.last().map(hex::encode),
            "mempool": s.transparent_mempool.len() + s.utxo_mempool.len(),
            "mempool_utxo": s.utxo_mempool.len(),
            "tips": s.tips.iter().map(hex::encode).collect::<Vec<_>>(),
            "ts_ms": crate::now_ms(),
        })
    }

    pub fn account(&self, address: &str) -> serde_json::Value {
        let s = self.read();
        let acct = s.accounts.iter().find_map(|(k, v)| {
            if crate::address::addresses_equivalent(k, address) {
                Some(v)
            } else {
                None
            }
        });
        let titles = s
            .registry
            .titles
            .values()
            .filter(|d| crate::address::addresses_equivalent(&d.current_owner, address))
            .count();
        let utxo_sum: u128 = s
            .utxo
            .entries
            .values()
            .filter(|o| {
                o.predicate
                    .locked_address()
                    .is_some_and(|a| crate::address::addresses_equivalent(a, address))
            })
            .map(|o| o.value)
            .sum();
        serde_json::json!({
            "address": address,
            "balance": acct.map(|a| a.balance).unwrap_or(0).to_string(),
            "utxo_value": utxo_sum.to_string(),
            "nonce": acct.map(|a| a.nonce).unwrap_or(0),
            "titles_held": titles,
            "bech32m": crate::address::is_bech32m_address(address),
            "chain_id": s.chain_id,
            "chain_hash": crate::chain_hash_hex(),
        })
    }

    pub fn submit_transfer(&self, tx: crate::TransparentTx) -> Result<serde_json::Value, String> {
        let tx_hash = hex::encode(tx.tx_hash());
        let abs = tx.abs_signature();
        let mut s = self.write();
        s.admit_transparent_to_mempool(tx)?;
        Ok(serde_json::json!({
            "status": "accepted",
            "tx_hash": tx_hash,
            "abs_signature": abs,
        }))
    }

    pub fn submit_registry_op(
        &self,
        op: crate::registry::RegistryOp,
    ) -> Result<serde_json::Value, String> {
        let op_hash = hex::encode(op.op_hash());
        let mut s = self.write();
        s.admit_registry_to_mempool(op)?;
        Ok(serde_json::json!({ "status": "accepted", "op_hash": op_hash }))
    }

    /// Submit an on-chain custody certificate (stake lock/unlock, bridge).
    pub fn submit_custody(
        &self,
        op: crate::custody::CustodyCertificate,
    ) -> Result<serde_json::Value, String> {
        let fp = hex::encode(crate::custody::custody_fingerprint(&op));
        let mut s = self.write();
        s.admit_custody_to_mempool(op)?;
        Ok(serde_json::json!({ "status": "accepted", "fingerprint512": fp }))
    }

    /// Verify a custody certificate (stake / bridge) against its Birth Certificate.
    pub fn verify_custody(
        &self,
        cert: &crate::custody::CustodyCertificate,
    ) -> Result<serde_json::Value, String> {
        let sid_bytes: [u8; 64] = hex::decode(&cert.settlement_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "settlement_id must be 64 bytes hex".to_string())?;
        cert.verify(&sid_bytes)?;
        if let Ok(mut g) = crate::ai_trace::global_trace().lock() {
            g.record_custody(cert);
        }
        Ok(serde_json::json!({
            "status": "verified",
            "kind": format!("{:?}", cert.kind),
            "birth_ok": true,
            "settlement_id": cert.settlement_id,
            "fingerprint512": hex::encode(crate::custody::custody_fingerprint(cert)),
        }))
    }

    pub fn verify_custody_round_trip(
        &self,
        exit_or_lock: &crate::custody::CustodyCertificate,
        enter_or_unlock: &crate::custody::CustodyCertificate,
    ) -> Result<serde_json::Value, String> {
        crate::custody::verify_round_trip(exit_or_lock, enter_or_unlock)?;
        Ok(serde_json::json!({
            "status": "round_trip_verified",
            "exit_kind": format!("{:?}", exit_or_lock.kind),
            "enter_kind": format!("{:?}", enter_or_unlock.kind),
        }))
    }

    /// AI-readable recent block/custody events (every step, PQ digests).
    pub fn ai_trace(&self, n: usize) -> serde_json::Value {
        let g = crate::ai_trace::global_trace();
        let log = g.lock().unwrap();
        serde_json::json!({
            "events": log.recent(n),
            "tip_digest512": log.tip_digest512(),
            "signature_scheme": "ML-DSA-87",
            "digest_bits": 512,
        })
    }

    pub fn ai_trace_block(&self, hash_hex: &str) -> serde_json::Value {
        let g = crate::ai_trace::global_trace();
        let log = g.lock().unwrap();
        serde_json::json!({
            "block": hash_hex,
            "events": log.for_block(hash_hex),
        })
    }

    /// Full block body dump for audit (every consensus field the node still holds).
    pub fn audit_block_dump(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (hash, b) = Self::resolve_block(&s, id)?;
        let gd = s.ghostdag.get(&hash);
        let height = s
            .main_chain
            .iter()
            .position(|h| h == &hash)
            .map(|i| s.pruned_selected_blocks + i as u64)
            .unwrap_or(b.height);
        Some(serde_json::json!({
            "hash": hex::encode(hash),
            "height": height,
            "timestamp": b.timestamp,
            "parents": b.parents.iter().map(hex::encode).collect::<Vec<_>>(),
            "interlinks": b.interlinks.iter().map(hex::encode).collect::<Vec<_>>(),
            "transparent_txs": b.transparent_txs.iter().map(|tx| {
                serde_json::json!({
                    "tx_hash": hex::encode(tx.tx_hash()),
                    "from": tx.from,
                    "to": tx.to,
                    "amount": tx.amount.to_string(),
                    "fee": tx.fee.to_string(),
                    "nonce": tx.nonce,
                    "chain_id": tx.chain_id,
                    "from_pubkey": hex::encode(&tx.from_pubkey),
                    "signature": hex::encode(&tx.signature),
                    "lock_blue_score": tx.lock_blue_score,
                    "relative_lock_blues": tx.relative_lock_blues,
                    "relay_bytes": tx.relay_bytes(),
                })
            }).collect::<Vec<_>>(),
            "utxo_txs": b.utxo_txs.iter().map(|tx| {
                serde_json::to_value(tx).unwrap_or(serde_json::json!({"error":"serialize"}))
            }).collect::<Vec<_>>(),
            "registry_ops": b.registry_ops.iter().map(|op| {
                serde_json::to_value(op).unwrap_or(serde_json::json!({"error":"serialize"}))
            }).collect::<Vec<_>>(),
            "custody_ops": b.custody_ops.iter().map(|op| {
                serde_json::to_value(op).unwrap_or(serde_json::json!({"error":"serialize"}))
            }).collect::<Vec<_>>(),
            "merkle_root": hex::encode(b.merkle_root),
            "state_root": hex::encode(b.state_root),
            "miner": crate::address::encode_hash(&b.miner),
            "creator_pubkey": hex::encode(&b.creator_pubkey),
            "nonce": b.nonce,
            "difficulty": b.difficulty,
            "version": b.version,
            "coinbase_entropy": b.coinbase_entropy,
            "stark_proof_hex": hex::encode(&b.stark_proof),
            "stark_proof_bytes": b.stark_proof.len(),
            "stark_kind": "sequential_work_companion",
            "stark_is_validity_zk": false,
            "birth_certificate": hex::encode(&b.birth_certificate.signature),
            "settlement_id": b.settlement_id().to_hex(),
            "size": b.size,
            "ghostdag": gd.map(|d| serde_json::json!({
                "blue_score": d.blue_score,
                "selected_parent": d.selected_parent.map(hex::encode),
                "mergeset_blues": d.mergeset_blues.iter().map(hex::encode).collect::<Vec<_>>(),
                "mergeset_reds": d.mergeset_reds.iter().map(hex::encode).collect::<Vec<_>>(),
            })),
            "is_chain_block": s.main_chain.contains(&hash),
            "birth_ok": b.verify_issuance().is_ok(),
        }))
    }

    /// Mergeset edge list for GHOSTDAG visualization.
    pub fn mergeset_edges(&self, id: &str) -> Option<serde_json::Value> {
        let s = self.read();
        let (hash, b) = Self::resolve_block(&s, id)?;
        let gd = s.ghostdag.get(&hash)?;
        let mut edges = Vec::new();
        for p in &b.parents {
            edges.push(serde_json::json!({
                "from": hex::encode(p),
                "to": hex::encode(hash),
                "kind": if gd.selected_parent == Some(*p) { "selected_parent" } else { "parent" },
            }));
        }
        for blue in &gd.mergeset_blues {
            if Some(*blue) != gd.selected_parent {
                edges.push(serde_json::json!({
                    "from": hex::encode(blue),
                    "to": hex::encode(hash),
                    "kind": "mergeset_blue",
                }));
            }
        }
        for red in &gd.mergeset_reds {
            edges.push(serde_json::json!({
                "from": hex::encode(red),
                "to": hex::encode(hash),
                "kind": "mergeset_red",
            }));
        }
        Some(serde_json::json!({
            "hash": hex::encode(hash),
            "blue_score": gd.blue_score,
            "selected_parent": gd.selected_parent.map(hex::encode),
            "mergeset_blues": gd.mergeset_blues.iter().map(hex::encode).collect::<Vec<_>>(),
            "mergeset_reds": gd.mergeset_reds.iter().map(hex::encode).collect::<Vec<_>>(),
            "edges": edges,
            "is_chain_block": s.main_chain.contains(&hash),
        }))
    }

    /// Replayable state-root / tip diff between two heights or blue scores.
    pub fn audit_diff(&self, from: &str, to: &str) -> serde_json::Value {
        let s = self.read();
        let resolve = |spec: &str| -> Option<(u64, Hash, Option<&crate::Block>)> {
            if let Some(rest) = spec.strip_prefix("blue:") {
                let bs: u64 = rest.parse().ok()?;
                let (i, h) = s.main_chain.iter().enumerate().find(|(_, h)| {
                    s.ghostdag.get(*h).map(|d| d.blue_score == bs).unwrap_or(false)
                })?;
                let height = s.pruned_selected_blocks + i as u64;
                return Some((height, *h, s.dag.get(h)));
            }
            let (h, b) = Self::resolve_block(&s, spec)?;
            let height = s
                .main_chain
                .iter()
                .position(|x| x == &h)
                .map(|i| s.pruned_selected_blocks + i as u64)
                .unwrap_or(b.height);
            Some((height, h, Some(b)))
        };
        let Some((fh, fhash, fb)) = resolve(from) else {
            return serde_json::json!({"error": "from not found", "from": from});
        };
        let Some((th, thash, tb)) = resolve(to) else {
            return serde_json::json!({"error": "to not found", "to": to});
        };
        let chain_slice: Vec<_> = s
            .main_chain
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                let h = s.pruned_selected_blocks + *i as u64;
                h > fh.min(th) && h <= fh.max(th)
            })
            .map(|(i, h)| {
                let height = s.pruned_selected_blocks + i as u64;
                let b = s.dag.get(h);
                serde_json::json!({
                    "height": height,
                    "hash": hex::encode(h),
                    "blue_score": s.ghostdag.get(h).map(|d| d.blue_score),
                    "state_root": b.map(|blk| hex::encode(blk.state_root)),
                    "transfers": b.map(|blk| blk.transparent_txs.len()).unwrap_or(0),
                })
            })
            .collect();
        serde_json::json!({
            "from": {
                "spec": from,
                "height": fh,
                "hash": hex::encode(fhash),
                "state_root": fb.map(|b| hex::encode(b.state_root)),
                "blue_score": s.ghostdag.get(&fhash).map(|d| d.blue_score),
            },
            "to": {
                "spec": to,
                "height": th,
                "hash": hex::encode(thash),
                "state_root": tb.map(|b| hex::encode(b.state_root)),
                "blue_score": s.ghostdag.get(&thash).map(|d| d.blue_score),
            },
            "height_delta": th as i64 - fh as i64,
            "state_root_changed": fb.map(|b| hex::encode(b.state_root)) != tb.map(|b| hex::encode(b.state_root)),
            "selected_chain_steps": chain_slice,
        })
    }

    /// Bounded UTXO set snapshot (cap entries to avoid huge responses).
    pub fn utxo_snapshot(&self, limit: usize) -> serde_json::Value {
        let s = self.read();
        let lim = limit.clamp(1, 2_000);
        let mut entries = Vec::new();
        for (op, out) in s.utxo.entries.iter().take(lim) {
            entries.push(serde_json::json!({
                "txid": hex::encode(op.txid),
                "vout": op.vout,
                "value": out.value.to_string(),
                "created_blue": out.created_blue,
                "coinbase": op.is_coinbase(),
                "predicate": format!("{:?}", out.predicate),
                "locked_address": out.predicate.locked_address(),
            }));
        }
        serde_json::json!({
            "utxo_commitment": hex::encode(s.utxo.commitment()),
            "total_entries": s.utxo.entries.len(),
            "returned": entries.len(),
            "truncated": s.utxo.entries.len() > lim,
            "entries": entries,
        })
    }

    /// Fee history export (confirmation-target samples).
    pub fn fee_history_export(&self) -> serde_json::Value {
        let s = self.read();
        serde_json::json!({
            "max_blocks": s.fee_history.max_blocks,
            "samples": s.fee_history.samples.iter().map(|sm| {
                serde_json::json!({
                    "blue_score": sm.blue_score,
                    "feerates": sm.feerates.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                    "confirm_blues": sm.confirm_blues,
                })
            }).collect::<Vec<_>>(),
        })
    }

    /// Full pruning proof bytes (linear and/or multilevel) for download.
    pub fn pruning_proof_download(&self) -> serde_json::Value {
        let s = self.read();
        let linear = s.build_pruning_proof();
        let multilevel = s.build_multilevel_pruning_proof(crate::PRUNING_PROOF_RECENT_WINDOW);
        let linear_bytes = linear
            .as_ref()
            .and_then(|p| bincode::serialize(p).ok())
            .map(hex::encode);
        let multilevel_bytes = multilevel
            .as_ref()
            .and_then(|p| bincode::serialize(p).ok())
            .map(hex::encode);
        let multilevel_json = multilevel
            .as_ref()
            .and_then(|p| serde_json::to_value(p).ok());
        serde_json::json!({
            "archival": s.archival,
            "pruning_point": s.pruning_point.map(hex::encode),
            "linear_proof_hex": linear_bytes,
            "linear_headers": linear.as_ref().map(|p| p.headers.len()),
            "multilevel_proof_hex": multilevel_bytes,
            "multilevel": multilevel_json,
            "stats": self.pruning_proof_stats(),
        })
    }

    /// Multi-section audit pack (JSON). Client may save as a single file.
    pub fn audit_pack(&self, block_id: Option<&str>) -> serde_json::Value {
        let s = self.read();
        let tip = s.main_chain.last().copied();
        let tip_id = tip.map(hex::encode);
        let block_dump = block_id
            .or(tip_id.as_deref())
            .and_then(|id| self.audit_block_dump(id));
        serde_json::json!({
            "generated_at_ms": crate::now_ms(),
            "crate_version": env!("CARGO_PKG_VERSION"),
            "genesis_domain": String::from_utf8_lossy(crate::GENESIS_DOMAIN),
            "status": self.status(),
            "supply": self.get_supply(),
            "network": self.network(),
            "fee_estimate": self.fee_estimate(),
            "fee_history": self.fee_history_export(),
            "pruning": self.pruning_proof_download(),
            "light_tip": self.light_tip(16),
            "utxo_snapshot": self.utxo_snapshot(256),
            "block": block_dump,
            "kernel_rules": hex::encode(crate::kernel::kernel_rules_id()),
        })
    }

    /// Enrich get_block with mergeset sizes when available (backward compatible).
    pub fn get_block_rich(&self, id: &str) -> Option<serde_json::Value> {
        let mut v = self.get_block(id)?;
        if let Some(obj) = v.as_object_mut() {
            if let Some(ms) = self.mergeset_edges(id) {
                obj.insert("mergeset_blues".into(), ms["mergeset_blues"].clone());
                obj.insert("mergeset_reds".into(), ms["mergeset_reds"].clone());
                obj.insert("mergeset_edges".into(), ms["edges"].clone());
            }
            if let Some(dump) = self.audit_block_dump(id) {
                obj.insert("stark_proof_bytes".into(), dump["stark_proof_bytes"].clone());
                obj.insert("coinbase_entropy".into(), dump["coinbase_entropy"].clone());
                obj.insert("interlinks".into(), dump["interlinks"].clone());
                obj.insert("registry_ops_detail".into(), dump["registry_ops"].clone());
                obj.insert("custody_ops_detail".into(), dump["custody_ops"].clone());
                obj.insert("utxo_txs_detail".into(), dump["utxo_txs"].clone());
            }
        }
        Some(v)
    }
}

#[cfg(test)]
mod audit_api_tests {
    use super::*;
    use crate::ChainState;
    use std::sync::{Arc, RwLock};

    #[test]
    fn audit_pack_and_utxo_snapshot_on_genesis() {
        let api = ApiServer::new(Arc::new(RwLock::new(ChainState::new())));
        let pack = api.audit_pack(None);
        assert!(pack.get("status").is_some());
        assert!(pack.get("supply").is_some());
        assert!(pack.get("pruning").is_some());
        let snap = api.utxo_snapshot(10);
        assert!(snap["returned"].as_u64().unwrap() <= 10);
        let fees = api.fee_history_export();
        assert!(fees.get("samples").is_some());
    }

    #[test]
    fn mergeset_and_diff_on_genesis_tip() {
        let state = ChainState::new();
        let tip = state.main_chain.last().map(hex::encode).expect("genesis");
        let api = ApiServer::new(Arc::new(RwLock::new(state)));
        let ms = api.mergeset_edges(&tip).expect("mergeset");
        assert!(ms.get("edges").is_some());
        let dump = api.audit_block_dump("0").expect("dump");
        assert_eq!(dump["height"], 0);
        let diff = api.audit_diff("0", "0");
        assert_eq!(diff["height_delta"], 0);
    }
}
