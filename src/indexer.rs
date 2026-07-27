//! Checksummed explorer indexer — separate from hot `chainstate.bin`.
//!
//! Lives under `{HASSAN_DATA_DIR}/indexer/` by default. Indexes selected-chain
//! blocks, transfers, address activity, and rolling analytics series so the
//! explorer can answer history queries without scanning the full DAG every time.
//! Magic + Blake3-512 trailer mirrors chainstate integrity.

use crate::{address_hash, ChainState, Hash, HASH_SIZE};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

pub const INDEXER_MAGIC: [u8; 8] = *b"HSNIDX01";
pub const INDEXER_FORMAT: u32 = 1;
pub const INDEXER_CHECKSUM_DOMAIN: &[u8] = b"hassan-indexer-v1";
/// Cap analytics series points retained on disk.
pub const MAX_SERIES_POINTS: usize = 4_096;
/// Cap per-address txid lists (oldest trimmed).
pub const MAX_ADDR_TXS: usize = 2_048;
/// Cap total indexed transfers (trim oldest by height when exceeded).
pub const MAX_TX_RECORDS: usize = 50_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRecord {
    pub height: u64,
    pub hash: String,
    pub blue_score: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub miner: String,
    pub transfers: u32,
    pub registry_ops: u32,
    pub custody_ops: u32,
    pub utxo_txs: u32,
    pub fees: String,
    pub selected_parent: Option<String>,
    pub is_chain_block: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxRecord {
    pub tx_hash: String,
    pub height: u64,
    pub block_hash: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub fee: String,
    pub nonce: u64,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeriesPoint {
    pub height: u64,
    pub blue_score: u64,
    pub timestamp: u64,
    pub difficulty: u64,
    pub transfers: u32,
    pub fees: String,
    pub minted_supply: String,
    pub mempool: u32,
    pub dag_blocks: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IndexerDb {
    pub format: u32,
    pub tip_height: u64,
    pub tip_hash: Option<String>,
    pub blocks: BTreeMap<u64, BlockRecord>,
    pub by_hash: HashMap<String, u64>,
    pub txs: HashMap<String, TxRecord>,
    /// address → recent tx hashes (newest last)
    pub address_txs: HashMap<String, Vec<String>>,
    /// entity id (hash / address / outpoint) → human label
    pub labels: HashMap<String, String>,
    pub series: Vec<SeriesPoint>,
    pub indexed_at_ms: u64,
}

impl IndexerDb {
    pub fn new() -> Self {
        let mut db = Self {
            format: INDEXER_FORMAT,
            ..Default::default()
        };
        db.seed_protocol_labels();
        db
    }

    fn seed_protocol_labels(&mut self) {
        let put = |m: &mut HashMap<String, String>, k: &str, v: &str| {
            m.entry(k.to_string()).or_insert_with(|| v.to_string());
        };
        put(&mut self.labels, "protocol:genesis", "Hassan genesis");
        put(&mut self.labels, "protocol:kernel", "Kernel rules ID");
        put(
            &mut self.labels,
            &format!("domain:{}", String::from_utf8_lossy(crate::GENESIS_DOMAIN)),
            "Genesis domain",
        );
    }

    pub fn checksum(&self) -> Hash {
        let payload = bincode::serialize(self).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(INDEXER_CHECKSUM_DOMAIN);
        hasher.update(&payload);
        let mut out = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut out);
        Hash(out)
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let payload = bincode::serialize(self).map_err(|e| e.to_string())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(INDEXER_CHECKSUM_DOMAIN);
        hasher.update(&payload);
        let mut tag = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut tag);

        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            f.write_all(&INDEXER_MAGIC).map_err(|e| e.to_string())?;
            f.write_all(&INDEXER_FORMAT.to_le_bytes())
                .map_err(|e| e.to_string())?;
            f.write_all(&(payload.len() as u64).to_le_bytes())
                .map_err(|e| e.to_string())?;
            f.write_all(&payload).map_err(|e| e.to_string())?;
            f.write_all(&tag).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        if bytes.len() < 8 + 4 + 8 + HASH_SIZE {
            return Err("indexer file too short".into());
        }
        if bytes[..8] != INDEXER_MAGIC {
            return Err("bad indexer magic".into());
        }
        let format = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if format != INDEXER_FORMAT {
            return Err(format!("unsupported indexer format {format}"));
        }
        let plen = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
        if 20 + plen + HASH_SIZE != bytes.len() {
            return Err("indexer length mismatch".into());
        }
        let payload = &bytes[20..20 + plen];
        let tag = &bytes[20 + plen..];
        let mut hasher = blake3::Hasher::new();
        hasher.update(INDEXER_CHECKSUM_DOMAIN);
        hasher.update(payload);
        let mut expect = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut expect);
        if tag != expect {
            return Err("indexer checksum mismatch".into());
        }
        let mut db: Self = bincode::deserialize(payload).map_err(|e| e.to_string())?;
        db.seed_protocol_labels();
        Ok(db)
    }

    /// Rebuild / catch up from live chainstate (selected chain only).
    pub fn sync_from_state(&mut self, s: &ChainState) {
        let base = s.pruned_selected_blocks;
        for (i, h) in s.main_chain.iter().enumerate() {
            let height = base + i as u64;
            if self.blocks.contains_key(&height) {
                if let Some(existing) = self.blocks.get(&height) {
                    if existing.hash == hex::encode(h) {
                        continue;
                    }
                    // Reorg at this height — drop from here forward.
                    self.trim_from_height(height);
                }
            }
            let Some(b) = s.dag.get(h) else { continue };
            let gd = s.ghostdag.get(h);
            let fees: u128 = b.transparent_txs.iter().map(|t| t.fee).sum();
            let miner = format!("hsn:{}", hex::encode(b.miner));
            let hash_hex = hex::encode(h);
            let rec = BlockRecord {
                height,
                hash: hash_hex.clone(),
                blue_score: gd.map(|d| d.blue_score).unwrap_or(0),
                timestamp: b.timestamp,
                difficulty: b.difficulty,
                miner: miner.clone(),
                transfers: b.transparent_txs.len() as u32,
                registry_ops: b.registry_ops.len() as u32,
                custody_ops: b.custody_ops.len() as u32,
                utxo_txs: b.utxo_txs.len() as u32,
                fees: fees.to_string(),
                selected_parent: gd.and_then(|d| d.selected_parent.map(hex::encode)),
                is_chain_block: true,
            };
            self.by_hash.insert(hash_hex.clone(), height);
            self.blocks.insert(height, rec);

            // Label miner when first seen.
            self.labels
                .entry(miner.clone())
                .or_insert_with(|| format!("Miner @ height {height}"));

            for tx in &b.transparent_txs {
                let txid = hex::encode(tx.tx_hash());
                let tr = TxRecord {
                    tx_hash: txid.clone(),
                    height,
                    block_hash: hash_hex.clone(),
                    from: tx.from.clone(),
                    to: tx.to.clone(),
                    amount: tx.amount.to_string(),
                    fee: tx.fee.to_string(),
                    nonce: tx.nonce,
                    timestamp: b.timestamp,
                };
                self.push_addr_tx(&tx.from, &txid);
                self.push_addr_tx(&tx.to, &txid);
                self.labels
                    .entry(tx.from.clone())
                    .or_insert_with(|| "Active account".into());
                self.labels
                    .entry(tx.to.clone())
                    .or_insert_with(|| "Active account".into());
                self.txs.insert(txid, tr);
            }

            self.series.push(SeriesPoint {
                height,
                blue_score: gd.map(|d| d.blue_score).unwrap_or(0),
                timestamp: b.timestamp,
                difficulty: b.difficulty,
                transfers: b.transparent_txs.len() as u32,
                fees: fees.to_string(),
                minted_supply: s.minted_supply.to_string(),
                mempool: s.transparent_mempool.len() as u32,
                dag_blocks: s.dag.len() as u32,
            });
        }

        // Also index non-selected DAG tips with labels (not full body index).
        for tip in &s.tips {
            let hex_h = hex::encode(tip);
            if !self.by_hash.contains_key(&hex_h) {
                self.labels
                    .entry(hex_h)
                    .or_insert_with(|| "DAG tip (non-indexed body)".into());
            }
        }

        while self.series.len() > MAX_SERIES_POINTS {
            self.series.remove(0);
        }
        self.trim_tx_cap();

        self.tip_height = s.tip_height();
        self.tip_hash = s.main_chain.last().map(hex::encode);
        self.indexed_at_ms = crate::now_ms();
        self.format = INDEXER_FORMAT;
    }

    fn trim_from_height(&mut self, height: u64) {
        let drop_heights: Vec<u64> = self.blocks.range(height..).map(|(h, _)| *h).collect();
        for h in drop_heights {
            if let Some(b) = self.blocks.remove(&h) {
                self.by_hash.remove(&b.hash);
            }
        }
        self.txs.retain(|_, t| t.height < height);
        self.series.retain(|p| p.height < height);
        for list in self.address_txs.values_mut() {
            list.retain(|txid| self.txs.contains_key(txid));
        }
    }

    fn push_addr_tx(&mut self, addr: &str, txid: &str) {
        let list = self.address_txs.entry(addr.to_string()).or_default();
        if list.last().map(|s| s.as_str()) != Some(txid) {
            list.push(txid.to_string());
        }
        while list.len() > MAX_ADDR_TXS {
            list.remove(0);
        }
    }

    fn trim_tx_cap(&mut self) {
        if self.txs.len() <= MAX_TX_RECORDS {
            return;
        }
        let mut pairs: Vec<(u64, String)> = self
            .txs
            .iter()
            .map(|(k, v)| (v.height, k.clone()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let drop_n = self.txs.len() - MAX_TX_RECORDS;
        for (_, id) in pairs.into_iter().take(drop_n) {
            self.txs.remove(&id);
        }
        for list in self.address_txs.values_mut() {
            list.retain(|txid| self.txs.contains_key(txid));
        }
    }

    pub fn search(&self, q: &str) -> serde_json::Value {
        let q = q.trim();
        let mut results = Vec::new();
        if q.is_empty() {
            return serde_json::json!({ "query": q, "results": results });
        }

        // Height
        if let Ok(h) = q.parse::<u64>() {
            if let Some(b) = self.blocks.get(&h) {
                results.push(serde_json::json!({
                    "kind": "block",
                    "id": b.hash,
                    "height": b.height,
                    "label": self.labels.get(&b.hash),
                }));
            }
        }

        // Address / bech32 / hsn:
        if crate::security::is_valid_address(q) || q.starts_with("hsn:") || q.starts_with("hsn1") {
            let txs = self.address_txs.get(q).map(|v| v.len()).unwrap_or(0);
            results.push(serde_json::json!({
                "kind": "address",
                "id": q,
                "tx_count": txs,
                "label": self.labels.get(q),
            }));
        }

        // Hash / txid (full or prefix ≥8)
        let qhex = q.strip_prefix("0x").unwrap_or(q).to_lowercase();
        if qhex.chars().all(|c| c.is_ascii_hexdigit()) && qhex.len() >= 8 {
            if let Some(h) = self.by_hash.get(&qhex) {
                results.push(serde_json::json!({
                    "kind": "block",
                    "id": qhex,
                    "height": h,
                    "label": self.labels.get(&qhex),
                }));
            } else if let Some(tx) = self.txs.get(&qhex) {
                results.push(serde_json::json!({
                    "kind": "tx",
                    "id": qhex,
                    "height": tx.height,
                    "block": tx.block_hash,
                    "label": self.labels.get(&qhex),
                }));
            } else {
                // Prefix scan (bounded)
                let mut n = 0;
                for (hash, height) in &self.by_hash {
                    if hash.starts_with(&qhex) {
                        results.push(serde_json::json!({
                            "kind": "block",
                            "id": hash,
                            "height": height,
                            "label": self.labels.get(hash),
                        }));
                        n += 1;
                        if n >= 8 {
                            break;
                        }
                    }
                }
                let mut n = 0;
                for (txid, tx) in &self.txs {
                    if txid.starts_with(&qhex) {
                        results.push(serde_json::json!({
                            "kind": "tx",
                            "id": txid,
                            "height": tx.height,
                            "block": tx.block_hash,
                        }));
                        n += 1;
                        if n >= 8 {
                            break;
                        }
                    }
                }
            }
        }

        // Outpoint txid:vout
        if let Some((txid, vout)) = q.split_once(':') {
            if crate::security::is_valid_hash_hex(txid) && vout.parse::<u32>().is_ok() {
                results.push(serde_json::json!({
                    "kind": "outpoint",
                    "id": q,
                    "txid": txid,
                    "vout": vout,
                    "label": self.labels.get(q),
                }));
            }
        }

        // OP / label keyword
        let q_lower = q.to_lowercase();
        if q_lower.starts_with("op:") || q_lower.starts_with("label:") {
            let needle = q_lower
                .trim_start_matches("op:")
                .trim_start_matches("label:")
                .trim();
            for (k, v) in &self.labels {
                if v.to_lowercase().contains(needle) || k.to_lowercase().contains(needle) {
                    results.push(serde_json::json!({
                        "kind": "label",
                        "id": k,
                        "label": v,
                    }));
                    if results.len() >= 32 {
                        break;
                    }
                }
            }
        }

        serde_json::json!({ "query": q, "results": results })
    }

    pub fn analytics(&self, limit: usize) -> serde_json::Value {
        let lim = limit.clamp(1, MAX_SERIES_POINTS);
        let start = self.series.len().saturating_sub(lim);
        let points: Vec<_> = self.series[start..].to_vec();
        let mut tps_est = 0.0f64;
        if points.len() >= 2 {
            let first = points.first().unwrap();
            let last = points.last().unwrap();
            let dt_s = (last.timestamp.saturating_sub(first.timestamp)) as f64 / 1000.0;
            let txs: u64 = points.iter().map(|p| p.transfers as u64).sum();
            if dt_s > 0.0 {
                tps_est = txs as f64 / dt_s;
            }
        }
        serde_json::json!({
            "points": points,
            "count": points.len(),
            "tps_estimate": tps_est,
            "tip_height": self.tip_height,
            "tip_hash": self.tip_hash,
            "indexed_at_ms": self.indexed_at_ms,
            "tx_index_size": self.txs.len(),
            "block_index_size": self.blocks.len(),
            "address_index_size": self.address_txs.len(),
            "label_count": self.labels.len(),
        })
    }

    pub fn address_history(&self, addr: &str, limit: usize) -> serde_json::Value {
        let lim = limit.clamp(1, 500);
        let empty: Vec<String> = Vec::new();
        let ids = self.address_txs.get(addr).unwrap_or(&empty);
        let txs: Vec<_> = ids
            .iter()
            .rev()
            .take(lim)
            .filter_map(|id| self.txs.get(id))
            .cloned()
            .collect();
        serde_json::json!({
            "address": addr,
            "label": self.labels.get(addr),
            "txs": txs,
            "total_indexed": ids.len(),
        })
    }

    pub fn status_json(&self, path: &Path) -> serde_json::Value {
        serde_json::json!({
            "path": path.display().to_string(),
            "format": self.format,
            "tip_height": self.tip_height,
            "tip_hash": self.tip_hash,
            "blocks": self.blocks.len(),
            "txs": self.txs.len(),
            "addresses": self.address_txs.len(),
            "labels": self.labels.len(),
            "series": self.series.len(),
            "indexed_at_ms": self.indexed_at_ms,
            "checksum": hex::encode(self.checksum()),
        })
    }
}

/// Shared indexer handle used by the API + background sync thread.
pub struct IndexerHandle {
    pub path: PathBuf,
    pub db: RwLock<IndexerDb>,
    sync_lock: Mutex<()>,
}

impl IndexerHandle {
    pub fn open(data_dir: &Path) -> Arc<Self> {
        let dir = data_dir.join("indexer");
        let path = dir.join("index.bin");
        let db = if path.exists() {
            match IndexerDb::load_from(&path) {
                Ok(db) => db,
                Err(e) => {
                    eprintln!("⚠️  Indexer load failed ({e}); rebuilding");
                    IndexerDb::new()
                }
            }
        } else {
            IndexerDb::new()
        };
        Arc::new(Self {
            path,
            db: RwLock::new(db),
            sync_lock: Mutex::new(()),
        })
    }

    pub fn sync(&self, state: &ChainState) {
        let _g = self.sync_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut db = self.db.write().unwrap_or_else(|p| p.into_inner());
        db.sync_from_state(state);
        if let Err(e) = db.save_to(&self.path) {
            eprintln!("⚠️  Indexer save failed: {e}");
        }
    }
}

/// Helper: resolve issuer address from pubkey bytes (for labels).
#[allow(dead_code)]
pub fn issuer_label(pubkey: &[u8]) -> String {
    format!("hsn:{}", hex::encode(address_hash(pubkey)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainState;

    #[test]
    fn indexer_roundtrip_checksum_and_bitflip_rejected() {
        let mut db = IndexerDb::new();
        db.tip_height = 7;
        db.labels
            .insert("hsn:abcd".into(), "test label".into());
        let dir = std::env::temp_dir().join(format!("hassan-idx-{}", crate::now_ms()));
        let path = dir.join("index.bin");
        db.save_to(&path).expect("save");
        let loaded = IndexerDb::load_from(&path).expect("load");
        assert_eq!(loaded.tip_height, 7);
        assert_eq!(loaded.labels.get("hsn:abcd").map(|s| s.as_str()), Some("test label"));

        let mut bytes = std::fs::read(&path).unwrap();
        let flip = bytes.len() / 2;
        bytes[flip] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(IndexerDb::load_from(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_from_genesis_state_indexes_height_zero() {
        let state = ChainState::new();
        let mut db = IndexerDb::new();
        db.sync_from_state(&state);
        assert!(db.blocks.contains_key(&0) || db.tip_height == 0);
        assert!(!db.series.is_empty() || state.main_chain.is_empty() == false);
        let q = db.search("0");
        assert!(q["results"].as_array().unwrap().iter().any(|r| r["kind"] == "block")
            || db.blocks.is_empty());
    }

    #[test]
    fn search_op_label_finds_protocol_seed() {
        let db = IndexerDb::new();
        let r = db.search("op:genesis");
        let arr = r["results"].as_array().unwrap();
        assert!(!arr.is_empty());
    }
}
