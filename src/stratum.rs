//! Stratum v1-lite + getblocktemplate helpers for external miners / pools.
//!
//! JSON-RPC style methods: `mining.subscribe`, `mining.authorize`,
//! `mining.notify`, `mining.submit`, plus share difficulty (vardiff).
//!
//! Worker auth: `mining.authorize` requires password matching
//! `HASSAN_STRATUM_PASSWORD`. Unauthenticated submits are rejected.

use crate::{Block, ChainState, Hash, HASH_SIZE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// Env var holding the shared stratum worker password / token.
pub const STRATUM_PASSWORD_ENV: &str = "HASSAN_STRATUM_PASSWORD";

/// Default share target difficulty (software-friendly for Blake3-512 PoW on
/// laptop / mobile CPUs). Full network difficulty remains era-gated.
pub const DEFAULT_SHARE_DIFFICULTY: u64 = 16;
pub const MIN_SHARE_DIFFICULTY: u64 = 1;
pub const MAX_SHARE_DIFFICULTY: u64 = 1_000_000;
/// Max authorized workers tracked in-process (DoS bound).
pub const MAX_STRATUM_WORKERS: usize = 256;
/// Max mining.submit calls per worker per rate window.
pub const MAX_SUBMITS_PER_WINDOW: u32 = 120;
/// Rate window length for submit budgets (ms).
pub const SUBMIT_WINDOW_MS: u64 = 60_000;
/// Consecutive low-diff / malformed rejects before temporary ban.
pub const MAX_CONSECUTIVE_REJECTS: u32 = 32;
/// Ban duration after hitting consecutive reject budget (ms).
pub const WORKER_BAN_MS: u64 = 60_000;
/// Jobs older than this are rejected (stale work / replay).
pub const MAX_JOB_AGE_MS: u64 = 120_000;
/// Max distinct nonces remembered per job (duplicate share filter).
pub const MAX_NONCES_PER_JOB: usize = 4_096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StratumShare {
    pub worker: String,
    pub job_id: String,
    pub nonce: u64,
    pub block_hash: Hash,
    pub difficulty: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug)]
struct WorkerState {
    authorized: bool,
    share_diff: u64,
    accepted: u64,
    rejected: u64,
    consecutive_rejects: u32,
    window_start_ms: u64,
    window_submits: u32,
    banned_until_ms: u64,
}

#[derive(Clone, Debug)]
struct Job {
    id: String,
    template_hash: Hash,
    difficulty: u64,
    created_ms: u64,
    seen_nonces: std::collections::HashSet<u64>,
}

/// In-memory stratum session store (one process / one pool endpoint).
pub struct StratumServer {
    state: Arc<RwLock<ChainState>>,
    workers: Mutex<HashMap<String, WorkerState>>,
    jobs: Mutex<HashMap<String, Job>>,
    shares: Mutex<Vec<StratumShare>>,
    next_job: Mutex<u64>,
    extranonce1: String,
    /// Required worker password (from env at construction). `None` = reject all.
    password: Option<String>,
}

impl StratumServer {
    pub fn new(state: Arc<RwLock<ChainState>>) -> Self {
        let password = match std::env::var(STRATUM_PASSWORD_ENV) {
            Ok(p) if !p.is_empty() => Some(p),
            _ => None,
        };
        Self {
            state,
            workers: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
            shares: Mutex::new(Vec::new()),
            next_job: Mutex::new(1),
            extranonce1: hex::encode([0x48u8, 0x53, 0x4e, 0x01]), // "HSN\x01"
            password,
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, ChainState> {
        self.state.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Handle one JSON-RPC request object; returns JSON-RPC response.
    pub fn handle_rpc(&self, req: &Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!([]));
        let result = match method {
            "mining.subscribe" => self.subscribe(&params),
            "mining.authorize" => self.authorize(&params),
            "mining.submit" => self.submit(&params),
            "mining.get_transactions" => Ok(json!([])),
            "mining.extranonce.subscribe" => Ok(json!(true)),
            "getblocktemplate" | "mining.get_block_template" => self.get_block_template(),
            _ => Err(format!("unknown method: {method}")),
        };
        match result {
            Ok(r) => json!({"id": id, "result": r, "error": null}),
            Err(e) => json!({"id": id, "result": null, "error": {"code": -1, "message": e}}),
        }
    }

    fn subscribe(&self, _params: &Value) -> Result<Value, String> {
        // [[notifications], extranonce1, extranonce2_size]
        Ok(json!([
            [["mining.notify", "hn"]],
            self.extranonce1,
            4
        ]))
    }

    fn authorize(&self, params: &Value) -> Result<Value, String> {
        let arr = params.as_array();
        let worker = arr
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
        let password = arr
            .and_then(|a| a.get(1))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected = self
            .password
            .as_deref()
            .ok_or_else(|| {
                format!("stratum auth not configured — set {STRATUM_PASSWORD_ENV}")
            })?;
        if password != expected {
            return Err("unauthorized".into());
        }
        let mut workers = self.workers.lock().unwrap_or_else(|p| p.into_inner());
        if !workers.contains_key(&worker) && workers.len() >= MAX_STRATUM_WORKERS {
            return Err("too many stratum workers".into());
        }
        let now = crate::now_ms();
        workers.insert(
            worker,
            WorkerState {
                authorized: true,
                share_diff: DEFAULT_SHARE_DIFFICULTY,
                accepted: 0,
                rejected: 0,
                consecutive_rejects: 0,
                window_start_ms: now,
                window_submits: 0,
                banned_until_ms: 0,
            },
        );
        Ok(Value::Bool(true))
    }

    /// Build a mining.notify-style job from current tips.
    pub fn make_notify(&self) -> Result<Value, String> {
        let st = self.read();
        let parents = st.tips.clone();
        let ts = crate::now_ms();
        let difficulty = st.expected_difficulty_at(&parents, ts);
        let job_id = {
            let mut n = self.next_job.lock().unwrap_or_else(|p| p.into_inner());
            let id = format!("{:x}", *n);
            *n = n.saturating_add(1);
            id
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hassan-stratum-job-v1");
        hasher.update(job_id.as_bytes());
        for p in &parents {
            hasher.update(p.as_bytes());
        }
        hasher.update(&difficulty.to_le_bytes());
        let mut th = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut th);
        let template_hash = Hash(th);
        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
            jobs.insert(
                job_id.clone(),
                Job {
                    id: job_id.clone(),
                    template_hash,
                    difficulty,
                    created_ms: ts,
                    seen_nonces: std::collections::HashSet::new(),
                },
            );
            if jobs.len() > 256 {
                // Drop oldest half by created_ms.
                let mut by_age: Vec<_> = jobs
                    .iter()
                    .map(|(k, j)| (k.clone(), j.created_ms))
                    .collect();
                by_age.sort_by_key(|(_, ms)| *ms);
                let drop_n = jobs.len() / 2;
                for (k, _) in by_age.into_iter().take(drop_n) {
                    jobs.remove(&k);
                }
            }
        }
        // job_id, prevhash-ish, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs
        Ok(json!([
            job_id,
            hex::encode(template_hash),
            "",
            "",
            parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
            format!("{:08x}", crate::versionbits::miner_version(&[0, 1, 2])),
            format!("{difficulty:x}"),
            format!("{ts:x}"),
            true
        ]))
    }

    fn get_block_template(&self) -> Result<Value, String> {
        let st = self.read();
        let parents = st.tips.clone();
        let ts = crate::now_ms();
        let difficulty = st.expected_difficulty_at(&parents, ts);
        let mtp = st.past_median_time(st.tips.first().unwrap_or(&Hash::ZERO));
        let mempool = st.transparent_mempool.clone();
        let txs: Vec<_> = st
            .select_valid_block_txs(&mempool)
            .into_iter()
            .map(|t| {
                json!({
                    "txid": hex::encode(t.tx_hash()),
                    "fee": t.fee.to_string(),
                    "from": t.from,
                    "to": t.to,
                    "amount": t.amount.to_string(),
                })
            })
            .collect();
        Ok(json!({
            "version": crate::versionbits::miner_version(&[0, 1, 2]),
            "parents": parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
            "difficulty": difficulty,
            "curtime": ts,
            "mintime": mtp,
            "state_root_hint": hex::encode(st.merkle_root()),
            "utxo_commitment": hex::encode(st.utxo.commitment()),
            "transactions": txs,
            "target_block_time_ms": crate::TARGET_BLOCK_TIME_MS,
            "longpollid": hex::encode(st.tips.first().copied().unwrap_or(Hash::ZERO)),
        }))
    }

    fn submit(&self, params: &Value) -> Result<Value, String> {
        let arr = params.as_array().ok_or("params must be array")?;
        let worker = arr
            .first()
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
        let job_id = arr
            .get(1)
            .and_then(|v| v.as_str())
            .ok_or("missing job_id")?
            .to_string();
        let nonce = arr
            .get(2)
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| u64::from_str_radix(s, 16).ok()))
            })
            .ok_or("missing nonce")?;

        let now = crate::now_ms();
        let mut workers = self.workers.lock().unwrap_or_else(|p| p.into_inner());
        let w = workers.entry(worker.clone()).or_insert(WorkerState {
            authorized: false,
            share_diff: DEFAULT_SHARE_DIFFICULTY,
            accepted: 0,
            rejected: 0,
            consecutive_rejects: 0,
            window_start_ms: now,
            window_submits: 0,
            banned_until_ms: 0,
        });
        if !w.authorized {
            w.rejected = w.rejected.saturating_add(1);
            return Err("unauthorized".into());
        }
        if now < w.banned_until_ms {
            return Err("worker temporarily banned".into());
        }
        if now.saturating_sub(w.window_start_ms) >= SUBMIT_WINDOW_MS {
            w.window_start_ms = now;
            w.window_submits = 0;
        }
        w.window_submits = w.window_submits.saturating_add(1);
        if w.window_submits > MAX_SUBMITS_PER_WINDOW {
            w.banned_until_ms = now.saturating_add(WORKER_BAN_MS);
            return Err("submit rate limit exceeded".into());
        }

        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let job = jobs.get_mut(&job_id).ok_or("unknown job")?;
        if job.id != job_id {
            return Err("job id mismatch".into());
        }
        if now.saturating_sub(job.created_ms) > MAX_JOB_AGE_MS {
            w.rejected = w.rejected.saturating_add(1);
            w.consecutive_rejects = w.consecutive_rejects.saturating_add(1);
            return Err("stale job".into());
        }
        if !job.seen_nonces.insert(nonce) {
            w.rejected = w.rejected.saturating_add(1);
            w.consecutive_rejects = w.consecutive_rejects.saturating_add(1);
            if w.consecutive_rejects >= MAX_CONSECUTIVE_REJECTS {
                w.banned_until_ms = now.saturating_add(WORKER_BAN_MS);
            }
            return Err("duplicate share nonce".into());
        }
        if job.seen_nonces.len() > MAX_NONCES_PER_JOB {
            let id = job_id.clone();
            drop(jobs);
            self.jobs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            return Err("job nonce budget exhausted".into());
        }
        let share_diff = w.share_diff.clamp(MIN_SHARE_DIFFICULTY, MAX_SHARE_DIFFICULTY);
        let target = share_diff.min(job.difficulty.max(MIN_SHARE_DIFFICULTY));
        let template_hash = job.template_hash;

        // Share PoW check: hash(job || nonce) must meet share target (not full block diff).
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hassan-stratum-share-v1");
        hasher.update(template_hash.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        let mut out = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut out);
        let meet = crate::verify_pow(&Hash(out), target);
        let share = StratumShare {
            worker: worker.clone(),
            job_id,
            nonce,
            block_hash: Hash(out),
            difficulty: target,
            accepted: meet,
        };
        drop(jobs);
        {
            let mut shares = self.shares.lock().unwrap_or_else(|p| p.into_inner());
            shares.push(share.clone());
            if shares.len() > 10_000 {
                let drain = shares.len() - 5_000;
                shares.drain(0..drain);
            }
        }
        if meet {
            w.accepted = w.accepted.saturating_add(1);
            w.consecutive_rejects = 0;
            if w.accepted % 20 == 0 {
                w.share_diff = w.share_diff.saturating_mul(2).min(MAX_SHARE_DIFFICULTY);
            }
            Ok(Value::Bool(true))
        } else {
            w.rejected = w.rejected.saturating_add(1);
            w.consecutive_rejects = w.consecutive_rejects.saturating_add(1);
            if w.consecutive_rejects >= MAX_CONSECUTIVE_REJECTS {
                w.banned_until_ms = now.saturating_add(WORKER_BAN_MS);
            }
            if w.rejected > 5 && w.share_diff > MIN_SHARE_DIFFICULTY {
                w.share_diff = (w.share_diff / 2).max(MIN_SHARE_DIFFICULTY);
            }
            Err("low difficulty share".into())
        }
    }

    pub fn worker_stats(&self) -> Value {
        let workers = self.workers.lock().unwrap_or_else(|p| p.into_inner());
        let list: Vec<_> = workers
            .iter()
            .map(|(name, w)| {
                json!({
                    "worker": name,
                    "authorized": w.authorized,
                    "share_diff": w.share_diff,
                    "accepted": w.accepted,
                    "rejected": w.rejected,
                })
            })
            .collect();
        json!({ "workers": list })
    }

    pub fn recent_shares(&self, n: usize) -> Value {
        let shares = self.shares.lock().unwrap_or_else(|p| p.into_inner());
        let list: Vec<_> = shares
            .iter()
            .rev()
            .take(n)
            .map(|s| {
                json!({
                    "worker": s.worker,
                    "job_id": s.job_id,
                    "nonce": s.nonce,
                    "difficulty": s.difficulty,
                    "accepted": s.accepted,
                    "hash": hex::encode(s.block_hash),
                })
            })
            .collect();
        json!({ "shares": list })
    }
}

/// Validate that a full block meets network difficulty (pool → node handoff).
pub fn block_meets_network_diff(block: &Block) -> bool {
    crate::verify_pow(&block.hash(), block.difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_server() -> StratumServer {
        std::env::set_var(STRATUM_PASSWORD_ENV, "test-stratum-secret");
        let st = Arc::new(RwLock::new(ChainState::new()));
        StratumServer::new(st)
    }

    #[test]
    fn authorize_rejects_wrong_password() {
        let srv = test_server();
        let bad = srv.handle_rpc(&json!({"id":1,"method":"mining.authorize","params":["miner1","wrong"]}));
        assert!(!bad.get("error").unwrap().is_null());
        let submit = srv.handle_rpc(&json!({
            "id": 2,
            "method": "mining.submit",
            "params": ["miner1", "0", "1"]
        }));
        assert!(
            submit["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("unauthorized")
        );
    }

    #[test]
    fn subscribe_authorize_submit_flow() {
        let srv = test_server();
        let sub = srv.handle_rpc(&json!({"id":1,"method":"mining.subscribe","params":[]}));
        assert!(sub.get("error").unwrap().is_null());
        let auth = srv.handle_rpc(&json!({
            "id":2,
            "method":"mining.authorize",
            "params":["miner1","test-stratum-secret"]
        }));
        assert_eq!(auth["result"], true);
        let notify = srv.make_notify().unwrap();
        let job_id = notify[0].as_str().unwrap().to_string();
        // Brute a share at default low difficulty.
        let mut accepted = false;
        for nonce in 0..50_000u64 {
            let r = srv.handle_rpc(&json!({
                "id": 3,
                "method": "mining.submit",
                "params": ["miner1", job_id, format!("{nonce:x}")]
            }));
            if r.get("error").map(|e| e.is_null()).unwrap_or(false) && r["result"] == true {
                accepted = true;
                break;
            }
        }
        assert!(accepted, "should find a share under default share difficulty");
        let stats = srv.worker_stats();
        assert!(stats["workers"].as_array().unwrap()[0]["accepted"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn getblocktemplate_has_parents() {
        let srv = test_server();
        let r = srv.handle_rpc(&json!({"id":1,"method":"getblocktemplate","params":[]}));
        assert!(r["result"]["parents"].as_array().unwrap().len() >= 1);
    }

    #[test]
    fn duplicate_share_nonce_is_rejected() {
        let srv = test_server();
        srv.handle_rpc(&json!({
            "id":1,"method":"mining.authorize","params":["dup","test-stratum-secret"]
        }));
        let notify = srv.make_notify().unwrap();
        let job_id = notify[0].as_str().unwrap().to_string();
        // Find one accepting nonce, then replay it.
        let mut good = None;
        for nonce in 0..50_000u64 {
            let r = srv.handle_rpc(&json!({
                "id": 2,
                "method": "mining.submit",
                "params": ["dup", job_id, format!("{nonce:x}")]
            }));
            if r.get("error").map(|e| e.is_null()).unwrap_or(false) && r["result"] == true {
                good = Some(nonce);
                break;
            }
        }
        let nonce = good.expect("need an accepted share");
        let replay = srv.handle_rpc(&json!({
            "id": 3,
            "method": "mining.submit",
            "params": ["dup", job_id, format!("{nonce:x}")]
        }));
        let msg = replay["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("duplicate"), "got: {msg}");
    }

    #[test]
    fn submit_rate_limit_trips() {
        let srv = test_server();
        srv.handle_rpc(&json!({
            "id":1,"method":"mining.authorize","params":["flood","test-stratum-secret"]
        }));
        let notify = srv.make_notify().unwrap();
        let job_id = notify[0].as_str().unwrap().to_string();
        let mut hit_limit = false;
        for nonce in 0..(MAX_SUBMITS_PER_WINDOW as u64 + 5) {
            let r = srv.handle_rpc(&json!({
                "id": nonce,
                "method": "mining.submit",
                "params": ["flood", job_id, format!("{nonce:x}")]
            }));
            let msg = r["error"]["message"].as_str().unwrap_or("");
            if msg.contains("rate limit") {
                hit_limit = true;
                break;
            }
        }
        assert!(hit_limit, "worker must trip submit rate limit");
    }
}
