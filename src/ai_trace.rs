//! AI-visible block trace — every consensus step emitted as structured events
//! so an AI (or any auditor) can track a block from issuance through custody.
//!
//! All digests in the trace are **Blake3-512**. Birth Certificate status is
//! included on every block event.

use crate::abs_sig::{digest512, DIGEST_512};
use crate::custody::CustodyCertificate;
use crate::Block;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiTraceEvent {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub event: String,
    pub block_hash: Option<String>,
    pub settlement_id: Option<String>,
    pub birth_ok: Option<bool>,
    pub detail: serde_json::Value,
    /// 512-bit fingerprint of this event (PQ-safe content id).
    pub event_digest512: String,
}

#[derive(Default)]
pub struct AiTraceLog {
    events: Vec<AiTraceEvent>,
    next_seq: u64,
}

impl AiTraceLog {
    pub fn record(&mut self, event: &str, block: Option<&Block>, detail: serde_json::Value) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let (block_hash, settlement_id, birth_ok) = if let Some(b) = block {
            (
                Some(hex::encode(b.hash())),
                Some(b.settlement_id().to_hex()),
                Some(b.verify_issuance().is_ok()),
            )
        } else {
            (None, None, None)
        };
        let payload = serde_json::json!({
            "seq": seq,
            "event": event,
            "block_hash": block_hash,
            "settlement_id": settlement_id,
            "birth_ok": birth_ok,
            "detail": detail,
        });
        let digest = digest512(b"ai-trace", payload.to_string().as_bytes());
        let ev = AiTraceEvent {
            seq,
            timestamp_ms: crate::now_ms(),
            event: event.into(),
            block_hash,
            settlement_id,
            birth_ok,
            detail,
            event_digest512: hex::encode(digest),
        };
        self.events.push(ev);
        // Bound memory: keep last 10_000 events.
        if self.events.len() > 10_000 {
            let drop_n = self.events.len() - 10_000;
            self.events.drain(0..drop_n);
        }
    }

    pub fn record_custody(&mut self, cert: &CustodyCertificate) {
        self.record(
            "custody",
            None,
            serde_json::json!({
                "kind": format!("{:?}", cert.kind),
                "owner": cert.owner,
                "amount": cert.amount.to_string(),
                "foreign_chain_id": cert.foreign_chain_id,
                "settlement_id": cert.settlement_id,
                "block_hash": hex::encode(cert.block_hash),
            }),
        );
    }

    pub fn recent(&self, n: usize) -> Vec<AiTraceEvent> {
        let len = self.events.len();
        self.events[len.saturating_sub(n)..].to_vec()
    }

    pub fn for_block(&self, hash_hex: &str) -> Vec<AiTraceEvent> {
        self.events
            .iter()
            .filter(|e| e.block_hash.as_deref() == Some(hash_hex))
            .cloned()
            .collect()
    }

    pub fn tip_digest512(&self) -> String {
        let mut hasher_input = Vec::new();
        for e in &self.events {
            hasher_input.extend_from_slice(e.event_digest512.as_bytes());
        }
        hex::encode(digest512(b"ai-trace-tip", &hasher_input))
    }
}

/// Process-global AI trace (node-local observability).
pub fn global_trace() -> Arc<Mutex<AiTraceLog>> {
    use std::sync::OnceLock;
    static TRACE: OnceLock<Arc<Mutex<AiTraceLog>>> = OnceLock::new();
    TRACE
        .get_or_init(|| Arc::new(Mutex::new(AiTraceLog::default())))
        .clone()
}

pub fn trace_block_accepted(block: &Block) {
    if let Ok(mut g) = global_trace().lock() {
        g.record(
            "block_accepted",
            Some(block),
            serde_json::json!({
                "height": block.height,
                "transfers": block.transparent_txs.len(),
                "registry_ops": block.registry_ops.len(),
                "issuer": crate::address::encode_hash(&block.miner),
                "settlement_bits": DIGEST_512 * 8,
                "birth_certificate_present": !block.birth_certificate.signature.is_empty(),
            }),
        );
    }
}

pub fn trace_block_rejected(reason: &str, block: Option<&Block>) {
    if let Ok(mut g) = global_trace().lock() {
        g.record(
            "block_rejected",
            block,
            serde_json::json!({ "reason": reason }),
        );
    }
}
