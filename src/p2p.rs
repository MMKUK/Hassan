//! Peer-to-peer networking: a framed message protocol, block gossip, and
//! orphan-driven backfill sync over TCP.
//!
//! This is the first step toward Hassan being an actual *network* rather than
//! a single node mining against itself — the gap flagged throughout
//! `SECURITY.md` as the most important one, because GHOSTDAG/PoW only deliver
//! real security once independent nodes run them and agree over a network.
//!
//! ## What this does
//! - A length-prefixed bincode wire protocol ([`Message`]) with a version +
//!   `chain_id` + genesis-implied handshake.
//! - `Node::listen` / `Node::connect` to accept and dial peers.
//! - Block **gossip**: an accepted block is announced (`Inv`) to all peers.
//! - **Sync**: a node that hears about a block it lacks pulls it (`GetBlock`);
//!   if the block's parents are missing it is buffered as an orphan and the
//!   parents are requested, so a fresh node backfills an entire chain parent-
//!   by-parent until it reaches the shared genesis. One mechanism handles both
//!   live relay and cold-start catch-up.
//! - Every received block goes through the full `ChainState::add_block`
//!   validation (PoW, difficulty, STARK, timestamp, tx checks) — peers cannot
//!   inject invalid blocks; they're simply dropped.
//!
//! ## Implemented hardening
//! - **Peer discovery** via address gossip: the handshake carries each node's
//!   listen address, `GetAddr`/`Addr` exchange known addresses, and nodes dial
//!   newly-learned peers automatically up to `MAX_PEERS`.
//! - **Resource bounds:** `MAX_PEERS` caps concurrent connections; an idle read
//!   timeout (`PEER_IDLE_TIMEOUT`) drops silent peers; the orphan pool is capped
//!   (`MAX_ORPHANS`); per-message size is bounded (`MAX_MESSAGE_BYTES`).
//!
//! ## Transport security (present)
//! - **Wire encryption + authentication.** Noise `XX` (X25519 / ChaCha20-Poly1305
//!   / BLAKE2s) mixed with an ML-KEM-768 PSK (HN/DL), then ML-DSA-87 signatures
//!   over the handshake hash (channel-bound peer auth). Silent live Q-MITM that
//!   forges another peer's ML-DSA identity is out of scope for a CRQC alone.
//! - **Optional Tor SOCKS5 outbound dials.** When configured (see
//!   [`Node::set_tor_proxy`] / `HASSAN_TOR=1` in `main`), outbound
//!   `connect`/`dial` go through a local Tor SOCKS5 proxy via
//!   [`crate::tor::socks5_connect_timeout`]. This is a real SOCKS *client*
//!   only — we do **not** publish a hidden service. Clearnet TCP is used when
//!   Tor is disabled.
//! - **Per-peer rate limiting + eclipse resistance.** Per-peer message-rate
//!   windows (`PEER_MSG_LIMIT`) trip on floods; per-IP-group caps
//!   (`MAX_PEERS_PER_GROUP`) limit how much of the peer table one network can
//!   occupy.
//!
//! ## Honest scope — what a production P2P stack still needs (NOT here)
//! - **Pinned peer-identity directory.** Set `HASSAN_PEER_PINS` (file or
//!   hex list); `HASSAN_PEER_PINS_STRICT=1` rejects unpinned ML-DSA ids.
//!   Without pins, first-contact auth remains TOFU (`peer_pin` module).
//! - **Full Kaspa-equivalent pruning proofs.** Multilevel proofs use a hard
//!   `verified_work` floor plus hop DAA clamp anchors; omitted-hop exact DAA
//!   is still not re-executed (succinctness trade).
//! - **Fork choice beyond local GHOSTDAG.** Nodes converge by each running
//!   GHOSTDAG over the union of blocks they receive; there is no explicit
//!   reorg/finality signalling.
//!
//! Headers-first body fetch (PoW-validate headers, rank by work, cap in-flight
//! `GetBlock`s) and UTXO mempool gossip are implemented.

use crate::tor::dial_target;
use crate::{abs_sig, generate_keypair, ghostdag, Block, ChainState, TransparentTx};
use bincode::Options as _;
use fips203::ml_kem_768::{CipherText, EncapsKey, CT_LEN, EK_LEN, KG};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

pub use crate::Hash;

pub const PROTOCOL_VERSION: u32 = 7;
/// Wire protocol magic — rejected peers with a mismatched hello are dropped.
pub const WIRE_MAGIC: [u8; 4] = *b"HSN1";
/// Hard cap on a single wire message. The largest legitimate message is a
/// `Block` including witness proofs, bounded by `crate::MAX_BLOCK_BYTES`
/// (256 KB); this leaves headroom for bincode framing. Kept as tight as the
/// real maximum to limit per-frame allocation amplification (red-team V4).
pub const MAX_MESSAGE_BYTES: usize = crate::MAX_BLOCK_BYTES + 16 * 1024;
/// Maximum peer addresses accepted from a single `Addr` message. Without this
/// a peer could send a huge address list and make us spawn a dial thread per
/// entry (red-team finding V2).
pub const MAX_ADDRS_PER_MSG: usize = 16;
/// Bounded connect timeout so a black-hole address (accepts SYN, never
/// replies) can't pin a dial thread for the OS default ~75s (red-team V3).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum simultaneous peer connections. Bounds resource use against an
/// attacker opening many connections; further inbound peers are refused.
pub const MAX_PEERS: usize = 64;
/// Maximum peers allowed from a single IP group (IPv4 /16, IPv6 /32). Without
/// this, an attacker controlling one address range could fill every peer slot
/// and eclipse the node from the honest network. Loopback is exempt so
/// multiple nodes can run on one host for local testing.
pub const MAX_PEERS_PER_GROUP: usize = 3;
/// Maximum blocks buffered in the orphan pool. A peer streaming blocks with
/// fabricated unknown parents could otherwise grow node memory without limit;
/// once this cap is hit, further orphans are dropped rather than buffered.
pub const MAX_ORPHANS: usize = 1_000;
/// Drop buffered orphans older than this (DoS + memory hygiene).
pub const ORPHAN_TTL: Duration = Duration::from_secs(600);
/// Ban-score points decayed every [`BAN_DECAY_INTERVAL`] of good behavior.
pub const BAN_DECAY_POINTS: u32 = 10;
pub const BAN_DECAY_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum peer listen-addresses remembered for discovery.
pub const MAX_KNOWN_ADDRS: usize = 1_024;
/// A peer that sends nothing for this long is dropped (frees its thread).
/// The discovery/keepalive traffic below keeps healthy peers well under it.
pub const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Bounded write timeout. Without it, a peer that connects and then stops
/// reading makes our blocking `write_all` block forever on its full TCP send
/// buffer — and since `broadcast` writes to peers serially, one such peer
/// stalls all gossip. This bounds any single write to a finite wait, after
/// which the write fails and the peer is dropped by the read loop (audit A5).
pub const PEER_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often to request peer addresses (also serves as keepalive) and dial
/// newly-discovered peers up to `MAX_PEERS`.
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// Process-wide P2P snapshot for the HTTP explorer / status API.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NetworkStatus {
    pub peer_count: usize,
    pub listening: bool,
    pub listen_addr: Option<String>,
    pub banned_count: usize,
    pub known_addrs: usize,
}

fn network_status_slot() -> &'static Mutex<NetworkStatus> {
    static SLOT: OnceLock<Mutex<NetworkStatus>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(NetworkStatus::default()))
}

/// Read-only network snapshot (safe for API threads).
pub fn network_status() -> NetworkStatus {
    network_status_slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

fn refresh_network_status(shared: &Shared) {
    let peer_count = shared.peers.lock().unwrap_or_else(|p| p.into_inner()).len();
    let banned_count = shared
        .banned_addrs
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len();
    let known_addrs = shared
        .known_addrs
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len();
    let listen_addr = shared
        .my_listen_addr
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let mut g = network_status_slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    g.peer_count = peer_count;
    g.banned_count = banned_count;
    g.known_addrs = known_addrs;
    g.listen_addr = listen_addr.clone();
    g.listening = listen_addr.is_some();
}

/// Max messages a single peer may send within `PEER_RATE_WINDOW` before it is
/// disconnected. Generous enough for legitimate sync bursts (each missing
/// block is one GetBlock + one Block), tight enough to cut off a flood.
pub const PEER_MSG_LIMIT: u32 = 20_000;
pub const PEER_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Misbehavior ("ban") score at which a peer is disconnected and its advertised
/// address is banned from redialing. This mirrors Bitcoin's ban-score and
/// Kaspa's peer-banning: *invalidity* is penalized, not just message volume. A
/// peer trickling provably-invalid blocks just under `PEER_MSG_LIMIT` — each
/// one forcing an expensive PoW + STARK verification — is a real CPU-DoS the
/// rate limiter alone does not stop; the ban score does.
pub const BAN_SCORE_THRESHOLD: u32 = 100;
/// Ban-score points charged per provably-invalid block (bad PoW /
/// difficulty / timestamp / structure). Five strikes reach the threshold.
/// Orphans (unknown-parent) are NOT penalized — that is honest sync, not abuse.
pub const INVALID_BLOCK_PENALTY: u32 = 20;
/// Extra ban weight for invalid/malformed STARK proofs — these are the
/// expensive CPU path an attacker races after cheap bootstrap-era PoW. Two
/// strikes (`2 * 50`) reach the ban threshold.
pub const INVALID_STARK_PENALTY: u32 = 50;
/// Ban-score points per provably-invalid gossiped transaction (bad signature).
/// A duplicate / already-known / stale-nonce tx is NOT penalized (normal gossip
/// overlap).
pub const INVALID_TX_PENALTY: u32 = 20;
/// How often the mempool announcer re-broadcasts newly-admitted transactions.
pub const MEMPOOL_ANNOUNCE_INTERVAL: Duration = Duration::from_millis(200);
/// Max verified headers waiting for a body download (DoS bound).
pub const MAX_PENDING_HEADERS: usize = 2_048;
/// Max concurrent body fetches triggered by headers-first sync.
pub const MAX_IN_FLIGHT_BODIES: usize = 32;
/// Max headers accepted in one `Headers` message (DoS / CPU bound).
pub const MAX_HEADERS_PER_MSG: usize = 2_000;
/// Max locator hashes in `GetHeaders` (Bitcoin-class bound).
pub const MAX_LOCATOR_HASHES: usize = 64;
/// Max concurrent pull requests for unknown txids (TxInv / UtxoTxInv floods).
pub const MAX_IN_FLIGHT_TX_GETS: usize = 64;
/// Max txs in a single `TxPackage` relay message.
pub const MAX_TX_PACKAGE: usize = crate::MAX_MEMPOOL_PACKAGE_NONCES;

/// Per-message-type payload caps (tighter than the global frame limit).
pub fn max_payload_for(msg: &Message) -> usize {
    match msg {
        Message::Hello { .. }
        | Message::Ping(_)
        | Message::Pong(_)
        | Message::GetAddr
        | Message::GetTips
        | Message::GetPruningProof
        | Message::GetMultiLevelPruningProof
        | Message::FeeFilter { .. }
        | Message::GetBlock(_)
        | Message::Inv(_)
        | Message::NotFound(_)
        | Message::TxInv(_)
        | Message::GetTx(_)
        | Message::UtxoTxInv(_)
        | Message::GetUtxoTx(_)
        | Message::GetPruningPointLedger(_) => 8 * 1024,
        Message::Addr(addrs) => 512 + addrs.len().saturating_mul(256).min(64 * 1024),
        Message::Tips(tips) => 256 + tips.len().saturating_mul(80),
        Message::Tx(_) | Message::TxPackage(_) | Message::UtxoTx(_) => 128 * 1024,
        Message::GetHeaders { locator, .. } => {
            512 + locator.len().min(MAX_LOCATOR_HASHES).saturating_mul(80)
        }
        Message::Headers(hs) => (512
            + hs
                .len()
                .min(MAX_HEADERS_PER_MSG)
                .saturating_mul(512))
        .min(MAX_MESSAGE_BYTES),
        Message::Identity { .. } => 16 * 1024,
        Message::CompactBlock { .. }
        | Message::GetBlockTxn { .. }
        | Message::BlockTxn { .. }
        | Message::Block(_)
        | Message::PruningProof(_)
        | Message::MultiLevelPruningProof(_)
        | Message::PruningPointLedger(_) => MAX_MESSAGE_BYTES,
    }
}

/// Serialized size check against [`max_payload_for`].
pub fn message_within_type_cap(msg: &Message, payload_len: usize) -> bool {
    payload_len <= max_payload_for(msg)
}

/// Reject gossip dial targets that are SSRF-shaped (cloud metadata /
/// link-local) or syntactically unusable. In `HASSAN_PUBLIC` /
/// `HASSAN_STRICT_DIALS` mode, also reject RFC1918 + loopback (use
/// [`crate::net_policy::is_publicly_dialable`]). Otherwise loopback/RFC1918
/// stay allowed for local multi-node setups.
fn is_dialable_gossip_addr(addr: &str) -> bool {
    if crate::net_policy::policy().strict_dials {
        return crate::net_policy::is_publicly_dialable(addr);
    }
    let addr = addr.trim();
    if addr.is_empty() || addr.len() > 256 {
        return false;
    }
    let (host, port_str) = match addr.rsplit_once(':') {
        Some(pair) => pair,
        None => return false,
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
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return !host.is_empty() && host.len() <= 253;
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_unicast_link_local(),
    }
}

/// A simple per-peer sliding-window message counter. `record()` returns
/// `false` once the peer exceeds `limit` within the current window,
/// which the connection handler treats as grounds to disconnect.
struct RateWindow {
    window_start: std::time::Instant,
    count: u32,
    limit: u32,
}

impl RateWindow {
    fn new(limit: u32) -> Self {
        Self {
            window_start: std::time::Instant::now(),
            count: 0,
            limit,
        }
    }

    fn record(&mut self) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.window_start) >= PEER_RATE_WINDOW {
            self.window_start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= self.limit
    }
}

/// The P2P wire protocol. Serialized with bincode, length-prefixed on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Sent by both sides on connect. Carries protocol version, chain id,
    /// current blue score so the lower node knows to start syncing, and the
    /// sender's own listen address (if it's listening) so peers can discover
    /// and dial it.
    Hello {
        version: u32,
        /// Must equal [`WIRE_MAGIC`].
        magic: [u8; 4],
        chain_id: u64,
        blue_score: u64,
        listen_addr: Option<String>,
    },
    /// "Send me peer addresses you know" — peer discovery + keepalive.
    GetAddr,
    /// A batch of known peer listen-addresses (reply to `GetAddr`).
    Addr(Vec<String>),
    /// "Tell me your current tips" — the entry point for cold-start sync.
    GetTips,
    /// Reply to `GetTips`.
    Tips(Vec<Hash>),
    /// "Send me this block."
    GetBlock(Hash),
    /// A full block (reply to `GetBlock`, or an unsolicited relay).
    Block(Box<Block>),
    /// "I have this block" — a gossip announcement; peers pull it if unknown.
    Inv(Hash),
    /// Negative reply to `GetBlock`.
    NotFound(Hash),
    /// Relay a signed transparent transfer for peers' mempools (tx gossip).
    Tx(Box<TransparentTx>),
    /// Announce a tx by hash (pull via GetTx) — bandwidth-efficient vs full push.
    TxInv(Hash),
    /// Request a full transparent tx by hash.
    GetTx(Hash),
    /// Parent+child package relay (account-nonce chains).
    TxPackage(Vec<TransparentTx>),
    /// Relay a signed UTXO spend (v27 primary peer-value path).
    UtxoTx(Box<crate::utxo_tx::UtxoTx>),
    /// Announce a UTXO tx by txid (pull via GetUtxoTx).
    UtxoTxInv(Hash),
    /// Request a full UTXO tx by txid.
    GetUtxoTx(Hash),
    /// Compact block announcement (short-ids; peer reconstructs from mempool).
    CompactBlock {
        header_hash: Hash,
        nonce: u64,
        /// First 8 bytes of each tx_hash (short id).
        short_ids: Vec<[u8; 8]>,
        /// Prefilled txs the sender believes the peer lacks (usually coinbase-like / novel).
        prefilled: Vec<TransparentTx>,
    },
    /// Request missing txs after a CompactBlock (by short-id index).
    GetBlockTxn {
        block_hash: Hash,
        indexes: Vec<u16>,
    },
    /// Reply to GetBlockTxn.
    BlockTxn {
        block_hash: Hash,
        txs: Vec<TransparentTx>,
    },
    /// Headers-first: request headers along selected parent from a locator tip.
    GetHeaders {
        locator: Vec<Hash>,
        stop_hash: Hash,
        limit: u32,
    },
    /// Batch of header-only blocks (reply to GetHeaders).
    Headers(Vec<Block>),
    /// Explicit keepalive with nonce (BIP31-class).
    Ping(u64),
    Pong(u64),
    /// BIP133-class fee filter: "do not announce txs with fee below `min_fee`".
    /// Absolute fee (base units) for a typical transfer floor; peers may still
    /// send, but honest announcers skip under-filter gossip.
    FeeFilter { min_fee: u128 },
    /// "Send me your cold-start pruning-point proof" (headers-first sync entry).
    /// Linear fallback; prefer [`Message::GetMultiLevelPruningProof`].
    GetPruningProof,
    /// A pruning-point proof (reply to `GetPruningProof`); served by archival
    /// nodes. The receiver verifies it from genesis before trusting the point.
    PruningProof(Box<crate::PruningProof>),
    /// Prefer succinct multi-level pruning proof (Kaspa-class IBD).
    GetMultiLevelPruningProof,
    /// Succinct multi-level pruning proof; adopt only on `verified_work`.
    MultiLevelPruningProof(Box<crate::superproof::MultiLevelPruningProof>),
    /// "Send me the account ledger at this pruning point."
    GetPruningPointLedger(Hash),
    /// Compact pruning-point ledger (reply); verify against PP `state_root`.
    PruningPointLedger(Box<crate::PruningPointLedger>),
    /// Post-quantum peer authentication: the sender's ML-DSA-87 identity public
    /// key and a signature over the Noise handshake hash (channel binding). Sent
    /// once, immediately after the handshake, before anything else.
    Identity { pubkey: Vec<u8>, signature: Vec<u8> },
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// Noise handshake pattern for the encrypted transport: mutual-auth XX with
/// X25519 key agreement, ChaCha20-Poly1305 AEAD, BLAKE2s. Hybrid PQ + classical
/// wire key agreement: the `psk3` modifier mixes a 32-byte secret from
/// ML-KEM-768 (FIPS 203) into the Noise chaining key so HN/DL against X25519
/// alone cannot recover transport keys. After the handshake, both sides prove
/// ML-DSA-87 ownership of the handshake hash (`pq_authenticate`) — channel-
/// bound peer authentication. Residual without `HASSAN_PEER_PINS`: TOFU still
/// allows an active MITM to present *their own* PQ identity; with pins +
/// strict mode that path is closed.
const NOISE_PARAMS: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
/// Max plaintext per Noise message (65535 AEAD limit − 16-byte tag). Larger
/// application messages are split across multiple encrypted frames.
const NOISE_MAX_PLAINTEXT: usize = 65535 - 16;

/// Establish the ML-KEM-768 shared secret used as the Noise PSK. The initiator
/// generates the KEM keypair and publishes its encapsulation key; the responder
/// encapsulates and returns the ciphertext. Both then hold the same 32-byte
/// secret. Key/ciphertext bytes are public by design (KEM security does not rely
/// on hiding them), so exchanging them in the clear before Noise is sound.
fn mlkem_shared_secret(stream: &mut TcpStream, initiator: bool) -> std::io::Result<[u8; 32]> {
    if initiator {
        let (ek, dk) = KG::try_keygen().map_err(io_err)?;
        write_raw_frame(stream, &ek.into_bytes())?;
        let ct_bytes = read_raw_frame(stream)?;
        let ct_arr: [u8; CT_LEN] = ct_bytes
            .as_slice()
            .try_into()
            .map_err(|_| io_err("ML-KEM ciphertext wrong length"))?;
        let ct = CipherText::try_from_bytes(ct_arr).map_err(io_err)?;
        Ok(dk.try_decaps(&ct).map_err(io_err)?.into_bytes())
    } else {
        let ek_bytes = read_raw_frame(stream)?;
        let ek_arr: [u8; EK_LEN] = ek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| io_err("ML-KEM encapsulation key wrong length"))?;
        let ek = EncapsKey::try_from_bytes(ek_arr).map_err(io_err)?;
        let (ssk, ct) = ek.try_encaps().map_err(io_err)?;
        write_raw_frame(stream, &ct.into_bytes())?;
        Ok(ssk.into_bytes())
    }
}

/// Perform the hybrid PQ Noise XXpsk3 handshake over `stream` and return the
/// established transport state **plus the handshake hash** — a unique per-session
/// transcript digest used as the channel-binding value for post-quantum peer
/// authentication (see `handle_conn`). Because the ML-KEM PSK is mixed into this
/// hash, a quantum adversary who breaks X25519 still cannot reproduce it.
/// `initiator` is true for the dialing side.
fn noise_handshake(
    stream: &mut TcpStream,
    initiator: bool,
    local_private: &[u8],
) -> std::io::Result<(snow::TransportState, Vec<u8>)> {
    // Post-quantum pre-handshake: derive the PSK from ML-KEM-768 first.
    let psk = mlkem_shared_secret(stream, initiator)?;
    let params = NOISE_PARAMS.parse().map_err(io_err)?;
    let builder = snow::Builder::new(params)
        .local_private_key(local_private)
        .map_err(io_err)?
        .psk(3, &psk)
        .map_err(io_err)?;
    let mut hs = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(io_err)?;

    let mut buf = vec![0u8; 1024];
    if initiator {
        let n = hs.write_message(&[], &mut buf).map_err(io_err)?; // -> e
        write_raw_frame(stream, &buf[..n])?;
        let msg = read_raw_frame(stream)?; // <- e, ee, s, es
        hs.read_message(&msg, &mut buf).map_err(io_err)?;
        let n = hs.write_message(&[], &mut buf).map_err(io_err)?; // -> s, se
        write_raw_frame(stream, &buf[..n])?;
    } else {
        let msg = read_raw_frame(stream)?;
        hs.read_message(&msg, &mut buf).map_err(io_err)?;
        let n = hs.write_message(&[], &mut buf).map_err(io_err)?;
        write_raw_frame(stream, &buf[..n])?;
        let msg = read_raw_frame(stream)?;
        hs.read_message(&msg, &mut buf).map_err(io_err)?;
    }
    // Capture the channel-binding hash before consuming the handshake state.
    let handshake_hash = hs.get_handshake_hash().to_vec();
    let transport = hs.into_transport_mode().map_err(io_err)?;
    Ok((transport, handshake_hash))
}

/// Plaintext length-prefixed frame, used only during the handshake (before the
/// encrypted channel is up).
fn write_raw_frame(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(data.len() as u16).to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()
}
fn read_raw_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut lb = [0u8; 2];
    stream.read_exact(&mut lb)?;
    let len = u16::from_be_bytes(lb) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Send an application message over the encrypted transport. Holds the socket
/// lock for the whole message so frames stay in send-nonce order; the
/// transport lock is taken only per-frame for the AEAD op (never during socket
/// I/O), so a slow peer can't block the concurrent read path.
fn noise_write(
    sock: &Arc<Mutex<TcpStream>>,
    transport: &Arc<Mutex<snow::TransportState>>,
    payload: &[u8],
) -> std::io::Result<()> {
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(io_err("outgoing message exceeds MAX_MESSAGE_BYTES"));
    }
    let mut s = sock.lock().map_err(|_| io_err("writer lock poisoned"))?;
    // Header frame: total plaintext length. Then the payload in chunks.
    write_enc_frame(&mut s, transport, &(payload.len() as u32).to_be_bytes())?;
    for chunk in payload.chunks(NOISE_MAX_PLAINTEXT) {
        write_enc_frame(&mut s, transport, chunk)?;
    }
    s.flush()
}

fn write_enc_frame(
    s: &mut TcpStream,
    transport: &Arc<Mutex<snow::TransportState>>,
    plaintext: &[u8],
) -> std::io::Result<()> {
    let mut ct = vec![0u8; plaintext.len() + 16];
    let n = transport
        .lock()
        .map_err(|_| io_err("transport lock poisoned"))?
        .write_message(plaintext, &mut ct)
        .map_err(io_err)?;
    ct.truncate(n);
    s.write_all(&(ct.len() as u16).to_be_bytes())?;
    s.write_all(&ct)
}

/// Receive one application message from the encrypted transport (reassembling
/// chunks). Returns the decrypted plaintext.
fn noise_read(
    read_stream: &mut TcpStream,
    transport: &Arc<Mutex<snow::TransportState>>,
) -> std::io::Result<Vec<u8>> {
    let header = read_enc_frame(read_stream, transport)?;
    if header.len() != 4 {
        return Err(io_err("bad noise length header"));
    }
    let total = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if total > MAX_MESSAGE_BYTES {
        return Err(io_err("incoming message exceeds MAX_MESSAGE_BYTES"));
    }
    let mut out = Vec::with_capacity(total.min(MAX_MESSAGE_BYTES));
    while out.len() < total {
        let chunk = read_enc_frame(read_stream, transport)?;
        if chunk.is_empty() {
            return Err(io_err("empty noise chunk"));
        }
        out.extend_from_slice(&chunk);
        if out.len() > total {
            return Err(io_err("noise chunk overflow"));
        }
    }
    Ok(out)
}

fn read_enc_frame(
    s: &mut TcpStream,
    transport: &Arc<Mutex<snow::TransportState>>,
) -> std::io::Result<Vec<u8>> {
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb)?;
    let clen = u16::from_be_bytes(lb) as usize;
    let mut ct = vec![0u8; clen];
    s.read_exact(&mut ct)?;
    let mut pt = vec![0u8; clen];
    let n = transport
        .lock()
        .map_err(|_| io_err("transport lock poisoned"))?
        .read_message(&ct, &mut pt)
        .map_err(io_err)?;
    pt.truncate(n);
    Ok(pt)
}

/// An encrypted connection to a peer: the writable socket half plus the shared
/// Noise transport state used for both directions.
#[derive(Clone)]
struct Conn {
    writer: Arc<Mutex<TcpStream>>,
    transport: Arc<Mutex<snow::TransportState>>,
}

/// Connect to `addr` with a bounded timeout, so an unreachable or black-hole
/// address can't pin the calling thread for the OS default connect timeout.
/// When `tor_proxy` is `Some("host:port")`, the dial goes through that SOCKS5
/// proxy (Tor); otherwise clearnet TCP.
fn connect_with_timeout(addr: &str, tor_proxy: Option<&str>) -> std::io::Result<TcpStream> {
    dial_target(addr, tor_proxy, CONNECT_TIMEOUT)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))
}

/// A connected peer: the IP group it belongs to (for eclipse-resistance
/// accounting; `None` = loopback, exempt), the encrypted connection, and the
/// peer's advertised fee filter (0 = accept any fee).
struct PeerHandle {
    group: Option<Vec<u8>>,
    conn: Conn,
    /// Peer's last [`Message::FeeFilter`] (`0` = no filter / unknown).
    fee_filter: Arc<Mutex<u128>>,
}

/// The IP "group" an address belongs to for anti-eclipse accounting: the /16
/// for IPv4, the /32 for IPv6. Returns `None` for loopback (exempt, so local
/// multi-node testing works and trusted local peers aren't capped).
fn ip_group(ip: std::net::IpAddr) -> Option<Vec<u8>> {
    if ip.is_loopback() {
        return None;
    }
    match ip {
        std::net::IpAddr::V4(v4) => Some(v4.octets()[..2].to_vec()),
        std::net::IpAddr::V6(v6) => Some(v6.octets()[..4].to_vec()),
    }
}

/// The shared, cloneable core of a node — all the `Arc`s the per-peer handler
/// threads capture. `Node` is a thin public wrapper around it.
#[derive(Clone)]
struct PendingCompact {
    short_ids: Vec<[u8; 8]>,
    /// Filled txs by short-id index (Some = known).
    filled: Vec<Option<TransparentTx>>,
}

fn tx_short_id(tx: &TransparentTx) -> [u8; 8] {
    let h = tx.tx_hash();
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&h.as_bytes()[..8]);
    sid
}

/// Reconstruct txs from mempool by short-id; return missing indexes.
/// On short-id collision (two mempool txs map to same id), treat as missing.
fn reconstruct_from_mempool(
    short_ids: &[[u8; 8]],
    mempool: &[TransparentTx],
    prefilled: &[TransparentTx],
) -> (Vec<Option<TransparentTx>>, Vec<u16>) {
    let mut by_sid: HashMap<[u8; 8], Vec<&TransparentTx>> = HashMap::new();
    for tx in mempool {
        by_sid.entry(tx_short_id(tx)).or_default().push(tx);
    }
    for tx in prefilled {
        by_sid.entry(tx_short_id(tx)).or_default().push(tx);
    }
    let mut filled = Vec::with_capacity(short_ids.len());
    let mut missing = Vec::new();
    for (i, sid) in short_ids.iter().enumerate() {
        match by_sid.get(sid) {
            Some(v) if v.len() == 1 => filled.push(Some((*v[0]).clone())),
            _ => {
                filled.push(None);
                missing.push(i as u16);
            }
        }
    }
    (filled, missing)
}

#[derive(Clone)]
struct OrphanBlock {
    block: Block,
    inserted_at: std::time::Instant,
}

/// A PoW-validated header awaiting body download (headers-first IBD).
#[derive(Clone)]
struct PendingHeader {
    /// Header-only block (bodies stripped). Retained for future parent-work
    /// walks / diagnostics; body fetch keys off the map hash.
    #[allow(dead_code)]
    header: Block,
    /// Cumulative difficulty-work along the path we used to accept it.
    work: u128,
    requested: bool,
}

#[derive(Clone)]
struct Shared {
    state: Arc<RwLock<ChainState>>,
    peers: Arc<Mutex<Vec<PeerHandle>>>,
    /// missing-parent-hash -> blocks waiting on it.
    orphans: Arc<Mutex<HashMap<Hash, Vec<OrphanBlock>>>>,
    /// Listen-addresses of peers we've heard about (for discovery).
    known_addrs: Arc<Mutex<HashSet<String>>>,
    /// AddrMan tried/new buckets + feelers (eclipse-resistant selection).
    addrman: Arc<Mutex<crate::addrman::AddrMan>>,
    /// Pending compact-block reconstructions (header_hash → short_ids / fills).
    pending_compact: Arc<Mutex<HashMap<Hash, PendingCompact>>>,
    /// Headers-first: PoW-validated headers waiting for full bodies.
    pending_headers: Arc<Mutex<HashMap<Hash, PendingHeader>>>,
    /// In-flight `GetBlock` hashes (Inv + headers-first + orphan backfill).
    in_flight_bodies: Arc<Mutex<HashSet<Hash>>>,
    /// In-flight `GetTx` / `GetUtxoTx` pulls (Inv flood backpressure).
    in_flight_tx_gets: Arc<Mutex<HashSet<Hash>>>,
    /// Listen-addresses we currently have a connection to (avoid redialing).
    connected_addrs: Arc<Mutex<HashSet<String>>>,
    /// Advertised addresses of peers banned for misbehavior — skipped by
    /// discovery and dialing so a banned peer can't immediately reconnect.
    banned_addrs: Arc<Mutex<HashSet<String>>>,
    /// The pruning point most recently established from a verified cold-start
    /// pruning-point proof. `None` until one is verified.
    ///
    /// Consumed by [`Shared::should_fetch`] and orphan-backfill `GetBlock`
    /// requests: ancestors of this hash are not pulled as full bodies (headers
    /// were imported via the proof). Serving peers may still answer with
    /// `header_only` below the floor.
    verified_pruning_point: Arc<Mutex<Option<Hash>>>,
    /// Whether we have an outstanding `GetPruningProof` request. A `PruningProof`
    /// that arrives while this is false is unsolicited and dropped *before* the
    /// expensive per-header verification — so a peer can't flood proofs as a DoS.
    expecting_pruning_proof: Arc<Mutex<bool>>,
    /// Outstanding `GetPruningPointLedger` after a verified PP import.
    expecting_pruning_ledger: Arc<Mutex<bool>>,
    /// Highest `cumulative_work` (linear proof / `verified_work`) accepted for
    /// cold-start. A weaker or equal proof cannot replace a stronger one.
    best_pruning_work: Arc<Mutex<u128>>,
    /// Our own listen address, advertised in Hello so peers can dial us.
    my_listen_addr: Arc<Mutex<Option<String>>>,
    /// Our static Noise (X25519) private key — this node's transport identity.
    noise_private: Arc<Vec<u8>>,
    /// This node's post-quantum (ML-DSA-87) identity keypair. Used to
    /// authenticate the wire: each side signs the Noise handshake hash so a
    /// quantum man-in-the-middle (who could break the X25519 static-key auth)
    /// still cannot impersonate a peer.
    identity_secret: Arc<Vec<u8>>,
    identity_public: Arc<Vec<u8>>,
    chain_id: u64,
    /// When `Some`, outbound dials use this SOCKS5 proxy (`host:port`), typically
    /// a local Tor daemon. `None` = clearnet. Not a hidden-service publisher.
    tor_proxy: Arc<Mutex<Option<String>>>,
}

impl Shared {
    fn prune_orphans(orph: &mut HashMap<Hash, Vec<OrphanBlock>>) {
        let now = std::time::Instant::now();
        orph.retain(|_, v| {
            v.retain(|o| now.duration_since(o.inserted_at) < ORPHAN_TTL);
            !v.is_empty()
        });
    }

    fn buffer_orphan(&self, missing: &[Hash], block: &Block, hash: Hash) {
        let mut orph = self.orphans.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_orphans(&mut orph);
        let total: usize = orph.values().map(|v| v.len()).sum();
        if total >= MAX_ORPHANS {
            return;
        }
        let entry = OrphanBlock {
            block: block.clone(),
            inserted_at: std::time::Instant::now(),
        };
        for p in missing {
            let waiting = orph.entry(*p).or_default();
            if !waiting.iter().any(|w| w.block.hash() == hash) {
                waiting.push(entry.clone());
            }
        }
    }

    fn our_blue_score(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .selected_tip_blue_score()
    }

    fn have(&self, hash: &Hash) -> bool {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .dag
            .contains_key(hash)
    }

    fn peer_count(&self) -> usize {
        self.peers.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    fn hello(&self) -> Message {
        Message::Hello {
            version: PROTOCOL_VERSION,
            magic: WIRE_MAGIC,
            chain_id: self.chain_id,
            blue_score: self.our_blue_score(),
            listen_addr: self
                .my_listen_addr
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        }
    }

    /// Remember a peer's listen address (bounded), ignoring our own.
    fn remember_addr(&self, addr: &str) {
        if !is_dialable_gossip_addr(addr) {
            return;
        }
        if Some(addr)
            == self
                .my_listen_addr
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_deref()
        {
            return;
        }
        if self
            .banned_addrs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(addr)
        {
            return; // never re-learn a banned peer's address
        }
        let mut known = self.known_addrs.lock().unwrap_or_else(|p| p.into_inner());
        if known.len() < MAX_KNOWN_ADDRS {
            known.insert(addr.to_string());
        }
        drop(known);
        self.addrman
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .add(addr, "gossip");
    }

    /// Dial a discovered peer, unless we're full, already connected to it, or
    /// it's our own address. Runs the connection on a background thread.
    fn dial(&self, addr: &str) {
        if !is_dialable_gossip_addr(addr) {
            return;
        }
        if self.peer_count() >= MAX_PEERS {
            return;
        }
        if Some(addr)
            == self
                .my_listen_addr
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_deref()
        {
            return;
        }
        if self
            .banned_addrs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(addr)
        {
            return; // don't redial a peer we banned for misbehavior
        }
        {
            let mut connected = self
                .connected_addrs
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if connected.contains(addr) {
                return;
            }
            // Optimistically reserve so concurrent discovery ticks don't
            // double-dial the same peer.
            connected.insert(addr.to_string());
        }
        let proxy = self
            .tor_proxy
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match connect_with_timeout(addr, proxy.as_deref()) {
            Ok(stream) => {
                let sh = self.clone();
                let dialed = addr.to_string();
                thread::spawn(move || sh.handle_conn(stream, Some(dialed)));
            }
            Err(_) => {
                // Dial failed — release the reservation so we can retry later.
                self.connected_addrs
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(addr);
            }
        }
    }

    /// Request a block body if under the global in-flight budget.
    fn request_block_body(&self, conn: &Conn, hash: Hash) {
        if !self.should_fetch(&hash) {
            return;
        }
        {
            let mut inflight = self
                .in_flight_bodies
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            // Drop hashes we already have so the budget recovers.
            inflight.retain(|h| self.should_fetch(h));
            if inflight.len() >= MAX_IN_FLIGHT_BODIES {
                return;
            }
            if !inflight.insert(hash) {
                return; // already requested
            }
        }
        // Mirror into pending_headers so headers-first ranking stays coherent.
        {
            let mut pending = self
                .pending_headers
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(p) = pending.get_mut(&hash) {
                p.requested = true;
            }
        }
        self.send(conn, &Message::GetBlock(hash));
    }

    /// Pull an unknown tx by hash if under the tx-get budget.
    fn request_tx_pull(&self, conn: &Conn, hash: Hash, utxo: bool) {
        {
            let mut inflight = self
                .in_flight_tx_gets
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if inflight.len() >= MAX_IN_FLIGHT_TX_GETS {
                return;
            }
            if !inflight.insert(hash) {
                return;
            }
        }
        if utxo {
            self.send(conn, &Message::GetUtxoTx(hash));
        } else {
            self.send(conn, &Message::GetTx(hash));
        }
    }

    fn clear_body_inflight(&self, hash: &Hash) {
        self.in_flight_bodies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(hash);
    }

    fn clear_tx_inflight(&self, hash: &Hash) {
        self.in_flight_tx_gets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(hash);
    }

    fn send(&self, conn: &Conn, msg: &Message) {
        // Must match the receive-side `bincode::options()` configuration exactly
        // (fixint + little-endian); default `bincode::serialize` uses varint and
        // breaks round-trips for some Message variants (e.g. multilevel proofs).
        if let Ok(payload) = bincode::options()
            .with_fixint_encoding()
            .with_little_endian()
            .allow_trailing_bytes()
            .serialize(msg)
        {
            let _ = noise_write(&conn.writer, &conn.transport, &payload);
        }
    }

    /// Post-quantum mutual authentication over the freshly-established transport:
    /// send our ML-DSA identity + a signature over the handshake hash, then read
    /// and verify the peer's (which must be its first post-handshake message).
    /// Returns false — meaning drop the connection — on any failure.
    ///
    /// `dialed_addr` is the peer listen address when we initiated the dial
    /// (used for address-bound pin checks); inbound connections pass `None`.
    fn pq_authenticate(
        &self,
        stream: &mut TcpStream,
        conn: &Conn,
        handshake_hash: &[u8],
        dialed_addr: Option<&str>,
    ) -> bool {
        let sig = match abs_sig::sign_pq512(b"p2p-identity", handshake_hash, &self.identity_secret)
        {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.send(
            conn,
            &Message::Identity {
                pubkey: (*self.identity_public).clone(),
                signature: sig,
            },
        );
        let plaintext = match noise_read(stream, &conn.transport) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let msg = match bincode::options()
            .with_fixint_encoding()
            .with_little_endian()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_BYTES as u64)
            .deserialize::<Message>(&plaintext)
        {
            Ok(m) => m,
            Err(_) => return false,
        };
        match msg {
            Message::Identity { pubkey, signature } => {
                if !abs_sig::verify_pq512(b"p2p-identity", handshake_hash, &pubkey, &signature) {
                    return false;
                }
                if let Err(e) = crate::peer_pin::check_peer_identity(&pubkey, dialed_addr) {
                    eprintln!("p2p: dropping peer — {e}");
                    return false;
                }
                true
            }
            _ => false, // the first post-handshake message must be a valid Identity
        }
    }

    fn broadcast(&self, msg: &Message) {
        let payload = match bincode::serialize(msg) {
            Ok(p) => p,
            Err(_) => return,
        };
        let conns: Vec<Conn> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.conn.clone())
            .collect();
        for c in conns {
            let _ = noise_write(&c.writer, &c.transport, &payload);
        }
    }

    /// Gossip a mempool transfer: TxInv (pull) plus full Tx push for first-hop
    /// liveness, honoring peer FeeFilter.
    fn broadcast_tx(&self, tx: &TransparentTx) {
        let inv_payload = bincode::serialize(&Message::TxInv(tx.tx_hash())).ok();
        let tx_payload = bincode::serialize(&Message::Tx(Box::new(tx.clone()))).ok();
        let peers: Vec<(Conn, u128)> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|p| {
                let f = *p.fee_filter.lock().unwrap_or_else(|e| e.into_inner());
                (p.conn.clone(), f)
            })
            .collect();
        for (c, filter) in peers {
            if filter > 0 && tx.fee < filter {
                continue;
            }
            if let Some(ref p) = inv_payload {
                let _ = noise_write(&c.writer, &c.transport, p);
            }
            if let Some(ref p) = tx_payload {
                let _ = noise_write(&c.writer, &c.transport, p);
            }
        }
    }

    /// Gossip a UTXO mempool spend (Inv + full push), honoring FeeFilter.
    fn broadcast_utxo_tx(&self, tx: &crate::utxo_tx::UtxoTx) {
        let inv_payload = bincode::serialize(&Message::UtxoTxInv(tx.txid())).ok();
        let tx_payload = bincode::serialize(&Message::UtxoTx(Box::new(tx.clone()))).ok();
        let peers: Vec<(Conn, u128)> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|p| {
                let f = *p.fee_filter.lock().unwrap_or_else(|e| e.into_inner());
                (p.conn.clone(), f)
            })
            .collect();
        for (c, filter) in peers {
            if filter > 0 && tx.fee < filter {
                continue;
            }
            if let Some(ref p) = inv_payload {
                let _ = noise_write(&c.writer, &c.transport, p);
            }
            if let Some(ref p) = tx_payload {
                let _ = noise_write(&c.writer, &c.transport, p);
            }
        }
    }

    /// Announce an accepted block as CompactBlock (short-ids) plus classic Inv.
    fn broadcast_compact_block(&self, block: &Block) {
        let header_hash = block.hash();
        let short_ids: Vec<[u8; 8]> = block
            .transparent_txs
            .iter()
            .map(|t| {
                let h = t.tx_hash();
                let mut sid = [0u8; 8];
                sid.copy_from_slice(&h.as_bytes()[..8]);
                sid
            })
            .collect();
        let msg = Message::CompactBlock {
            header_hash,
            nonce: block.nonce,
            short_ids,
            prefilled: vec![],
        };
        self.broadcast(&msg);
        self.broadcast(&Message::Inv(header_hash));
    }

    /// Handle a connection (inbound or outbound): register it as a peer (unless
    /// we're at `MAX_PEERS`), send our Hello, then read and dispatch messages
    /// until it closes or goes idle past `PEER_IDLE_TIMEOUT`. `dialed_addr` is
    /// the peer's listen address when we dialed out (known up front); for
    /// inbound peers it's learned from their Hello.
    fn handle_conn(self, mut stream: TcpStream, dialed_addr: Option<String>) {
        // The peer's IP group, for anti-eclipse accounting (None = loopback).
        let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
        if let Some(ip) = peer_ip {
            if crate::net_policy::ip_bans().is_banned(ip) {
                return; // banned remote socket — refuse before handshake CPU
            }
        }
        let group = peer_ip.and_then(ip_group);

        // Perform the Noise handshake FIRST, so everything after is encrypted
        // and authenticated. The dialer is the initiator. Bound handshake I/O
        // with the idle timeout so a stalled handshake can't pin a thread.
        let _ = stream.set_read_timeout(Some(PEER_IDLE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(PEER_WRITE_TIMEOUT));
        let (transport, handshake_hash) =
            match noise_handshake(&mut stream, dialed_addr.is_some(), &self.noise_private) {
                Ok(t) => t,
                Err(_) => return, // handshake failed — drop the connection
            };
        let transport = Arc::new(Mutex::new(transport));

        let write_half = match stream.try_clone() {
            Ok(w) => w,
            Err(_) => return,
        };
        let conn = Conn {
            writer: Arc::new(Mutex::new(write_half)),
            transport,
        };

        // Post-quantum peer authentication. Both sides prove ownership of their
        // ML-DSA-87 identity by signing the Noise handshake hash (channel
        // binding). Since the ML-KEM PSK is mixed into that hash, a quantum
        // adversary who breaks the X25519 static-key auth still cannot forge a
        // valid signature for this session — so the wire is authenticated
        // post-quantum, not just encrypted post-quantum. A peer that fails this
        // is dropped before it is ever registered.
        if !self.pq_authenticate(&mut stream, &conn, &handshake_hash, dialed_addr.as_deref()) {
            return;
        }

        // Enforce the total peer cap AND the per-IP-group cap atomically. The
        // group cap stops one address range from filling every slot and
        // eclipsing us from the honest network.
        let peer_fee_filter = {
            let mut peers = self.peers.lock().unwrap();
            if peers.len() >= MAX_PEERS {
                return; // refuse; connection drops as it falls out of scope
            }
            if let Some(g) = &group {
                let same_group = peers.iter().filter(|p| p.group.as_ref() == Some(g)).count();
                if same_group >= MAX_PEERS_PER_GROUP {
                    return; // too many peers from this IP group — refuse
                }
            }
            let fee_filter = Arc::new(Mutex::new(0u128));
            peers.push(PeerHandle {
                group: group.clone(),
                conn: conn.clone(),
                fee_filter: fee_filter.clone(),
            });
            fee_filter
        };
        refresh_network_status(&self);

        // Tracks the peer's advertised listen address, for discovery cleanup.
        let peer_listen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(dialed_addr.clone()));
        if let Some(a) = &dialed_addr {
            self.remember_addr(a);
        }

        self.send(&conn, &self.hello());
        // Advertise a non-zero FeeFilter only under mempool congestion so idle
        // peers still receive size-priced transfers; always honor received filters.
        let our_min = {
            let st = self.state.read().unwrap_or_else(|p| p.into_inner());
            let utxo_hot = st.utxo_mempool.len() * 4 >= crate::MAX_MEMPOOL_SIZE * 3;
            let acct_hot = st.transparent_mempool.len() * 4 >= crate::MAX_MEMPOOL_SIZE * 3;
            if utxo_hot || acct_hot {
                st.current_min_relay_fee()
            } else {
                0
            }
        };
        self.send(&conn, &Message::FeeFilter { min_fee: our_min });

        // Idle timeout so a silent peer can't pin a thread forever, plus a
        // per-peer message-rate limit so a flooding peer is cut off.
        let mut read_stream = stream;
        let policy = crate::net_policy::policy();
        let mut rate = RateWindow::new(policy.peer_msg_limit);
        let stark_budget = crate::net_policy::StarkVerifyBudget::new(
            policy.stark_verifies_per_window,
            policy.stark_window,
        );
        let mut ban_score: u32 = 0;
        let mut last_ban_decay = std::time::Instant::now();
        // Kept as an explicit `match`/`break` (not `while let`) so the exit
        // reasons stay documented at the break site.
        #[allow(clippy::while_let_loop)]
        loop {
            if last_ban_decay.elapsed() >= BAN_DECAY_INTERVAL {
                ban_score = ban_score.saturating_sub(BAN_DECAY_POINTS);
                last_ban_decay = std::time::Instant::now();
            }
            let plaintext = match noise_read(&mut read_stream, &conn.transport) {
                Ok(p) => p,
                Err(_) => break, // disconnected, idle timeout, or decrypt failure
            };
            // Deserialize with an explicit byte limit matching the wire cap, so
            // a crafted length prefix (e.g. a Vec claiming billions of elements)
            // can't drive an unbounded allocation → OOM/abort before the data is
            // even read. The options are configured to match `bincode::serialize`
            // (fixint, little-endian, trailing allowed) so the format is
            // identical — only bounded.
            let msg = match bincode::options()
                .with_fixint_encoding()
                .with_little_endian()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_BYTES as u64)
                .deserialize::<Message>(&plaintext)
            {
                Ok(m) => m,
                Err(_) => break, // malformed, oversized, or decrypt-garbage
            };
            if !message_within_type_cap(&msg, plaintext.len()) {
                ban_score = ban_score.saturating_add(INVALID_TX_PENALTY);
                if ban_score >= BAN_SCORE_THRESHOLD {
                    break;
                }
                continue;
            }
            if !rate.record() {
                break; // peer is flooding — disconnect it
            }
            if let Message::FeeFilter { min_fee } = &msg {
                *peer_fee_filter.lock().unwrap_or_else(|p| p.into_inner()) = *min_fee;
            }
            ban_score = ban_score
                .saturating_add(self.dispatch(msg, &conn, &peer_listen, Some(&stark_budget)));
            if ban_score >= BAN_SCORE_THRESHOLD {
                // Persistently misbehaving: ban advertised listen addr AND the
                // remote socket IP so inbound reconnects from a new listen
                // advertisement still fail.
                if let Some(a) = peer_listen.lock().unwrap_or_else(|p| p.into_inner()).clone() {
                    let mut banned = self.banned_addrs.lock().unwrap_or_else(|p| p.into_inner());
                    if banned.len() < MAX_KNOWN_ADDRS {
                        banned.insert(a.clone());
                    }
                    self.known_addrs
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&a);
                }
                if let Some(ip) = peer_ip {
                    crate::net_policy::ip_bans().ban(ip);
                }
                break;
            }
        }

        // Deregister on disconnect, and free its listen address for redialing.
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|p| !Arc::ptr_eq(&p.conn.writer, &conn.writer));
        let disconnected_addr = peer_listen.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(a) = disconnected_addr {
            self.connected_addrs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&a);
        }
        refresh_network_status(&self);
    }

    /// Handle one message; returns the ban-score points it earned (0 for
    /// everything except a provably-invalid block).
    fn dispatch(
        &self,
        msg: Message,
        conn: &Conn,
        peer_listen: &Arc<Mutex<Option<String>>>,
        stark_budget: Option<&crate::net_policy::StarkVerifyBudget>,
    ) -> u32 {
        match msg {
            Message::Hello {
                version,
                magic,
                chain_id,
                blue_score,
                listen_addr,
            } => {
                // Incompatible peers are dropped (ban-threshold disconnect).
                if version != PROTOCOL_VERSION || magic != WIRE_MAGIC || chain_id != self.chain_id {
                    return BAN_SCORE_THRESHOLD;
                }
                if let Some(a) = listen_addr {
                    self.remember_addr(&a);
                    self.connected_addrs
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(a.clone());
                    *peer_listen.lock().unwrap_or_else(|p| p.into_inner()) = Some(a);
                }
                // Cold-start: request linear + succinct multilevel. Linear is
                // asked first so a small proof can adopt even if a multilevel
                // reply is slow or dropped. Adopt ranking is hard work only
                // (linear `cumulative_work` / multilevel `verified_work`);
                // multilevel `estimated_total_work` never decides adopt.
                if blue_score > self.our_blue_score() {
                    if self
                        .verified_pruning_point
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .is_none()
                    {
                        *self
                            .expecting_pruning_proof
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = true;
                        self.send(conn, &Message::GetPruningProof);
                        self.send(conn, &Message::GetMultiLevelPruningProof);
                    }
                    self.send(conn, &Message::GetTips);
                }
                // Kick off discovery on this fresh peer.
                self.send(conn, &Message::GetAddr);
            }
            Message::GetAddr => {
                // Share up to a bounded sample of known addresses.
                let addrs: Vec<String> = self
                    .known_addrs
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .take(64)
                    .cloned()
                    .collect();
                if !addrs.is_empty() {
                    self.send(conn, &Message::Addr(addrs));
                }
            }
            Message::Addr(addrs) => {
                // Cap how many addresses we act on per message — a peer must
                // not be able to make us spawn an unbounded number of dial
                // threads (red-team V2). `dial` itself no-ops once we're at
                // MAX_PEERS.
                for a in addrs.into_iter().take(MAX_ADDRS_PER_MSG) {
                    self.remember_addr(&a);
                    self.dial(&a);
                }
            }
            Message::GetTips => {
                let tips = self
                    .state
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .tips
                    .clone();
                self.send(conn, &Message::Tips(tips));
            }
            Message::Tips(tips) => {
                for t in tips {
                    self.request_block_body(conn, t);
                }
            }
            Message::GetBlock(h) => {
                let block = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    if let Some(b) = st.dag.get(&h) {
                        if st.is_body_pruned(&h) {
                            // Headers-first: still serve the header so peers can
                            // verify ancestry/PoW without the pruned body.
                            Some(b.header_only())
                        } else if let Some(pp) = *self
                            .verified_pruning_point
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                        {
                            if !st.archival
                                && st.dag.contains_key(&pp)
                                && h != pp
                                && st.reachability.is_ancestor(&h, &pp, &st.dag)
                            {
                                Some(b.header_only())
                            } else {
                                Some(b.clone())
                            }
                        } else {
                            Some(b.clone())
                        }
                    } else {
                        None
                    }
                };
                match block {
                    Some(b) => self.send(conn, &Message::Block(Box::new(b))),
                    None => self.send(conn, &Message::NotFound(h)),
                }
            }
            Message::Block(b) => {
                let hash = b.hash();
                let pen = self.ingest_block(*b, stark_budget);
                self.clear_body_inflight(&hash);
                return pen;
            }
            Message::Inv(h) => {
                self.request_block_body(conn, h);
            }
            Message::NotFound(h) => {
                self.clear_body_inflight(&h);
                self.clear_tx_inflight(&h);
            }
            Message::Tx(tx) => {
                let hash = tx.tx_hash();
                let pen = self.relay_transparent(*tx);
                self.clear_tx_inflight(&hash);
                return pen;
            }
            Message::TxInv(h) => {
                let have = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    st.transparent_mempool.iter().any(|t| t.tx_hash() == h)
                };
                if !have {
                    self.request_tx_pull(conn, h, false);
                }
            }
            Message::GetTx(h) => {
                let tx = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    st.transparent_mempool
                        .iter()
                        .find(|t| t.tx_hash() == h)
                        .cloned()
                };
                if let Some(tx) = tx {
                    self.send(conn, &Message::Tx(Box::new(tx)));
                } else {
                    self.send(conn, &Message::NotFound(h));
                }
            }
            Message::TxPackage(txs) => {
                let mut ban = 0u32;
                for tx in txs.into_iter().take(MAX_TX_PACKAGE) {
                    ban = ban.saturating_add(self.relay_transparent(tx));
                }
                return ban;
            }
            Message::UtxoTx(tx) => {
                let hash = tx.txid();
                let pen = self.relay_utxo(*tx);
                self.clear_tx_inflight(&hash);
                return pen;
            }
            Message::UtxoTxInv(h) => {
                let have = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    st.utxo_mempool.iter().any(|t| t.txid() == h)
                };
                if !have {
                    self.request_tx_pull(conn, h, true);
                }
            }
            Message::GetUtxoTx(h) => {
                let tx = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    st.utxo_mempool.iter().find(|t| t.txid() == h).cloned()
                };
                if let Some(tx) = tx {
                    self.send(conn, &Message::UtxoTx(Box::new(tx)));
                } else {
                    self.send(conn, &Message::NotFound(h));
                }
            }
            Message::CompactBlock {
                header_hash,
                nonce: _,
                short_ids,
                prefilled,
            } => {
                // High-BW path: reconstruct from mempool + prefilled; GetBlockTxn
                // for misses; short-id collisions treated as missing.
                for tx in &prefilled {
                    let _ = self.relay_transparent(tx.clone());
                }
                let mempool = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    st.transparent_mempool.clone()
                };
                let (filled, missing) =
                    reconstruct_from_mempool(&short_ids, &mempool, &prefilled);
                {
                    let mut pending = self
                        .pending_compact
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    pending.insert(
                        header_hash,
                        PendingCompact {
                            short_ids: short_ids.clone(),
                            filled,
                        },
                    );
                    if pending.len() > 128 {
                        let keys: Vec<_> = pending.keys().copied().take(pending.len() / 2).collect();
                        for k in keys {
                            pending.remove(&k);
                        }
                    }
                }
                if !missing.is_empty() {
                    self.send(
                        conn,
                        &Message::GetBlockTxn {
                            block_hash: header_hash,
                            indexes: missing,
                        },
                    );
                }
                if self.should_fetch(&header_hash) {
                    self.request_block_body(conn, header_hash);
                }
            }
            Message::GetBlockTxn { block_hash, indexes } => {
                let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                if let Some(b) = st.dag.get(&block_hash) {
                    let mut txs = Vec::new();
                    for idx in indexes {
                        if let Some(tx) = b.transparent_txs.get(idx as usize) {
                            txs.push(tx.clone());
                        }
                    }
                    drop(st);
                    self.send(
                        conn,
                        &Message::BlockTxn {
                            block_hash,
                            txs,
                        },
                    );
                }
            }
            Message::BlockTxn { block_hash, txs } => {
                let mut ban = 0u32;
                for tx in &txs {
                    ban = ban.saturating_add(self.relay_transparent(tx.clone()));
                }
                if let Some(pending) = self
                    .pending_compact
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get_mut(&block_hash)
                {
                    let mut ti = 0usize;
                    for (i, slot) in pending.filled.iter_mut().enumerate() {
                        if slot.is_none() {
                            if let Some(tx) = txs.get(ti) {
                                if i < pending.short_ids.len()
                                    && tx_short_id(tx) == pending.short_ids[i]
                                {
                                    *slot = Some(tx.clone());
                                }
                                ti += 1;
                            }
                        }
                    }
                }
                return ban;
            }
            Message::GetHeaders {
                locator,
                stop_hash,
                limit,
            } => {
                let limit = (limit as usize).clamp(1, MAX_HEADERS_PER_MSG);
                let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                let start = locator
                    .iter()
                    .take(MAX_LOCATOR_HASHES)
                    .find(|h| st.dag.contains_key(h))
                    .copied()
                    .or_else(|| st.main_chain.first().copied());
                let mut headers = Vec::new();
                if let Some(cur) = start {
                    // Walk selected chain forward from locator toward tip.
                    let chain = st.main_chain.clone();
                    if let Some(pos) = chain.iter().position(|h| *h == cur) {
                        for h in chain.iter().skip(pos).take(limit) {
                            if let Some(b) = st.dag.get(h) {
                                headers.push(b.header_only());
                            }
                            if *h == stop_hash && stop_hash != Hash::ZERO {
                                break;
                            }
                        }
                    }
                }
                drop(st);
                if !headers.is_empty() {
                    self.send(conn, &Message::Headers(headers));
                }
            }
            Message::Headers(headers) => {
                // Headers-first: cheap PoW/difficulty gate before any GetBlock.
                // Rank by cumulative difficulty-work and cap in-flight body fetches
                // so a peer cannot force unbounded STARK verification.
                if headers.len() > MAX_HEADERS_PER_MSG {
                    return INVALID_BLOCK_PENALTY;
                }
                let mut ban = 0u32;
                let mut accepted: Vec<(Hash, PendingHeader)> = Vec::new();
                {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    for h in headers {
                        let hash = h.hash();
                        if st.dag.contains_key(&hash) {
                            continue;
                        }
                        match st.precheck_header(&h) {
                            Ok(()) => {
                                let parent_work: u128 = h
                                    .parents
                                    .iter()
                                    .filter_map(|p| st.dag.get(p).map(|b| b.difficulty))
                                    .map(ChainState::header_work_units)
                                    .max()
                                    .unwrap_or(0);
                                let work = parent_work
                                    .saturating_add(ChainState::header_work_units(h.difficulty));
                                accepted.push((
                                    hash,
                                    PendingHeader {
                                        header: h.header_only(),
                                        work,
                                        requested: false,
                                    },
                                ));
                            }
                            Err(e) if e.contains("Unknown parent") => {
                                // Parent not yet local — pull it if we should.
                                for p in &h.parents {
                                    self.request_block_body(conn, *p);
                                }
                            }
                            Err(e)
                                if e.contains("Invalid proof of work")
                                    || e.contains("Wrong difficulty")
                                    || e.contains("Duplicate parent")
                                    || e.contains("Too many parents")
                                    || e.contains("no parents")
                                    || e.contains("interlinks") =>
                            {
                                ban = ban.saturating_add(INVALID_BLOCK_PENALTY);
                            }
                            Err(_) => {}
                        }
                    }
                }
                if !accepted.is_empty() {
                    let mut pending = self
                        .pending_headers
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    // Drop stale entries once capped.
                    if pending.len() + accepted.len() > MAX_PENDING_HEADERS {
                        let overflow =
                            pending.len() + accepted.len() - MAX_PENDING_HEADERS;
                        let mut by_work: Vec<Hash> = pending.keys().copied().collect();
                        by_work.sort_by(|a, b| {
                            let wa = pending.get(a).map(|p| p.work).unwrap_or(0);
                            let wb = pending.get(b).map(|p| p.work).unwrap_or(0);
                            wa.cmp(&wb)
                        });
                        for h in by_work.into_iter().take(overflow) {
                            pending.remove(&h);
                        }
                    }
                    for (hash, ph) in accepted {
                        pending.entry(hash).or_insert(ph);
                    }
                    // Request bodies for highest-work unverified headers first.
                    let mut ranked: Vec<(Hash, u128)> = pending
                        .iter()
                        .filter(|(_, p)| !p.requested)
                        .map(|(h, p)| (*h, p.work))
                        .collect();
                    ranked.sort_by(|a, b| b.1.cmp(&a.1));
                    drop(pending);
                    for (hash, _) in ranked {
                        let before = self
                            .in_flight_bodies
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .len();
                        if before >= MAX_IN_FLIGHT_BODIES {
                            break;
                        }
                        self.request_block_body(conn, hash);
                    }
                }
                return ban;
            }
            Message::Ping(nonce) => {
                self.send(conn, &Message::Pong(nonce));
            }
            Message::Pong(_) => {}
            Message::GetPruningProof => {
                // Only an archival node holding the full header history can build
                // one; others simply don't answer.
                if let Some(proof) = self.state.read().unwrap().build_pruning_proof() {
                    self.send(conn, &Message::PruningProof(Box::new(proof)));
                }
            }
            Message::GetMultiLevelPruningProof => {
                // Prefer succinct multilevel with a DAA-sized recent window; if
                // the chain is too short to compress at that window, retry with
                // a small window; only then fall back to the linear proof.
                let st = self.state.read().unwrap();
                let ml = st
                    .build_multilevel_pruning_proof(crate::PRUNING_PROOF_RECENT_WINDOW)
                    .or_else(|| st.build_multilevel_pruning_proof(2));
                if let Some(ml) = ml {
                    drop(st);
                    self.send(conn, &Message::MultiLevelPruningProof(Box::new(ml)));
                } else if let Some(proof) = st.build_pruning_proof() {
                    drop(st);
                    self.send(conn, &Message::PruningProof(Box::new(proof)));
                }
            }
            Message::PruningProof(proof) => {
                // Drop unsolicited proofs cheaply — do NOT run the expensive
                // per-header PoW verification unless we actually asked for one.
                if !*self
                    .expecting_pruning_proof
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                {
                    return 0;
                }
                // Cold-start adopt: fully verify *before* any state mutation.
                // Adopt only on strictly greater hard `cumulative_work` — never
                // on statistical multilevel estimates (those are API-only).
                let summary = match crate::verify_pruning_proof(&proof) {
                    Ok(s) => s,
                    Err(_) => return INVALID_BLOCK_PENALTY,
                };
                let tip = proof.headers.last().unwrap();
                let fresh_ctx = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    let best = *self
                        .best_pruning_work
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    let tip_h = st.tip_height();
                    crate::superproof::IbdFreshnessContext {
                        now_ms: crate::now_ms(),
                        local_best_work: best,
                        local_tip_height: tip_h,
                        local_tip_timestamp: st
                            .dag
                            .get(st.main_chain.last().unwrap_or(&crate::genesis_hash()))
                            .map(|b| b.timestamp)
                            .unwrap_or(crate::GENESIS_TIMESTAMP_MS),
                        local_past_genesis: tip_h > 0,
                    }
                };
                if crate::superproof::check_ibd_proof_freshness(
                    proof.headers[0].hash(),
                    tip.height,
                    tip.timestamp,
                    summary.cumulative_work,
                    &fresh_ctx,
                )
                .is_err()
                {
                    *self
                        .expecting_pruning_proof
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = false;
                    return INVALID_BLOCK_PENALTY;
                }
                {
                    let best = self
                        .best_pruning_work
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    if summary.cumulative_work <= *best {
                        *self
                            .expecting_pruning_proof
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = false;
                        return 0;
                    }
                }
                // Import verified headers into the DAG before recording work/PP.
                if self
                    .state
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
                    .import_verified_pruning_headers(&proof.headers)
                    .is_err()
                {
                    return INVALID_BLOCK_PENALTY;
                }
                {
                    let mut best = self
                        .best_pruning_work
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    if summary.cumulative_work > *best {
                        *best = summary.cumulative_work;
                    }
                }
                *self
                    .expecting_pruning_proof
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = false;
                *self
                    .verified_pruning_point
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(summary.pruning_point);
                crate::assume_valid::note_pruning_point_engaged(&summary.pruning_point);
                // Topology alone leaves empty genesis accounts — fetch PP ledger.
                *self
                    .expecting_pruning_ledger
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = true;
                self.send(conn, &Message::GetPruningPointLedger(summary.pruning_point));
            }
            Message::MultiLevelPruningProof(proof) => {
                if !*self
                    .expecting_pruning_proof
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                {
                    return 0;
                }
                // Adopt only on strictly greater `verified_work` (never on
                // estimated_total_work), with IBD freshness / upgrade gates.
                let headers = proof.headers_genesis_first();
                let fresh_ctx = {
                    let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                    let best = *self
                        .best_pruning_work
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    let tip_h = st.tip_height();
                    crate::superproof::IbdFreshnessContext {
                        now_ms: crate::now_ms(),
                        local_best_work: best,
                        local_tip_height: tip_h,
                        local_tip_timestamp: st
                            .dag
                            .get(st.main_chain.last().unwrap_or(&crate::genesis_hash()))
                            .map(|b| b.timestamp)
                            .unwrap_or(crate::GENESIS_TIMESTAMP_MS),
                        local_past_genesis: tip_h > 0,
                    }
                };
                let adopt_result = crate::superproof::adopt_multilevel_pruning_proof_fresh(
                    &proof,
                    &fresh_ctx,
                    |summary| -> Result<bool, String> {
                        {
                            let best = self
                                .best_pruning_work
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            if summary.verified_work <= *best {
                                return Ok(false);
                            }
                        }
                        self.state
                            .write()
                            .unwrap_or_else(|p| p.into_inner())
                            .import_verified_pruning_headers(&headers)?;
                        {
                            let mut best = self
                                .best_pruning_work
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            if summary.verified_work > *best {
                                *best = summary.verified_work;
                            }
                        }
                        *self
                            .verified_pruning_point
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) =
                            Some(summary.pruning_point);
                        crate::assume_valid::note_pruning_point_engaged(&summary.pruning_point);
                        *self
                            .expecting_pruning_ledger
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = true;
                        Ok(true)
                    },
                );
                match adopt_result {
                    Ok(Ok(true)) => {
                        *self
                            .expecting_pruning_proof
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = false;
                        if let Some(pp) = *self.verified_pruning_point.lock().unwrap() {
                            self.send(conn, &Message::GetPruningPointLedger(pp));
                        }
                    }
                    Ok(Ok(false)) => {
                        *self
                            .expecting_pruning_proof
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = false;
                    }
                    Ok(Err(_)) | Err(_) => return INVALID_BLOCK_PENALTY,
                }
            }
            Message::GetPruningPointLedger(pp) => {
                let st = self.state.read().unwrap();
                if st.pruning_point != Some(pp) {
                    return 0;
                }
                if let Some(ledger) = st.build_pruning_point_ledger() {
                    drop(st);
                    self.send(conn, &Message::PruningPointLedger(Box::new(ledger)));
                }
            }
            Message::PruningPointLedger(msg) => {
                if !*self
                    .expecting_pruning_ledger
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                {
                    return 0;
                }
                let mut st = self.state.write().unwrap_or_else(|p| p.into_inner());
                if st.adopt_pruning_point_ledger(&msg).is_err() {
                    return INVALID_BLOCK_PENALTY;
                }
                *self
                    .expecting_pruning_ledger
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = false;
            }
            // Peer authentication happens once, right after the handshake (see
            // `handle_conn`); a stray Identity mid-session is simply ignored.
            Message::FeeFilter { .. } => {
                // Applied on the receive path via peer_fee_filter before dispatch.
            }
            Message::Identity { .. } => {}
        }
        0
    }

    /// Whether we should request this block hash (unknown, and not buried
    /// under a verified pruning point).
    fn should_fetch(&self, h: &Hash) -> bool {
        if self.have(h) {
            return false;
        }
        let pp = match *self
            .verified_pruning_point
            .lock()
            .unwrap_or_else(|p| p.into_inner())
        {
            Some(pp) => pp,
            None => return true,
        };
        let st = self.state.read().unwrap_or_else(|p| p.into_inner());
        if !st.dag.contains_key(&pp) {
            return true;
        }
        // Skip ancestors of the pruning point (history we treat as finalized/pruned).
        if *h != pp && st.reachability.is_ancestor(h, &pp, &st.dag) {
            return false;
        }
        true
    }

    /// Admit a gossiped UTXO spend. Penalize only provably-invalid txs.
    fn relay_utxo(&self, tx: crate::utxo_tx::UtxoTx) -> u32 {
        match self
            .state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .admit_utxo_to_mempool(tx)
        {
            Ok(()) => 0,
            Err(e)
                if e == "Invalid signature"
                    || e == "Wrong chain_id"
                    || e.starts_with("Invalid")
                    || e.contains("Fee")
                    || e.contains("dust")
                    || e.contains("Duplicate input")
                    || e.contains("requires at least") =>
            {
                INVALID_TX_PENALTY
            }
            Err(_) => 0,
        }
    }

    /// Admit a gossiped transparent transfer to the mempool. Returns ban-score
    /// points: nonzero only for a provably-invalid tx (bad signature / wrong
    /// chain). A duplicate / stale-nonce / full-mempool result is benign (0).
    /// No rebroadcast here — the mempool announcer propagates newly-admitted
    /// txs, which keeps gossip loop-free (an already-present tx is not re-sent).
    fn relay_transparent(&self, tx: TransparentTx) -> u32 {
        match self
            .state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .admit_transparent_to_mempool(tx)
        {
            Ok(()) => 0,
            Err(e)
                if e == "Invalid signature"
                    || e == "Wrong chain_id"
                    || e == "Insufficient balance"
                    || e.starts_with("Invalid")
                    || e.starts_with("Package nonce depth")
                    || e.contains("Fee")
                    || e.contains("Amount") =>
            {
                INVALID_TX_PENALTY
            }
            Err(_) => 0,
        }
    }

    /// Try to add a block, resolving any orphans it unlocks. Uses an explicit
    /// work queue (not recursion) so backfilling a long chain can't overflow
    /// the stack. A block whose parents are missing is buffered and its
    /// parents are requested from all peers.
    /// Returns the misbehavior (ban-score) points the *directly received* block
    /// earned — `INVALID_BLOCK_PENALTY` if it was provably invalid, 0 otherwise
    /// (valid, duplicate, or an honest orphan). Orphans unlocked from the pool
    /// came from other peers already, so their validity is never charged here.
    fn ingest_block(
        &self,
        block: Block,
        stark_budget: Option<&crate::net_policy::StarkVerifyBudget>,
    ) -> u32 {
        let mut penalty: u32 = 0;
        // (block, is_direct): only the caller's own block can incur a penalty.
        let mut queue = vec![(block, true)];
        while let Some((b, is_direct)) = queue.pop() {
            let hash = b.hash();
            if self.have(&hash) {
                continue;
            }

            // Cheap precheck under a read lock before the expensive write path
            // (STARK + GHOSTDAG). Unknown-parent orphans still need buffering.
            {
                let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                match st.precheck_block(&b) {
                    Err(e) if e.contains("Unknown parent") => {
                        drop(st);
                        let missing: Vec<Hash> = {
                            let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                            b.parents
                                .iter()
                                .filter(|p| !st.dag.contains_key(*p))
                                .copied()
                                .collect()
                        };
                        {
                            self.buffer_orphan(&missing, &b, hash);
                        }
                        for p in &missing {
                            // Orphan backfill: broadcast GetBlock under budget
                            // via a synthetic peer-local request when possible.
                            // Without a Conn here, mark in-flight and broadcast.
                            if !self.should_fetch(p) {
                                continue;
                            }
                            let mut inflight = self
                                .in_flight_bodies
                                .lock()
                                .unwrap_or_else(|inner| inner.into_inner());
                            inflight.retain(|h| self.should_fetch(h));
                            if inflight.len() >= MAX_IN_FLIGHT_BODIES {
                                break;
                            }
                            if inflight.insert(*p) {
                                drop(inflight);
                                self.broadcast(&Message::GetBlock(*p));
                            }
                        }
                        continue;
                    }
                    Err(e) => {
                        if is_direct {
                            penalty = penalty.saturating_add(block_ban_penalty(&e));
                        }
                        continue;
                    }
                    Ok(()) => {}
                }
            }

            // Per-peer STARK verify budget: after cheap format/PoW precheck,
            // refuse to run winterfell if this peer already burned its window.
            if is_direct {
                if let Some(budget) = stark_budget {
                    if !budget.try_consume() {
                        penalty = penalty.saturating_add(INVALID_STARK_PENALTY);
                        continue;
                    }
                }
            }

            let result = self
                .state
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .add_block(b.clone());
            match result {
                Ok(()) => {
                    self.clear_body_inflight(&hash);
                    self.pending_headers
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&hash);
                    // Compact short-id announce + classic Inv for older peers.
                    self.broadcast_compact_block(&b);
                    if let Some(children) = self
                        .orphans
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&hash)
                    {
                        let now = std::time::Instant::now();
                        queue.extend(children.into_iter().filter_map(|c| {
                            if now.duration_since(c.inserted_at) < ORPHAN_TTL {
                                Some((c.block, false))
                            } else {
                                None
                            }
                        }));
                    }
                }
                Err(e) if e.contains("Unknown parent") => {
                    let missing: Vec<Hash> = {
                        let st = self.state.read().unwrap_or_else(|p| p.into_inner());
                        b.parents
                            .iter()
                            .filter(|p| !st.dag.contains_key(*p))
                            .copied()
                            .collect()
                    };
                    self.buffer_orphan(&missing, &b, hash);
                    for p in &missing {
                        if self.should_fetch(p) {
                            self.broadcast(&Message::GetBlock(*p));
                        }
                    }
                }
                Err(e) => {
                    if is_direct {
                        penalty = penalty.saturating_add(block_ban_penalty(&e));
                    }
                }
            }
        }
        penalty
    }
}

fn block_ban_penalty(err: &str) -> u32 {
    if err.contains("STARK") {
        INVALID_STARK_PENALTY
    } else {
        INVALID_BLOCK_PENALTY
    }
}

fn load_or_create_identity(data_dir: Option<&std::path::Path>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    if let Some(dir) = data_dir {
        let path = dir.join("p2p_identity.bin");
        if let Ok(bytes) = std::fs::read(&path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        eprintln!(
                            "refusing world/group-readable p2p identity {} (mode {mode:o}); chmod 600 and restart",
                            path.display()
                        );
                        // Fall through to ephemeral keys rather than load a leaked identity.
                        let noise_private =
                            snow::Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
                                .generate_keypair()
                                .expect("noise keypair generation")
                                .private;
                        let (identity_secret, identity_public) = generate_keypair();
                        return (noise_private, identity_secret, identity_public);
                    }
                }
            }
            if bytes.len() >= 32 + crate::PQ_SECRET_KEY_SIZE + crate::PQ_PUBLIC_KEY_SIZE {
                let noise_private = bytes[..32].to_vec();
                let identity_secret = bytes[32..32 + crate::PQ_SECRET_KEY_SIZE].to_vec();
                let identity_public = bytes[32 + crate::PQ_SECRET_KEY_SIZE
                    ..32 + crate::PQ_SECRET_KEY_SIZE + crate::PQ_PUBLIC_KEY_SIZE]
                    .to_vec();
                return (noise_private, identity_secret, identity_public);
            }
        }
        let noise_private = snow::Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .generate_keypair()
            .expect("noise keypair generation")
            .private;
        let (identity_secret, identity_public) = generate_keypair();
        let mut out = Vec::with_capacity(32 + identity_secret.len() + identity_public.len());
        out.extend_from_slice(&noise_private);
        out.extend_from_slice(&identity_secret);
        out.extend_from_slice(&identity_public);
        let _ = std::fs::create_dir_all(dir);
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
            {
                let _ = f.write_all(&out);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = std::fs::write(&path, &out);
        }
        return (noise_private, identity_secret, identity_public);
    }
    let noise_private = snow::Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
        .generate_keypair()
        .expect("noise keypair generation")
        .private;
    let (identity_secret, identity_public) = generate_keypair();
    (noise_private, identity_secret, identity_public)
}

/// A P2P node: wraps a shared `ChainState` and manages peer connections,
/// gossip, and sync. Cheap to construct; all work happens on background
/// threads started by `listen`/`connect`/`spawn_tip_announcer`.
pub struct Node {
    shared: Shared,
}

impl Node {
    pub fn new(state: Arc<RwLock<ChainState>>) -> Self {
        Self::with_data_dir(state, None)
    }

    /// Construct a node, optionally loading/persisting Noise + PQ identity under
    /// `data_dir` so peer reputation survives restarts.
    pub fn with_data_dir(
        state: Arc<RwLock<ChainState>>,
        data_dir: Option<&std::path::Path>,
    ) -> Self {
        let chain_id = state.read().unwrap_or_else(|p| p.into_inner()).chain_id;
        let (noise_private, identity_secret, identity_public) = load_or_create_identity(data_dir);
        Self {
            shared: Shared {
                state,
                peers: Arc::new(Mutex::new(Vec::new())),
                orphans: Arc::new(Mutex::new(HashMap::new())),
                known_addrs: Arc::new(Mutex::new(HashSet::new())),
                addrman: Arc::new(Mutex::new(crate::addrman::AddrMan::new())),
                pending_compact: Arc::new(Mutex::new(HashMap::new())),
                pending_headers: Arc::new(Mutex::new(HashMap::new())),
                in_flight_bodies: Arc::new(Mutex::new(HashSet::new())),
                in_flight_tx_gets: Arc::new(Mutex::new(HashSet::new())),
                connected_addrs: Arc::new(Mutex::new(HashSet::new())),
                banned_addrs: Arc::new(Mutex::new(HashSet::new())),
                verified_pruning_point: Arc::new(Mutex::new(None)),
                expecting_pruning_proof: Arc::new(Mutex::new(false)),
                expecting_pruning_ledger: Arc::new(Mutex::new(false)),
                best_pruning_work: Arc::new(Mutex::new(0)),
                my_listen_addr: Arc::new(Mutex::new(None)),
                noise_private: Arc::new(noise_private),
                identity_secret: Arc::new(identity_secret),
                identity_public: Arc::new(identity_public),
                chain_id,
                tor_proxy: Arc::new(Mutex::new(None)),
            },
        }
    }

    /// Route outbound P2P dials through a SOCKS5 proxy (`host:port`), or clearnet
    /// when `None`. Typical Tor default: `127.0.0.1:9050`. This only affects
    /// *outbound* `connect`/`dial` — inbound listen stays clearnet TCP, and we
    /// do **not** publish a Tor hidden service.
    pub fn set_tor_proxy(&self, proxy: Option<&str>) {
        *self
            .shared
            .tor_proxy
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = proxy.map(|s| s.to_string());
    }

    /// Bind a listener and accept peers in the background. Returns the actual
    /// bound address (useful when binding to port 0 for an ephemeral port).
    /// Records our listen address so it's advertised to peers for discovery,
    /// and starts the discovery/keepalive loop.
    pub fn listen(&self, addr: &str) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        *self.shared.my_listen_addr.lock().unwrap() = Some(local.to_string());
        refresh_network_status(&self.shared);
        self.spawn_discovery();
        let shared = self.shared.clone();
        // Gate return on the accept thread actually starting — otherwise a
        // dialer can complete TCP connect (kernel backlog) and begin the
        // Noise/ML-KEM handshake before any responder is reading.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = ready_tx.send(());
            for s in listener.incoming().flatten() {
                // Bound thread spawning: if we're already at the peer cap,
                // drop the connection here instead of spawning a handler
                // that would only reject it after allocating a thread
                // (red-team V1). `s` closes as it falls out of scope.
                if shared.peer_count() >= MAX_PEERS {
                    continue;
                }
                let sh = shared.clone();
                thread::spawn(move || sh.handle_conn(s, None));
            }
        });
        let _ = ready_rx.recv();
        Ok(local)
    }

    /// Dial a peer and start handling it in the background.
    pub fn connect(&self, addr: &str) -> std::io::Result<()> {
        let proxy = self.shared.tor_proxy.lock().unwrap().clone();
        let stream = connect_with_timeout(addr, proxy.as_deref())?;
        self.shared.remember_addr(addr);
        self.shared
            .connected_addrs
            .lock()
            .unwrap()
            .insert(addr.to_string());
        let shared = self.shared.clone();
        let dialed = addr.to_string();
        thread::spawn(move || shared.handle_conn(stream, Some(dialed)));
        Ok(())
    }

    /// Periodically ask peers for more addresses (keepalive + discovery) and
    /// dial newly-learned peers up to `MAX_PEERS`.
    fn spawn_discovery(&self) {
        let shared = self.shared.clone();
        thread::spawn(move || loop {
            thread::sleep(DISCOVERY_INTERVAL);
            if shared.peer_count() < MAX_PEERS {
                shared.broadcast(&Message::GetAddr);
                let candidates: Vec<String> =
                    shared.known_addrs.lock().unwrap().iter().cloned().collect();
                for a in candidates {
                    if shared.peer_count() >= MAX_PEERS {
                        break;
                    }
                    shared.dial(&a);
                }
            }
        });
    }

    /// Periodically announce the current selected tip to peers, so freshly
    /// mined blocks propagate. Announcing only the tip is enough: peers that
    /// are behind will `GetBlock` it and backfill the gap via orphan
    /// resolution.
    pub fn spawn_tip_announcer(&self) {
        let shared = self.shared.clone();
        thread::spawn(move || {
            let mut last: Option<Hash> = None;
            loop {
                thread::sleep(Duration::from_millis(200));
                let tip = {
                    let st = shared.state.read().unwrap();
                    ghostdag::selected_tip(&st.ghostdag, &st.tips)
                };
                if tip != last {
                    if let Some(h) = tip {
                        shared.broadcast(&Message::Inv(h));
                    }
                    last = tip;
                }
            }
        });
    }

    /// Periodically gossip mempool transactions to peers so a tx submitted to
    /// one node (mining or not) reaches the miners. This decouples the API from
    /// P2P: any tx that lands in the mempool — via the local API or a peer's
    /// relay — is announced once and propagates hop-by-hop. Each node announces
    /// a given tx once while it's in its mempool; once mined (and dropped from
    /// the mempool) it falls out of the announced set, so the set stays bounded
    /// by the mempool size and re-broadcast loops can't form.
    pub fn spawn_mempool_announcer(&self) {
        let shared = self.shared.clone();
        thread::spawn(move || {
            let mut announced: HashSet<Hash> = HashSet::new();
            let mut announced_utxo: HashSet<Hash> = HashSet::new();
            loop {
                thread::sleep(MEMPOOL_ANNOUNCE_INTERVAL);
                // Cheap first pass: collect the current mempool tx *hashes*
                // without cloning any (potentially ~50 KB) tx bodies.
                let (current, current_utxo): (HashSet<Hash>, HashSet<Hash>) = {
                    let st = shared.state.read().unwrap();
                    (
                        st.transparent_mempool.iter().map(|t| t.tx_hash()).collect(),
                        st.utxo_mempool.iter().map(|t| t.txid()).collect(),
                    )
                };
                let want: HashSet<Hash> = current.difference(&announced).copied().collect();
                if !want.is_empty() {
                    let txs: Vec<TransparentTx> = {
                        let st = shared.state.read().unwrap();
                        st.transparent_mempool
                            .iter()
                            .filter(|tx| want.contains(&tx.tx_hash()))
                            .cloned()
                            .collect()
                    };
                    for tx in &txs {
                        shared.broadcast_tx(tx);
                    }
                }
                let want_utxo: HashSet<Hash> =
                    current_utxo.difference(&announced_utxo).copied().collect();
                if !want_utxo.is_empty() {
                    let txs: Vec<crate::utxo_tx::UtxoTx> = {
                        let st = shared.state.read().unwrap();
                        st.utxo_mempool
                            .iter()
                            .filter(|tx| want_utxo.contains(&tx.txid()))
                            .cloned()
                            .collect()
                    };
                    for tx in &txs {
                        shared.broadcast_utxo_tx(tx);
                    }
                }
                // Mark exactly the current mempool as announced, so mined/evicted
                // txs drop out and the set can't grow past the mempool.
                announced = current;
                announced_utxo = current_utxo;
            }
        });
    }

    /// Ask peers for a cold-start pruning-point proof (headers-first sync). An
    /// archival peer replies with a multilevel proof when possible (linear as
    /// fallback); on receipt it is verified from genesis and, if valid,
    /// recorded (see `verified_pruning_point`).
    pub fn request_pruning_proof(&self) {
        *self.shared.expecting_pruning_proof.lock().unwrap() = true;
        // Linear first (small), then multilevel (may upgrade on verified_work).
        self.shared.broadcast(&Message::GetPruningProof);
        self.shared
            .broadcast(&Message::GetMultiLevelPruningProof);
    }

    /// Explicit linear-proof request (fallback when a peer does not serve
    /// multilevel). Prefer [`Self::request_pruning_proof`].
    pub fn request_linear_pruning_proof(&self) {
        *self.shared.expecting_pruning_proof.lock().unwrap() = true;
        self.shared.broadcast(&Message::GetPruningProof);
    }

    /// The pruning point established from a verified pruning-point proof, if any.
    pub fn verified_pruning_point(&self) -> Option<Hash> {
        *self.shared.verified_pruning_point.lock().unwrap()
    }

    pub fn peer_count(&self) -> usize {
        self.shared.peers.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor::build_socks5_connect_request;
    use crate::{
        generate_keypair, now_ms, seal_block, stark, test_address, test_miner_keys, Block,
        HASH_SIZE,
    };
    use std::io::{Read, Write};

    /// Mine one valid block on top of the current tips (trivial PoW at
    /// difficulty 1, real per-block STARK proof, sealed issuance) and add it
    /// locally.
    fn mine_one(state: &Arc<RwLock<ChainState>>) -> Hash {
        let mut s = state.write().unwrap();
        let parents = s.tips.clone();
        let height = s.main_chain.len() as u64;
        let difficulty = s.difficulty;
        let mut block = Block {
            height,
            timestamp: now_ms(),
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
            nonce: height, // distinct per height so hashes differ
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        s.bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&s, &mut block, sk, pk);
        let hash = block.hash();
        s.add_block(block)
            .expect("locally mined block must be valid");
        hash
    }

    fn wait_until<F: Fn() -> bool>(timeout: Duration, cond: F) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        cond()
    }

    #[test]
    fn genesis_is_identical_across_fresh_nodes() {
        // Prerequisite for any networking: two fresh nodes must share genesis.
        let a = ChainState::new();
        let b = ChainState::new();
        assert_eq!(a.tips, b.tips, "fresh nodes must have the same genesis tip");
    }

    #[test]
    fn a_fresh_node_syncs_an_existing_chain_from_a_peer() {
        // Node A mines a 3-block chain; node B starts with only genesis and
        // must catch up purely over the wire.
        let a_state = Arc::new(RwLock::new(ChainState::new()));
        for _ in 0..3 {
            mine_one(&a_state);
        }
        assert_eq!(a_state.read().unwrap().selected_tip_blue_score(), 3);

        let node_a = Node::new(a_state.clone());
        let addr = node_a.listen("127.0.0.1:0").expect("bind A");

        let b_state = Arc::new(RwLock::new(ChainState::new()));
        let node_b = Node::new(b_state.clone());
        node_b.connect(&addr.to_string()).expect("connect B->A");

        let synced = wait_until(Duration::from_secs(10), || {
            b_state.read().unwrap().selected_tip_blue_score() == 3
        });
        assert!(synced, "node B failed to sync the chain from node A");
        assert_eq!(
            a_state.read().unwrap().main_chain,
            b_state.read().unwrap().main_chain,
            "both nodes must converge on the identical selected chain",
        );
    }

    #[test]
    fn a_newly_mined_block_propagates_to_a_connected_peer() {
        // Both nodes start in sync (genesis); A mines after connecting and the
        // block should reach B via the tip announcer + gossip.
        let a_state = Arc::new(RwLock::new(ChainState::new()));
        let b_state = Arc::new(RwLock::new(ChainState::new()));

        let node_a = Node::new(a_state.clone());
        let addr = node_a.listen("127.0.0.1:0").expect("bind A");
        node_a.spawn_tip_announcer();

        let node_b = Node::new(b_state.clone());
        node_b.connect(&addr.to_string()).expect("connect B->A");

        // Give the handshake a moment, then mine on A.
        assert!(wait_until(Duration::from_secs(3), || node_b.peer_count() >= 1));
        mine_one(&a_state);

        let propagated = wait_until(Duration::from_secs(10), || {
            b_state.read().unwrap().selected_tip_blue_score() == 1
        });
        assert!(
            propagated,
            "a freshly mined block failed to propagate to the peer"
        );
    }

    #[test]
    fn an_invalid_block_from_a_peer_is_rejected_not_applied() {
        // A peer sending a block with a bogus STARK proof must not corrupt us.
        let state = Arc::new(RwLock::new(ChainState::new()));
        let shared = Node::new(state.clone()).shared.clone();
        let genesis = state.read().unwrap().tips[0];

        let bogus = Block {
            height: 1,
            timestamp: now_ms(),
            parents: vec![genesis],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash([1u8; HASH_SIZE]),
            creator_pubkey: vec![],
            nonce: 0,
            difficulty: state.read().unwrap().difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![0u8; 64], // not a real proof
            birth_certificate: Default::default(),
            size: 0,
        };
        let before = state.read().unwrap().dag.len();
        let penalty = shared.ingest_block(bogus, None);
        assert_eq!(
            state.read().unwrap().dag.len(),
            before,
            "invalid block must not be added"
        );
        assert_eq!(
            penalty, INVALID_BLOCK_PENALTY,
            "an invalid block must charge a ban penalty"
        );
    }

    #[test]
    fn an_invalid_block_charges_ban_score_but_an_orphan_does_not() {
        // Ban-scoring must penalize *invalidity* (a CPU-DoS: each invalid block
        // forces a PoW + STARK check) while leaving honest orphans — the normal
        // out-of-order arrival during sync — completely unpenalized.
        let state = Arc::new(RwLock::new(ChainState::new()));
        let shared = Node::new(state.clone()).shared.clone();
        let genesis = state.read().unwrap().tips[0];

        let invalid = Block {
            height: 1,
            timestamp: now_ms(),
            parents: vec![genesis],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash([1u8; HASH_SIZE]),
            nonce: 0,
            creator_pubkey: vec![],
            difficulty: state.read().unwrap().difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![0u8; 64],
            size: 0,
            birth_certificate: Default::default(),
        };
        let orphan = Block {
            height: 1,
            timestamp: now_ms(),
            parents: vec![Hash([9u8; HASH_SIZE])], // unknown parent
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash([2u8; HASH_SIZE]),
            creator_pubkey: vec![],
            nonce: 1,
            difficulty: 1,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };

        assert_eq!(shared.ingest_block(invalid, None), INVALID_BLOCK_PENALTY);
        assert_eq!(
            shared.ingest_block(orphan, None),
            0,
            "an honest orphan must not be penalized"
        );
        // Five invalid blocks reach the disconnect/ban threshold. This is a
        // deliberate invariant over two consts (hence the constant assertion).
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                5 * INVALID_BLOCK_PENALTY >= BAN_SCORE_THRESHOLD,
                "threshold reachable in a few strikes"
            );
        }
    }

    #[test]
    fn a_banned_address_is_neither_remembered_nor_dialed() {
        let state = Arc::new(RwLock::new(ChainState::new()));
        let shared = Node::new(state).shared.clone();
        let addr = "203.0.113.7:9000";
        shared.banned_addrs.lock().unwrap().insert(addr.to_string());

        shared.remember_addr(addr);
        assert!(
            !shared.known_addrs.lock().unwrap().contains(addr),
            "banned addr must not be learned"
        );
        // dial() must no-op on a banned addr — it must not create a connected reservation.
        shared.dial(addr);
        assert!(
            !shared.connected_addrs.lock().unwrap().contains(addr),
            "banned addr must not be dialed"
        );
    }

    /// Minimal SOCKS5 accept-only mock (same shape as `tor` tests): enough to
    /// prove P2P `connect_with_timeout` routes through the configured proxy.
    fn mock_socks5_accept() -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            stream.write_all(&[0x05, 0x00]).unwrap();
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(head[3], 0x03, "onion/hostname must use domain ATYP");
            let domain_len = head[4] as usize;
            let mut domain = vec![0u8; domain_len + 2];
            stream.read_exact(&mut domain).unwrap();
            let host = domain[..domain_len].to_vec();
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            host
        });
        (addr, handle)
    }

    #[test]
    fn outbound_dial_uses_configured_tor_socks_proxy() {
        let (proxy_addr, handle) = mock_socks5_accept();
        let stream = connect_with_timeout(
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz.onion:9333",
            Some(&proxy_addr.to_string()),
        );
        assert!(
            stream.is_ok(),
            "SOCKS dial should succeed against mock: {:?}",
            stream.err()
        );
        let requested = String::from_utf8(handle.join().unwrap()).unwrap();
        assert!(requested.ends_with(".onion"));
    }

    #[test]
    fn clearnet_dial_when_tor_proxy_unset() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = thread::spawn(move || listener.accept().unwrap().0);
        let stream = connect_with_timeout(&addr.to_string(), None).expect("clearnet");
        drop(stream);
        accept.join().unwrap();
    }

    #[test]
    fn set_tor_proxy_is_honored_by_node_connect_path() {
        let (proxy_addr, handle) = mock_socks5_accept();
        let node = Node::new(Arc::new(RwLock::new(ChainState::new())));
        node.set_tor_proxy(Some(&proxy_addr.to_string()));
        // connect spawns a handler thread; we only care that the SOCKS dial
        // reached the mock (Noise will then fail harmlessly on the mock stream).
        let _ = node.connect("testhost.onion:9333");
        let requested = String::from_utf8(handle.join().unwrap()).unwrap();
        assert_eq!(requested, "testhost.onion");
        // Sanity: ATYP helper still matches what P2P sends for hostnames.
        let req = build_socks5_connect_request("testhost.onion", 9333).unwrap();
        assert_eq!(req[3], 0x03);
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn an_invalid_gossiped_transfer_is_penalized_and_a_valid_one_admitted() {
        let state = Arc::new(RwLock::new(ChainState::new()));
        let shared = Node::new(state.clone()).shared.clone();
        let chain_id = state.read().unwrap().chain_id;
        let (sk, pk) = generate_keypair();
        let from = crate::hash_to_address(&pk);
        state.write().unwrap().accounts.insert(
            from,
            crate::Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: crate::Hash::ZERO,
            },
        );
        let mut tx = TransparentTx::new(pk, test_address(0xb), 1000, 0, chain_id);
        tx.sign(&sk).unwrap();

        assert_eq!(
            shared.relay_transparent(tx.clone()),
            0,
            "a valid transfer is admitted, not penalized"
        );
        assert_eq!(
            state.read().unwrap().transparent_mempool.len(),
            1,
            "valid transfer entered the mempool"
        );

        let mut forged = tx;
        forged.signature[0] ^= 0xff; // corrupt the signature
        assert_eq!(
            shared.relay_transparent(forged),
            INVALID_TX_PENALTY,
            "a bad signature is penalized"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn a_gossiped_transfer_propagates_to_a_connected_peer() {
        // Liveness: a tx that lands in one node's mempool must reach a peer's
        // mempool via the announcer + relay, even though neither mines it here.
        let a_state = Arc::new(RwLock::new(ChainState::new()));
        let b_state = Arc::new(RwLock::new(ChainState::new()));
        let node_a = Node::new(a_state.clone());
        let addr = node_a.listen("127.0.0.1:0").expect("bind A");
        node_a.spawn_mempool_announcer();
        let node_b = Node::new(b_state.clone());
        node_b.connect(&addr.to_string()).expect("connect B->A");
        assert!(wait_until(Duration::from_secs(3), || node_b.peer_count() >= 1));

        let chain_id = a_state.read().unwrap().chain_id;
        let (sk, pk) = generate_keypair();
        let from = crate::hash_to_address(&pk);
        let funded = crate::Account {
            balance: 1_000_000,
            nonce: 0,
                last_spend_blue: 0,
            code_hash: None,
            storage_root: crate::Hash::ZERO,
        };
        a_state
            .write()
            .unwrap()
            .accounts
            .insert(from.clone(), funded.clone());
        // Peer B must also see the funded account to admit (balance precheck).
        b_state.write().unwrap().accounts.insert(from, funded);
        let mut tx = TransparentTx::new(pk, test_address(0xb), 1000, 0, chain_id);
        tx.sign(&sk).unwrap();
        let txh = tx.tx_hash();
        a_state
            .write()
            .unwrap()
            .admit_transparent_to_mempool(tx)
            .unwrap();

        let propagated = wait_until(Duration::from_secs(10), || {
            b_state
                .read()
                .unwrap()
                .transparent_mempool
                .iter()
                .any(|t| t.tx_hash() == txh)
        });
        assert!(
            propagated,
            "a gossiped transfer failed to reach the peer's mempool"
        );
    }

    #[test]
    fn a_fresh_node_verifies_a_pruning_proof_from_an_archival_peer() {
        // Cold-start headers-first: an archival peer serves a genesis→pruning-
        // point header proof; the fresh node verifies it from genesis (PoW +
        // linkage + DAA difficulty) and records the trusted pruning point —
        // without downloading any block bodies. Short chains fall back to the
        // linear proof when multilevel cannot compress.
        let a_state = Arc::new(RwLock::new(ChainState::new()));
        a_state.write().unwrap().archival = true;
        for _ in 0..4 {
            mine_one(&a_state);
        }
        let pp = {
            let s = a_state.read().unwrap();
            let tip = ghostdag::selected_tip(&s.ghostdag, &s.tips).unwrap();
            ghostdag::selected_chain(&s.ghostdag, &tip)[2]
        };
        a_state
            .write()
            .unwrap()
            .set_serving_pruning_point(pp)
            .expect("archival caches PP ledger");

        let node_a = Node::new(a_state.clone());
        let addr = node_a.listen("127.0.0.1:0").expect("bind A");
        let b_state = Arc::new(RwLock::new(ChainState::new()));
        let node_b = Node::new(b_state.clone());
        node_b.connect(&addr.to_string()).expect("connect B->A");
        assert!(
            wait_until(Duration::from_secs(15), || node_b.peer_count() >= 1),
            "B must peer with A"
        );

        node_b.request_pruning_proof();
        let verified = wait_until(Duration::from_secs(20), || {
            node_b.verified_pruning_point() == Some(pp)
        });
        assert!(
            verified,
            "B must verify and record the pruning point served by A"
        );
        assert!(
            b_state.read().unwrap().dag.contains_key(&pp),
            "adopt must import proof headers so the pruning point is in B's DAG"
        );
        assert_eq!(
            b_state.read().unwrap().pruning_point,
            Some(pp),
            "import sets chain pruning_point"
        );
        let ledger_ok = wait_until(Duration::from_secs(20), || {
            let b = b_state.read().unwrap();
            b.pruning_ledger
                .as_ref()
                .map(|l| l.minted_supply > 0)
                .unwrap_or(false)
        });
        assert!(
            ledger_ok,
            "B must adopt PP ledger with non-zero minted supply (not empty genesis)"
        );
        let a_ledger = a_state.read().unwrap().build_pruning_point_ledger().unwrap();
        let b = b_state.read().unwrap();
        assert_eq!(
            b.pruning_ledger.as_ref().unwrap().minted_supply,
            a_ledger.ledger.minted_supply
        );
        assert_eq!(b.base.accounts, a_ledger.ledger.accounts);
        assert_eq!(b.base.minted_supply, a_ledger.ledger.minted_supply);
        assert!(
            b.minted_supply >= a_ledger.ledger.minted_supply,
            "live may advance past PP via tip sync, but never below adopted base"
        );
    }

    #[test]
    fn a_fresh_node_adopts_a_multilevel_pruning_proof_from_an_archival_peer() {
        // Short chain + small recent window still produces multilevel (handler
        // retries window=2 when DAA_WINDOW cannot compress).
        let a_state = Arc::new(RwLock::new(ChainState::new()));
        a_state.write().unwrap().archival = true;
        for _ in 0..5 {
            mine_one(&a_state);
        }
        let pp = {
            let s = a_state.read().unwrap();
            let tip = ghostdag::selected_tip(&s.ghostdag, &s.tips).unwrap();
            let chain = ghostdag::selected_chain(&s.ghostdag, &tip);
            chain[3]
        };
        a_state
            .write()
            .unwrap()
            .set_serving_pruning_point(pp)
            .expect("archival caches PP ledger");
        assert!(
            a_state
                .read()
                .unwrap()
                .build_multilevel_pruning_proof(2)
                .is_some(),
            "test fixture must produce a multilevel proof"
        );

        let node_a = Node::new(a_state.clone());
        let addr = node_a.listen("127.0.0.1:0").expect("bind A");
        let b_state = Arc::new(RwLock::new(ChainState::new()));
        let node_b = Node::new(b_state.clone());
        node_b.connect(&addr.to_string()).expect("connect B->A");
        assert!(
            wait_until(Duration::from_secs(15), || node_b.peer_count() >= 1),
            "B must peer with A"
        );

        node_b.request_pruning_proof();
        let verified = wait_until(Duration::from_secs(20), || {
            node_b.verified_pruning_point() == Some(pp)
        });
        assert!(
            verified,
            "B must adopt A's multilevel pruning proof on verified_work"
        );
        assert!(
            b_state.read().unwrap().dag.contains_key(&pp),
            "multilevel adopt must import headers into B's DAG"
        );
        let ledger_ok = wait_until(Duration::from_secs(20), || {
            let b = b_state.read().unwrap();
            b.pruning_ledger
                .as_ref()
                .map(|l| l.minted_supply > 0)
                .unwrap_or(false)
        });
        assert!(
            ledger_ok,
            "multilevel IBD must end with PP ledger balances, not empty genesis"
        );
        let want = a_state.read().unwrap().build_pruning_point_ledger().unwrap();
        let b = b_state.read().unwrap();
        assert_eq!(b.base.accounts, want.ledger.accounts);
        assert_eq!(b.base.minted_supply, want.ledger.minted_supply);
        assert_eq!(
            b.pruning_ledger.as_ref().unwrap().minted_supply,
            want.ledger.minted_supply
        );
    }

    #[test]
    fn a_forged_estimated_total_work_cannot_beat_lower_verified_work() {
        // Ranking / adopt uses verified_work only. Inflating estimated_total_work
        // must not let a weaker proof displace a stronger verified_work.
        let state = {
            let mut s = ChainState::new();
            s.archival = true;
            for i in 1..=6u64 {
                let parents = s.tips.clone();
                let t = crate::GENESIS_TIMESTAMP_MS + i * crate::TARGET_BLOCK_TIME_MS;
                let difficulty = s.expected_difficulty_at(&parents, t);
                let mut block = Block {
                    height: s.main_chain.len() as u64,
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
                    nonce: i,
                    difficulty,
                    version: crate::default_block_version(),
                    coinbase_entropy: 0,
                    stark_proof: vec![],
                    birth_certificate: Default::default(),
                    size: 0,
                };
                s.bind_parent_commitments(&mut block).unwrap();
                let (sk, pk) = test_miner_keys();
                seal_block(&s, &mut block, sk, pk);
                s.add_block(block).unwrap();
            }
            let tip = ghostdag::selected_tip(&s.ghostdag, &s.tips).unwrap();
            let chain = ghostdag::selected_chain(&s.ghostdag, &tip);
            s.pruning_point = Some(chain[3]);
            s
        };
        let strong = state
            .build_multilevel_pruning_proof(2)
            .expect("strong multilevel");
        let strong_summary =
            crate::superproof::verify_multilevel_pruning_proof(&strong).expect("verify strong");

        let mut best = 0u128;
        let adopted = crate::superproof::adopt_multilevel_pruning_proof(&strong, |s| {
            if s.verified_work > best {
                best = s.verified_work;
                true
            } else {
                false
            }
        })
        .expect("adopt strong");
        assert!(adopted);
        assert_eq!(best, strong_summary.verified_work);

        // Equal verified_work must not replace; estimate is irrelevant.
        let again = crate::superproof::adopt_multilevel_pruning_proof(&strong, |s| {
            let _ignore_estimate = s.estimated_total_work;
            s.verified_work > best
        })
        .expect("re-verify");
        assert!(
            !again,
            "equal verified_work must not replace; estimate is irrelevant"
        );

        // A shorter recent window ships fewer recent headers → lower or equal
        // verified_work; forged estimate must not override the hard bound.
        let weak = state
            .build_multilevel_pruning_proof(3)
            .expect("alternate multilevel");
        let weak_summary =
            crate::superproof::verify_multilevel_pruning_proof(&weak).expect("verify weak");
        let beat = crate::superproof::adopt_multilevel_pruning_proof(&weak, |s| {
            let _forged_estimate = u128::MAX;
            s.verified_work > best
        })
        .expect("verify");
        if weak_summary.verified_work <= strong_summary.verified_work {
            assert!(
                !beat,
                "lower/equal verified_work must not adopt regardless of estimate"
            );
        }
    }

    #[test]
    fn cold_start_auto_requests_pruning_proof_when_peer_is_ahead() {
        // When B's tip is behind A, Hello triggers GetMultiLevelPruningProof so
        // cold-start sync can bound body fetches. Unsolicited proofs are still
        // ignored when `expecting_pruning_proof` is false.
        let a_state = Arc::new(RwLock::new(ChainState::new()));
        a_state.write().unwrap().archival = true;
        for _ in 0..4 {
            mine_one(&a_state);
        }
        let pp = {
            let s = a_state.read().unwrap();
            let tip = ghostdag::selected_tip(&s.ghostdag, &s.tips).unwrap();
            ghostdag::selected_chain(&s.ghostdag, &tip)[2]
        };
        a_state.write().unwrap().pruning_point = Some(pp);

        let node_a = Node::new(a_state.clone());
        let addr = node_a.listen("127.0.0.1:0").expect("bind A");
        let b_state = Arc::new(RwLock::new(ChainState::new()));
        let node_b = Node::new(b_state);
        node_b.connect(&addr.to_string()).expect("connect B->A");
        assert!(wait_until(Duration::from_secs(15), || node_b.peer_count() >= 1));

        let verified = wait_until(Duration::from_secs(20), || {
            node_b.verified_pruning_point() == Some(pp)
        });
        assert!(
            verified,
            "cold-start Hello must auto-request and adopt A's pruning proof"
        );
    }

    #[test]
    fn mlkem_exchange_derives_the_same_shared_secret_on_both_ends() {
        // The PQ half of the hybrid handshake: initiator and responder must
        // agree on an identical, non-trivial 32-byte secret (which then becomes
        // the Noise PSK). This isolates the ML-KEM round-trip from Noise.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            mlkem_shared_secret(&mut sock, false).unwrap() // responder
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let initiator_secret = mlkem_shared_secret(&mut client, true).unwrap();
        let responder_secret = server.join().unwrap();
        assert_eq!(
            initiator_secret, responder_secret,
            "both ends must agree on the ML-KEM secret"
        );
        assert_ne!(
            initiator_secret, [0u8; 32],
            "the shared secret must not be trivial"
        );
    }

    #[test]
    fn hybrid_handshake_establishes_a_working_encrypted_channel() {
        // End-to-end: run the full hybrid PQ Noise XXpsk3 handshake between two
        // ends and confirm an application message round-trips through the
        // resulting transport (i.e. the ML-KEM PSK was mixed in consistently on
        // both sides — a mismatch would make the AEAD fail).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder_priv = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .generate_keypair()
            .unwrap()
            .private;
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (transport, _hh) = noise_handshake(&mut sock, false, &responder_priv).unwrap();
            let conn = Conn {
                writer: Arc::new(Mutex::new(sock.try_clone().unwrap())),
                transport: Arc::new(Mutex::new(transport)),
            };
            let msg = noise_read(&mut sock, &conn.transport).unwrap();
            assert_eq!(msg, b"ping over hybrid PQ noise");
        });
        let initiator_priv = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .generate_keypair()
            .unwrap()
            .private;
        let mut client = TcpStream::connect(addr).unwrap();
        let (transport, _hh) = noise_handshake(&mut client, true, &initiator_priv).unwrap();
        let conn = Conn {
            writer: Arc::new(Mutex::new(client)),
            transport: Arc::new(Mutex::new(transport)),
        };
        noise_write(&conn.writer, &conn.transport, b"ping over hybrid PQ noise").unwrap();
        server.join().unwrap();
    }

    #[test]
    fn a_channel_bound_signature_does_not_verify_against_a_different_handshake() {
        // The MITM defence: an ML-DSA signature over one session's handshake hash
        // must not verify against another session's hash, so a relay can't splice
        // two connections by replaying a victim's identity signature.
        let (sk, pk) = generate_keypair();
        let h1 = b"handshake-hash-session-one";
        let h2 = b"handshake-hash-session-two";
        let sig = abs_sig::sign_pq512(b"p2p-identity", h1, &sk).unwrap();
        assert!(
            abs_sig::verify_pq512(b"p2p-identity", h1, &pk, &sig),
            "valid over its own session"
        );
        assert!(
            !abs_sig::verify_pq512(b"p2p-identity", h2, &pk, &sig),
            "must not verify against a different session"
        );
    }

    #[test]
    fn honest_peers_complete_post_quantum_wire_authentication() {
        // Two honest nodes run the full hybrid handshake and channel-bound
        // ML-DSA authentication; both sides must accept.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let a = Node::new(Arc::new(RwLock::new(ChainState::new())))
            .shared
            .clone();
        let b = Node::new(Arc::new(RwLock::new(ChainState::new())))
            .shared
            .clone();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (transport, hh) = noise_handshake(&mut sock, false, &a.noise_private).unwrap();
            let conn = Conn {
                writer: Arc::new(Mutex::new(sock.try_clone().unwrap())),
                transport: Arc::new(Mutex::new(transport)),
            };
            a.pq_authenticate(&mut sock, &conn, &hh, None)
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let (transport, hh) = noise_handshake(&mut client, true, &b.noise_private).unwrap();
        let conn = Conn {
            writer: Arc::new(Mutex::new(client.try_clone().unwrap())),
            transport: Arc::new(Mutex::new(transport)),
        };
        let client_ok = b.pq_authenticate(&mut client, &conn, &hh, None);
        let server_ok = server.join().unwrap();
        assert!(
            client_ok && server_ok,
            "both honest peers must authenticate"
        );
    }

    #[test]
    fn orphan_pool_is_bounded_against_a_flood() {
        // A hostile peer streams blocks referencing distinct fabricated
        // parents; each is an orphan. The pool must stop growing at MAX_ORPHANS
        // rather than buffer them without limit. Orphan blocks need no valid
        // PoW/STARK: `add_block` rejects them with "Unknown parent" before any
        // of those checks, which is exactly the path that buffers orphans.
        let state = Arc::new(RwLock::new(ChainState::new()));
        let shared = Node::new(state.clone()).shared.clone();

        for i in 0..(MAX_ORPHANS as u32 + 100) {
            let mut fake_parent = Hash::ZERO;
            fake_parent[..4].copy_from_slice(&i.to_be_bytes());
            let orphan = Block {
                height: 1,
                timestamp: now_ms(),
                parents: vec![fake_parent], // parent not in the DAG => orphan
                interlinks: vec![],
                transparent_txs: vec![],
                utxo_txs: vec![],
                registry_ops: vec![],
                custody_ops: vec![],
                merkle_root: Hash::ZERO,
                state_root: Hash::ZERO,
                miner: Hash([2u8; HASH_SIZE]),
                creator_pubkey: vec![],
                nonce: i as u64, // distinct hash per orphan
                difficulty: 1,
                version: crate::default_block_version(),
                coinbase_entropy: 0,
                stark_proof: vec![],
                birth_certificate: Default::default(),
                size: 0,
            };
            shared.ingest_block(orphan, None);
        }

        let total: usize = shared
            .orphans
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum();
        assert!(
            total <= MAX_ORPHANS,
            "orphan pool grew to {total}, past cap {MAX_ORPHANS}"
        );
    }

    #[test]
    fn a_full_block_message_still_fits_the_tightened_size_cap() {
        // V4 tightened MAX_MESSAGE_BYTES; make sure a real, maximally-sized
        // Block message (block near the 22KB cap + a per-block STARK proof)
        // still serializes comfortably under it, so legitimate traffic is
        // unaffected while the attacker's amplification headroom is cut.
        let mut block = Block {
            height: 1,
            timestamp: now_ms(),
            parents: vec![Hash::ZERO; crate::MAX_BLOCK_PARENTS],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash([7u8; HASH_SIZE]),
            creator_pubkey: vec![],
            nonce: 0,
            difficulty: 1,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![0u8; 22 * 1024], // an over-large stand-in proof
            birth_certificate: Default::default(),
            size: 0,
        };
        block.stark_proof = stark::prove(block.hash().as_slice());
        let msg = Message::Block(Box::new(block));
        let payload = bincode::serialize(&msg).unwrap();
        assert!(
            payload.len() < MAX_MESSAGE_BYTES,
            "a legitimate block message ({} bytes) must fit under the {} byte cap",
            payload.len(),
            MAX_MESSAGE_BYTES,
        );
    }

    #[test]
    fn ip_grouping_exempts_loopback_and_groups_public_ips() {
        use std::net::IpAddr;
        // Loopback is exempt (so local multi-node testing isn't capped).
        assert_eq!(ip_group("127.0.0.1".parse::<IpAddr>().unwrap()), None);
        assert_eq!(ip_group("::1".parse::<IpAddr>().unwrap()), None);
        // Two public IPs in the same /16 share a group; a different /16 doesn't.
        let a = ip_group("203.0.113.7".parse::<IpAddr>().unwrap());
        let b = ip_group("203.0.42.9".parse::<IpAddr>().unwrap());
        let c = ip_group("198.51.100.1".parse::<IpAddr>().unwrap());
        assert!(a.is_some());
        assert_eq!(a, b, "same /16 must be the same group");
        assert_ne!(a, c, "different /16 must be a different group");
    }

    #[test]
    fn per_peer_rate_window_trips_at_the_limit() {
        let mut rate = RateWindow::new(PEER_MSG_LIMIT);
        // Up to the limit: allowed.
        for _ in 0..PEER_MSG_LIMIT {
            assert!(rate.record());
        }
        // The next message in the same window trips it (grounds to disconnect).
        assert!(
            !rate.record(),
            "exceeding PEER_MSG_LIMIT must trip the rate window"
        );
    }

    #[test]
    fn a_peer_is_discovered_transitively_through_a_shared_node() {
        // Topology: C—A and B—A directly. Via address gossip, B should learn
        // about C (from A) and dial it, ending up connected to both A and C —
        // without ever being told about C directly.
        let a = Node::new(Arc::new(RwLock::new(ChainState::new())));
        let addr_a = a.listen("127.0.0.1:0").unwrap();

        let c = Node::new(Arc::new(RwLock::new(ChainState::new())));
        c.listen("127.0.0.1:0").unwrap(); // C must listen so it's dialable
        c.connect(&addr_a.to_string()).unwrap();

        // Let A learn C's listen address before B joins.
        assert!(wait_until(Duration::from_secs(3), || a.peer_count() >= 1));

        let b = Node::new(Arc::new(RwLock::new(ChainState::new())));
        b.listen("127.0.0.1:0").unwrap();
        b.connect(&addr_a.to_string()).unwrap();

        // B connects to A (1 peer), then discovers and dials C (2 peers).
        let discovered = wait_until(Duration::from_secs(10), || b.peer_count() >= 2);
        assert!(
            discovered,
            "B failed to discover C transitively through A (peers: {})",
            b.peer_count()
        );
    }

    #[test]
    fn multilevel_wire_payload_fits_message_cap() {
        let mut s = ChainState::new();
        s.archival = true;
        for i in 1..=5u64 {
            let parents = s.tips.clone();
            let t = crate::GENESIS_TIMESTAMP_MS + i * crate::TARGET_BLOCK_TIME_MS;
            let difficulty = s.expected_difficulty_at(&parents, t);
            let mut block = Block {
                height: s.main_chain.len() as u64,
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
                nonce: i,
                difficulty,
                version: crate::default_block_version(),
                coinbase_entropy: 0,
                stark_proof: vec![],
                birth_certificate: Default::default(),
                size: 0,
            };
            s.bind_parent_commitments(&mut block).unwrap();
            let (sk, pk) = test_miner_keys();
            seal_block(&s, &mut block, sk, pk);
            s.add_block(block).unwrap();
        }
        let tip = ghostdag::selected_tip(&s.ghostdag, &s.tips).unwrap();
        let chain = ghostdag::selected_chain(&s.ghostdag, &tip);
        s.pruning_point = Some(chain[3]);
        let ml = s.build_multilevel_pruning_proof(2).expect("ml");
        let msg = Message::MultiLevelPruningProof(Box::new(ml.clone()));
        let payload = bincode::serialize(&msg).unwrap();
        assert!(
            payload.len() < MAX_MESSAGE_BYTES,
            "multilevel payload {} exceeds cap {}",
            payload.len(),
            MAX_MESSAGE_BYTES
        );
        let back: Message = bincode::options()
            .with_fixint_encoding()
            .with_little_endian()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_BYTES as u64)
            .deserialize(&payload)
            .expect("wire round-trip");
        match back {
            Message::MultiLevelPruningProof(p) => {
                assert_eq!(p.recent_headers.len(), ml.recent_headers.len());
                assert_eq!(p.hops.len(), ml.hops.len());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn headers_and_locator_caps_bound_payload_estimates() {
        assert!(MAX_HEADERS_PER_MSG >= 64);
        assert!(MAX_LOCATOR_HASHES >= 8);
        assert!(MAX_IN_FLIGHT_BODIES >= 8);
        assert!(MAX_IN_FLIGHT_TX_GETS >= 8);
        assert_eq!(MAX_TX_PACKAGE, crate::MAX_MEMPOOL_PACKAGE_NONCES);

        let locator = vec![Hash([1u8; 64]); MAX_LOCATOR_HASHES + 40];
        let msg = Message::GetHeaders {
            locator,
            stop_hash: Hash::ZERO,
            limit: 9_999,
        };
        // Cap uses min(locator.len(), MAX_LOCATOR_HASHES) so estimate stays bounded.
        let est = max_payload_for(&msg);
        assert!(est <= 512 + MAX_LOCATOR_HASHES * 80 + 64);

        let headers = vec![crate::genesis_block().header_only(); MAX_HEADERS_PER_MSG + 1];
        let hmsg = Message::Headers(headers);
        let hest = max_payload_for(&hmsg);
        assert!(hest <= MAX_MESSAGE_BYTES);
        assert!(hest <= 512 + MAX_HEADERS_PER_MSG * 512);
    }
}
