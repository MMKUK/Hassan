use hassan::api::{ApiServer, TxSubmitRequest};
use hassan::consensus::{BlockDAGConsensus, SoloMiner};
use hassan::p2p::Node;
use hassan::security::{self, RateLimiter};
use hassan::tor::TorLayer;
use hassan::ChainState;
use hassan::Miner;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

fn main() {
    // Role CLI first — sets Tor-only / archival / API bind defaults into env
    // before NetPolicy and the rest of startup read them.
    let profile = hassan::node_role::parse_args(std::env::args());
    profile.apply_env();

    println!(
        r#"
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║               H A S S A N   B L O C K C H A I N   v1.0               ║
    ║                                                                      ║
    ║   Transparent settlement · ML-DSA-87 · Blake3-512 everywhere         ║
    ║                                                                      ║
    ║   [x] Birth Certificate on every block (verifiable worldwide)       ║
    ║   [x] 512-bit Settlement ID + 512-bit PQ prehash on all signatures  ║
    ║   [x] ABS wallet signatures — decimal number + absolute type 87     ║
    ║   [ ] Cross-chain exit/enter — consensus-disabled until bridge ships║
    ║   [x] AI block trace — every accepted block tracked                 ║
    ║   [x] Title registry + BDPE peer escrow (2-of-2 vault / timeouts)   ║
    ║   [x] Noise XX + ML-KEM-768 PSK (HN/DL) + ML-DSA channel-bound auth  ║
    ║   [x] STARK companion = sequential work (not validity / privacy ZK) ║
    ║   [x] UTXO peer value (v27); accounts = registry/custody overlay     ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    "#
    );
    println!("   Hassan ($HSN) — ML-DSA-87 · Blake3-512 · transparent settlement \n");
    profile.print_banner();

    // Operational hard-mode (API auth, dial policy, STARK budgets). Consensus
    // constants are compile-time (v31+) regardless of this flag.
    let policy = hassan::net_policy::NetPolicy::from_env();
    hassan::net_policy::init(policy.clone());
    if policy.public_mode {
        println!(
            "PUBLIC LOCK — explicit API token · strict dials · STARK budgets · soft overrides refused"
        );
    }
    println!(
        "⚙️  Consensus: genesis {} · chain_id={} · chain_hash={}… · MIN_DIFFICULTY={} (effective {}) · MIN_TX_FEE={}",
        String::from_utf8_lossy(hassan::GENESIS_DOMAIN),
        hassan::CHAIN_ID,
        &hassan::chain_hash_hex()[..16],
        hassan::MIN_DIFFICULTY,
        hassan::effective_min_difficulty(),
        hassan::MIN_TX_FEE
    );
    if hassan::lab_easy_pow() {
        println!(
            "⚠️  {}=1 — keeping bootstrap PoW floor {} past 1M minted; peers without this flag will fork after hard era.",
            hassan::BOOTSTRAP_EASY_ENV,
            hassan::BOOTSTRAP_MIN_DIFFICULTY
        );
    }

    // Persistence: load the saved chain from the data dir if present, else start
    // fresh from genesis (height 0). Set HASSAN_DATA_DIR to choose where state
    // lives (default ./hassan-data). A node thus survives restarts instead of
    // resyncing from genesis every time. v30 genesis / STATE_FORMAT_VERSION
    // rejects older chainstate.bin — the node starts from block 0.
    let data_dir = std::env::var("HASSAN_DATA_DIR").unwrap_or_else(|_| "./hassan-data".to_string());
    let state_path = std::path::Path::new(&data_dir).join("chainstate.bin");
    let mempool_path = std::env::var("HASSAN_MEMPOOL_PATH").ok().map(std::path::PathBuf::from);
    let loaded_state = if state_path.exists() {
        match ChainState::load_from(&state_path) {
            Ok(s) => {
                println!(
                    "💾 Loaded chain state from {} (height {})",
                    state_path.display(),
                    s.tip_height()
                );
                Some(s)
            }
            Err(e) => {
                // Fail closed: never wipe a present chainstate by silently
                // restarting at genesis (that would overwrite on next save).
                eprintln!(
                    "FATAL: could not load chainstate at {}: {e}",
                    state_path.display()
                );
                eprintln!(
                    "Refusing to start from genesis over an existing data dir. \
                     Fix the file, restore a backup (*.bak), or wipe {data_dir} explicitly \
                     (see NODE.md for version upgrades)."
                );
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    let state = Arc::new(RwLock::new(loaded_state.unwrap_or_else(ChainState::new)));
    if let Some(ref mp) = mempool_path {
        if mp.exists() {
            match state.write().unwrap().load_mempool_from(mp) {
                Ok(n) => println!("Loaded {n} mempool txs from {}", mp.display()),
                Err(e) => eprintln!("Could not load mempool dump ({e})"),
            }
        }
    }

    // Explorer indexer: checksummed store under {data_dir}/indexer/, separate
    // from hot chainstate. Syncs selected-chain history for fast search/analytics.
    // Light role skips the indexer to keep RAM/disk cheap on small machines.
    let indexer = hassan::indexer::IndexerHandle::open(std::path::Path::new(&data_dir));
    if profile.enable_indexer {
        let idx = indexer.clone();
        let st = state.clone();
        let data_dir_log = data_dir.clone();
        thread::spawn(move || {
            {
                let s = st.read().unwrap_or_else(|p| p.into_inner());
                idx.sync(&s);
            }
            println!(
                "📇 Indexer ready at {}/indexer/index.bin",
                data_dir_log
            );
            loop {
                thread::sleep(Duration::from_secs(3));
                let s = st.read().unwrap_or_else(|p| p.into_inner());
                idx.sync(&s);
            }
        });
    } else {
        println!("📇 Indexer off (light profile)");
    }

    // Persist the chain promptly after it advances, so a restart resumes with
    // as few missing recent blocks as possible. Polls every few seconds and only
    // writes when the chain actually grew (a dirty check), so an idle node
    // doesn't rewrite the same state repeatedly. The snapshot is cloned under a
    // brief read lock and serialized OUTSIDE the lock, so saving never stalls
    // block production, the API, or P2P.
    {
        let save_state = state.clone();
        let save_path = state_path.clone();
        thread::spawn(move || {
            let mut last_saved: u64 = u64::MAX; // force a first save
            loop {
                thread::sleep(Duration::from_secs(5));
                let (height, mut snapshot) = {
                    let s = save_state.read().unwrap();
                    let h = s.tip_height();
                    if h == last_saved {
                        continue; // nothing new to persist
                    }
                    (h, s.clone())
                };
                match snapshot.save_to(&save_path) {
                    Ok(()) => last_saved = height,
                    Err(e) => eprintln!("⚠️  Failed to persist chain state: {e}"),
                }
            }
        });
    }

    // Graceful-shutdown save: on Ctrl-C (SIGINT) or SIGTERM (e.g. `docker stop`,
    // `kill`), flush the latest chain state durably before exiting — so a clean
    // stop never loses recent blocks (a hard SIGKILL still can't be caught, but
    // the atomic+fsync periodic save bounds that loss and never corrupts).
    {
        let shutdown_state = state.clone();
        let shutdown_path = state_path.clone();
        let shutdown_mempool = mempool_path.clone();
        let _ = ctrlc::set_handler(move || {
            let mut snapshot = shutdown_state.read().unwrap().clone();
            match snapshot.save_to(&shutdown_path) {
                Ok(()) => eprintln!("\n💾 Chain state saved on shutdown — bye."),
                Err(e) => eprintln!("\n⚠️  Failed to save on shutdown: {e}"),
            }
            if let Some(ref mp) = shutdown_mempool {
                if let Err(e) = snapshot.dump_mempool_to(mp) {
                    eprintln!("⚠️  Failed to dump mempool: {e}");
                }
            }
            std::process::exit(0);
        });
    }

    // Archive role / HASSAN_ARCHIVAL=1 keeps full history for IBD seeds.
    // Validator + light prune past finality (cheap disk on ordinary machines).
    let archival = profile.archival
        || std::env::var("HASSAN_ARCHIVAL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    if archival {
        state.write().unwrap().archival = true;
        println!(
            "🗄️  Archival mode: pruning disabled, full history retained (serves cold-start sync)"
        );
    } else {
        println!(
            "📦 Pruned mode: bodies past finality + headers past pruning depth dropped; mempools not on disk"
        );
    }

    // Outbound Tor: opt-in via HASSAN_TOR=1. Optional HASSAN_TOR_PROXY=host:port
    // (default 127.0.0.1:9050). This is a SOCKS5 *client* for P2P dials only —
    // we do not publish a hidden service (no ADD_ONION / control port).
    let tor = TorLayer::from_env();
    if tor.is_enabled {
        println!(
            "🧅 TOR enabled — outbound P2P dials via SOCKS5 at {} (display id: {}; not a published hidden service)",
            tor.proxy_addr(),
            tor.onion_address
        );
    } else {
        println!(
            "🧅 TOR disabled — clearnet P2P dials (set HASSAN_TOR=1 to route outbound peers through SOCKS5)"
        );
    }

    println!("🔍 Transparent ledger — every account, balance, and transfer is public");

    let consensus = BlockDAGConsensus::new(state.clone());

    if profile.enable_mining {
        let solo_miner = SoloMiner::new();
        // Block identity (miner address + creator pubkey + birth certificate) is
        // always this node's solo-miner key. Honor HASSAN_MINER_ADDRESS only when
        // it matches that key.
        let reward_address = match std::env::var("HASSAN_MINER_ADDRESS") {
            Ok(addr) if addr == solo_miner.address => {
                println!("⛏️  Mining rewards will be paid to: {addr}");
                addr
            }
            Ok(addr) if hassan::security::is_valid_address(&addr) => {
                eprintln!(
                    "⚠️  miner address '{addr}' is not this node's key — using solo-miner address {} (birth certificates require the local signing key)",
                    solo_miner.address
                );
                solo_miner.address.clone()
            }
            Ok(addr) => {
                eprintln!("⚠️  miner address '{addr}' is not a valid Hassan address — using this node's solo-miner key instead");
                solo_miner.address.clone()
            }
            Err(_) => solo_miner.address.clone(),
        };
        consensus.register_miner(Miner {
            address: reward_address.clone(),
            public_key: solo_miner.public_key.clone(),
            signing_key: Some(solo_miner.secret_key.clone()),
            stake: 0,
            hashrate: 0,
            tor_address: None,
            is_pool: false,
        });
        println!("⛏️  Solo miner ready: {reward_address}");
        consensus.start();
        println!(
            "⛏️  BlockDAG consensus started ({} ms block time)",
            hassan::BLOCK_TIME_MS
        );
    } else {
        println!("⛏️  Solo producer off (--no-mine); validating / serving only");
        // Still start consensus loop for tip maintenance without a local miner
        // registration — produce_block paths no-op without a registered miner.
        consensus.start();
    }

    let api_state = state.clone();
    let api_indexer = indexer.clone();
    thread::spawn(move || {
        start_api_server(api_state, api_indexer);
    });

    // P2P: Tor-only roles dial known peers (no clearnet listen). Clearnet
    // (`--clearnet --listen`) may accept inbound. Dial-only works without listen.
    let listen = std::env::var("HASSAN_P2P_LISTEN").ok().filter(|s| !s.is_empty());
    let mut peers = profile.peers.clone();
    if peers.is_empty() {
        if let Ok(one) = std::env::var("HASSAN_P2P_PEER") {
            if !one.trim().is_empty() {
                peers.push(one);
            }
        }
        if let Ok(many) = std::env::var("HASSAN_P2P_PEERS") {
            for p in many.split([',', ';']) {
                let p = p.trim();
                if !p.is_empty() {
                    peers.push(p.to_string());
                }
            }
        }
    }
    let _p2p_node = if listen.is_some() || !peers.is_empty() {
        let node = Node::with_data_dir(state.clone(), Some(std::path::Path::new(&data_dir)));
        if tor.is_enabled {
            node.set_tor_proxy(Some(&tor.proxy_addr()));
        }
        if let Some(ref addr) = listen {
            match node.listen(addr) {
                Ok(bound) => println!("🔗 P2P listening on {bound}"),
                Err(e) => eprintln!("❌ P2P failed to bind {addr}: {e}"),
            }
        } else if profile.tor_only {
            println!("🔗 P2P dial-only (Tor) — no clearnet listen");
        }
        for peer in &peers {
            match node.connect(peer) {
                Ok(()) => {
                    if tor.is_enabled {
                        println!("🔗 P2P dialing peer {peer} via Tor SOCKS5");
                    } else {
                        println!("🔗 P2P dialing peer {peer}");
                    }
                }
                Err(e) => eprintln!("⚠️  P2P could not connect to {peer}: {e}"),
            }
        }
        if hassan::peer_pin::has_pins() {
            let strict = hassan::peer_pin::directory().strict;
            println!(
                "🔗 Peer pins loaded ({})",
                if strict { "strict" } else { "warn-only" }
            );
        }
        node.spawn_tip_announcer();
        node.spawn_mempool_announcer();
        Some(node)
    } else {
        println!(
            "🔗 P2P idle — add `--peer host:port` (or `.onion:port` under Tor) \
             or `--clearnet --listen 0.0.0.0:9333`"
        );
        None
    };

    let monitor_state = state.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let s = monitor_state.read().unwrap();

        let total_txs: usize = s
            .main_chain
            .iter()
            .filter_map(|h| s.dag.get(h))
            .map(|b| b.transparent_txs.len())
            .sum();

        let latest_tx = s
            .main_chain
            .last()
            .and_then(|h| s.dag.get(h))
            .and_then(|b| b.transparent_txs.last())
            .map(|tx| hex::encode(&tx.tx_hash()[..4]))
            .unwrap_or_else(|| "none".to_string());

        println!(
                "📊 Height: {} | DAG: {} | BlueScore: {} | Diff: {} | Mempool: {} | Txs: {} | LatestTx: {}…",
                s.tip_height(),
                s.dag.len(),
                s.selected_tip_blue_score(),
                s.difficulty,
                s.transparent_mempool.len(),
                total_txs,
                latest_tx
            );
    });

    println!("\n✅ HASSAN v1.0 IS LIVE");
    println!(
        "   Transparent quantum-safe BlockDAG. Mining every {}ms...\n",
        hassan::BLOCK_TIME_MS
    );

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn start_api_server(
    state: Arc<RwLock<ChainState>>,
    indexer: Arc<hassan::indexer::IndexerHandle>,
) {
    // Default bind is loopback so a node is not LAN-exposed by accident.
    // Override with HASSAN_API_BIND=0.0.0.0:8080 when you intentionally want
    // remote access — that requires HASSAN_API_TOKEN.
    let bind = std::env::var("HASSAN_API_BIND").unwrap_or_else(|_| {
        let port = std::env::var("HASSAN_API_PORT").unwrap_or_else(|_| "8080".to_string());
        format!("127.0.0.1:{port}")
    });
    let bind_host = bind
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or(&bind);
    let public_bind = !matches!(bind_host, "127.0.0.1" | "localhost" | "::1");
    let policy = hassan::net_policy::policy();
    if public_bind && policy.api_token.is_none() {
        eprintln!(
            "❌ Refusing to bind API on {bind} without HASSAN_API_TOKEN — \
             public write routes would be unauthenticated"
        );
        return;
    }
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("❌ Failed to bind API on {bind}: {}", e);
            return;
        }
    };
    println!(
        "🌐 API server listening on http://{bind} (rate-limited: {} req/{}s/IP, {}KB request cap{})",
        security::MAX_REQUESTS_PER_WINDOW,
        security::WINDOW.as_secs(),
        security::MAX_REQUEST_BYTES / 1024,
        if policy.writes_require_token() {
            "; writes require Bearer token"
        } else {
            ""
        }
    );

    let limiter = Arc::new(RateLimiter::new());
    // Bound concurrent API connections (audit M-5): thread-per-connection with a
    // 5s read timeout means a slow-loris flood can pin at most this many threads,
    // and each is reclaimed within the timeout.
    const MAX_API_CONNECTIONS: usize = 256;
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if active.load(std::sync::atomic::Ordering::Relaxed) >= MAX_API_CONNECTIONS {
                    continue; // at the cap — drop the connection immediately
                }
                active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let state = state.clone();
                let limiter = limiter.clone();
                let indexer = indexer.clone();
                let active = active.clone();
                thread::spawn(move || {
                    handle_request(stream, state, limiter, indexer);
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
            Err(e) => eprintln!("API connection failed: {}", e),
        }
    }
}

/// Reads a request up to `security::MAX_REQUEST_BYTES`, stopping once the
/// full body (per `Content-Length`) has arrived or the connection closes.
/// Rejects (rather than silently truncating, as the old fixed 4KB single
/// `read()` did) anything over the cap.
fn read_request(stream: &mut TcpStream, max_bytes: usize) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e.to_string()),
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max_bytes {
            return Err(format!("request exceeds {} byte cap", max_bytes));
        }

        if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buf[..header_end]);
            let content_length: usize = headers
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())
                        .flatten()
                })
                .unwrap_or(0);
            // Reject declared body sizes that cannot fit under the request cap
            // (avoids waiting on a slow peer for an inevitably oversized body).
            let header_total = header_end + 4;
            if content_length > max_bytes.saturating_sub(header_total) {
                return Err(format!("request exceeds {} byte cap", max_bytes));
            }
            let body_have = buf.len() - header_total;
            if body_have >= content_length {
                break;
            }
        }
    }
    Ok(buf)
}

/// Extract a header value (case-insensitive name) from a raw HTTP request.
fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// True iff an `Origin` header points at the local machine (so a same-origin web
/// app is allowed; an arbitrary website driving a drive-by write is not).
fn origin_is_local(origin: &str) -> bool {
    let host = origin.split("://").nth(1).unwrap_or(origin);
    let host = host.split('/').next().unwrap_or(host);
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

fn handle_request(
    mut stream: TcpStream,
    state: Arc<RwLock<ChainState>>,
    limiter: Arc<RateLimiter>,
    indexer: Arc<hassan::indexer::IndexerHandle>,
) {
    let peer_ip = match stream.peer_addr() {
        Ok(addr) => addr.ip(),
        Err(_) => return,
    };

    let raw = match read_request(&mut stream, security::MAX_REQUEST_BYTES) {
        Ok(r) => r,
        Err(reason) => {
            let body = serde_json::json!({"error": reason}).to_string();
            let response = format!(
                "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            return;
        }
    };
    if raw.is_empty() {
        return;
    }

    let request = String::from_utf8_lossy(&raw);
    let raw_path = request
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("/");
    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw_path, ""),
    };

    // Explorer shell assets must stay reachable even when the JSON API is
    // rate-limited — otherwise a burst of Overview polls makes `/` itself
    // return 429 and the first page cannot open at all.
    let is_explorer_static = matches!(path, "/" | "/explorer" | "/app.js" | "/style.css");
    if !is_explorer_static {
        if let Err(reason) = limiter.check(peer_ip) {
            let body = serde_json::json!({"error": reason}).to_string();
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            return;
        }
    }

    // CSRF + API token defence for every mempool / transfer write, plus
    // CPU-heavy mining probe (light mine) which must not be open when writes
    // require a token.
    let is_write = matches!(
        path,
        "/api/v1/tx/submit"
            | "/api/v1/tx/transfer"
            | "/api/v1/utxo/submit"
            | "/api/v1/custody/submit"
            | "/api/v1/registry/submit"
            | "/api/v1/mining/light"
    );
    let policy = hassan::net_policy::policy();
    if is_write {
        if let Some(origin) = header_value(&request, "origin") {
            let local_ok = origin_is_local(&origin);
            let cors_ok = policy.cors_allows(&origin);
            if !local_ok && !cors_ok {
                let body = "{\"error\":\"cross-site write rejected\"}";
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                return;
            }
        }
        if policy.writes_require_token() {
            let token = bearer_token(&request);
            if !policy.token_ok(token.as_deref()) {
                let body = "{\"error\":\"unauthorized — set Authorization: Bearer <HASSAN_API_TOKEN>\"}";
                let response = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                return;
            }
        }
    }

    // Long-lived SSE: stream tip events until deadline or client disconnect.
    // Cap concurrent SSE streams process-wide so a client farm cannot pin
    // unbounded handler threads on keep-alive.
    if path == "/api/v1/events" || path == "/api/v1/events/sse" {
        if !acquire_sse_slot() {
            let body = "{\"error\":\"too many concurrent event streams\"}";
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            return;
        }
        serve_sse(&mut stream, &state, &request);
        release_sse_slot();
        return;
    }

    let api = ApiServer::new(state.clone());
    let (status, content_type, body, cache) = match path {
        // Web block explorer: the real `hassan-explorer/` app, served directly
        // from this node so there's exactly one URL to open (this API's own
        // origin) instead of a separate static server. Same-origin, so the
        // explorer's default (same-origin) API base just works.
        "/" | "/explorer" => (
            "200 OK",
            "text/html; charset=utf-8",
            EXPLORER_INDEX_HTML.to_string(),
            "no-cache",
        ),
        "/app.js" => (
            "200 OK",
            "application/javascript; charset=utf-8",
            EXPLORER_APP_JS.to_string(),
            "public, max-age=60",
        ),
        "/style.css" => (
            "200 OK",
            "text/css; charset=utf-8",
            EXPLORER_STYLE_CSS.to_string(),
            "public, max-age=60",
        ),
        "/api/v1/status" => {
            let body = api.status().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/blocks" => {
            let body =
                serde_json::to_string(&api.latest_blocks(200)).unwrap_or_else(|_| "[]".to_string());
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/mining" => {
            let body = api.mining_stats().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        // Issuance certificate: /api/v1/block/<height|hash>/issuance
        p if p.starts_with("/api/v1/block/") && p.ends_with("/issuance") => {
            let id = p
                .strip_prefix("/api/v1/block/")
                .and_then(|s| s.strip_suffix("/issuance"))
                .unwrap_or("");
            let body = api
                .get_block_issuance(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Block not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=10")
        }
        // Economic Entity: /api/v1/block/<height|hash>/economic-entity
        p if p.starts_with("/api/v1/block/") && p.ends_with("/economic-entity") => {
            let id = p
                .strip_prefix("/api/v1/block/")
                .and_then(|s| s.strip_suffix("/economic-entity"))
                .unwrap_or("");
            let body = api
                .get_block_economic_entity(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Block not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=5")
        }
        // Economic Biography: /api/v1/block/<height|hash>/economic-biography
        p if p.starts_with("/api/v1/block/") && p.ends_with("/economic-biography") => {
            let id = p
                .strip_prefix("/api/v1/block/")
                .and_then(|s| s.strip_suffix("/economic-biography"))
                .unwrap_or("");
            let body = api
                .get_block_economic_biography(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Block not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=5")
        }
        // DAG ancestry / settlement chain: /api/v1/block/<id>/family
        p if p.starts_with("/api/v1/block/") && p.ends_with("/family") => {
            let id = p
                .strip_prefix("/api/v1/block/")
                .and_then(|s| s.strip_suffix("/family"))
                .unwrap_or("");
            let body = api
                .get_block_family(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Block not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=5")
        }
        // Full audit dump: /api/v1/block/<id>/audit
        p if p.starts_with("/api/v1/block/") && p.ends_with("/audit") => {
            let id = p
                .strip_prefix("/api/v1/block/")
                .and_then(|s| s.strip_suffix("/audit"))
                .unwrap_or("");
            let body = api
                .audit_block_dump(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Block not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=30")
        }
        // Mergeset edges: /api/v1/block/<id>/mergeset
        p if p.starts_with("/api/v1/block/") && p.ends_with("/mergeset") => {
            let id = p
                .strip_prefix("/api/v1/block/")
                .and_then(|s| s.strip_suffix("/mergeset"))
                .unwrap_or("");
            let body = api
                .mergeset_edges(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Block not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=10")
        }
        // Title deed + chain of title
        "/api/v1/titles" => {
            let body =
                serde_json::to_string(&api.list_titles(200)).unwrap_or_else(|_| "[]".to_string());
            ("200 OK", "application/json", body, "no-store")
        }
        p if p.starts_with("/api/v1/title/") => {
            let id = p.strip_prefix("/api/v1/title/").unwrap_or("");
            let body = api
                .get_title(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Title not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=5")
        }
        // Escrow accounts
        "/api/v1/escrows" => {
            let body =
                serde_json::to_string(&api.list_escrows(200)).unwrap_or_else(|_| "[]".to_string());
            ("200 OK", "application/json", body, "no-store")
        }
        p if p.starts_with("/api/v1/escrow/") => {
            let id = p.strip_prefix("/api/v1/escrow/").unwrap_or("");
            let body = api
                .get_escrow(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Escrow not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=5")
        }
        p if p.starts_with("/api/v1/owner/") && p.ends_with("/titles") => {
            let addr = p
                .strip_prefix("/api/v1/owner/")
                .and_then(|s| s.strip_suffix("/titles"))
                .unwrap_or("");
            let body = serde_json::to_string(&api.titles_for_owner(addr))
                .unwrap_or_else(|_| "[]".to_string());
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/ai/trace" => {
            let body = api.ai_trace(200).to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        p if p.starts_with("/api/v1/ai/block/") => {
            let h = p.strip_prefix("/api/v1/ai/block/").unwrap_or("");
            (
                "200 OK",
                "application/json",
                api.ai_trace_block(h).to_string(),
                "no-store",
            )
        }
        "/api/v1/custody/verify" => {
            let body_str = request.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let response =
                match serde_json::from_str::<hassan::custody::CustodyCertificate>(body_str) {
                    Ok(cert) => match api.verify_custody(&cert) {
                        Ok(v) => v.to_string(),
                        Err(e) => serde_json::json!({"error": e}).to_string(),
                    },
                    Err(_) => serde_json::json!({"error": "Invalid custody JSON"}).to_string(),
                };
            ("200 OK", "application/json", response, "no-store")
        }
        // Block by absolute height or hash: /api/v1/block/<height|hash>
        p if p.starts_with("/api/v1/block/") => {
            let id = p.strip_prefix("/api/v1/block/").unwrap_or("");
            let body = api
                .get_block_rich(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Block not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=5")
        }
        "/api/v1/tx/submit" => {
            let body_str = request.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let response = match serde_json::from_str::<TxSubmitRequest>(body_str) {
                Ok(req) => match api.submit_tx(req) {
                    Ok(resp) => serde_json::to_string(&resp).unwrap(),
                    Err(e) => serde_json::json!({"error": e}).to_string(),
                },
                Err(_) => serde_json::json!({"error": "Invalid JSON"}).to_string(),
            };
            ("200 OK", "application/json", response, "no-store")
        }
        "/api/v1/utxo/submit" => {
            let body_str = request.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let response = match serde_json::from_str::<hassan::utxo_tx::UtxoTx>(body_str) {
                Ok(tx) => match api.submit_utxo_tx(tx) {
                    Ok(v) => v.to_string(),
                    Err(e) => serde_json::json!({"error": e}).to_string(),
                },
                Err(e) => serde_json::json!({"error": format!("Invalid UTXO tx JSON: {e}")})
                    .to_string(),
            };
            ("200 OK", "application/json", response, "no-store")
        }
        "/api/v1/bdpe/vaults" | "/api/v1/escrow/vaults" => {
            let mut addr: Option<String> = None;
            let mut limit = 64usize;
            for part in query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    match k {
                        "address" | "addr" => {
                            if !v.is_empty() {
                                addr = Some(percent_decode(v));
                            }
                        }
                        "limit" => {
                            if let Ok(n) = v.parse::<usize>() {
                                limit = n.min(256);
                            }
                        }
                        _ => {}
                    }
                }
            }
            let body = serde_json::to_string(&api.list_bdpe_vaults(addr.as_deref(), limit))
                .unwrap_or_else(|_| "[]".to_string());
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/registry/submit" => {
            let body_str = request.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let response = match serde_json::from_str::<hassan::registry::RegistryOp>(body_str) {
                Ok(op) => match api.submit_registry_op(op) {
                    Ok(v) => v.to_string(),
                    Err(e) => serde_json::json!({"error": e}).to_string(),
                },
                Err(e) => serde_json::json!({"error": format!("Invalid registry op JSON: {e}")})
                    .to_string(),
            };
            ("200 OK", "application/json", response, "no-store")
        }
        "/api/v1/custody/submit" => {
            let body_str = request.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let response =
                match serde_json::from_str::<hassan::custody::CustodyCertificate>(body_str) {
                    Ok(op) => match api.submit_custody(op) {
                        Ok(v) => v.to_string(),
                        Err(e) => serde_json::json!({"error": e}).to_string(),
                    },
                    Err(e) => serde_json::json!({"error": format!("Invalid custody JSON: {e}")})
                        .to_string(),
                };
            ("200 OK", "application/json", response, "no-store")
        }
        "/api/v1/mempool" => {
            let body =
                serde_json::to_string(&api.mempool_txs()).unwrap_or_else(|_| "[]".to_string());
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/versionbits" => {
            let body = api.version_bits().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/network" | "/api/v1/peers" => {
            let body = api.network().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/custody" | "/api/v1/custody/list" => {
            let body = api.list_custody().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/mining/light" => {
            let mut max_hashes = 10_000u64;
            let mut share_diff: Option<u64> = None;
            for part in query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    match k {
                        "max" | "max_hashes" => {
                            if let Ok(n) = v.parse::<u64>() {
                                max_hashes = n;
                            }
                        }
                        "diff" | "share_difficulty" => {
                            if let Ok(n) = v.parse::<u64>() {
                                share_diff = Some(n);
                            }
                        }
                        _ => {}
                    }
                }
            }
            let body = api.light_mine(max_hashes, share_diff).to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/light/tip" => {
            let body = api.light_tip(32).to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        p if p.starts_with("/api/v1/ghostdag/") => {
            let id = p.strip_prefix("/api/v1/ghostdag/").unwrap_or("");
            let body = api
                .ghostdag_info(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=10")
        }
        p if p.starts_with("/api/v1/utxos/") => {
            let addr = p.strip_prefix("/api/v1/utxos/").unwrap_or("");
            let body = api.list_utxos(addr).to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/stratum" => {
            let srv = hassan::stratum::StratumServer::new(Arc::clone(&state));
            let notify = srv.make_notify().unwrap_or(serde_json::json!({"error":"notify"}));
            let body = serde_json::json!({
                "notify": notify,
                "workers": srv.worker_stats(),
            })
            .to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        // Transfer Economic Entity: /api/v1/tx/<hash>/economic-entity
        p if p.starts_with("/api/v1/tx/") && p.ends_with("/economic-entity") => {
            let id = p
                .strip_prefix("/api/v1/tx/")
                .and_then(|s| s.strip_suffix("/economic-entity"))
                .unwrap_or("");
            let body = api
                .get_tx_economic_entity(id)
                .map(|b| b.to_string())
                .unwrap_or_else(|| "{\"error\":\"Transfer not found\"}".to_string());
            ("200 OK", "application/json", body, "public, max-age=5")
        }
        "/api/v1/fee/estimate" => {
            let body = api.fee_estimate().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/fees/history" | "/api/v1/fee/history" => {
            let body = api.fee_history_export().to_string();
            ("200 OK", "application/json", body, "public, max-age=15")
        }
        "/api/v1/mining/template" | "/api/v1/getblocktemplate" => {
            let body = api.get_block_template().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/supply" => {
            let body = api.get_supply().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/economics/verification" => {
            let body = api.verification_economics().to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/pruning/stats" => {
            let body = api.pruning_proof_stats().to_string();
            ("200 OK", "application/json", body, "public, max-age=30")
        }
        "/api/v1/pruning/proof" | "/api/v1/pruning/download" => {
            let body = api.pruning_proof_download().to_string();
            ("200 OK", "application/json", body, "public, max-age=60")
        }
        "/api/v1/utxo/snapshot" => {
            let mut limit = 256usize;
            for part in query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "limit" {
                        if let Ok(n) = v.parse::<usize>() {
                            limit = n;
                        }
                    }
                }
            }
            let body = api.utxo_snapshot(limit).to_string();
            ("200 OK", "application/json", body, "public, max-age=10")
        }
        "/api/v1/audit/pack" => {
            let mut block_id: Option<&str> = None;
            for part in query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "block" && !v.is_empty() {
                        block_id = Some(v);
                    }
                }
            }
            let body = api.audit_pack(block_id).to_string();
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/audit/diff" => {
            let mut from = "0";
            let mut to = "";
            for part in query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    match k {
                        "from" => from = v,
                        "to" => to = v,
                        _ => {}
                    }
                }
            }
            let to = if to.is_empty() {
                state
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .tip_height()
                    .to_string()
            } else {
                to.to_string()
            };
            let body = api.audit_diff(from, &to).to_string();
            ("200 OK", "application/json", body, "public, max-age=10")
        }
        "/api/v1/search" => {
            let mut q = "";
            for part in query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "q" {
                        q = v;
                    }
                }
            }
            let q = percent_decode(q);
            let body = {
                let db = indexer.db.read().unwrap_or_else(|p| p.into_inner());
                db.search(&q).to_string()
            };
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/analytics" | "/api/v1/analytics/history" => {
            let mut limit = 512usize;
            for part in query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "limit" {
                        if let Ok(n) = v.parse::<usize>() {
                            limit = n;
                        }
                    }
                }
            }
            let body = {
                let db = indexer.db.read().unwrap_or_else(|p| p.into_inner());
                db.analytics(limit).to_string()
            };
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/indexer" | "/api/v1/indexer/status" => {
            let body = {
                let db = indexer.db.read().unwrap_or_else(|p| p.into_inner());
                db.status_json(&indexer.path).to_string()
            };
            ("200 OK", "application/json", body, "no-store")
        }
        "/api/v1/labels" => {
            let body = {
                let db = indexer.db.read().unwrap_or_else(|p| p.into_inner());
                let mut pairs: Vec<_> = db.labels.iter().collect();
                pairs.sort_by(|a, b| a.0.cmp(b.0));
                pairs.truncate(500);
                serde_json::json!({
                    "labels": pairs.into_iter().map(|(k,v)| serde_json::json!({"id": k, "label": v})).collect::<Vec<_>>(),
                })
                .to_string()
            };
            ("200 OK", "application/json", body, "public, max-age=15")
        }
        p if p.starts_with("/api/v1/address/") && p.ends_with("/history") => {
            let addr = p
                .strip_prefix("/api/v1/address/")
                .and_then(|s| s.strip_suffix("/history"))
                .unwrap_or("");
            let addr = percent_decode(addr);
            let body = {
                let db = indexer.db.read().unwrap_or_else(|p| p.into_inner());
                db.address_history(&addr, 100).to_string()
            };
            ("200 OK", "application/json", body, "no-store")
        }
        // Submit an already-signed transparent transfer.
        "/api/v1/tx/transfer" => {
            let body_str = request.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let response = match serde_json::from_str::<serde_json::Value>(body_str) {
                Ok(j) => {
                    let from_pubkey =
                        hex::decode(j["from_pubkey"].as_str().unwrap_or("")).unwrap_or_default();
                    let to = j["to"].as_str().unwrap_or("").to_string();
                    let amount = j["amount"]
                        .as_str()
                        .and_then(|s| s.parse::<u128>().ok())
                        .or_else(|| j["amount"].as_u64().map(|v| v as u128))
                        .unwrap_or(0);
                    let nonce = j["nonce"].as_u64().unwrap_or(0);
                    let chain_id = j["chain_id"].as_u64().unwrap_or(hassan::CHAIN_ID);
                    let signature =
                        hex::decode(j["signature"].as_str().unwrap_or("")).unwrap_or_default();
                    let mut tx =
                        hassan::TransparentTx::new(from_pubkey, to, amount, nonce, chain_id);
                    tx.signature = signature;
                    match api.submit_transfer(tx) {
                        Ok(v) => v.to_string(),
                        Err(e) => serde_json::json!({ "error": e }).to_string(),
                    }
                }
                Err(_) => serde_json::json!({ "error": "Invalid JSON" }).to_string(),
            };
            ("200 OK", "application/json", response, "no-store")
        }
        // Account balance + next nonce: /api/v1/account/hsn:<addr>
        p if p.starts_with("/api/v1/account/") => {
            let addr = p.strip_prefix("/api/v1/account/").unwrap_or("");
            (
                "200 OK",
                "application/json",
                api.account(addr).to_string(),
                "no-store",
            )
        }
        _ => ("404 Not Found", "text/plain", "Not Found".to_string(), "no-store"),
    };

    let cors = match (
        header_value(&request, "origin"),
        hassan::net_policy::policy().cors_header_value(),
    ) {
        (Some(origin), _) if hassan::net_policy::policy().cors_allows(&origin) => {
            format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n")
        }
        (_, Some(single)) => format!("Access-Control-Allow-Origin: {single}\r\n"),
        _ => String::new(),
    };
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nCache-Control: {}\r\n{}Content-Length: {}\r\n\r\n{}",
        status,
        content_type,
        cache,
        cors,
        body.len(),
        body
    );

    let _ = stream.write_all(response.as_bytes());
}

/// Minimal percent-decoding for search / address path segments.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = || -> Option<u8> {
                let hi = (bytes[i + 1] as char).to_digit(16)? as u8;
                let lo = (bytes[i + 2] as char).to_digit(16)? as u8;
                Some((hi << 4) | lo)
            };
            if let Some(b) = h() {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Cap concurrent SSE tip streams (each holds a handler thread ~25s).
const MAX_SSE_STREAMS: u32 = 32;
static SSE_STREAMS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn acquire_sse_slot() -> bool {
    use std::sync::atomic::Ordering;
    loop {
        let cur = SSE_STREAMS.load(Ordering::Relaxed);
        if cur >= MAX_SSE_STREAMS {
            return false;
        }
        if SSE_STREAMS
            .compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

fn release_sse_slot() {
    SSE_STREAMS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
}

/// SSE tip stream: send an initial snapshot, then pulse on tip/mempool change
/// for up to ~25s (CDN-friendly short streams; clients reconnect).
fn serve_sse(
    stream: &mut TcpStream,
    state: &Arc<RwLock<ChainState>>,
    request: &str,
) {
    let cors = match (
        header_value(request, "origin"),
        hassan::net_policy::policy().cors_header_value(),
    ) {
        (Some(origin), _) if hassan::net_policy::policy().cors_allows(&origin) => {
            format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n")
        }
        (_, Some(single)) => format!("Access-Control-Allow-Origin: {single}\r\n"),
        _ => String::new(),
    };
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n{}\r\n",
        cors
    );
    if stream.write_all(headers.as_bytes()).is_err() {
        return;
    }
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let api = ApiServer::new(state.clone());
    let mut last = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    while std::time::Instant::now() < deadline {
        let snap = api.events_snapshot().to_string();
        if snap != last {
            let frame = format!("event: tip\ndata: {snap}\n\n");
            if stream.write_all(frame.as_bytes()).is_err() {
                return;
            }
            let _ = stream.flush();
            last = snap;
        } else {
            // keepalive comment
            if stream.write_all(b": keepalive\n\n").is_err() {
                return;
            }
        }
        thread::sleep(Duration::from_millis(400));
    }
    let _ = stream.write_all(b"event: end\ndata: {\"ok\":true}\n\n");
}

fn bearer_token(request: &str) -> Option<String> {
    if let Some(v) = header_value(request, "authorization") {
        let v = v.trim();
        if let Some(rest) = v
            .strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
        {
            return Some(rest.trim().to_string());
        }
    }
    header_value(request, "x-hassan-api-token")
}

/// The real block explorer app (`hassan-explorer/`), embedded at compile time
/// so the running node can serve it directly at its own origin — one URL to
/// open, no separate static file server, and the explorer's default
/// same-origin API base just works. Source of truth is the checked-in
/// `hassan-explorer/` folder; these are read-only compile-time includes, not
/// copies to maintain separately.
const EXPLORER_INDEX_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/hassan-explorer/index.html"
));
const EXPLORER_APP_JS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/hassan-explorer/app.js"
));
const EXPLORER_STYLE_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/hassan-explorer/style.css"
));
