//! `hassan-wallet` — a minimal command-line wallet for the transparent
//! (ML-DSA-87 post-quantum) transfer path. It uses only the public crate API
//! (`hassan::wallet::Wallet`) and talks to a running node's HTTP API. Keys are
//! generated and signed locally; the node never sees a secret key.
//!
//! KEYSTORE AT REST: secret keys are encrypted with Argon2id + ChaCha20-Poly1305.
//! `HASSAN_WALLET_PASSWORD` is required for `new` (unless `--insecure`).
//! Plaintext keystores are refused by default.

use hassan::keystore::{self, PASSWORD_ENV};
use hassan::{CHAIN_ID, GENESIS_DOMAIN};
use hassan::wallet::Wallet;
use std::io::{Read, Write};
use std::net::TcpStream;

const DEFAULT_WALLET: &str = "wallet.json";
const DEFAULT_API: &str = "127.0.0.1:8080";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[2.min(args.len())..];

    let result = match cmd {
        "new" | "generate" => cmd_new(rest),
        "address" | "addr" => cmd_address(rest),
        "network" | "net" => cmd_network(rest),
        "balance" | "bal" => cmd_balance(rest),
        "send" => cmd_send(rest),
        "send-fee" => cmd_send_fee(rest),
        "bump" | "rbf" => cmd_bump(rest),
        "fee-estimate" | "fees" => cmd_fee_estimate(rest),
        "utxos" | "list-utxos" => cmd_utxos(rest),
        "mempool" => cmd_mempool(rest),
        "mine" | "light-mine" => cmd_mine(rest),
        "escrow" => cmd_escrow(rest),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown command '{other}'. Run `hassan-wallet help`."
        )),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "hassan-wallet — Hassan Blockchain v1.0\n\n\
         USAGE:\n\
         \x20 hassan-wallet new         [FILE]                              generate a wallet -> FILE (default {DEFAULT_WALLET})\n\
         \x20 hassan-wallet address     [FILE]                              print the wallet's hsn1… bech32m address\n\
         \x20 hassan-wallet network     [API]                               print chain_id, chain_hash, genesis_domain\n\
         \x20 hassan-wallet balance     <hsn1…|hsn:ADDR> [API]              query a node for balance + nonce\n\
         \x20 hassan-wallet send        <hsn1…|hsn:TO> <AMOUNT> [FILE] [API]  sign & submit a transfer at the protocol min fee\n\
         \x20 hassan-wallet send-fee    <hsn1…|hsn:TO> <AMOUNT> <FEE> [FILE] [API]  sign & submit a transfer at a chosen fee\n\
         \x20 hassan-wallet bump        <hsn1…|hsn:TO> <AMOUNT> <NONCE> <NEW_FEE> [FILE] [API]\n\
         \x20                                                              replace-by-fee (RBF): re-sign the SAME nonce at a\n\
         \x20                                                              higher fee to bump a stuck queued transfer\n\
         \x20 hassan-wallet fee-estimate [API]                              show confirmation-target fee estimates (high≈6 / medium≈20 / low≈100 blues)\n\
         \x20 hassan-wallet utxos       <hsn1…|hsn:ADDR> [API]              list UTXOs locked to an address\n\
         \x20 hassan-wallet mempool     [API]                               inspect mempool ancestor packages / feerates\n\
         \x20 hassan-wallet mine        [API] [max_hashes]                  Blake3-512 light mine (CPU/laptop share probe)\n\
         \x20 hassan-wallet escrow      <subcommand> …                      peer escrow — try `escrow tutorial` (see ESCROW.md)\n\n\
         API defaults to {DEFAULT_API}.\n\n\
         ADD NETWORK (wallets):\n\
         \x20 Use /api/v1/status fields chain_hash (hex) + RPC URL; chain_id is the numeric u64 for txs.\n\n\
         ENCRYPTION AT REST:\n\
         \x20 {PASSWORD_ENV} is REQUIRED for `new` (Argon2id + ChaCha20-Poly1305).\n\
         \x20   {PASSWORD_ENV}='hunter2' hassan-wallet new my.json\n\
         \x20 Pass `--insecure` to write a plaintext keystore (explicit opt-in only)."
    );
}

fn password() -> Option<String> {
    keystore::password_from_env()
}

fn save_wallet(path: &str, w: &Wallet, allow_plaintext: bool) -> Result<bool, String> {
    keystore::save_wallet(path, w, allow_plaintext)
}

fn load_wallet(path: &str) -> Result<Wallet, String> {
    keystore::load_wallet(path)
}

// ===== Commands =====

fn cmd_new(args: &[String]) -> Result<(), String> {
    let mut allow_plaintext = false;
    let mut path = DEFAULT_WALLET.to_string();
    for a in args {
        if a == "--insecure" {
            allow_plaintext = true;
        } else if !a.starts_with('-') {
            path = a.clone();
        } else {
            return Err(format!("unknown flag '{a}' (supported: --insecure)"));
        }
    }
    if std::path::Path::new(&path).exists() {
        return Err(format!(
            "{path} already exists — refusing to overwrite an existing wallet"
        ));
    }
    if !allow_plaintext && password().is_none() {
        return Err(format!(
            "set {PASSWORD_ENV} to encrypt the keystore, or pass --insecure for plaintext"
        ));
    }
    let w = Wallet::generate();
    let encrypted = save_wallet(&path, &w, allow_plaintext)?;
    println!("✅ New wallet created.");
    println!("   address : {}", w.address());
    println!("   chain_id: {CHAIN_ID}");
    println!("   chain_hash: {}", hassan::chain_hash_hex());
    println!(
        "   genesis : {}",
        String::from_utf8_lossy(GENESIS_DOMAIN)
    );
    if encrypted {
        println!("   keystore: {path}  (encrypted — you'll need {PASSWORD_ENV} to spend)");
    } else {
        println!("   keystore: {path}  (UNENCRYPTED — created with --insecure)");
    }
    Ok(())
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let path = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let w = load_wallet(path)?;
    println!("{}", w.address());
    Ok(())
}

fn cmd_network(args: &[String]) -> Result<(), String> {
    let api = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    match http_get(api, "/api/v1/status") {
        Ok(body) => {
            let j: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| format!("bad node response: {e}"))?;
            println!(
                "chain_id: {}",
                j["chain_id"].as_u64().unwrap_or(CHAIN_ID)
            );
            let local_hash = hassan::chain_hash_hex();
            println!(
                "chain_hash: {}",
                j["chain_hash"].as_str().unwrap_or(&local_hash)
            );
            let local_domain = String::from_utf8_lossy(GENESIS_DOMAIN);
            println!(
                "genesis_domain: {}",
                j["genesis_domain"].as_str().unwrap_or(&local_domain)
            );
            if let Some(rpc) = j["p2p_listen_addr"].as_str() {
                println!("p2p: {rpc}");
            }
            println!("rpc: http://{api}");
        }
        Err(_) => {
            // Offline: print compile-time / local genesis identity.
            println!("chain_id: {CHAIN_ID}");
            println!("chain_hash: {}", hassan::chain_hash_hex());
            println!(
                "genesis_domain: {}",
                String::from_utf8_lossy(GENESIS_DOMAIN)
            );
            println!("(node unreachable at {api} — showing local constants)");
        }
    }
    Ok(())
}

fn cmd_balance(args: &[String]) -> Result<(), String> {
    let addr = args
        .first()
        .ok_or("usage: hassan-wallet balance <hsn:ADDR> [API]")?;
    let api = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let body = http_get(api, &format!("/api/v1/account/{addr}"))?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad node response: {e}"))?;
    println!("address: {}", j["address"].as_str().unwrap_or(addr));
    println!("balance: {}", j["balance"].as_str().unwrap_or("0"));
    println!("nonce  : {}", j["nonce"].as_u64().unwrap_or(0));
    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), String> {
    let to = args
        .first()
        .ok_or("usage: hassan-wallet send <hsn:TO> <AMOUNT> [FILE] [API]")?;
    let amount: u128 = args
        .get(1)
        .ok_or("missing AMOUNT")?
        .parse()
        .map_err(|_| "AMOUNT must be a non-negative integer".to_string())?;
    let path = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let api = args.get(3).map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    send_at_fresh_nonce(to, amount, None, path, api)
}

fn cmd_send_fee(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet send-fee <hsn:TO> <AMOUNT> <FEE> [FILE] [API]";
    let to = args.first().ok_or(usage)?;
    let amount: u128 = args
        .get(1)
        .ok_or("missing AMOUNT")?
        .parse()
        .map_err(|_| "AMOUNT must be a non-negative integer".to_string())?;
    let fee: u128 = args
        .get(2)
        .ok_or("missing FEE")?
        .parse()
        .map_err(|_| "FEE must be a non-negative integer".to_string())?;
    let path = args.get(3).map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let api = args.get(4).map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    send_at_fresh_nonce(to, amount, Some(fee), path, api)
}

/// Replace-by-fee (RBF): re-sign a transfer at an EXPLICIT (already-used)
/// nonce with a higher fee, so it replaces whatever is currently queued at
/// that nonce instead of being rejected as a duplicate. `TO`/`AMOUNT` must
/// match what you actually want mined at that nonce — replacement only
/// changes the fee, it does not "edit" an in-flight transfer's destination
/// (the node has no idea what the original send was; you're submitting a
/// brand-new signed transfer that happens to reuse the same nonce).
fn cmd_bump(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet bump <hsn:TO> <AMOUNT> <NONCE> <NEW_FEE> [FILE] [API]";
    let to = args.first().ok_or(usage)?;
    let amount: u128 = args
        .get(1)
        .ok_or("missing AMOUNT")?
        .parse()
        .map_err(|_| "AMOUNT must be a non-negative integer".to_string())?;
    let nonce: u64 = args
        .get(2)
        .ok_or("missing NONCE (the nonce of the stuck transfer you're replacing)")?
        .parse()
        .map_err(|_| "NONCE must be a non-negative integer".to_string())?;
    let new_fee: u128 = args
        .get(3)
        .ok_or("missing NEW_FEE")?
        .parse()
        .map_err(|_| "NEW_FEE must be a non-negative integer".to_string())?;
    let path = args.get(4).map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let api = args.get(5).map(|s| s.as_str()).unwrap_or(DEFAULT_API);

    let w = load_wallet(path)?;
    submit_transfer(&w, to, amount, new_fee, nonce, api, "replacement (RBF)")
}

fn cmd_fee_estimate(args: &[String]) -> Result<(), String> {
    let api = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let body = http_get(api, "/api/v1/fee/estimate")?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad node response: {e}"))?;
    println!(
        "mempool txs    : {}",
        j["mempool_txs"].as_u64().unwrap_or(0)
    );
    println!(
        "history blocks : {}",
        j["fee_history_blocks"].as_u64().unwrap_or(0)
    );
    println!(
        "packages       : {}",
        j["package_count"].as_u64().unwrap_or(0)
    );
    println!(
        "best package   : {}",
        j["best_package_fee"].as_str().unwrap_or("?")
    );
    println!(
        "protocol min   : {}",
        j["protocol_min_fee"].as_str().unwrap_or("?")
    );
    println!(
        "current relay  : {}",
        j["min_relay_fee"].as_str().unwrap_or("?")
    );
    let ht = j["high_target_blues"].as_u64().unwrap_or(6);
    let mt = j["medium_target_blues"].as_u64().unwrap_or(20);
    let lt = j["low_target_blues"].as_u64().unwrap_or(100);
    println!(
        "high (~{ht} blues): {}",
        j["high"].as_str().unwrap_or("?")
    );
    println!(
        "medium (~{mt} blues): {}",
        j["medium"].as_str().unwrap_or("?")
    );
    println!(
        "low (~{lt} blues) : {}",
        j["low"].as_str().unwrap_or("?")
    );
    Ok(())
}

fn cmd_utxos(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet utxos <hsn:ADDR> [API]";
    let addr = args.first().ok_or(usage)?;
    let api = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let path = format!("/api/v1/utxos/{addr}");
    let body = http_get(api, &path)?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad node response: {e}"))?;
    let utxos = j["utxos"].as_array().cloned().unwrap_or_default();
    println!("address : {}", j["address"].as_str().unwrap_or(addr));
    println!("utxos   : {}", utxos.len());
    for u in utxos {
        println!(
            "  {}:{}  value={}  blue={}  coinbase={}  {}",
            u["txid"].as_str().unwrap_or("?"),
            u["vout"].as_u64().unwrap_or(0),
            u["value"].as_str().unwrap_or("?"),
            u["created_blue"].as_u64().unwrap_or(0),
            u["coinbase"].as_bool().unwrap_or(false),
            u["predicate"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

fn cmd_mempool(args: &[String]) -> Result<(), String> {
    let api = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let body = http_get(api, "/api/v1/mempool")?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad node response: {e}"))?;
    let txs = if j.is_array() {
        j.as_array().cloned().unwrap_or_default()
    } else {
        j["txs"].as_array().cloned().unwrap_or_default()
    };
    println!("mempool entries: {}", txs.len());
    for t in txs.iter().take(32) {
        println!(
            "  fee={} feerate={} ancestor_fee={} from={}",
            t["fee"].as_str().or_else(|| t["fee"].as_u64().map(|_| "")).unwrap_or("?"),
            t["feerate"].as_str().unwrap_or("?"),
            t["ancestor_fee"].as_str().unwrap_or("?"),
            t["from"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

fn cmd_mine(args: &[String]) -> Result<(), String> {
    let api = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let max = args
        .get(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(50_000);
    let body = http_get(api, &format!("/api/v1/mining/light?max={max}"))?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad node response: {e}"))?;
    println!("pow_algo={}", j["pow_algo"].as_str().unwrap_or("blake3-512"));
    println!(
        "share_difficulty={} network_difficulty={}",
        j["share_difficulty"], j["network_difficulty"]
    );
    println!(
        "hashes_tried={} elapsed_ms={} hashes_per_sec={}",
        j["hashes_tried"], j["elapsed_ms"], j["hashes_per_sec"]
    );
    println!(
        "found={} nonce={:?} share_hash={:?}",
        j["found"], j["nonce"], j["share_hash"]
    );
    Ok(())
}

// ===== BDPE escrow (UTXO vault) =====

fn escrow_store_path(wallet_path: &str) -> String {
    format!("{wallet_path}.escrow.json")
}

fn load_escrows(wallet_path: &str) -> Result<Vec<tuep_escrow::EscrowRecord>, String> {
    let path = escrow_store_path(wallet_path);
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("bad escrow store: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(format!("read {path}: {e}")),
    }
}

fn save_escrows(wallet_path: &str, rows: &[tuep_escrow::EscrowRecord]) -> Result<(), String> {
    let path = escrow_store_path(wallet_path);
    let raw = serde_json::to_string_pretty(rows).map_err(|e| e.to_string())?;
    std::fs::write(&path, raw).map_err(|e| format!("write {path}: {e}"))
}

fn find_escrow_mut<'a>(
    rows: &'a mut [tuep_escrow::EscrowRecord],
    id: &str,
) -> Result<&'a mut tuep_escrow::EscrowRecord, String> {
    rows.iter_mut()
        .find(|r| r.escrow_id == id || r.escrow_id.starts_with(id))
        .ok_or_else(|| format!("escrow not found: {id}"))
}

fn tip_blue(api: &str) -> Result<u64, String> {
    let body = http_get(api, "/api/v1/status")?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad status: {e}"))?;
    Ok(j["blue_score"]
        .as_u64()
        .or_else(|| j["selected_blue_score"].as_u64())
        .unwrap_or(0))
}

fn pick_funding_utxo(
    api: &str,
    addr: &str,
    need: u128,
) -> Result<(hassan::utxo::OutPoint, u128), String> {
    let body = http_get(api, &format!("/api/v1/utxos/{addr}"))?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad utxos: {e}"))?;
    let utxos = j["utxos"].as_array().cloned().unwrap_or_default();
    let mut best: Option<(hassan::utxo::OutPoint, u128)> = None;
    for u in utxos {
        // Prefer plain PayToAddress (skip already-vaulted outputs).
        if u["bdpe_vault"].is_object() {
            continue;
        }
        let pred = u["predicate"].as_str().unwrap_or("");
        if pred.contains("MultiSig") || pred.contains("Or") {
            continue;
        }
        let value: u128 = u["value"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        if value < need {
            continue;
        }
        let txid_hex = u["txid"].as_str().unwrap_or("");
        let vout = u["vout"].as_u64().unwrap_or(0) as u32;
        let op = hassan::bdpe::outpoint_from_hex(txid_hex, vout)?;
        if best.as_ref().map(|(_, v)| value < *v).unwrap_or(true) {
            best = Some((op, value));
        }
    }
    best.ok_or_else(|| format!("no funding UTXO ≥ {need} for {addr}"))
}

fn submit_utxo(api: &str, tx: &hassan::utxo_tx::UtxoTx) -> Result<serde_json::Value, String> {
    let payload = serde_json::to_string(tx).map_err(|e| e.to_string())?;
    let resp = http_post(api, "/api/v1/utxo/submit", &payload)?;
    let rj: serde_json::Value =
        serde_json::from_str(&resp).map_err(|e| format!("bad node response: {e}"))?;
    if let Some(err) = rj["error"].as_str() {
        return Err(err.to_string());
    }
    Ok(rj)
}

fn print_escrow_help() {
    println!(
        "hassan-wallet escrow — Hassan peer escrow (buyer + seller)\n\n\
         Easy start:\n\
         \x20 1.  hassan-wallet escrow tutorial     (plain steps + copy-paste examples)\n\
         \x20 2.  Create wallets, fund the buyer, then follow the numbered steps.\n\
         \x20 3.  Watch live vaults in Explorer → Escrow (#/escrow); balances on Wallet (#/wallet).\n\n\
         Commands:\n\
         \x20 escrow tutorial | sketch | guide       beginner walkthrough (this help’s friend)\n\
         \x20 escrow open   <SELLER> <AMOUNT> <TIMEOUT_BLUES> [MEMO] [FILE]\n\
         \x20 escrow fund   <ESCROW_ID> [FILE] [API]              ← publishes / locks on-chain\n\
         \x20 escrow settle <ESCROW_ID> --with <OTHER_WALLET.json> [FILE] [API]\n\
         \x20 escrow refund <ESCROW_ID> --with <OTHER_WALLET.json> [FILE] [API]\n\
         \x20 escrow timeout-claim <ESCROW_ID> [FILE] [API]\n\
         \x20 escrow status <ESCROW_ID> [FILE] [API]\n\
         \x20 escrow list   [FILE]\n\
         \x20 escrow history <ESCROW_ID> [FILE]\n\
         \x20 escrow vaults [ADDR] [API]   (on-chain vault list from the node)\n\n\
         What “publish” means: `open` only saves terms on your disk. `fund` / `settle` /\n\
         `refund` / `timeout-claim` send signed txs to the node API so the vault appears\n\
         on-chain and in Explorer.\n\n\
         Local terms: FILE.escrow.json · Docs: ESCROW.md · TUEP.md · tuep-escrow/SPEC.md"
    );
}

fn print_escrow_tutorial() {
    // Raw string so ASCII indent survives (escaped `\` line-continuations
    // discard leading whitespace on the next line).
    println!(
        r#"Hassan escrow — easy tutorial
=============================

In plain words
--------------
Escrow holds HSN safely between a buyer and a seller until they both agree
(or until a timeout lets the buyer reclaim).

  • open   = write the deal on your computer (not on the chain yet)
  • fund   = publish / lock money into an on-chain vault  ← this is “publish”
  • settle = both sign → seller gets paid
  • refund = both sign → buyer gets money back
  • timeout-claim = after the wait height, buyer alone reclaims

Nothing moves on Hassan until you fund (or later spend) via the node API.

Picture
-------
  1.create deal (open)
        |
        v
  2.publish / lock money (fund)  ---->  vault shows in Explorer #/escrow
        |
        +-- both agree settle  --> seller
        +-- both agree refund  --> buyer
        +-- wait expires       --> buyer (timeout-claim)

Numbered steps (copy-paste)
---------------------------
Prep — make two wallets and give the buyer spendable HSN:

  hassan-wallet new buyer.json
  hassan-wallet new seller.json
  # note seller address:  hassan-wallet address seller.json
  # fund buyer from your node / faucet / another wallet, then:

Step 1 — Create (open) the deal on the buyer machine:

  hassan-wallet escrow open <SELLER_hsn1…> <AMOUNT_sats> <TIMEOUT_BLUES> "goods" buyer.json

  → prints escrow_id
  → saves terms in buyer.json.escrow.json
  → NOT on-chain yet (Explorer will not show a vault)

Step 2 — Publish / fund (locks HSN on-chain):

  hassan-wallet escrow fund <ESCROW_ID> buyer.json http://127.0.0.1:8080

  → spends buyer coins into a vault UTXO
  → after the node accepts the tx, the vault appears under:
       Explorer → Escrow  (#/escrow)
       or:  hassan-wallet escrow vaults http://127.0.0.1:8080

Step 3 — Finish one of three ways:

  A) Pay the seller (both wallets must sign):
     hassan-wallet escrow settle <ESCROW_ID> --with seller.json buyer.json http://127.0.0.1:8080

  B) Refund the buyer (both wallets must sign):
     hassan-wallet escrow refund <ESCROW_ID> --with seller.json buyer.json http://127.0.0.1:8080

  C) Buyer reclaim after timeout (buyer alone; media blue ≥ timeout):
     hassan-wallet escrow timeout-claim <ESCROW_ID> buyer.json http://127.0.0.1:8080

Check status anytime:

  hassan-wallet escrow status  <ESCROW_ID> buyer.json
  hassan-wallet escrow history <ESCROW_ID> buyer.json
  hassan-wallet escrow list    buyer.json

What “publish” means
--------------------
“Publish” = broadcast a fund / settle / refund / timeout tx to your Hassan
node’s HTTP API (default http://127.0.0.1:8080). The node validates and
includes it; Explorer then lists the vault. Opening alone is local only.

Common mistakes
---------------
  • Looking in Explorer before fund — open does not create a vault.
  • Funding from the seller wallet — only the buyer funds.
  • Wrong API URL — pass the node base (…:8080), not the Explorer page.
  • Settle/refund without --with <other wallet.json> — both keys required.
  • Timeout too early — wait until media blue ≥ timeout_blue.
  • Short escrow_id — you can paste a unique prefix of the id.
  • No buyer balance / UTXO — fund fails until the buyer has coins.

Where to look next
------------------
  Explorer Escrow : #/escrow   (live vaults)
  Explorer Wallet : #/wallet   (address balance, UTXOs, vaults)
  Docs            : ESCROW.md · TUEP.md · tuep-escrow/SPEC.md
  CLI aliases     : tutorial · sketch · guide"#
    );
}

fn cmd_escrow(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[1.min(args.len())..];
    match sub {
        "help" | "-h" | "--help" => {
            print_escrow_help();
            Ok(())
        }
        "tutorial" | "sketch" | "guide" => {
            print_escrow_tutorial();
            Ok(())
        }
        "open" => escrow_open(rest),
        "fund" => escrow_fund(rest),
        "settle" => escrow_coop(rest, tuep_escrow::PayoutVector::ToSeller),
        "refund" => escrow_coop(rest, tuep_escrow::PayoutVector::ToBuyer),
        "timeout-claim" | "timeout" | "claim" => escrow_timeout(rest),
        "status" => escrow_status(rest),
        "list" => escrow_list(rest),
        "history" => escrow_history(rest),
        "vaults" => escrow_vaults(rest),
        other => Err(format!("unknown escrow subcommand '{other}' — see `escrow help`")),
    }
}

fn escrow_open(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet escrow open <SELLER> <AMOUNT> <TIMEOUT_BLUES> [MEMO] [FILE]";
    let seller = args.first().ok_or(usage)?.clone();
    let amount: u128 = args
        .get(1)
        .ok_or("missing AMOUNT")?
        .parse()
        .map_err(|_| "AMOUNT must be integer base units".to_string())?;
    let timeout_blues: u64 = args
        .get(2)
        .ok_or("missing TIMEOUT_BLUES (absolute media blue when buyer may reclaim)")?
        .parse()
        .map_err(|_| "TIMEOUT_BLUES must be u64".to_string())?;
    let memo = args.get(3).cloned().unwrap_or_default();
    // If arg3 looks like a wallet file, treat as FILE with empty memo.
    let (memo, path) = if memo.ends_with(".json") && args.get(4).is_none() {
        (String::new(), memo)
    } else {
        (
            memo,
            args.get(4)
                .cloned()
                .unwrap_or_else(|| DEFAULT_WALLET.to_string()),
        )
    };
    let w = load_wallet(&path)?;
    let status = http_get(
        args.get(5).map(|s| s.as_str()).unwrap_or(DEFAULT_API),
        "/api/v1/status",
    )
    .ok();
    let tip = status
        .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
        .and_then(|j| j["blue_score"].as_u64())
        .unwrap_or(0);
    let timeout_blue = tip.saturating_add(timeout_blues.max(1));
    let seed_hex = {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        hex::encode(b)
    };
    let terms = hassan::bdpe::terms_with_timeout(
        w.address().to_string(),
        seller,
        amount,
        timeout_blue,
        memo,
        seed_hex,
    );
    let rec = tuep_escrow::EscrowRecord::open(w.address(), terms)?;
    let mut rows = load_escrows(&path)?;
    if rows.iter().any(|r| r.escrow_id == rec.escrow_id) {
        return Err("escrow id collision — retry open".into());
    }
    println!("escrow_id     : {}", rec.escrow_id);
    println!("buyer         : {}", rec.terms.buyer);
    println!("seller        : {}", rec.terms.seller);
    println!("amount        : {}", rec.terms.amount);
    println!("timeout_blue  : {}", rec.terms.timeout_blue());
    println!("phase         : {}", rec.phase.as_str());
    rows.push(rec);
    save_escrows(&path, &rows)?;
    println!("stored in     : {}", escrow_store_path(&path));
    Ok(())
}

fn escrow_fund(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet escrow fund <ESCROW_ID> [FILE] [API]";
    let id = args.first().ok_or(usage)?;
    let path = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let api = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let w = load_wallet(path)?;
    let mut rows = load_escrows(path)?;
    let rec = find_escrow_mut(&mut rows, id)?;
    if rec.phase != tuep_escrow::EscrowPhase::Offered {
        return Err(format!("escrow phase is {} (need offered)", rec.phase.as_str()));
    }
    if w.address() != rec.terms.buyer {
        return Err("only the buyer wallet can fund".into());
    }
    let fee_floor = hassan::MIN_TX_FEE;
    let need = rec.terms.amount.saturating_add(fee_floor.saturating_mul(2));
    let (funding, funding_value) = pick_funding_utxo(api, w.address(), need)?;
    let (sk, pk) = w.export();
    let mut tx = hassan::bdpe::build_fund_tx(
        pk,
        funding,
        funding_value,
        &rec.terms,
        0,
        CHAIN_ID,
    )?;
    tx.sign(&sk)?;
    let media = tip_blue(api)?;
    let rj = submit_utxo(api, &tx)?;
    let vault_txid = hex::encode(tx.tx_hash());
    rec.apply(tuep_escrow::EscrowEvent::Funded {
        escrow_id: rec.escrow_id.clone(),
        outpoint_txid: vault_txid.clone(),
        outpoint_vout: 0,
        amount: rec.terms.amount,
        media_blue: media,
    })?;
    println!("funded escrow {}", rec.escrow_id);
    println!("vault         : {vault_txid}:0");
    println!("txid          : {}", rj["txid"].as_str().unwrap_or("?"));
    println!("phase         : {}", rec.phase.as_str());
    save_escrows(path, &rows)?;
    Ok(())
}

fn take_flag<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>, String> {
    for i in 0..args.len() {
        if args[i] == name {
            return Ok(Some(
                args.get(i + 1)
                    .map(|s| s.as_str())
                    .ok_or_else(|| format!("{name} needs a value"))?,
            ));
        }
    }
    Ok(None)
}

fn escrow_coop(args: &[String], payout: tuep_escrow::PayoutVector) -> Result<(), String> {
    let label = match payout {
        tuep_escrow::PayoutVector::ToSeller => "settle",
        tuep_escrow::PayoutVector::ToBuyer => "refund",
    };
    let usage = format!(
        "usage: hassan-wallet escrow {label} <ESCROW_ID> --with <OTHER_WALLET.json> [FILE] [API]"
    );
    let id = args.first().ok_or(usage.as_str())?;
    let other_path = take_flag(args, "--with")?.ok_or("--with <OTHER_WALLET.json> required")?;
    let path = args
        .iter()
        .skip(1)
        .find(|a| a.ends_with(".json") && a.as_str() != other_path && *a != "--with")
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_WALLET);
    let api = args
        .iter()
        .rev()
        .find(|a| a.contains(':') && !a.ends_with(".json"))
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_API);

    let primary = load_wallet(path)?;
    let other = load_wallet(other_path)?;
    let mut rows = load_escrows(path)?;
    let rec = find_escrow_mut(&mut rows, id)?;
    if rec.phase != tuep_escrow::EscrowPhase::Funded {
        return Err(format!("escrow phase is {} (need funded)", rec.phase.as_str()));
    }
    let vault = rec
        .vault
        .clone()
        .ok_or("escrow has no vault outpoint — fund first")?;
    let vault_op = hassan::bdpe::outpoint_from_hex(&vault.txid_hex, vault.vout)?;
    // Confirm vault still live and read value.
    let body = http_get(api, &format!("/api/v1/utxos/{}", rec.terms.buyer))?;
    let uj: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad utxos: {e}"))?;
    let vault_val = uj["utxos"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|u| {
            u["txid"].as_str() == Some(vault.txid_hex.as_str())
                && u["vout"].as_u64() == Some(vault.vout as u64)
        })
        .and_then(|u| u["value"].as_str()?.parse::<u128>().ok())
        .ok_or("vault UTXO not found on node (spent or not yet mined)")?;

    let (psk, ppk) = primary.export();
    let (osk, opk) = other.export();
    let media = tip_blue(api)?;
    let mut tx = hassan::bdpe::build_spend_tx(
        ppk,
        Some(opk),
        Some(&osk),
        vault_op,
        vault_val,
        &rec.terms,
        tuep_escrow::SpendPath::Coop2of2 { payout },
        media,
        0,
        CHAIN_ID,
    )?;
    tx.sign(&psk)?;
    let rj = submit_utxo(api, &tx)?;
    let spend_txid = hex::encode(tx.tx_hash());
    let to = match payout {
        tuep_escrow::PayoutVector::ToSeller => rec.terms.seller.clone(),
        tuep_escrow::PayoutVector::ToBuyer => rec.terms.buyer.clone(),
    };
    let ev = match payout {
        tuep_escrow::PayoutVector::ToSeller => tuep_escrow::EscrowEvent::CoopSettled {
            escrow_id: rec.escrow_id.clone(),
            payout,
            to,
            amount: vault_val,
            spend_txid: spend_txid.clone(),
        },
        tuep_escrow::PayoutVector::ToBuyer => tuep_escrow::EscrowEvent::CoopRefunded {
            escrow_id: rec.escrow_id.clone(),
            payout,
            to,
            amount: vault_val,
            spend_txid: spend_txid.clone(),
        },
    };
    rec.apply(ev)?;
    println!("{label} submitted");
    println!("spend_txid : {spend_txid}");
    println!("node_txid  : {}", rj["txid"].as_str().unwrap_or("?"));
    println!("phase      : {}", rec.phase.as_str());
    save_escrows(path, &rows)?;
    Ok(())
}

fn escrow_timeout(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet escrow timeout-claim <ESCROW_ID> [FILE] [API]";
    let id = args.first().ok_or(usage)?;
    let path = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let api = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let w = load_wallet(path)?;
    let mut rows = load_escrows(path)?;
    let rec = find_escrow_mut(&mut rows, id)?;
    if rec.phase != tuep_escrow::EscrowPhase::Funded {
        return Err(format!("escrow phase is {} (need funded)", rec.phase.as_str()));
    }
    if w.address() != rec.terms.buyer {
        return Err("only the buyer can timeout-claim".into());
    }
    let vault = rec
        .vault
        .clone()
        .ok_or("escrow has no vault outpoint")?;
    let vault_op = hassan::bdpe::outpoint_from_hex(&vault.txid_hex, vault.vout)?;
    let body = http_get(api, &format!("/api/v1/utxos/{}", rec.terms.buyer))?;
    let uj: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad utxos: {e}"))?;
    let vault_val = uj["utxos"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|u| {
            u["txid"].as_str() == Some(vault.txid_hex.as_str())
                && u["vout"].as_u64() == Some(vault.vout as u64)
        })
        .and_then(|u| u["value"].as_str()?.parse::<u128>().ok())
        .ok_or("vault UTXO not found on node")?;
    let media = tip_blue(api)?;
    let (sk, pk) = w.export();
    let mut tx = hassan::bdpe::build_spend_tx(
        pk,
        None,
        None,
        vault_op,
        vault_val,
        &rec.terms,
        tuep_escrow::SpendPath::TimeoutBuyer,
        media,
        0,
        CHAIN_ID,
    )?;
    tx.sign(&sk)?;
    let rj = submit_utxo(api, &tx)?;
    let spend_txid = hex::encode(tx.tx_hash());
    rec.apply(tuep_escrow::EscrowEvent::TimeoutClaimed {
        escrow_id: rec.escrow_id.clone(),
        payout: tuep_escrow::PayoutVector::ToBuyer,
        to: rec.terms.buyer.clone(),
        amount: vault_val,
        spend_txid: spend_txid.clone(),
        media_blue: media,
    })?;
    println!("timeout-claim submitted");
    println!("spend_txid : {spend_txid}");
    println!("node_txid  : {}", rj["txid"].as_str().unwrap_or("?"));
    println!("phase      : {}", rec.phase.as_str());
    save_escrows(path, &rows)?;
    Ok(())
}

fn escrow_status(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet escrow status <ESCROW_ID> [FILE] [API]";
    let id = args.first().ok_or(usage)?;
    let path = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let api = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_API);
    let rows = load_escrows(path)?;
    let rec = rows
        .iter()
        .find(|r| r.escrow_id == *id || r.escrow_id.starts_with(id.as_str()))
        .ok_or_else(|| format!("escrow not found: {id}"))?;
    let media = tip_blue(api).unwrap_or(0);
    println!("escrow_id    : {}", rec.escrow_id);
    println!("phase        : {}", rec.phase.as_str());
    println!("buyer        : {}", rec.terms.buyer);
    println!("seller       : {}", rec.terms.seller);
    println!("amount       : {}", rec.terms.amount);
    println!("timeout_blue : {}", rec.terms.timeout_blue());
    println!("media_blue   : {media}");
    println!(
        "timeout_ok   : {}",
        rec.terms.clock.reached(media)
    );
    if let Some(v) = &rec.vault {
        println!("vault        : {}:{}", v.txid_hex, v.vout);
    }
    println!("events       : {}", rec.history.len());
    Ok(())
}

fn escrow_list(args: &[String]) -> Result<(), String> {
    let path = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let rows = load_escrows(path)?;
    println!("escrows: {} ({})", rows.len(), escrow_store_path(path));
    for r in rows {
        println!(
            "  {}  {}  {} → {}  amount={}",
            &r.escrow_id[..16.min(r.escrow_id.len())],
            r.phase.as_str(),
            r.terms.buyer,
            r.terms.seller,
            r.terms.amount
        );
    }
    Ok(())
}

fn escrow_history(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-wallet escrow history <ESCROW_ID> [FILE]";
    let id = args.first().ok_or(usage)?;
    let path = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_WALLET);
    let rows = load_escrows(path)?;
    let rec = rows
        .iter()
        .find(|r| r.escrow_id == *id || r.escrow_id.starts_with(id.as_str()))
        .ok_or_else(|| format!("escrow not found: {id}"))?;
    for ev in &rec.history {
        println!("{}", serde_json::to_string(ev).unwrap_or_default());
    }
    Ok(())
}

fn escrow_vaults(args: &[String]) -> Result<(), String> {
    let (addr, api) = match args.len() {
        0 => (None, DEFAULT_API),
        1 if args[0].contains(':') && !args[0].starts_with("hsn") => (None, args[0].as_str()),
        1 => (Some(args[0].as_str()), DEFAULT_API),
        _ => (Some(args[0].as_str()), args[1].as_str()),
    };
    let path = match addr {
        Some(a) => format!("/api/v1/bdpe/vaults?address={a}"),
        None => "/api/v1/bdpe/vaults".to_string(),
    };
    let body = http_get(api, &path)?;
    let j: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad response: {e}"))?;
    let arr = j.as_array().cloned().unwrap_or_default();
    println!("bdpe vaults: {}", arr.len());
    for v in arr {
        println!(
            "  {}:{}  value={}  buyer={}  seller={}  timeout_blue={}  status={}",
            v["txid"].as_str().unwrap_or("?"),
            v["vout"].as_u64().unwrap_or(0),
            v["value"].as_str().unwrap_or("?"),
            v["buyer"].as_str().unwrap_or("?"),
            v["seller"].as_str().unwrap_or("?"),
            v["timeout_blue"].as_u64().unwrap_or(0),
            v["status"]
                .as_str()
                .unwrap_or(if v["timeout_reached"].as_bool().unwrap_or(false) {
                    "claimable"
                } else {
                    "funded"
                })
        );
    }
    Ok(())
}

fn send_at_fresh_nonce(
    to: &str,
    amount: u128,
    fee: Option<u128>,
    path: &str,
    api: &str,
) -> Result<(), String> {
    let w = load_wallet(path)?;
    // Fetch the sender's current on-chain nonce from the node.
    let acct = http_get(api, &format!("/api/v1/account/{}", w.address()))?;
    let aj: serde_json::Value =
        serde_json::from_str(&acct).map_err(|e| format!("bad node response: {e}"))?;
    let nonce = aj["nonce"].as_u64().unwrap_or(0);
    let fee = fee.unwrap_or(0); // 0 → wallet bumps to size-priced min
    submit_transfer(&w, to, amount, fee, nonce, api, "transfer")
}

fn submit_transfer(
    w: &Wallet,
    to: &str,
    amount: u128,
    fee: u128,
    nonce: u64,
    api: &str,
    label: &str,
) -> Result<(), String> {
    let tx = w.create_transfer_with_fee(to.to_string(), amount, fee, nonce, CHAIN_ID)?;
    let (_sk, pk) = w.export();
    // NOTE: `TxSubmitRequest.amount`/`.fee` are plain `u128` fields (derived
    // Deserialize), so they must be raw JSON numbers here, not strings —
    // unlike `/api/v1/tx/transfer`'s handler, which parses either.
    let payload = serde_json::json!({
        "from_pubkey": hex::encode(pk),
        "to": to,
        "amount": amount,
        "fee": fee,
        "nonce": nonce,
        "chain_id": CHAIN_ID,
        "signature": hex::encode(&tx.signature),
    })
    .to_string();

    let resp = http_post(api, "/api/v1/tx/submit", &payload)?;
    let rj: serde_json::Value =
        serde_json::from_str(&resp).map_err(|e| format!("bad node response: {e}"))?;
    if let Some(err) = rj["error"].as_str() {
        return Err(format!("node rejected {label}: {err}"));
    }
    println!("✅ {label} submitted");
    println!("   from  : {}", w.address());
    println!("   to    : {to}");
    println!("   amount: {amount}");
    println!("   fee   : {fee}");
    println!("   nonce : {nonce}");
    if let Some(h) = rj["tx_hash"].as_str() {
        println!("   tx    : {h}");
    }
    Ok(())
}

// ===== Minimal raw-HTTP client (no dependency; matches the node's plain API) =====

fn host_port(api: &str) -> String {
    api.trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

fn http_get(api: &str, path: &str) -> Result<String, String> {
    let hp = host_port(api);
    let mut stream =
        TcpStream::connect(&hp).map_err(|e| format!("connect {hp}: {e} (is the node running?)"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {hp}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    read_body(&mut stream)
}

fn http_post(api: &str, path: &str, body: &str) -> Result<String, String> {
    let hp = host_port(api);
    let mut stream =
        TcpStream::connect(&hp).map_err(|e| format!("connect {hp}: {e} (is the node running?)"))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hp}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    read_body(&mut stream)
}

fn read_body(stream: &mut TcpStream) -> Result<String, String> {
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| e.to_string())?;
    resp.split("\r\n\r\n")
        .nth(1)
        .map(|s| s.to_string())
        .ok_or_else(|| "empty node response".into())
}
