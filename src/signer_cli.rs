//! `hassan-signer` — offline ML-DSA-87 key tool (create, sign, verify).
//!
//! Does not talk to the node. Compatible with `hassan-wallet` keystore JSON
//! (`HASSAN_WALLET_PASSWORD` for encrypted files).

use hassan::abs_sig::AbsSignature;
use hassan::keystore::{self, PASSWORD_ENV};
use hassan::wallet::Wallet;

const DEFAULT_KEY: &str = "signer.json";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[2.min(args.len())..];

    let result = match cmd {
        "new" | "generate" => cmd_new(rest),
        "address" | "addr" => cmd_address(rest),
        "pubkey" | "public-key" => cmd_pubkey(rest),
        "sign" => cmd_sign(rest),
        "sign-hex" => cmd_sign_hex(rest),
        "verify" => cmd_verify(rest),
        "verify-hex" => cmd_verify_hex(rest),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown command '{other}'. Run `hassan-signer help`."
        )),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "hassan-signer — offline ML-DSA-87 key + Absolute Binding Signature\n\n\
         USAGE:\n\
         \x20 hassan-signer new       [FILE]                 create keystore (default {DEFAULT_KEY})\n\
         \x20 hassan-signer address   [FILE]                 print hsn1… address\n\
         \x20 hassan-signer pubkey    [FILE]                 print public key hex\n\
         \x20 hassan-signer sign      <DOMAIN> <MESSAGE> [FILE]\n\
         \x20                                              sign UTF-8 message; print ABS JSON\n\
         \x20 hassan-signer sign-hex  <DOMAIN> <HEX> [FILE]  sign raw bytes (hex)\n\
         \x20 hassan-signer verify    <DOMAIN> <MESSAGE> <SIG.json>\n\
         \x20                                              verify ABS JSON against UTF-8 message\n\
         \x20 hassan-signer verify-hex <DOMAIN> <HEX> <SIG.json>\n\
         \x20                                              verify ABS JSON against raw hex bytes\n\n\
         ENCRYPTION:\n\
         \x20 {PASSWORD_ENV} required for `new` (unless --insecure).\n\
         \x20 Same keystore format as hassan-wallet.\n\n\
         EXAMPLES:\n\
         \x20 {PASSWORD_ENV}='secret' hassan-signer new keys.json\n\
         \x20 {PASSWORD_ENV}='secret' hassan-signer sign hassan-doc \"hello\" keys.json > sig.json\n\
         \x20 hassan-signer verify hassan-doc \"hello\" sig.json\n"
    );
}

fn cmd_new(args: &[String]) -> Result<(), String> {
    let mut allow_plaintext = false;
    let mut path = DEFAULT_KEY.to_string();
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
        return Err(format!("{path} already exists — refusing to overwrite"));
    }
    if !allow_plaintext && keystore::password_from_env().is_none() {
        return Err(format!(
            "set {PASSWORD_ENV} to encrypt the keystore, or pass --insecure for plaintext"
        ));
    }
    let w = Wallet::generate();
    let encrypted = keystore::save_wallet(&path, &w, allow_plaintext)?;
    println!("created : {path}");
    println!("address : {}", w.address());
    println!(
        "storage : {}",
        if encrypted {
            "encrypted (Argon2id + ChaCha20-Poly1305)"
        } else {
            "PLAINTEXT (--insecure)"
        }
    );
    Ok(())
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let path = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_KEY);
    let w = keystore::load_wallet(path)?;
    println!("{}", w.address());
    Ok(())
}

fn cmd_pubkey(args: &[String]) -> Result<(), String> {
    let path = args.first().map(|s| s.as_str()).unwrap_or(DEFAULT_KEY);
    let w = keystore::load_wallet(path)?;
    println!("{}", hex::encode(w.public_key()));
    Ok(())
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-signer sign <DOMAIN> <MESSAGE> [FILE]";
    let domain = args.first().ok_or(usage)?;
    let message = args.get(1).ok_or(usage)?;
    let path = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_KEY);
    let w = keystore::load_wallet(path)?;
    let (sk, pk) = w.export();
    let abs = AbsSignature::sign(domain.as_bytes(), message.as_bytes(), &sk, &pk)?;
    println!("{}", serde_json::to_string_pretty(&abs).map_err(|e| e.to_string())?);
    Ok(())
}

fn cmd_sign_hex(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-signer sign-hex <DOMAIN> <HEX> [FILE]";
    let domain = args.first().ok_or(usage)?;
    let hex_msg = args.get(1).ok_or(usage)?;
    let path = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_KEY);
    let msg = hex::decode(hex_msg.trim()).map_err(|_| "bad message hex")?;
    let w = keystore::load_wallet(path)?;
    let (sk, pk) = w.export();
    let abs = AbsSignature::sign(domain.as_bytes(), &msg, &sk, &pk)?;
    println!("{}", serde_json::to_string_pretty(&abs).map_err(|e| e.to_string())?);
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-signer verify <DOMAIN> <MESSAGE> <SIG.json>";
    let domain = args.first().ok_or(usage)?;
    let message = args.get(1).ok_or(usage)?;
    let sig_path = args.get(2).ok_or(usage)?;
    verify_abs(domain.as_bytes(), message.as_bytes(), sig_path)
}

fn cmd_verify_hex(args: &[String]) -> Result<(), String> {
    let usage = "usage: hassan-signer verify-hex <DOMAIN> <HEX> <SIG.json>";
    let domain = args.first().ok_or(usage)?;
    let hex_msg = args.get(1).ok_or(usage)?;
    let sig_path = args.get(2).ok_or(usage)?;
    let msg = hex::decode(hex_msg.trim()).map_err(|_| "bad message hex")?;
    verify_abs(domain.as_bytes(), &msg, sig_path)
}

fn verify_abs(domain: &[u8], message: &[u8], sig_path: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(sig_path).map_err(|e| format!("read {sig_path}: {e}"))?;
    let abs: AbsSignature =
        serde_json::from_str(&raw).map_err(|e| format!("parse signature JSON: {e}"))?;
    if abs.verify(domain, message) {
        println!("OK — signature valid");
        let pk = hex::decode(&abs.public_key).map_err(|_| "bad pubkey in sig")?;
        println!("address : {}", hassan::hash_to_address(&pk));
        Ok(())
    } else {
        Err("signature INVALID".into())
    }
}
