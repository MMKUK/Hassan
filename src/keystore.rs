//! Encrypted keystore helpers (Argon2id + ChaCha20-Poly1305).
//! Shared by `hassan-wallet` and `hassan-signer`.

use crate::wallet::Wallet;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;

pub const PASSWORD_ENV: &str = "HASSAN_WALLET_PASSWORD";

const M_COST_KIB: u32 = 65_536; // 64 MiB
const T_COST: u32 = 3;
const P_COST: u32 = 1;

pub fn password_from_env() -> Option<String> {
    match std::env::var(PASSWORD_ENV) {
        Ok(p) if !p.is_empty() => Some(p),
        _ => None,
    }
}

fn derive_key(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| format!("argon2 params: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2 kdf: {e}"))?;
    Ok(key)
}

pub fn encrypt(password: &str, secret: &[u8]) -> serde_json::Value {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = derive_key(password, &salt, M_COST_KIB, T_COST, P_COST).expect("argon2 derive");
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), secret)
        .expect("chacha20poly1305 encrypt");

    serde_json::json!({
        "kdf": "argon2id",
        "argon2": { "v": 19, "m_cost": M_COST_KIB, "t_cost": T_COST, "p_cost": P_COST },
        "cipher": "chacha20poly1305",
        "salt": hex::encode(salt),
        "nonce": hex::encode(nonce),
        "ciphertext": hex::encode(&ct),
    })
}

pub fn decrypt(password: &str, c: &serde_json::Value) -> Result<Vec<u8>, String> {
    if c["kdf"].as_str() != Some("argon2id") {
        return Err("unsupported keystore KDF (expected argon2id)".into());
    }
    if c["cipher"].as_str() != Some("chacha20poly1305") {
        return Err("unsupported keystore cipher".into());
    }
    let m_cost = c["argon2"]["m_cost"].as_u64().unwrap_or(M_COST_KIB as u64) as u32;
    let t_cost = c["argon2"]["t_cost"].as_u64().unwrap_or(T_COST as u64) as u32;
    let p_cost = c["argon2"]["p_cost"].as_u64().unwrap_or(P_COST as u64) as u32;
    if m_cost > 1_048_576 {
        return Err("keystore argon2 m_cost too large (> 1 GiB)".into());
    }
    if t_cost > 16 || p_cost > 16 {
        return Err("keystore argon2 t_cost/p_cost too large (> 16)".into());
    }

    let salt = hex::decode(c["salt"].as_str().unwrap_or("")).map_err(|_| "bad salt")?;
    let nonce = hex::decode(c["nonce"].as_str().unwrap_or("")).map_err(|_| "bad nonce")?;
    if nonce.len() != 12 {
        return Err("bad nonce length".into());
    }
    let ct = hex::decode(c["ciphertext"].as_str().unwrap_or("")).map_err(|_| "bad ciphertext")?;

    let key = derive_key(password, &salt, m_cost, t_cost, p_cost)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| "bad key")?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| "wrong password or corrupt keystore (authentication failed)".into())
}

/// Save wallet JSON (encrypted if `HASSAN_WALLET_PASSWORD` set, else plaintext only with allow).
pub fn save_wallet(path: &str, w: &Wallet, allow_plaintext: bool) -> Result<bool, String> {
    let (sk, pk) = w.export();
    let mut json = serde_json::json!({
        "version": 2,
        "address": w.address(),
        "public_key": hex::encode(&pk),
    });
    let encrypted = if let Some(pw) = password_from_env() {
        json["crypto"] = encrypt(&pw, &sk);
        true
    } else if allow_plaintext {
        json["secret_key"] = serde_json::Value::String(hex::encode(&sk));
        false
    } else {
        return Err(format!(
            "refusing plaintext keystore — set {PASSWORD_ENV}, or pass --insecure"
        ));
    };
    write_keystore(path, &json)?;
    Ok(encrypted)
}

fn write_keystore(path: &str, json: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_string_pretty(json).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("write {path}: {e}"))?;
        f.write_all(bytes.as_bytes())
            .map_err(|e| format!("write {path}: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| format!("write {path}: {e}"))?;
    }
    Ok(())
}

/// Load wallet from encrypted or plaintext keystore JSON.
pub fn load_wallet(path: &str) -> Result<Wallet, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("read {path}: {e} (run `hassan-wallet new`?)"))?;
    let j: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&bytes))
        .map_err(|e| format!("parse {path}: {e}"))?;
    let pk =
        hex::decode(j["public_key"].as_str().unwrap_or("")).map_err(|_| "bad public_key hex")?;

    let sk = if j.get("crypto").is_some() {
        let pw = password_from_env()
            .ok_or_else(|| format!("{path} is encrypted — set {PASSWORD_ENV} to unlock it"))?;
        decrypt(&pw, &j["crypto"])?
    } else {
        hex::decode(j["secret_key"].as_str().unwrap_or("")).map_err(|_| "bad secret_key hex")?
    };
    Wallet::import(sk, pk)
}
