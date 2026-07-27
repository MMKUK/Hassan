//! Node role CLI — archive / validator / light profiles + public lock.
//!
//! Defaults (all roles unless `--clearnet` or `--public`):
//! - HTTP API on loopback only
//! - Tor-only outbound P2P (SOCKS5); dial known peers, no clearnet listen
//! - Peer pin strict mode when `HASSAN_PEER_PINS` is set
//!
//! `--public` locks ops for open-internet peers: `HASSAN_PUBLIC=1`, explicit
//! `HASSAN_API_TOKEN`, clearnet P2P, refuses soft/lab overrides.

use std::env;
use std::process;

/// Which storage / work profile this process runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// Full history; pruning off.
    Archive,
    /// Pruned validator (default cheap node).
    Validator,
    /// Light miner profile (pruned, no indexer); future: true light client.
    Light,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Validator => "validator",
            Self::Light => "light",
        }
    }
}

/// Parsed CLI + effective operator profile.
#[derive(Clone, Debug)]
pub struct NodeProfile {
    pub role: NodeRole,
    /// Keep all bodies/headers (archive only).
    pub archival: bool,
    /// Run explorer indexer thread.
    pub enable_indexer: bool,
    /// Register solo miner + produce blocks.
    pub enable_mining: bool,
    /// Force Tor SOCKS for P2P dials; refuse clearnet listen.
    pub tor_only: bool,
    /// Ops hard-mode for open-internet peers (`HASSAN_PUBLIC=1`).
    pub public_lock: bool,
    /// Optional clearnet/Tor P2P listen bind (only when `!tor_only` or loopback).
    pub p2p_listen: Option<String>,
    /// Peers to dial (`host:port` or `.onion:port`).
    pub peers: Vec<String>,
    pub data_dir: Option<String>,
    pub api_bind: Option<String>,
}

impl NodeProfile {
    pub fn print_banner(&self) {
        let p2p = if self.public_lock && !self.tor_only {
            "clearnet (public lock)"
        } else if self.tor_only {
            "Tor-only dial (+ peer pins when configured)"
        } else {
            "clearnet allowed (--clearnet)"
        };
        println!(
            "Node role: {} · API lock: loopback default · P2P: {}{}",
            self.role.as_str(),
            p2p,
            if self.public_lock {
                " · PUBLIC LOCK on"
            } else {
                ""
            }
        );
        match self.role {
            NodeRole::Archive => println!(
                "  archive — full history on disk; suited to a seed / IBD helper on a normal machine"
            ),
            NodeRole::Validator => println!(
                "  validator — pruned DAG; suited to ordinary cheap VPS / laptop validators"
            ),
            NodeRole::Light => println!(
                "  light — pruned + mine, indexer off (cheapest CPU box today). \
                 True headers-only / mobile light client is a future release."
            ),
        }
        if self.public_lock {
            println!(
                "  public lock — explicit API token required; unauth writes / relax-net / bootstrap-easy refused"
            );
        }
    }

    /// Apply profile defaults into the process environment before `NetPolicy::from_env`.
    pub fn apply_env(&self) {
        if let Some(ref d) = self.data_dir {
            env::set_var("HASSAN_DATA_DIR", d);
        }
        if let Some(ref b) = self.api_bind {
            env::set_var("HASSAN_API_BIND", b);
        } else if env::var_os("HASSAN_API_BIND").is_none() {
            // Locked-down default: never LAN-expose API by accident.
            env::set_var("HASSAN_API_BIND", "127.0.0.1:8080");
        }

        if self.archival {
            env::set_var("HASSAN_ARCHIVAL", "1");
        } else if env::var_os("HASSAN_ARCHIVAL").is_none() {
            env::set_var("HASSAN_ARCHIVAL", "0");
        }

        if self.public_lock {
            env::set_var("HASSAN_PUBLIC", "1");
            env::set_var("HASSAN_STRICT_DIALS", "1");
            // Public seeds need a listen address.
            if self.p2p_listen.is_none() && env::var_os("HASSAN_P2P_LISTEN").is_none() {
                eprintln!(
                    "FATAL: --public requires --listen <addr> (e.g. 0.0.0.0:9333) \
                     or HASSAN_P2P_LISTEN"
                );
                process::exit(1);
            }
        }

        if self.tor_only {
            if env::var_os("HASSAN_TOR").is_none() {
                env::set_var("HASSAN_TOR", "1");
            }
            if env::var_os("HASSAN_PEER_PINS").is_some()
                && env::var_os("HASSAN_PEER_PINS_STRICT").is_none()
            {
                env::set_var("HASSAN_PEER_PINS_STRICT", "1");
            }
        }

        if !self.peers.is_empty() && env::var_os("HASSAN_P2P_PEERS").is_none() {
            env::set_var("HASSAN_P2P_PEERS", self.peers.join(","));
        }
        if let Some(ref listen) = self.p2p_listen {
            if self.tor_only && !is_loopback_bind(listen) {
                eprintln!(
                    "Tor-only profile refuses clearnet P2P listen `{listen}`. \
                     Use --clearnet or --public, or omit --listen and dial .onion peers."
                );
                process::exit(1);
            }
            env::set_var("HASSAN_P2P_LISTEN", listen);
        } else if self.tor_only {
            if let Ok(l) = env::var("HASSAN_P2P_LISTEN") {
                if !is_loopback_bind(&l) {
                    eprintln!(
                        "Tor-only: ignoring non-loopback HASSAN_P2P_LISTEN={l} \
                         (dial known peers only). Pass --clearnet or --public to listen."
                    );
                    env::remove_var("HASSAN_P2P_LISTEN");
                }
            }
        }
    }
}

fn is_loopback_bind(addr: &str) -> bool {
    let host = addr.split(':').next().unwrap_or(addr);
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn print_help() {
    println!(
        r#"Hassan node

USAGE:
  hassan <role> [options]
  hassan                  # same as: hassan validator

ROLES (cheap machines):
  archive      Full history (no prune). Seed / IBD helper.
  validator    Pruned validating node (default). Ordinary VPS / laptop.
  light        Cheapest mine-focused profile today (pruned, no indexer).
               Headers-only / mobile light client = future release.

DEFAULT SAFETY (roles without --public):
  • HTTP API bound to 127.0.0.1 (override with --api-bind)
  • Write routes need a token (ephemeral if HASSAN_API_TOKEN unset)
  • P2P Tor-only dials; no clearnet listen
  • When HASSAN_PEER_PINS is set, strict pin checks turn on

PUBLIC LOCK (--public):
  • Sets HASSAN_PUBLIC=1 (strict dials, tighter budgets)
  • Requires explicit HASSAN_API_TOKEN (no ephemeral)
  • Refuses HASSAN_ALLOW_UNAUTH_WRITES / HASSAN_RELAX_NET / HASSAN_BOOTSTRAP_EASY
  • Implies clearnet P2P; requires --listen (or HASSAN_P2P_LISTEN)
  • API still defaults to loopback — set --api-bind only if you intend remote HTTP

OPTIONS:
  --public             Ops hard-lock for open-internet peers (see above)
  --clearnet           Allow clearnet P2P without full public lock
  --listen <addr>      P2P listen bind (e.g. 0.0.0.0:9333)
  --peer <addr>        Dial peer (repeatable)
  --data-dir <path>    Chainstate directory (default ./hassan-data)
  --api-bind <addr>    HTTP API bind (default 127.0.0.1:8080)
  --no-mine            Do not run the local solo producer
  -h, --help           Show this help

ENV (still honored):
  HASSAN_TOR / HASSAN_TOR_PROXY   Tor SOCKS
  HASSAN_PEER_PINS[_STRICT]       Out-of-band peer identity pins
  HASSAN_API_TOKEN                Bearer for write / mining / stratum HTTP
  HASSAN_P2P_PEER / HASSAN_P2P_PEERS
  HASSAN_STRATUM_PASSWORD         Required for stratum submits

EXAMPLES:
  hassan validator --peer abcdef.onion:9333
  hassan archive --data-dir ./hassan-archive
  hassan archive --public --listen 0.0.0.0:9333
  hassan validator --public --listen 0.0.0.0:9333 --peer SEED:9333
"#
    );
}

/// Parse `std::env::args()`. Exits on help / bad usage.
pub fn parse_args<I, S>(raw: I) -> NodeProfile
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args: Vec<String> = raw.into_iter().map(|s| s.as_ref().to_string()).collect();
    if !args.is_empty() {
        args.remove(0); // argv0
    }

    if args
        .iter()
        .any(|a| a == "-h" || a == "--help" || a == "help")
    {
        print_help();
        process::exit(0);
    }

    let mut role = NodeRole::Validator;
    let mut idx = 0usize;
    if let Some(first) = args.first().map(|s| s.as_str()) {
        match first {
            "archive" | "full" => {
                role = NodeRole::Archive;
                idx = 1;
            }
            "validator" | "prune" | "pruned" => {
                role = NodeRole::Validator;
                idx = 1;
            }
            "light" | "lite" | "miner" => {
                role = NodeRole::Light;
                idx = 1;
            }
            s if s.starts_with('-') => {}
            other => {
                eprintln!("Unknown role `{other}`. Try: hassan --help");
                process::exit(2);
            }
        }
    }

    let mut clearnet = false;
    let mut public_lock = false;
    let mut p2p_listen = None;
    let mut peers = Vec::new();
    let mut data_dir = None;
    let mut api_bind = None;
    let mut enable_mining = true;

    while idx < args.len() {
        match args[idx].as_str() {
            "--public" => {
                public_lock = true;
                clearnet = true; // public peers need clearnet listen/dial
                idx += 1;
            }
            "--clearnet" => {
                clearnet = true;
                idx += 1;
            }
            "--no-mine" => {
                enable_mining = false;
                idx += 1;
            }
            "--listen" => {
                idx += 1;
                let v = args.get(idx).cloned().unwrap_or_else(|| {
                    eprintln!("--listen needs an address");
                    process::exit(2);
                });
                p2p_listen = Some(v);
                idx += 1;
            }
            "--peer" => {
                idx += 1;
                let v = args.get(idx).cloned().unwrap_or_else(|| {
                    eprintln!("--peer needs an address");
                    process::exit(2);
                });
                peers.push(v);
                idx += 1;
            }
            "--data-dir" => {
                idx += 1;
                let v = args.get(idx).cloned().unwrap_or_else(|| {
                    eprintln!("--data-dir needs a path");
                    process::exit(2);
                });
                data_dir = Some(v);
                idx += 1;
            }
            "--api-bind" => {
                idx += 1;
                let v = args.get(idx).cloned().unwrap_or_else(|| {
                    eprintln!("--api-bind needs an address");
                    process::exit(2);
                });
                api_bind = Some(v);
                idx += 1;
            }
            other => {
                eprintln!("Unknown option `{other}`. Try: hassan --help");
                process::exit(2);
            }
        }
    }

    if let Ok(one) = env::var("HASSAN_P2P_PEER") {
        if !one.trim().is_empty() && !peers.iter().any(|p| p == &one) {
            peers.push(one);
        }
    }
    if let Ok(many) = env::var("HASSAN_P2P_PEERS") {
        for p in many.split([',', ';', ' ']) {
            let p = p.trim();
            if !p.is_empty() && !peers.iter().any(|x| x == p) {
                peers.push(p.to_string());
            }
        }
    }

    // Env can also request public lock without the CLI flag.
    if env_flag("HASSAN_PUBLIC") {
        public_lock = true;
        clearnet = true;
    }

    let (archival, enable_indexer) = match role {
        NodeRole::Archive => (true, true),
        NodeRole::Validator => (false, true),
        NodeRole::Light => (false, false),
    };

    NodeProfile {
        role,
        archival,
        enable_indexer,
        enable_mining,
        tor_only: !clearnet,
        public_lock,
        p2p_listen,
        peers,
        data_dir,
        api_bind,
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_validator_tor_only() {
        let p = parse_args(["hassan"]);
        assert_eq!(p.role, NodeRole::Validator);
        assert!(p.tor_only);
        assert!(!p.public_lock);
        assert!(!p.archival);
        assert!(p.enable_indexer);
    }

    #[test]
    fn archive_and_light() {
        let a = parse_args(["hassan", "archive"]);
        assert!(a.archival);
        let l = parse_args(["hassan", "light", "--peer", "x.onion:9333"]);
        assert_eq!(l.role, NodeRole::Light);
        assert!(!l.enable_indexer);
        assert_eq!(l.peers, vec!["x.onion:9333".to_string()]);
    }

    #[test]
    fn clearnet_flag() {
        let p = parse_args(["hassan", "validator", "--clearnet", "--listen", "0.0.0.0:9333"]);
        assert!(!p.tor_only);
        assert_eq!(p.p2p_listen.as_deref(), Some("0.0.0.0:9333"));
    }

    #[test]
    fn public_lock_implies_clearnet() {
        let p = parse_args([
            "hassan",
            "archive",
            "--public",
            "--listen",
            "0.0.0.0:9333",
        ]);
        assert!(p.public_lock);
        assert!(!p.tor_only);
        assert!(p.archival);
    }
}
