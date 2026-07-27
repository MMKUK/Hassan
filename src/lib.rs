use blake3::Hasher as Blake3Hasher;
use fips204::ml_dsa_87::{self, PrivateKey, PublicKey};
use fips204::traits::{SerDes, Signer as PqSigner, Verifier as PqVerifier, KeyGen};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

pub mod addrman;
pub mod address;
pub mod assurance;
pub mod assume_valid;
pub mod bdpe;
pub mod genesis;
pub mod hd;
pub mod kernel;
pub mod keystore;
pub mod net_policy;
pub mod node_role;
pub mod peer_pin;
pub mod predicate;
pub mod stratum;
pub mod superproof;
pub mod utxo;
pub mod utxo_tx;
pub mod versionbits;

pub const HASH_SIZE: usize = 64; // 512-bit digests everywhere (Blake3 XOF)
/// Magic bytes prefixing a persisted chain-state file, so a foreign/corrupt file
/// is rejected cleanly.
pub const STATE_MAGIC: [u8; 8] = *b"HASSANST";
/// Max bytes for a persisted chainstate bincode payload (corrupt-file / DoS bound).
pub const MAX_CHAINSTATE_BYTES: u64 = 512 * 1024 * 1024;
/// Trailing Blake3-512 integrity tag length after magic+version+payload.
pub const STATE_CHECKSUM_LEN: usize = HASH_SIZE;

// Canonical monetary + consensus parameters (see `genesis.toml` / `genesis.rs`).
pub use genesis::{
    block_subsidy, cumulative_issuance, effective_min_difficulty, era_min_difficulty, lab_easy_pow,
    BLOCK_REWARD, BLOCK_REWARD_COINS, BLOCK_TIME_MS, BOOTSTRAP_ERA_END, BOOTSTRAP_EASY_ENV,
    BOOTSTRAP_MIN_DIFFICULTY, CHAIN_ID,
    COIN, DAA_WINDOW, DAA_WINDOW_CONSENSUS, DUST_THRESHOLD, FINALITY_DEPTH,
    FINALITY_DEPTH_CONSENSUS, FOUNDER, GENESIS_DIFFICULTY, GENESIS_DOMAIN, GENESIS_TIMESTAMP_MS,
    HALVING_INTERVAL, HARD_ERA_MIN_DIFFICULTY, LAB_EASY_DIFFICULTY, MAX_BLOCK_BYTES,
    MAX_BLOCK_PARENTS, MAX_BLOCK_SIZE, MAX_FUTURE_DRIFT_MS, MAX_MEMPOOL_BYTES,
    MAX_MEMPOOL_PACKAGE_NONCES, MAX_MEMPOOL_SIZE, MAX_MERGESET_SIZE, MAX_SUPPLY, MAX_SUPPLY_COINS,
    MAX_UTXO_PACKAGE_BYTES, MAX_UTXO_PACKAGE_COUNT, MIN_DIFFICULTY, MIN_FEE_PER_BYTE, MIN_TX_FEE,
    PRUNING_DEPTH, PRUNING_DEPTH_CONSENSUS, PRUNING_PROOF_RECENT_WINDOW, SLOGAN,
    STATE_FORMAT_VERSION, TARGET_BLOCK_TIME_MS, TOTAL_SUPPLY, ACCOUNT_PEER_TRANSFERS,
};

/// ML-DSA-87 (FIPS 204) key/signature sizes, re-exported so callers don't
/// need to depend on `fips204` directly to size buffers.
/// ML-DSA-87 (FIPS 204) key/signature sizes — highest Dilithium parameter set.
pub const PQ_PUBLIC_KEY_SIZE: usize = ml_dsa_87::PK_LEN;
pub const PQ_SECRET_KEY_SIZE: usize = ml_dsa_87::SK_LEN;
pub const PQ_SIGNATURE_SIZE: usize = ml_dsa_87::SIG_LEN;
/// All PQ signatures are over a Blake3-512 digest (512-bit security prehash).
pub const PQ_DIGEST_BITS: u32 = 512;

/// 512-bit consensus digest. Newtype so we get `Default` / `Serialize` /
/// `Deserialize` — plain `[u8; 64]` is not supported by serde (or this
/// toolchain's `Default`) beyond length 32.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 64]);

const _: () = assert!(HASH_SIZE == 64);

impl Hash {
    pub const ZERO: Self = Self([0u8; 64]);
    pub const MAX: Self = Self([0xff; 64]);

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::ZERO
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Hash {
    type Target = [u8; 64];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<[u8; 64]> for Hash {
    fn from(value: [u8; 64]) -> Self {
        Self(value)
    }
}

impl From<Hash> for [u8; 64] {
    fn from(value: Hash) -> Self {
        value.0
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = std::array::TryFromSliceError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 64] = value.try_into()?;
        Ok(Self(arr))
    }
}

impl Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(64)?;
        for byte in &self.0 {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVisitor;
        impl<'de> serde::de::Visitor<'de> for HashVisitor {
            type Value = Hash;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a 64-byte (512-bit) hash")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Hash, A::Error> {
                let mut bytes = [0u8; 64];
                for (i, slot) in bytes.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Hash(bytes))
            }
        }
        deserializer.deserialize_tuple(64, HashVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub timestamp: u64,
    pub parents: Vec<Hash>,
    /// NIPoPoW/FlyClient-style skip-link vector: `interlinks[L]` is the hash of
    /// the nearest strict ancestor (along this block's own selected-parent
    /// chain) that itself qualifies as a level-`L`-or-higher "superblock" (see
    /// `superproof::superblock_level`). Computed deterministically from the
    /// selected parent's own interlinks + achieved level *before* mining (it
    /// depends only on already-settled ancestor state, never on this block's
    /// own nonce), so it's safe to bind into the PoW hash like `parents` — see
    /// `Block::absorb_identity`. This is what lets `superproof` build a
    /// succinct multi-level pruning proof that skips over long, settled
    /// stretches of history instead of shipping every header (closing part of
    /// the gap vs. Kaspa's succinct pruning-point proofs). Empty for genesis.
    #[serde(default)]
    pub interlinks: Vec<Hash>,
    /// Transparent (account-model) transfers included in this block — the sole
    /// cash-movement type on Hassan. Committed to by `merkle_root`, validated and
    /// applied by `ChainState::add_block`.
    pub transparent_txs: Vec<TransparentTx>,
    /// Hybrid UTXO spends (outpoints / predicates). Committed in `merkle_root`.
    #[serde(default)]
    pub utxo_txs: Vec<utxo_tx::UtxoTx>,
    /// Title-registry & escrow operations (issue / transfer / escrow lifecycle).
    /// Fully public — every ownership change is on the glass ledger.
    #[serde(default)]
    pub registry_ops: Vec<registry::RegistryOp>,
    /// On-chain custody ops (stake lock/unlock, bridge exit/enter).
    #[serde(default)]
    pub custody_ops: Vec<custody::CustodyCertificate>,
    pub merkle_root: Hash,
    pub state_root: Hash,
    pub miner: Hash,
    /// Full ML-DSA-87 public key of the block creator. Bound into `hash()` /
    /// the Settlement ID so the creator identity is consensus-critical. Must
    /// hash to `miner`.
    #[serde(default)]
    pub creator_pubkey: Vec<u8>,
    pub nonce: u64,
    pub difficulty: u64,
    /// Soft-upgrade version bits (BIP9-class TOP bits + deployment signals).
    #[serde(default = "default_block_version")]
    pub version: u32,
    /// Extra entropy binding the UTXO coinbase outpoint (unique among siblings
    /// that share miner/parents/timestamp). Not derived from PoW nonce.
    #[serde(default)]
    pub coinbase_entropy: u64,
    pub stark_proof: Vec<u8>,
    /// ML-DSA-87 signature over the block's Settlement ID. Witness data — verified in
    /// `add_block`, stripped from the 22KB base size (like `stark_proof`).
    #[serde(default)]
    pub birth_certificate: issuance::BirthCertificate,
    pub size: usize,
}

pub fn default_block_version() -> u32 {
    versionbits::VERSIONBITS_TOP_BITS
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
    /// Blue score when this account last successfully spent (CSV media base).
    #[serde(default)]
    pub last_spend_blue: u64,
    pub code_hash: Option<Hash>,
    pub storage_root: Hash,
}

/// A snapshot of the *value* state — everything that is a deterministic function
/// of the applied transactions. The virtual (live) state is computed as a
/// `Ledger` base (finalized at the pruning point) plus a replay of the retained
/// blocks in canonical GHOSTDAG order. Two nodes with the same DAG therefore
/// compute the same state, regardless of the order blocks arrived.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub accounts: HashMap<String, Account>,
    pub minted_supply: u128,
    pub fees_burned: u128,
    pub treasury: u128,
    /// Public title deeds + escrow accounts (ownership as clear as glass).
    #[serde(default)]
    pub registry: registry::RegistryState,
    /// Coins locked in stake (debit from free balance on StakeLock).
    #[serde(default)]
    pub staked: HashMap<String, u128>,
    /// Transparent UTXO set (hybrid with account overlay for registry/custody).
    #[serde(default)]
    pub utxo: utxo::UtxoSet,
}

impl Ledger {
    /// Account-balance commitment matching [`ChainState::merkle_root`].
    pub fn merkle_root(&self) -> Hash {
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"hassan-state-root-v2");
        let mut addrs: Vec<&String> = self.accounts.keys().collect();
        addrs.sort();
        for addr in addrs {
            let acc = &self.accounts[addr];
            hasher.update(addr.as_bytes());
            hasher.update(&acc.balance.to_le_bytes());
            hasher.update(&acc.nonce.to_le_bytes());
            hasher.update(&acc.last_spend_blue.to_le_bytes());
        }
        hasher.update(self.utxo.commitment().as_bytes());
        hasher.update(&self.minted_supply.to_le_bytes());
        hasher.update(&self.fees_burned.to_le_bytes());
        let mut out = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut out);
        Hash(out)
    }
}

/// Compact wireable snapshot of the account ledger at a pruning point.
/// Verified against the pruning-point header's post-mergeset `state_root`
/// before a cold node adopts it as `base`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningPointLedger {
    pub pruning_point: Hash,
    pub ledger: Ledger,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub dag: HashMap<Hash, Block>,
    pub tips: Vec<Hash>,
    pub main_chain: Vec<Hash>,
    pub accounts: HashMap<String, Account>,
    /// Hybrid UTXO set for transparent outpoint spends.
    #[serde(default)]
    pub utxo: utxo::UtxoSet,
    pub total_supply: u128,
    /// Cumulative coins minted via block subsidies so far (circulating issuance).
    /// Block subsidies stop once this reaches `MAX_SUPPLY`.
    #[serde(default)]
    pub minted_supply: u128,
    pub block_reward: u128,
    pub difficulty: u64,
    pub chain_id: u64,
    /// Pending transparent transfers — **not** written to disk (ephemeral like
    /// BTC/Kaspa mempools). Rebuilt from P2P / API after restart.
    /// v27: peer account transfers are consensus-disabled; this vec stays empty
    /// unless `ACCOUNT_PEER_TRANSFERS` is re-enabled.
    #[serde(skip)]
    pub transparent_mempool: Vec<TransparentTx>,
    /// Pending UTXO spends — not persisted (v27 primary peer-value mempool).
    #[serde(skip)]
    pub utxo_mempool: Vec<utxo_tx::UtxoTx>,
    /// Pending title / escrow ops — not persisted.
    #[serde(skip)]
    pub registry_mempool: Vec<registry::RegistryOp>,
    /// Live title registry & escrow state (mirrored into `base.registry` on fold).
    #[serde(default)]
    pub registry: registry::RegistryState,
    /// Pending custody certificates — not persisted.
    #[serde(skip)]
    pub custody_mempool: Vec<custody::CustodyCertificate>,
    /// Coins locked in stake (mirrored into `base.staked` on fold).
    #[serde(default)]
    pub staked: HashMap<String, u128>,
    pub fees_burned: u128,
    pub treasury: u128,
    pub tor_nodes: HashSet<String>,
    /// Per-block GHOSTDAG metadata (blue score, selected parent, mergeset
    /// coloring). Keyed by block hash. `main_chain` is derived from this.
    pub ghostdag: HashMap<Hash, ghostdag::GhostdagData>,
    /// Reachability oracle: O(1) ancestor queries for GHOSTDAG coloring,
    /// replacing per-query BFS. Not serialized — rebuilt from the DAG on load.
    #[serde(skip)]
    pub reachability: reachability::Reachability,
    /// The current pruning point: the deepest selected-chain block below which
    /// all block headers, GHOSTDAG data, and reachability nodes have been
    /// discarded. `None` until the chain first grows past `PRUNING_DEPTH`. The
    /// retained DAG is rooted here; cumulative state (accounts) is kept in full
    /// and is unaffected by pruning.
    /// When true, this node keeps ALL history (no header/body pruning) so it can
    /// serve cold-start sync to brand-new peers. Set on an archival node via the
    /// `HASSAN_ARCHIVAL` env var. Not serialized — it's an operator choice per
    /// process, rebuilt on load.
    #[serde(skip)]
    pub archival: bool,
    /// The finalized value state at (below) the pruning point. The live/virtual
    /// state is `base` + a canonical-order replay of the retained blocks, so it
    /// is a deterministic function of the DAG. `base` advances (folds in the
    /// newly-finalized blocks) when the pruning point advances.
    #[serde(default)]
    pub base: Ledger,
    /// Whether `base` has captured the pre-chain (genesis) value state yet. On
    /// the first block we snapshot the then-current live state (any genesis
    /// premine / pool pre-seed set before mining) into `base`, so it survives the
    /// deterministic recompute. Set true after a load so we never re-capture.
    #[serde(default)]
    pub base_captured: bool,
    /// `base` includes the effects of exactly the canonical-order PREFIX up to
    /// and including this finality point. The live state replays the canonical
    /// suffix after it (the finality window). Tracked by hash (not blue score)
    /// because `canonical_order` isn't score-sorted — a merged block can have a
    /// lower blue score than an earlier selected-chain block, so a score cutoff
    /// could fold blocks out of canonical order and resolve a boundary-straddling
    /// conflict non-deterministically. `None` until the first finality point.
    #[serde(default)]
    pub base_frontier: Option<Hash>,
    #[serde(default)]
    pub pruning_point: Option<Hash>,
    /// Account ledger committed by the current pruning point's post-mergeset
    /// `state_root`. Served to cold peers for Kaspa-style IBD (topology proof
    /// alone is not enough). Updated when the pruning point advances or when
    /// an archival node publishes a serving PP.
    #[serde(default)]
    pub pruning_ledger: Option<Ledger>,
    /// Number of selected-chain blocks discarded off the front by pruning, so
    /// reported block height stays absolute even though `main_chain` only holds
    /// the retained suffix.
    #[serde(default)]
    pub pruned_selected_blocks: u64,
    /// Mempool-admission timestamps for [`economics::TransactionJourney`]
    /// dwell-time reporting. Best-effort explorer/economics telemetry only —
    /// not consensus state: never persisted, never affects validation.
    #[serde(skip)]
    pub tx_first_seen_ms: HashMap<Hash, u64>,
    /// Selected-tip blue score at mempool admission (for confirmation-target
    /// fee history). Best-effort, not persisted, not consensus-critical.
    #[serde(skip)]
    pub tx_first_seen_blue: HashMap<Hash, u64>,
    /// Rolling confirmation-target fee samples (Bitcoin Core–style history).
    /// Policy/API only — not consensus-critical. Persisted with chain state.
    #[serde(default)]
    pub fee_history: FeeRateHistory,
}

/// Confirmation-target distances (blue-score) for fee estimates.
/// Rough horizons analogous to Bitcoin Core short/medium/long confirm targets
/// (not a full `CBlockPolicyEstimator` bucket clone): high≈6, medium≈20, low≈100.
pub const FEE_TARGET_HIGH_BLUES: u64 = 6;
pub const FEE_TARGET_MEDIUM_BLUES: u64 = 20;
pub const FEE_TARGET_LOW_BLUES: u64 = 100;

/// One selected-chain block's fee-rate samples (fee / relay_bytes).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FeeBlockSample {
    pub blue_score: u64,
    /// Feerates of transfers included in this block (base units per relay byte).
    pub feerates: Vec<u128>,
    /// Confirmation lag in blues from first-seen (same order as `feerates`).
    /// Empty when first-seen was unknown; treated as immediate (0).
    #[serde(default)]
    pub confirm_blues: Vec<u64>,
}

/// Ring of recent block fee samples for confirmation-target estimates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRateHistory {
    pub samples: Vec<FeeBlockSample>,
    pub max_blocks: usize,
}

impl Default for FeeRateHistory {
    fn default() -> Self {
        Self {
            samples: Vec::new(),
            max_blocks: 500,
        }
    }
}

impl FeeRateHistory {
    pub fn record(&mut self, blue_score: u64, feerates: Vec<u128>, confirm_blues: Vec<u64>) {
        if feerates.is_empty() {
            return;
        }
        self.samples.push(FeeBlockSample {
            blue_score,
            feerates,
            confirm_blues,
        });
        let max = self.max_blocks.max(1);
        if self.samples.len() > max {
            let drop = self.samples.len() - max;
            self.samples.drain(0..drop);
        }
    }

    /// Estimate the *minimum* feerate (base units / byte) that historically
    /// met confirmation within `target_blues` of first-seen.
    ///
    /// Bitcoin Core–style (simplified `EstimateMedianVal` / greater-all-passed):
    /// walk unique feerates from high→low; among samples with feerate ≥ R,
    /// require ≥85% confirmed within the target; return the lowest R that
    /// still passes. Returns `None` when history has no in-window successes
    /// (caller should fall back to live mempool percentiles) — never silently
    /// ignores the target by averaging all rates.
    pub fn estimate_for_target(&self, target_blues: u64) -> Option<u128> {
        self.estimate_for_target_with_extra(target_blues, &[])
    }

    /// Same as [`estimate_for_target`], plus extra `(feerate, confirmed_in_window)`
    /// observations (e.g. mempool waiters treated as failures when lag > target).
    pub fn estimate_for_target_with_extra(
        &self,
        target_blues: u64,
        extra: &[(u128, bool)],
    ) -> Option<u128> {
        // 85% matches Bitcoin Core's mid `SUCCESS_PCT` for confTarget.
        const SUCCESS_PCT_NUM: u64 = 85;
        const SUCCESS_PCT_DEN: u64 = 100;

        let mut points: Vec<(u128, bool)> = Vec::new();
        for s in &self.samples {
            for (i, rate) in s.feerates.iter().enumerate() {
                let lag = s.confirm_blues.get(i).copied().unwrap_or(0);
                points.push((*rate, lag <= target_blues));
            }
        }
        points.extend_from_slice(extra);
        if points.is_empty() || !points.iter().any(|(_, ok)| *ok) {
            return None;
        }

        let mut rates: Vec<u128> = points.iter().map(|(r, _)| *r).collect();
        rates.sort_unstable();
        rates.dedup();

        // Greater-all-passed: high→low, keep the lowest R that still clears
        // the success threshold; stop at the first failure after a pass.
        let mut last_pass: Option<u128> = None;
        for &candidate in rates.iter().rev() {
            let mut total = 0u64;
            let mut ok = 0u64;
            for (rate, success) in &points {
                if *rate >= candidate {
                    total += 1;
                    if *success {
                        ok += 1;
                    }
                }
            }
            if total == 0 {
                continue;
            }
            // ok/total >= 85/100 ⇔ ok * 100 >= total * 85
            if ok.saturating_mul(SUCCESS_PCT_DEN) >= total.saturating_mul(SUCCESS_PCT_NUM) {
                last_pass = Some(candidate);
            } else if last_pass.is_some() {
                break;
            }
        }
        last_pass
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Miner {
    pub address: String,
    /// Full ML-DSA-87 public key (1312 bytes) — too large to fit HASH_SIZE,
    /// unlike `address`, which is just its blake3 digest.
    pub public_key: Vec<u8>,
    /// Local-only signing key used to issue Birth Certificates when this node
    /// mines. Never serialized / never sent on the wire.
    #[serde(skip)]
    pub signing_key: Option<Vec<u8>>,
    pub stake: u128,
    pub hashrate: u64,
    pub tor_address: Option<String>,
    pub is_pool: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningWork {
    pub block_template: Block,
    pub target: Hash,
    pub job_id: String,
    pub extranonce: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StratumShare {
    pub job_id: String,
    pub nonce: u64,
    pub miner: String,
    pub result: Hash,
    pub tor_proof: Option<String>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        let mut hasher = Blake3Hasher::new();
        self.absorb_identity(&mut hasher);
        let mut out = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut out);
        Hash(out)
    }

    /// A header-only copy: identical PoW-relevant fields (so `hash()` is
    /// unchanged), but with transaction bodies, STARK proofs, and birth
    /// certificates stripped. Used to build a compact pruning-point proof —
    /// `hash()` commits to `merkle_root`, not the tx bodies, so a header
    /// verifies PoW on its own.
    pub fn header_only(&self) -> Block {
        Block {
            height: self.height,
            timestamp: self.timestamp,
            parents: self.parents.clone(),
            interlinks: self.interlinks.clone(),
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: self.merkle_root,
            state_root: self.state_root,
            miner: self.miner,
            creator_pubkey: self.creator_pubkey.clone(),
            nonce: self.nonce,
            difficulty: self.difficulty,
            version: self.version,
            coinbase_entropy: self.coinbase_entropy,
            stark_proof: vec![],
            birth_certificate: issuance::BirthCertificate::default(),
            size: 0,
        }
    }

    /// The block's *base* size for the 22KB consensus cap: everything EXCEPT
    /// the block `stark_proof` and birth-certificate signature. Those are
    /// witness data — committed to and transmitted alongside the block, but
    /// deliberately outside the 22KB budget (segwit-style). They are still
    /// bound: the STARK is re-verified against the block hash, and the birth
    /// certificate is verified over the Settlement ID.
    pub fn base_size(&self) -> usize {
        let mut base = self.clone();
        base.stark_proof = Vec::new();
        base.birth_certificate = issuance::BirthCertificate::default();
        bincode::serialize(&base).unwrap_or_default().len()
    }

    pub fn verify_size(&self) -> bool {
        self.base_size() <= MAX_BLOCK_SIZE
    }

    /// The canonical commitment to this block's body (transparent transfers +
    /// registry / escrow operations, in order). `add_block` requires
    /// `merkle_root` equal this value so the body is bound to PoW.
    pub fn merkle_root(&self) -> Hash {
        if self.transparent_txs.is_empty()
            && self.utxo_txs.is_empty()
            && self.registry_ops.is_empty()
            && self.custody_ops.is_empty()
        {
            return Hash::ZERO;
        }
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"hassan-block-body-v4");
        hasher.update(&(self.transparent_txs.len() as u64).to_le_bytes());
        for tx in &self.transparent_txs {
            hasher.update(tx.tx_hash().as_slice());
        }
        hasher.update(&(self.utxo_txs.len() as u64).to_le_bytes());
        for tx in &self.utxo_txs {
            hasher.update(tx.tx_hash().as_slice());
        }
        hasher.update(&(self.registry_ops.len() as u64).to_le_bytes());
        for op in &self.registry_ops {
            hasher.update(op.op_hash().as_slice());
        }
        hasher.update(&(self.custody_ops.len() as u64).to_le_bytes());
        for op in &self.custody_ops {
            hasher.update(&custody::custody_fingerprint(op));
        }
        let mut out = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut out);
        Hash(out)
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainState {
    pub fn new() -> Self {
        let mut state = Self {
            dag: HashMap::new(),
            tips: vec![],
            main_chain: vec![],
            accounts: HashMap::new(),
            utxo: utxo::UtxoSet::default(),
            total_supply: TOTAL_SUPPLY,
            minted_supply: 0,
            block_reward: BLOCK_REWARD,
            difficulty: effective_min_difficulty(),
            chain_id: CHAIN_ID,
            transparent_mempool: vec![],
            utxo_mempool: vec![],
            registry_mempool: vec![],
            registry: registry::RegistryState::default(),
            custody_mempool: vec![],
            staked: HashMap::new(),
            fees_burned: 0,
            treasury: 0,
            tor_nodes: HashSet::new(),
            ghostdag: HashMap::new(),
            reachability: reachability::Reachability::new(),
            archival: false,
            base: Ledger::default(),
            base_captured: false,
            base_frontier: None,
            pruning_point: None,
            pruning_ledger: None,
            pruned_selected_blocks: 0,
            tx_first_seen_ms: HashMap::new(),
            tx_first_seen_blue: HashMap::new(),
            fee_history: FeeRateHistory::default(),
        };
        state.create_genesis();
        state
    }

    fn create_genesis(&mut self) {
        let genesis = genesis_block();
        let hash = genesis.hash();
        self.dag.insert(hash, genesis);
        self.tips.push(hash);
        self.main_chain.push(hash);
        self.ghostdag
            .insert(hash, ghostdag::GhostdagData::genesis());
        self.reachability.add_block(hash, None, &[], &self.dag);
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), String> {
        // Reject a block we already hold (audit L-2). Without this, re-adding the
        // same hash would overwrite its dag/ghostdag entries and append a
        // duplicate tip; the P2P layer's `have()` masks it, but the core must not
        // rely on that.
        if self.dag.contains_key(&block.hash()) {
            return Err("Block already known".into());
        }
        if !block.verify_size() {
            return Err("Block base exceeds 22KB limit".into());
        }
        // Bound total wire size (base + witness proofs) so witness data can't
        // grow without limit.
        if bincode::serialize(&block).unwrap_or_default().len() > MAX_BLOCK_BYTES {
            return Err("Block (with witness) exceeds total size limit".into());
        }

        // Bound the number of parents (anti-amplification-DoS): a tiny block
        // must not be able to force a huge amount of GHOSTDAG work. Also reject
        // an empty parent list (only genesis has no parents, and it isn't
        // created via this path) and duplicate parents.
        if block.parents.is_empty() {
            return Err("Block has no parents".into());
        }
        if block.parents.len() > MAX_BLOCK_PARENTS {
            return Err(format!(
                "Too many parents: {} exceeds cap {}",
                block.parents.len(),
                MAX_BLOCK_PARENTS
            ));
        }
        {
            let mut seen = HashSet::new();
            for parent in &block.parents {
                if !seen.insert(*parent) {
                    return Err("Duplicate parent in block".into());
                }
            }
        }

        for parent in &block.parents {
            if !self.dag.contains_key(parent) {
                return Err("Unknown parent block".into());
            }
        }

        // Finality / deep-reorg protection (Kaspa-style). A block's selected
        // chain MUST descend from the current finality point. If it doesn't, the
        // block is attempting to rewrite history deeper than `FINALITY_DEPTH` —
        // the classic double-spend a low-hashrate chain is otherwise open to
        // (rent hashrate, secretly build a longer chain from a deep fork, reorg
        // everyone). The honest network has committed to history up to the
        // finality point, so such a block is rejected outright. Shallow reorgs
        // (within the finality window) are still allowed — that's normal DAG
        // operation. Only kicks in once the chain is deeper than FINALITY_DEPTH.
        if let (Some(fp), Some(sp)) = (
            self.finality_point(),
            ghostdag::select_parent(&self.ghostdag, &block.parents),
        ) {
            if self.reachability.is_chain_ancestor(&fp, &sp) == Some(false) {
                return Err(
                    "Finality violation: block's selected chain does not include the finality point".into(),
                );
            }
        }

        // Difficulty is miner-supplied and untrusted. Required value = per-block
        // DAA of the selected-parent window, floored by the supply-era schedule
        // (`era_min_difficulty`) at this block's timestamp.
        let required_difficulty = self.expected_difficulty_at(&block.parents, block.timestamp);
        if block.difficulty != required_difficulty {
            return Err(format!(
                "Wrong difficulty: block's past requires {}, block claims {}",
                required_difficulty, block.difficulty
            ));
        }

        let hash = block.hash();
        if !verify_pow(&hash, block.difficulty) {
            return Err("Invalid proof of work".into());
        }

        // Consensus blocks MUST carry STARK + Birth Certificate witnesses.
        // Header-only copies (`Block::header_only`) are for pruning-proof /
        // GetBlock *serving* only — admitting them here previously let an
        // attacker mine empty stubs (skip STARK/issuance), collect subsidy,
        // and permanently censor a merklized body that could never be filled
        // in later (`"Block already known"`). Deep history sync uses
        // `verify_pruning_proof` / multilevel adopt, not this path.
        if block.stark_proof.is_empty() || block.birth_certificate.signature.is_empty() {
            return Err(
                "Header-only / empty-witness blocks are not consensus-admissible".into(),
            );
        }
        // Cheap STARK framing before the expensive winterfell verify (DoS).
        stark::precheck_format(&block.stark_proof)
            .map_err(|e| format!("Invalid STARK proof: {e}"))?;

        // Interlinks bind to the GHOSTDAG selected parent (unchanged).
        let selected_parent = ghostdag::select_parent(&self.ghostdag, &block.parents)
            .ok_or_else(|| "Cannot select parent".to_string())?;
        let expected_interlinks = self
            .dag
            .get(&selected_parent)
            .map(crate::superproof::compute_interlinks)
            .unwrap_or_default();
        if block.interlinks != expected_interlinks {
            return Err("interlinks do not match selected parent".into());
        }

        // Bind the body to the PoW hash via merkle_root (cheap).
        if block.merkle_root != block.merkle_root() {
            return Err("merkle_root does not commit to the block's transactions".into());
        }

        // Timestamp sanity before expensive crypto verifies.
        let max_parent_ts = block
            .parents
            .iter()
            .filter_map(|p| self.dag.get(p))
            .map(|b| b.timestamp)
            .max()
            .unwrap_or(0);
        if block.timestamp < max_parent_ts {
            return Err("Block timestamp predates its parents".into());
        }
        // Past-median-time (BIP113-class): block time must be strictly greater
        // than the median timestamp of the selected-parent chain window.
        let mtp = self.past_median_time(&selected_parent);
        if block.timestamp <= mtp {
            return Err(format!(
                "Block timestamp {0} not beyond past median time {mtp}",
                block.timestamp
            ));
        }
        if block.timestamp > now_ms().saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err("Block timestamp too far in the future".into());
        }

        // assume_valid: when a pin is configured and this block is the pin or a
        // strict ancestor of an already-imported pin, skip the expensive STARK
        // winterfell verify (PoW + birth + state_root still required). Audit only.
        let skip_stark = assume_valid::may_skip_stark_verify(&hash, |pin| {
            self.dag.contains_key(pin) && self.reachability.is_ancestor(&hash, pin, &self.dag)
        });
        if !skip_stark && !verify_stark_proof(&block) {
            return Err("Invalid STARK proof".into());
        }
        block.verify_issuance()?;

        // Validate the FORM of every transaction / custody / registry op.
        self.validate_block_transactions(&block)?;

        // Compute GHOSTDAG data before body admission so we can validate against
        // the selected-parent virtual *plus* this block's mergeset (Kaspa-shaped
        // account admission). Coloring only sees already-ordered ancestors.
        let gd = ghostdag::try_compute_ghostdag_data(
            &self.dag,
            &self.ghostdag,
            &self.reachability,
            &block.parents,
            MAX_MERGESET_SIZE,
        )?;
        let mergeset: Vec<Hash> = gd
            .mergeset_blues
            .iter()
            .skip(1)
            .chain(gd.mergeset_reds.iter())
            .copied()
            .collect();
        // Strict body check on SP + mergeset virtual, then require `state_root`
        // equal the post-mergeset tip commitment (body + subsidy).
        let expected_state_root =
            self.post_mergeset_state_root(&selected_parent, &mergeset, &block, gd.blue_score)?;
        if block.state_root != expected_state_root {
            return Err("state_root does not match post-mergeset tip state".into());
        }

        // The reachability tree parent is the GHOSTDAG selected parent; the
        // future-covering-set insertion set is this block's mergeset (every
        // merged block, i.e. the blues after the selected parent plus the reds).
        let sp = gd.selected_parent;
        self.dag.insert(hash, block.clone());
        self.ghostdag.insert(hash, gd);
        self.reachability.add_block(hash, sp, &mergeset, &self.dag);

        for parent in &block.parents {
            self.tips.retain(|t| t != parent);
        }
        self.tips.push(hash);

        self.order_main_chain();
        // On the first block, capture any pre-chain seeded state (a genesis
        // premine or pool pre-seed set on the fresh state before mining) into
        // `base` — at this point the live state holds exactly those seeds (no
        // block effects have been applied yet, since state is only ever applied
        // via the recompute below). This makes seeds part of the finalized base
        // so the deterministic recompute preserves them.
        if !self.base_captured {
            self.base = self.snapshot_ledger();
            self.base_captured = true;
        }
        // Advance the finalized base (fold newly-finalized blocks), then
        // recompute the live state = base + canonical-order replay of the
        // finality window. State is thus a deterministic function of the DAG,
        // independent of block arrival order — every node with the same DAG
        // agrees (closes the conflicting-transaction determinism gap). Then drop
        // this block's transactions from the mempools.
        self.advance_finalized_base();
        self.recompute_virtual_state();
        self.record_selected_chain_fee_samples();
        self.drop_included_from_mempools(&block);

        // Cache the difficulty the next block (built on the current selected
        // tip) must claim. This is just a convenience/display value —
        // `expected_difficulty_at` is the authoritative, per-block computation.
        let tip_ts = self
            .tips
            .iter()
            .filter_map(|h| self.dag.get(h).map(|b| b.timestamp))
            .max()
            .unwrap_or(GENESIS_TIMESTAMP_MS);
        self.difficulty =
            self.expected_difficulty_at(&self.tips, tip_ts.saturating_add(TARGET_BLOCK_TIME_MS));

        // Bound memory by pruning the bodies of blocks now buried past the
        // finality depth. Safe: only tx/proof bytes are cleared; all consensus
        // data stays.
        self.prune_bodies();
        // Deeper still: discard headers/GHOSTDAG/reachability for blocks buried
        // past PRUNING_DEPTH, advancing the pruning point. Cumulative state is
        // untouched; only far-finalized historical blocks are dropped.
        self.prune_history();

        ai_trace::trace_block_accepted(&block);
        Ok(())
    }

    /// Recompute the consensus main chain as the GHOSTDAG selected chain:
    /// the selected-parent chain from the highest-blue-score tip back to
    /// genesis. This replaced a naive reverse-BFS over *every* block (which
    /// wasn't a real chain — it just listed all blocks and gave no
    /// attack-resistant ordering). See `ghostdag` module.
    fn order_main_chain(&mut self) {
        if let Some(tip) = ghostdag::selected_tip(&self.ghostdag, &self.tips) {
            self.main_chain = ghostdag::selected_chain(&self.ghostdag, &tip);
        }
    }

    /// The blue score of the current selected tip — the amount of accumulated
    /// GHOSTDAG "blue work" the honest chain has, and the quantity an attacker
    /// must outpace. 0 if only genesis exists.
    /// Absolute tip height on the selected chain (genesis = 0).
    pub fn tip_height(&self) -> u64 {
        self.pruned_selected_blocks
            .saturating_add(self.main_chain.len() as u64)
            .saturating_sub(1)
    }

    pub fn selected_tip_blue_score(&self) -> u64 {
        ghostdag::selected_tip(&self.ghostdag, &self.tips)
            .and_then(|t| self.ghostdag.get(&t))
            .map(|d| d.blue_score)
            .unwrap_or(0)
    }

    /// BIP113-class past median time: median of up to 11 selected-parent
    /// timestamps ending at `tip` (inclusive). Genesis-only → tip timestamp.
    pub fn past_median_time(&self, tip: &Hash) -> u64 {
        let mut times = Vec::with_capacity(11);
        let mut cur = *tip;
        for _ in 0..11 {
            let Some(block) = self.dag.get(&cur) else {
                break;
            };
            times.push(block.timestamp);
            let Some(gd) = self.ghostdag.get(&cur) else {
                break;
            };
            let Some(sp) = gd.selected_parent else {
                break;
            };
            if sp == cur {
                break;
            }
            cur = sp;
        }
        if times.is_empty() {
            return 0;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// The current **finality point**: the deepest selected-chain block at least
    /// `FINALITY_DEPTH` blue-score levels below the selected tip. The honest
    /// network is considered to have committed to all history up to here, so a
    /// block whose selected chain does not descend from it is a deep-reorg
    /// attempt and is rejected (see `add_block`). `None` until the chain first
    /// grows past `FINALITY_DEPTH`.
    pub fn finality_point(&self) -> Option<Hash> {
        let tip = ghostdag::selected_tip(&self.ghostdag, &self.tips)?;
        let tip_score = self.ghostdag.get(&tip)?.blue_score;
        if tip_score <= FINALITY_DEPTH {
            return None;
        }
        let threshold = tip_score - FINALITY_DEPTH;
        let chain = ghostdag::selected_chain(&self.ghostdag, &tip);
        let mut fp = None;
        for h in &chain {
            let score = self
                .ghostdag
                .get(h)
                .map(|d| d.blue_score)
                .unwrap_or(u64::MAX);
            if score <= threshold {
                fp = Some(*h);
            } else {
                break;
            }
        }
        fp
    }

    /// Read-only FORM validation of every transaction in a block. Mutates
    /// nothing. Rejects genuine invalidity (forged proof, unknown anchor, bad
    /// signature, duplicate nullifier within one block, fee-arithmetic overflow),
    /// but NOT conflicts (double-spent nullifier / stale nonce), which are
    /// resolved by canonical-order replay. `gas_price * gas_limit` is checked
    /// because those are attacker-controlled u128 values that previously
    /// overflowed into a panic (node death under `panic = "abort"`).
    fn validate_block_transactions(&self, block: &Block) -> Result<(), String> {
        // Form-only (signature, chain id, sizes). Nonce/balance against the
        // SP+mergeset virtual are checked in
        // `validate_block_body_against_mergeset_virtual`.
        self.validate_account_forms(&block.transparent_txs)?;
        self.validate_utxo_forms(&block.utxo_txs)?;
        self.validate_registry_ops(block)?;
        self.validate_custody_ops(block)?;
        Ok(())
    }

    fn validate_utxo_forms(&self, txs: &[utxo_tx::UtxoTx]) -> Result<(), String> {
        let mut seen = std::collections::BTreeSet::new();
        for tx in txs {
            tx.validate_form()
                .map_err(|e| format!("Utxo tx: {e}"))?;
            if tx.chain_id != self.chain_id {
                return Err("Utxo tx: wrong chain_id".into());
            }
            for tin in &tx.inputs {
                if !seen.insert(tin.previous) {
                    return Err("Utxo tx: duplicate outpoint within block".into());
                }
            }
        }
        // Parallel ML-DSA-87 verify across the block body (CPU-bound).
        use rayon::prelude::*;
        if txs.par_iter().any(|tx| !tx.verify()) {
            return Err("Utxo tx: invalid signature".into());
        }
        Ok(())
    }

    /// Kaspa-shaped account admission helper (body-only). Prefer
    /// [`Self::post_mergeset_state_root`] which also applies subsidy and
    /// returns the tip commitment.
    #[allow(dead_code)]
    fn validate_block_body_against_mergeset_virtual(
        &self,
        selected_parent: &Hash,
        mergeset: &[Hash],
        block: &Block,
    ) -> Result<(), String> {
        let mut sim = self.virtual_state_at(selected_parent);
        for m in mergeset {
            let Some(mb) = self.dag.get(m) else {
                continue;
            };
            if let Some(gd) = self.ghostdag.get(m) {
                sim.ghostdag.insert(*m, gd.clone());
            }
            // Conflict-skip: parallel/red txs that already lost stay skipped.
            sim.apply_block_effects(mb);
        }
        let media = self
            .ghostdag
            .get(selected_parent)
            .map(|d| d.blue_score.saturating_add(1))
            .unwrap_or(1);
        sim.simulate_apply_block_body(block, media).map(|_| ())
    }

    /// Post-mergeset tip commitment: SP virtual + mergeset (conflict-skip) +
    /// this block's body (strict) + subsidy. This is the honest `state_root`
    /// miners must put in the header. Parallel siblings may differ.
    pub fn post_mergeset_state_root(
        &self,
        selected_parent: &Hash,
        mergeset: &[Hash],
        block: &Block,
        blue_score: u64,
    ) -> Result<Hash, String> {
        let mut sim = self.virtual_state_at(selected_parent);
        for m in mergeset {
            let Some(mb) = self.dag.get(m) else {
                continue;
            };
            if let Some(gd) = self.ghostdag.get(m) {
                sim.ghostdag.insert(*m, gd.clone());
            }
            sim.apply_block_effects(mb);
        }
        let fees = sim.simulate_apply_block_body(block, blue_score)?;
        sim.apply_block_reward(block, blue_score, fees);
        Ok(sim.merkle_root())
    }

    /// Apply every transparent / registry / custody / utxo op in `block` against `self`
    /// (caller must already hold the SP+mergeset virtual). Any failure
    /// rejects — used by admission, not by historical mergeset replay.
    /// Returns fees collected from successfully applied txs (paid to miner coinbase).
    fn simulate_apply_block_body(&mut self, block: &Block, media_blue: u64) -> Result<u128, String> {
        let mut fees = 0u128;
        for tx in &block.transparent_txs {
            self.apply_transparent_tx(tx).map_err(|e| {
                format!("Transparent tx does not apply on mergeset virtual: {e}")
            })?;
            fees = fees.saturating_add(tx.fee);
        }
        for tx in &block.utxo_txs {
            if tx.chain_id != self.chain_id {
                return Err("Utxo tx: wrong chain_id".into());
            }
            let mut tx_fee = 0u128;
            utxo_tx::apply_utxo_tx(
                &mut self.utxo,
                &mut self.accounts,
                tx,
                media_blue,
                &mut tx_fee,
            )
            .map_err(|e| format!("Utxo tx does not apply on mergeset virtual: {e}"))?;
            fees = fees.saturating_add(tx_fee);
        }
        let settlement = block.settlement_id().to_hex();
        for op in &block.registry_ops {
            self.registry
                .apply_op(&mut self.accounts, op, block, &settlement, media_blue)
                .map_err(|e| {
                    format!("Registry op does not apply on mergeset virtual: {e}")
                })?;
        }
        for op in &block.custody_ops {
            self.apply_custody_op(op).map_err(|e| {
                format!("Custody op does not apply on mergeset virtual: {e}")
            })?;
        }
        Ok(fees)
    }

    /// Mint this block's **UTXO coinbase**: subsidy (new issuance) + fees
    /// collected from body txs (redistributed to miner). Only subsidy increases
    /// `minted_supply`. No account overlay credit.
    fn apply_block_reward(&mut self, block: &Block, blue_score: u64, fees: u128) {
        let subsidy = block_subsidy(blue_score).min(MAX_SUPPLY.saturating_sub(self.minted_supply));
        let total = subsidy.saturating_add(fees);
        if total == 0 {
            return;
        }
        if subsidy > 0 {
            self.minted_supply = self.minted_supply.saturating_add(subsidy);
        }
        let miner_addr = crate::address::encode_hash(&block.miner);
        let op = utxo::OutPoint::coinbase(utxo::coinbase_txid(block));
        self.utxo.insert(
            op,
            utxo::TxOut {
                value: total,
                predicate: predicate::Predicate::PayToAddress {
                    address: miner_addr,
                },
                created_blue: blue_score,
            },
        );
    }

    /// Soft-upgrade signaling status from the selected chain tip.
    pub fn version_bits_status(&self) -> versionbits::VersionBitsState {
        let mut st = versionbits::VersionBitsState::new();
        for h in &self.main_chain {
            if let (Some(b), Some(gd)) = (self.dag.get(h), self.ghostdag.get(h)) {
                st.observe(gd.blue_score, b.version);
            }
        }
        st
    }

    /// Hard supply identity: minted = accounts + staked + utxo + fees_burned.
    ///
    /// `fees_burned` is a legacy counter (always 0 on fresh v26+ chains).
    /// From v26, tx fees are paid to the miner coinbase UTXO instead of burned,
    /// so they remain inside `utxo` (or accounts after CreditAccount bridges).
    pub fn supply_invariant_ok(&self) -> bool {
        let accounts: u128 = self.accounts.values().map(|a| a.balance).sum();
        let staked: u128 = self.staked.values().copied().sum();
        let utxo = self.utxo.total_value();
        accounts
            .saturating_add(staked)
            .saturating_add(utxo)
            .saturating_add(self.fees_burned)
            == self.minted_supply
    }

    /// Form-only validation of a block's account operations: valid signature and
    /// matching chain id. Nonce/balance against SP+mergeset virtual are enforced
    /// by `validate_block_body_against_mergeset_virtual` /
    /// `post_mergeset_state_root`.
    fn validate_account_forms(&self, transfers: &[TransparentTx]) -> Result<(), String> {
        if !ACCOUNT_PEER_TRANSFERS && !transfers.is_empty() {
            return Err(
                "Account peer transfers disabled (v27); use UTXO for value moves".into(),
            );
        }
        for tx in transfers {
            tx.validate_form()
                .map_err(|e| format!("Transparent tx: {e}"))?;
            if tx.chain_id != self.chain_id {
                return Err("Transparent tx: wrong chain_id".into());
            }
        }
        use rayon::prelude::*;
        if transfers.par_iter().any(|tx| !tx.verify()) {
            return Err("Transparent tx: invalid signature".into());
        }
        Ok(())
    }

    /// Take a snapshot of the current value state.
    fn snapshot_ledger(&self) -> Ledger {
        Ledger {
            accounts: self.accounts.clone(),
            minted_supply: self.minted_supply,
            fees_burned: self.fees_burned,
            treasury: self.treasury,
            registry: self.registry.clone(),
            staked: self.staked.clone(),
            utxo: self.utxo.clone(),
        }
    }

    /// Reset the live value state to a ledger snapshot.
    fn restore_ledger(&mut self, l: &Ledger) {
        self.accounts = l.accounts.clone();
        self.minted_supply = l.minted_supply;
        self.fees_burned = l.fees_burned;
        self.treasury = l.treasury;
        self.registry = l.registry.clone();
        self.staked = l.staked.clone();
        self.utxo = l.utxo.clone();
    }

    /// Apply ONE block's value effects (transfers, title/escrow ops, custody, subsidy).
    /// Conflict-skip: stale/underfunded ops from *historical* mergeset replay are
    /// skipped (parallel/red conflicts). Admission rejects blocks whose own body
    /// cannot apply on the SP+mergeset virtual (strict).
    fn apply_block_effects(&mut self, block: &Block) {
        if block.parents.is_empty() {
            return; // genesis
        }
        let mut collected_fees = 0u128;
        for tx in &block.transparent_txs {
            // Conflict-skip: stale/underfunded ops from historical mergeset replay.
            if self.apply_transparent_tx(tx).is_ok() {
                collected_fees = collected_fees.saturating_add(tx.fee);
            }
        }
        let media_blue = self
            .ghostdag
            .get(&block.hash())
            .map(|d| d.blue_score)
            .unwrap_or_else(|| self.selected_tip_blue_score());
        for tx in &block.utxo_txs {
            let mut tx_fee = 0u128;
            if utxo_tx::apply_utxo_tx(
                &mut self.utxo,
                &mut self.accounts,
                tx,
                media_blue,
                &mut tx_fee,
            )
            .is_ok()
            {
                collected_fees = collected_fees.saturating_add(tx_fee);
            }
        }
        let settlement = block.settlement_id().to_hex();
        for op in &block.registry_ops {
            let _ = self
                .registry
                .apply_op(&mut self.accounts, op, block, &settlement, media_blue);
        }
        for op in &block.custody_ops {
            let _ = self.apply_custody_op(op);
        }

        // Coinbase = subsidy (new mint) + fees from this block's body (to miner).
        let blue_score = self
            .ghostdag
            .get(&block.hash())
            .map(|d| d.blue_score)
            .unwrap_or(0);
        self.apply_block_reward(block, blue_score, collected_fees);
        debug_assert!(
            self.supply_invariant_ok(),
            "supply invariant broken after apply_block_effects"
        );
    }

    /// On-chain stake lock/unlock and bridge exit/enter (conflict-skip on failure).
    fn apply_custody_op(&mut self, op: &custody::CustodyCertificate) -> Result<(), String> {
        if op.chain_id != self.chain_id {
            return Err("Wrong chain_id".into());
        }
        if op.amount == 0 {
            return Err("Custody amount must be > 0".into());
        }
        if !security::is_valid_address(&op.owner) {
            return Err("Invalid custody owner".into());
        }
        let sid: [u8; 64] = hex::decode(&op.settlement_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "bad settlement id".to_string())?;
        op.verify(&sid)?;

        let nonce = self.account_nonce(&op.owner);
        if op.nonce != nonce {
            return Err("Bad custody nonce".into());
        }

        match op.kind {
            custody::CustodyKind::StakeLock => {
                let bal = self.account_balance(&op.owner);
                if bal < op.amount {
                    return Err("Insufficient free balance to stake".into());
                }
                self.accounts.entry(op.owner.clone()).or_default().balance -= op.amount;
                *self.staked.entry(op.owner.clone()).or_default() =
                    self.staked.get(&op.owner).copied().unwrap_or(0) + op.amount;
            }
            custody::CustodyKind::StakeUnlock => {
                let locked = self.staked.get(&op.owner).copied().unwrap_or(0);
                if locked < op.amount {
                    return Err("Insufficient staked balance".into());
                }
                *self.staked.get_mut(&op.owner).unwrap() = locked - op.amount;
                self.accounts.entry(op.owner.clone()).or_default().balance =
                    self.account_balance(&op.owner) + op.amount;
            }
            custody::CustodyKind::BridgeExit | custody::CustodyKind::BridgeEnter => {
                // Disabled: BridgeEnter previously minted up to MAX_SUPPLY with
                // only a self-consistent (forgeable) birth-cert + owner
                // signature — no DAG anchor, no matching BridgeExit nullifier.
                // Re-enable only with pending-exit accounting + on-chain
                // anchor resolution.
                return Err(
                    "Bridge exit/enter disabled until a real cross-chain bridge ships".into(),
                );
            }
        }
        self.accounts.entry(op.owner.clone()).or_default().nonce = nonce.saturating_add(1);
        Ok(())
    }

    /// The canonical total order of the retained blocks (GHOSTDAG order): walk
    /// the selected chain base→tip; at each selected-chain block emit its merged
    /// blocks (blues after the selected parent, then reds — already topologically
    /// ordered) before the block itself. Deterministic from GHOSTDAG data, so
    /// every node with the same DAG produces the same order and thus the same
    /// state.
    fn canonical_order(&self) -> Vec<Hash> {
        match ghostdag::selected_tip(&self.ghostdag, &self.tips) {
            Some(t) => self.canonical_order_at(&t),
            None => Vec::new(),
        }
    }

    /// Canonical order as if `tip` were the selected tip (selected-parent chain
    /// ending at `tip`, with mergesets emitted at each step).
    fn canonical_order_at(&self, tip: &Hash) -> Vec<Hash> {
        if !self.ghostdag.contains_key(tip) {
            return Vec::new();
        }
        let chain = ghostdag::selected_chain(&self.ghostdag, tip); // base → tip
        let mut order = Vec::with_capacity(self.dag.len());
        let mut seen: HashSet<Hash> = HashSet::new();
        for h in &chain {
            if let Some(gd) = self.ghostdag.get(h) {
                for m in gd
                    .mergeset_blues
                    .iter()
                    .skip(1)
                    .chain(gd.mergeset_reds.iter())
                {
                    if self.dag.contains_key(m) && seen.insert(*m) {
                        order.push(*m);
                    }
                }
            }
            if seen.insert(*h) {
                order.push(*h);
            }
        }
        order
    }

    /// Account-state merkle root after applying the virtual state at `tip`
    /// (base + canonical replay of the selected chain ending at `tip`). This is
    /// the honest `state_root` a child of `tip` (or any block whose selected
    /// parent is `tip`) must commit.
    pub fn merkle_root_at(&self, tip: &Hash) -> Hash {
        self.virtual_state_at(tip).merkle_root()
    }

    /// Build a throwaway `ChainState` holding the ledger after replaying the
    /// canonical order ending at `tip` (selected-parent virtual).
    fn virtual_state_at(&self, tip: &Hash) -> ChainState {
        let order = self.canonical_order_at(tip);
        let start = self.replay_start(&order);
        // Before the first block captures `base`, live accounts are the seed
        // ledger (test premine / operator pre-seed). After capture, replay from
        // the finalized base only.
        let (accounts, minted_supply, fees_burned, treasury, registry, staked, utxo) =
            if self.base_captured {
                (
                    self.base.accounts.clone(),
                    self.base.minted_supply,
                    self.base.fees_burned,
                    self.base.treasury,
                    self.base.registry.clone(),
                    self.base.staked.clone(),
                    self.base.utxo.clone(),
                )
            } else {
                (
                    self.accounts.clone(),
                    self.minted_supply,
                    self.fees_burned,
                    self.treasury,
                    self.registry.clone(),
                    self.staked.clone(),
                    self.utxo.clone(),
                )
            };
        let mut sim = ChainState {
            dag: HashMap::new(),
            tips: vec![],
            main_chain: vec![],
            accounts,
            utxo,
            total_supply: self.total_supply,
            minted_supply,
            block_reward: self.block_reward,
            difficulty: self.difficulty,
            chain_id: self.chain_id,
            transparent_mempool: vec![],
            utxo_mempool: vec![],
            registry_mempool: vec![],
            registry,
            custody_mempool: vec![],
            staked,
            fees_burned,
            treasury,
            tor_nodes: HashSet::new(),
            ghostdag: HashMap::new(),
            reachability: reachability::Reachability::new(),
            archival: false,
            base: Ledger::default(),
            base_captured: true,
            base_frontier: None,
            pruning_point: None,
            pruning_ledger: None,
            pruned_selected_blocks: 0,
            tx_first_seen_ms: HashMap::new(),
            tx_first_seen_blue: HashMap::new(),
            fee_history: FeeRateHistory::default(),
        };
        for h in order.iter().skip(start) {
            let Some(block) = self.dag.get(h) else {
                continue;
            };
            if let Some(gd) = self.ghostdag.get(h) {
                sim.ghostdag.insert(*h, gd.clone());
            }
            sim.apply_block_effects(block);
        }
        sim
    }

    /// Set `state_root` + `interlinks` for mining/templates. `state_root` is the
    /// post-mergeset tip commitment (SP + mergeset conflict-skip + this block's
    /// body + subsidy). Call **after** `block.miner` / body are final — subsidy
    /// credits the miner address baked into the PoW hash.
    pub fn bind_parent_commitments(&self, block: &mut Block) -> Result<(), String> {
        let gd = ghostdag::try_compute_ghostdag_data(
            &self.dag,
            &self.ghostdag,
            &self.reachability,
            &block.parents,
            MAX_MERGESET_SIZE,
        )?;
        let sp = gd
            .selected_parent
            .ok_or_else(|| "Cannot select parent for commitments".to_string())?;
        let mergeset: Vec<Hash> = gd
            .mergeset_blues
            .iter()
            .skip(1)
            .chain(gd.mergeset_reds.iter())
            .copied()
            .collect();
        block.interlinks = self
            .dag
            .get(&sp)
            .map(crate::superproof::compute_interlinks)
            .unwrap_or_default();
        block.state_root = self.post_mergeset_state_root(&sp, &mergeset, block, gd.blue_score)?;
        Ok(())
    }

    /// Index in `order` right after `base_frontier` (the first block NOT yet in
    /// `base`). 0 if there is no frontier. `base_frontier` is always retained
    /// (the finality point is shallower than the pruning point), so it is found.
    fn replay_start(&self, order: &[Hash]) -> usize {
        match self.base_frontier {
            None => 0,
            Some(f) => order
                .iter()
                .position(|h| *h == f)
                .map(|i| i + 1)
                .unwrap_or(0),
        }
    }

    /// Recompute the live value state deterministically = `base` (the canonical
    /// prefix up to `base_frontier`, already folded in) + a canonical-order
    /// replay of the suffix after it (the finality window). This makes state a
    /// pure function of the DAG (arrival-order independent); the replay is
    /// bounded by the finality depth.
    fn recompute_virtual_state(&mut self) {
        let base = self.base.clone();
        self.restore_ledger(&base);
        let order = self.canonical_order();
        let start = self.replay_start(&order);
        for h in order.iter().skip(start) {
            if let Some(block) = self.dag.get(h).cloned() {
                self.apply_block_effects(&block);
            }
        }
    }

    /// Advance the finalized `base` as the finality point moves forward: fold the
    /// canonical-order prefix from just after the old `base_frontier` up to and
    /// including the new finality point. Folding the exact canonical prefix (not
    /// a blue-score cutoff) is what keeps conflict resolution identical whether a
    /// block is folded incrementally or replayed fresh on reload. Once folded, a
    /// block's effects are permanent (finality forbids reorging past it) and its
    /// body may be pruned. Monotonic: the finality point only advances, so each
    /// block is folded exactly once.
    fn advance_finalized_base(&mut self) {
        let fp = match self.finality_point() {
            Some(f) => f,
            None => return,
        };
        if self.base_frontier == Some(fp) {
            return; // already folded up to here
        }
        let order = self.canonical_order();
        let fp_idx = match order.iter().position(|h| *h == fp) {
            Some(i) => i,
            None => return, // finality point not found (shouldn't happen) — don't risk a bad fold
        };
        let start = self.replay_start(&order);
        if start > fp_idx + 1 {
            return; // nothing to add (defensive)
        }
        let to_fold: Vec<Hash> = order[start..=fp_idx].to_vec();
        let base = self.base.clone();
        self.restore_ledger(&base);
        for h in &to_fold {
            if let Some(block) = self.dag.get(h).cloned() {
                self.apply_block_effects(&block);
            }
        }
        self.base = self.snapshot_ledger();
        self.base_frontier = Some(fp);
        // Caller recomputes the live state on top of the advanced base.
    }

    /// Remove a just-added block's transactions from the mempools (they're now
    /// on-chain). Separate from state application, which is a full recompute.
    fn drop_included_from_mempools(&mut self, block: &Block) {
        self.transparent_mempool.retain(|tx| {
            !block
                .transparent_txs
                .iter()
                .any(|btx| btx.from == tx.from && btx.nonce == tx.nonce)
        });
        self.utxo_mempool.retain(|tx| {
            !block
                .utxo_txs
                .iter()
                .any(|btx| btx.txid() == tx.txid())
        });
        self.registry_mempool.retain(|op| {
            !block
                .registry_ops
                .iter()
                .any(|bop| bop.signer_address() == op.signer_address() && bop.nonce() == op.nonce())
        });
        self.custody_mempool.retain(|op| {
            !block
                .custody_ops
                .iter()
                .any(|bop| bop.owner == op.owner && bop.nonce == op.nonce && bop.kind == op.kind)
        });
        for tx in &block.transparent_txs {
            let h = tx.tx_hash();
            // Keep `tx_first_seen_ms` so confirmed journeys can report dwell
            // time; blue-score lag was already folded into fee_history above.
            self.tx_first_seen_blue.remove(&h);
        }
        for tx in &block.utxo_txs {
            self.tx_first_seen_blue.remove(&tx.txid());
        }
    }

    /// Append fee/relay_bytes samples for newly selected-chain blocks (policy
    /// history for confirmation-target estimates). Idempotent on blue_score.
    fn record_selected_chain_fee_samples(&mut self) {
        let tip = match ghostdag::selected_tip(&self.ghostdag, &self.tips) {
            Some(t) => t,
            None => return,
        };
        let chain = ghostdag::selected_chain(&self.ghostdag, &tip);
        let last_recorded = self
            .fee_history
            .samples
            .last()
            .map(|s| s.blue_score)
            .unwrap_or(0);
        let mut pending: Vec<(u64, Vec<u128>, Vec<u64>)> = Vec::new();
        for h in &chain {
            let Some(gd) = self.ghostdag.get(h) else {
                continue;
            };
            if gd.blue_score <= last_recorded {
                continue;
            }
            let Some(block) = self.dag.get(h) else {
                continue;
            };
            let n_samples = block.transparent_txs.len() + block.utxo_txs.len();
            if n_samples == 0 {
                continue;
            }
            let mut feerates = Vec::with_capacity(n_samples);
            let mut confirm_blues = Vec::with_capacity(n_samples);
            for tx in &block.transparent_txs {
                let bytes = tx.relay_bytes().max(1) as u128;
                feerates.push(tx.fee / bytes);
                let lag = self
                    .tx_first_seen_blue
                    .get(&tx.tx_hash())
                    .map(|seen| gd.blue_score.saturating_sub(*seen))
                    .unwrap_or(0);
                confirm_blues.push(lag);
            }
            for tx in &block.utxo_txs {
                let bytes = tx.relay_bytes().max(1) as u128;
                feerates.push(tx.fee / bytes);
                let lag = self
                    .tx_first_seen_blue
                    .get(&tx.txid())
                    .map(|seen| gd.blue_score.saturating_sub(*seen))
                    .unwrap_or(0);
                confirm_blues.push(lag);
            }
            // Cheap package feerate: total fee / total bytes of the block body.
            if n_samples > 1 {
                let pkg_fee: u128 = block
                    .transparent_txs
                    .iter()
                    .map(|t| t.fee)
                    .chain(block.utxo_txs.iter().map(|t| t.fee))
                    .sum();
                let pkg_bytes: u128 = block
                    .transparent_txs
                    .iter()
                    .map(|t| t.relay_bytes().max(1) as u128)
                    .chain(block.utxo_txs.iter().map(|t| t.relay_bytes().max(1) as u128))
                    .sum::<u128>()
                    .max(1);
                feerates.push(pkg_fee / pkg_bytes);
                confirm_blues.push(confirm_blues.iter().copied().max().unwrap_or(0));
            }
            pending.push((gd.blue_score, feerates, confirm_blues));
        }
        for (bs, rates, lags) in pending {
            self.fee_history.record(bs, rates, lags);
        }
    }

    /// Clear the bodies (transactions + STARK proof) of every block buried
    /// more than `FINALITY_DEPTH` blue-score levels below the current selected
    /// tip. This bounds memory (bodies are the bulk of a block) without
    /// touching any consensus data — parents, timestamp, difficulty, and the
    /// GHOSTDAG map are all kept, so ordering/scoring/validation of new blocks
    /// is unaffected. A block whose body has been pruned can no longer be
    /// *served* to a syncing peer (see `p2p`'s `GetBlock` handling), which is
    /// the standard archival-vs-pruned tradeoff.
    ///
    /// `is_body_pruned` reports whether a given block has been pruned.
    pub fn prune_bodies(&mut self) {
        if self.archival {
            return; // archival nodes keep all history for cold-start sync
        }
        let tip_score = self.selected_tip_blue_score();
        if tip_score <= FINALITY_DEPTH {
            return; // nothing is buried deeply enough yet
        }
        let threshold = tip_score - FINALITY_DEPTH;
        // Collect the newly-buried blocks first (avoids borrowing `self.dag`
        // mutably while also touching `self.ghostdag`/`self.reachability`).
        let to_prune: Vec<Hash> = self
            .dag
            .iter()
            .filter(|(hash, block)| {
                let score = self
                    .ghostdag
                    .get(*hash)
                    .map(|d| d.blue_score)
                    .unwrap_or(u64::MAX);
                score <= threshold && !Self::is_body_empty(block)
            })
            .map(|(hash, _)| *hash)
            .collect();
        for hash in to_prune {
            if let Some(block) = self.dag.get_mut(&hash) {
                block.transparent_txs.clear();
                block.utxo_txs.clear();
                block.registry_ops.clear();
                block.custody_ops.clear();
                block.stark_proof.clear();
                block.birth_certificate = issuance::BirthCertificate::default();
            }
            // Try to drop the block from the reachability oracle. This only
            // removes it if it's a tree leaf — removing an interior node would
            // sever its descendants' ancestry, and the interval oracle stores
            // only O(1) per node anyway, so retaining buried interior nodes is
            // cheap. Whole old prefixes are removed together by full pruning.
            self.reachability.drop_leaf(&hash);
        }
    }

    fn is_body_empty(block: &Block) -> bool {
        block.transparent_txs.is_empty()
            && block.utxo_txs.is_empty()
            && block.registry_ops.is_empty()
            && block.custody_ops.is_empty()
            && block.stark_proof.is_empty()
            && block.birth_certificate.signature.is_empty()
    }

    /// Whether the given block's body has been pruned (so it can't be served
    /// to peers as a valid block). A genesis-style block with no transactions
    /// and an already-empty proof reads as pruned, which is harmless — nobody
    /// needs to sync genesis's body.
    pub fn is_body_pruned(&self, hash: &Hash) -> bool {
        self.dag.get(hash).map(Self::is_body_empty).unwrap_or(false)
    }

    /// Full history pruning: advance the pruning point and discard every block
    /// (header, GHOSTDAG data, reachability node, tip entry) buried more than
    /// `PRUNING_DEPTH` blue-score levels below the selected tip. Cumulative
    /// value state (accounts) is kept in full; only historical *blocks* are
    /// dropped. Safe because everything discarded is far below finality: new
    /// blocks attach near the tips and their GHOSTDAG mergeset walks never
    /// reach across the pruning point, so ordering, scoring, and validation of
    /// new blocks are unaffected (verified by
    /// `full_pruning_keeps_the_chain_correct`).
    pub fn prune_history(&mut self) {
        if self.archival {
            return; // archival nodes keep all headers for cold-start sync
        }
        let tip = match ghostdag::selected_tip(&self.ghostdag, &self.tips) {
            Some(t) => t,
            None => return,
        };
        let tip_score = self.ghostdag.get(&tip).map(|d| d.blue_score).unwrap_or(0);
        if tip_score <= PRUNING_DEPTH {
            return; // not deep enough to prune any headers yet
        }
        let threshold = tip_score - PRUNING_DEPTH;

        // The new pruning point: the deepest selected-chain block whose blue
        // score is still <= threshold. Walk the selected chain (genesis-first)
        // and take the last such block.
        let chain = ghostdag::selected_chain(&self.ghostdag, &tip);
        let mut new_pp = None;
        let mut pp_index_in_chain = 0usize;
        for (i, h) in chain.iter().enumerate() {
            let score = self
                .ghostdag
                .get(h)
                .map(|d| d.blue_score)
                .unwrap_or(u64::MAX);
            if score <= threshold {
                new_pp = Some(*h);
                pp_index_in_chain = i;
            } else {
                break;
            }
        }
        let pp = match new_pp {
            Some(p) => p,
            None => return,
        };
        let pp_score = self.ghostdag.get(&pp).map(|d| d.blue_score).unwrap_or(0);

        // Everything strictly below the pruning point's score is discarded;
        // the pruning point itself and all higher blocks are kept.
        let keep: HashSet<Hash> = self
            .dag
            .keys()
            .copied()
            .filter(|h| {
                self.ghostdag
                    .get(h)
                    .map(|d| d.blue_score >= pp_score)
                    .unwrap_or(true)
            })
            .collect();
        if keep.len() == self.dag.len() {
            return; // nothing to remove
        }

        self.dag.retain(|h, _| keep.contains(h));
        self.ghostdag.retain(|h, _| keep.contains(h));
        self.reachability.retain(&keep);
        self.tips.retain(|t| keep.contains(t));

        // Re-root every retained block whose selected parent was just pruned:
        // cut the dangling link so it points at nothing removed. This is NOT
        // just the pruning point — in a wide DAG, side/boundary blocks (score
        // >= pp_score) can have a selected parent below pp_score that was
        // removed. Leaving those dangling would let `selected_chain` walk into a
        // deleted hash (corrupting `main_chain`) and would desync the GHOSTDAG
        // map from `reachability`, whose `retain` already nulls exactly these.
        for d in self.ghostdag.values_mut() {
            if let Some(sp) = d.selected_parent {
                if !keep.contains(&sp) {
                    d.selected_parent = None;
                }
            }
        }

        // Count the selected-chain blocks dropped off the front so reported
        // height stays absolute, then rebuild the retained main chain.
        self.pruned_selected_blocks += pp_index_in_chain as u64;
        self.pruning_point = Some(pp);
        // Best-effort cache: only succeeds while bodies along the path remain.
        if let Some(ledger) = self.ledger_via_genesis_replay(&pp) {
            if self.dag.get(&pp).map(|b| b.state_root) == Some(ledger.merkle_root()) {
                self.pruning_ledger = Some(ledger);
            }
        }
        self.order_main_chain();
    }

    // ===== Persistence =====

    /// Serialize lean chain state to `path` (atomically: write a temp file then
    /// rename). Non-archival nodes prune bodies/headers first so finalized
    /// history is not rewritten to disk. Mempools are never serialized.
    /// The file begins with an 8-byte magic + a `u32` format version so a state
    /// written by a different (incompatible) build is detected cleanly instead
    /// of half-parsing into garbage. The derived, non-consensus fields
    /// (`reachability`) are `#[serde(skip)]` and rebuilt on load.
    pub fn save_to(&mut self, path: &std::path::Path) -> Result<(), String> {
        use std::io::Write;
        if !self.archival {
            self.prune_bodies();
            self.prune_history();
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&STATE_MAGIC);
        bytes.extend_from_slice(&STATE_FORMAT_VERSION.to_le_bytes());
        let payload =
            bincode::serialize(self).map_err(|e| format!("serialize state: {e}"))?;
        if payload.len() as u64 > MAX_CHAINSTATE_BYTES {
            return Err("chainstate payload exceeds MAX_CHAINSTATE_BYTES".into());
        }
        bytes.extend_from_slice(&payload);
        // Integrity tag: Blake3-512 over magic||version||payload so torn/corrupt
        // writes are detected before any consensus state is trusted.
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"hassan-chainstate-v1");
        hasher.update(&bytes);
        let mut tag = [0u8; STATE_CHECKSUM_LEN];
        hasher.finalize_xof().fill(&mut tag);
        bytes.extend_from_slice(&tag);
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| format!("create data dir: {e}"))?;
            }
        }

        // Durable, crash-safe write (like a real node):
        //   1. write the new state to a temp file and **fsync** it to disk;
        //   2. roll the previous good state to `.bak`;
        //   3. **atomically** rename temp -> path;
        //   4. fsync the directory so the rename survives a power loss.
        // Worst case (a crash exactly mid-save) loses only the single most-recent
        // save — never the whole chain — and `load_from` falls back to `.bak` if
        // the primary file is ever corrupt.
        let tmp = path.with_extension("tmp");
        {
            let mut f =
                std::fs::File::create(&tmp).map_err(|e| format!("create temp state: {e}"))?;
            f.write_all(&bytes)
                .map_err(|e| format!("write state: {e}"))?;
            f.sync_all().map_err(|e| format!("fsync state: {e}"))?;
        }
        if path.exists() {
            // Rolling backups: chainstate.bak → chainstate.bak.1 (one generation).
            let bak = path.with_extension("bak");
            let bak1 = path.with_extension("bak.1");
            if bak.exists() {
                let _ = std::fs::rename(&bak, &bak1);
            }
            let _ = std::fs::rename(path, &bak);
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("rename state: {e}"))?;
        // fsync the directory entry so the rename itself is durable.
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => std::path::PathBuf::from("."),
        };
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Optional mempool dump (separate from lean chainstate). Policy-only.
    pub fn dump_mempool_to(&self, path: &std::path::Path) -> Result<(), String> {
        let blob = bincode::serialize(&self.transparent_mempool)
            .map_err(|e| format!("serialize mempool: {e}"))?;
        let mut bytes = Vec::with_capacity(16 + blob.len());
        bytes.extend_from_slice(b"HSNMEMPOOL1");
        bytes.extend_from_slice(&(self.transparent_mempool.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&blob);
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| format!("create mempool dir: {e}"))?;
            }
        }
        std::fs::write(path, bytes).map_err(|e| format!("write mempool: {e}"))
    }

    /// Load transparent mempool from [`Self::dump_mempool_to`] file (best-effort).
    pub fn load_mempool_from(&mut self, path: &std::path::Path) -> Result<usize, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read mempool: {e}"))?;
        if bytes.len() < 15 || &bytes[..11] != b"HSNMEMPOOL1" {
            return Err("not a Hassan mempool dump".into());
        }
        let txs: Vec<TransparentTx> =
            bincode::deserialize(&bytes[15..]).map_err(|e| format!("deserialize mempool: {e}"))?;
        let mut loaded = 0usize;
        for tx in txs {
            if self.admit_transparent_to_mempool(tx).is_ok() {
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    /// Load chain state from `path`. If the primary file is missing or corrupt,
    /// falls back to the rolling `.bak` backup (crash resilience) before giving
    /// up. A *version* mismatch is NOT recovered from backup (the backup is the
    /// same old version), so the node starts fresh with a clear message. Magic +
    /// version are checked before deserialization so an incompatible build fails
    /// cleanly rather than half-parsing into garbage.
    pub fn load_from(path: &std::path::Path) -> Result<Self, String> {
        match Self::load_one(path) {
            Ok(s) => Ok(s),
            // Version / genesis / chain_id mismatch: do not fall back to .bak
            // (same consensus identity).
            Err(e)
                if e.starts_with("incompatible state format")
                    || e.starts_with("wrong chain_id")
                    || e.starts_with("missing hardcoded genesis")
                    || e.starts_with("corrupt hardcoded genesis")
                    || e.starts_with("corrupt genesis") =>
            {
                Err(e)
            }
            // Missing/corrupt primary: try rolling backups.
            Err(primary) => {
                for ext in ["bak", "bak.1"] {
                    if let Ok(s) = Self::load_one(&path.with_extension(ext)) {
                        return Ok(s);
                    }
                }
                Err(primary)
            }
        }
    }

    /// Read + validate + rebuild one state file (no backup fallback).
    fn load_one(path: &std::path::Path) -> Result<Self, String> {
        use bincode::Options as _;
        let bytes = std::fs::read(path).map_err(|e| format!("read state: {e}"))?;
        if bytes.len() < 12 || bytes[..8] != STATE_MAGIC {
            return Err("not a Hassan state file (bad magic)".into());
        }
        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != STATE_FORMAT_VERSION {
            return Err(format!(
                "incompatible state format (file v{version}, this build expects v{STATE_FORMAT_VERSION}) — starting fresh; \
                 wipe the data dir or resync from an archival node"
            ));
        }
        // v27+: integrity tag is mandatory. Refuse corrupt/truncated tags
        // (no legacy untagged fallback — that allowed truncate-tag loads).
        if bytes.len() < 12 + STATE_CHECKSUM_LEN {
            return Err("chainstate missing integrity tag".into());
        }
        let split = bytes.len() - STATE_CHECKSUM_LEN;
        let (body, tag) = bytes.split_at(split);
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"hassan-chainstate-v1");
        hasher.update(body);
        let mut expect = [0u8; STATE_CHECKSUM_LEN];
        hasher.finalize_xof().fill(&mut expect);
        if tag != expect {
            return Err("corrupt chainstate: integrity tag mismatch".into());
        }
        let payload = &body[12..];
        if payload.len() as u64 > MAX_CHAINSTATE_BYTES {
            return Err("chainstate payload exceeds MAX_CHAINSTATE_BYTES".into());
        }
        // Must match `bincode::serialize` (fixint). DefaultOptions alone uses
        // varint and would fail to read files we just wrote.
        let mut state: ChainState = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_CHAINSTATE_BYTES)
            .deserialize(payload)
            .map_err(|e| format!("deserialize state: {e}"))?;
        state.validate_hardcoded_chain()?;
        if !state.supply_invariant_ok() {
            return Err("corrupt chainstate: supply invariant failed".into());
        }
        state.rebuild_derived();
        Ok(state)
    }

    /// Reject foreign / corrupt snapshots that do not match compile-time
    /// consensus (hardcoded genesis + chain id) — same class of check as
    /// BTC/Kaspa/XMR refusing a wrong genesis.
    fn validate_hardcoded_chain(&self) -> Result<(), String> {
        if self.chain_id != CHAIN_ID {
            return Err(format!(
                "wrong chain_id in state file (got {}, this build is {CHAIN_ID}) — wipe data dir or use a matching binary",
                self.chain_id
            ));
        }
        let gh = genesis_hash();
        if let Some(b) = self.dag.get(&gh) {
            if b.height != 0 || !b.parents.is_empty() {
                return Err("corrupt hardcoded genesis block".into());
            }
            if b.difficulty != GENESIS_DIFFICULTY {
                return Err("corrupt genesis difficulty".into());
            }
            // Genesis block bytes must match compile-time genesis (domain bump).
            if b.hash() != gh {
                return Err(format!(
                    "genesis hash mismatch (file tip != hassan genesis {}) — wipe chainstate",
                    String::from_utf8_lossy(GENESIS_DOMAIN)
                ));
            }
        } else if self.pruning_point.is_none() {
            return Err(format!(
                "missing hardcoded genesis block for {} — wipe chainstate or resync",
                String::from_utf8_lossy(GENESIS_DOMAIN)
            ));
        }
        for h in &self.main_chain {
            if !self.dag.contains_key(h) {
                return Err("corrupt chainstate: main_chain hash missing from DAG".into());
            }
        }
        if self.dag.len() < self.main_chain.len() {
            return Err("corrupt chainstate: DAG smaller than main_chain".into());
        }
        if self.minted_supply > MAX_SUPPLY {
            return Err("corrupt chainstate: minted_supply exceeds MAX_SUPPLY".into());
        }
        Ok(())
    }

    /// A topological order of the DAG (every block after all of its in-DAG
    /// parents), via iterative post-order DFS over parent edges. Used to replay
    /// blocks into the derived indexes in a valid order regardless of blue-score
    /// ties.
    fn topological_order(&self) -> Vec<Hash> {
        let mut order = Vec::with_capacity(self.dag.len());
        let mut mark: HashMap<Hash, u8> = HashMap::new(); // 1=in-progress, 2=done
        for &start in self.dag.keys() {
            if mark.get(&start).copied().unwrap_or(0) == 2 {
                continue;
            }
            let mut stack = vec![(start, false)];
            while let Some((node, processed)) = stack.pop() {
                if processed {
                    if mark.insert(node, 2) != Some(2) {
                        order.push(node);
                    }
                    continue;
                }
                if mark.get(&node).copied().unwrap_or(0) != 0 {
                    continue; // already done or on-stack
                }
                mark.insert(node, 1);
                stack.push((node, true));
                if let Some(b) = self.dag.get(&node) {
                    for p in &b.parents {
                        if self.dag.contains_key(p) && mark.get(p).copied().unwrap_or(0) != 2 {
                            stack.push((*p, false));
                        }
                    }
                }
            }
        }
        order
    }

    /// Rebuild the `#[serde(skip)]` derived indexes from the persisted DAG +
    /// GHOSTDAG data after a load. Rebuilds the reachability oracle (replaying
    /// each block, parents-first, with its stored selected parent and mergeset),
    /// then recomputes the live value state from the persisted `base`.
    pub fn rebuild_derived(&mut self) {
        let order = self.topological_order();
        let mut reach = reachability::Reachability::new();
        for h in &order {
            if let Some(gd) = self.ghostdag.get(h) {
                let sp = gd.selected_parent;
                let mergeset: Vec<Hash> = gd
                    .mergeset_blues
                    .iter()
                    .skip(1)
                    .chain(gd.mergeset_reds.iter())
                    .copied()
                    .collect();
                reach.add_block(*h, sp, &mergeset, &self.dag);
            }
        }
        self.reachability = reach;

        // A loaded state's `base` is already authoritative — never re-capture it
        // from the (recomputed) live state, which would double-count.
        self.base_captured = true;

        // Recompute the live value state authoritatively from the persisted
        // finalized `base` plus a canonical-order replay of the retained blocks,
        // so a reloaded node's state is exactly the deterministic function of its
        // DAG, never a stale serialized copy.
        self.recompute_virtual_state();
    }

    /// Build a cold-start pruning-point proof: the header-only selected chain
    /// from genesis up to the current pruning point (see [`PruningProof`]).
    /// Returns `None` if there is no pruning point yet, or if this node no longer
    /// retains the full genesis→pruning-point header history (a body-pruned,
    /// non-archival node) — only an archival node can serve the proof.
    pub fn build_pruning_proof(&self) -> Option<PruningProof> {
        let pp = self.pruning_point?;
        let tip = ghostdag::selected_tip(&self.ghostdag, &self.tips)?;
        let chain = ghostdag::selected_chain(&self.ghostdag, &tip); // genesis-first
        let mut headers = Vec::new();
        let mut reached_pp = false;
        for h in &chain {
            let b = self.dag.get(h)?; // a pruned node lacks early headers → None
            headers.push(b.header_only());
            if *h == pp {
                reached_pp = true;
                break;
            }
        }
        // Only a proof that actually anchors at genesis and reaches the pruning
        // point is well-formed; anything else means we can't serve it.
        if !reached_pp || headers.first().map(|b| b.hash()) != Some(genesis_hash()) {
            return None;
        }
        Some(PruningProof { headers })
    }

    /// Build the succinct multi-level pruning proof (see [`superproof`]):
    /// same reachability requirement as [`Self::build_pruning_proof`] (an
    /// archival node), but compresses the settled, older history into an
    /// interlink hop chain instead of shipping every header. `recent_window`
    /// is how many of the most recent blocks stay fully detailed.
    pub fn build_multilevel_pruning_proof(
        &self,
        recent_window: usize,
    ) -> Option<superproof::MultiLevelPruningProof> {
        let pp = self.pruning_point?;
        let tip = ghostdag::selected_tip(&self.ghostdag, &self.tips)?;
        let chain = ghostdag::selected_chain(&self.ghostdag, &tip);
        let mut headers = Vec::new();
        let mut reached_pp = false;
        for h in &chain {
            let b = self.dag.get(h)?;
            headers.push(b.header_only());
            if *h == pp {
                reached_pp = true;
                break;
            }
        }
        if !reached_pp || headers.first().map(|b| b.hash()) != Some(genesis_hash()) {
            return None;
        }
        superproof::build_multilevel_pruning_proof(&headers, recent_window)
    }

    /// Import already-verified pruning-proof headers into the DAG (topology /
    /// PoW scaffolding for cold-start IBD). Bodies are empty — **account
    /// effects are not replayed** (no fake subsidies). Sets `pruning_point` and
    /// `base_frontier` to the tip header so live ledger stays at the captured
    /// base until post-PP blocks arrive with real bodies.
    ///
    /// `headers` must be genesis-first (as produced by a verified linear proof,
    /// or [`superproof::MultiLevelPruningProof::headers_genesis_first`]).
    pub fn import_verified_pruning_headers(&mut self, headers: &[Block]) -> Result<Hash, String> {
        if headers.is_empty() {
            return Err("empty pruning header list".into());
        }
        if headers[0].hash() != genesis_hash() {
            return Err("pruning headers must start at genesis".into());
        }
        // Ensure local genesis matches the proof anchor.
        let local_genesis = genesis_hash();
        if !self.dag.contains_key(&local_genesis) {
            return Err("local genesis missing".into());
        }

        let mut prev_inserted = local_genesis;
        for (i, hdr) in headers.iter().enumerate() {
            let hash = hdr.hash();
            if i == 0 {
                continue; // genesis already present
            }
            if self.dag.contains_key(&hash) {
                prev_inserted = hash;
                continue;
            }
            let header = hdr.header_only();
            // Prefer real GHOSTDAG when every parent is already in the DAG
            // (contiguous linear / recent window). Otherwise attach along the
            // already-imported proof chain (skip hops whose parents were omitted).
            let gd = match ghostdag::try_compute_ghostdag_data(
                &self.dag,
                &self.ghostdag,
                &self.reachability,
                &header.parents,
                MAX_MERGESET_SIZE,
            ) {
                // Real GHOSTDAG only when a selected parent was resolved among
                // known DAG tips. `Ok(genesis())` for unknown parents must not
                // be treated as success for a non-genesis header.
                Ok(gd) if gd.selected_parent.is_some() => gd,
                _ => {
                    let sp_score = self
                        .ghostdag
                        .get(&prev_inserted)
                        .map(|d| d.blue_score)
                        .unwrap_or(0);
                    ghostdag::GhostdagData {
                        blue_score: sp_score.saturating_add(1),
                        selected_parent: Some(prev_inserted),
                        mergeset_blues: vec![prev_inserted],
                        mergeset_reds: vec![],
                    }
                }
            };
            let sp = gd.selected_parent;
            let mergeset: Vec<Hash> = gd
                .mergeset_blues
                .iter()
                .skip(1)
                .chain(gd.mergeset_reds.iter())
                .copied()
                .collect();
            self.dag.insert(hash, header);
            self.ghostdag.insert(hash, gd);
            self.reachability.add_block(hash, sp, &mergeset, &self.dag);
            prev_inserted = hash;
        }

        let pp = headers.last().map(|b| b.hash()).unwrap();
        self.tips = vec![pp];
        self.order_main_chain();
        self.pruning_point = Some(pp);
        // Freeze ledger at pre-import base; do not mint subsidies from empty bodies.
        // Caller must follow with [`Self::adopt_pruning_point_ledger`] so balances
        // match the pruning point (topology alone leaves genesis-empty accounts).
        if !self.base_captured {
            self.base = self.snapshot_ledger();
            self.base_captured = true;
        }
        self.base_frontier = Some(pp);
        let base = self.base.clone();
        self.restore_ledger(&base);
        Ok(pp)
    }

    /// Genesis-replay ledger at `tip` (ignores finalized `base`). Requires full
    /// block bodies along the canonical path — archival nodes have them.
    fn ledger_via_genesis_replay(&self, tip: &Hash) -> Option<Ledger> {
        let order = self.canonical_order_at(tip);
        let mut sim = ChainState::new();
        sim.chain_id = self.chain_id;
        sim.total_supply = self.total_supply;
        sim.block_reward = self.block_reward;
        // Preserve any pre-chain seed that was captured into our base at genesis
        // (test premine). After base_captured, seeds live in base from the first
        // fold; for archival genesis-replay of a PP we start empty unless the
        // caller seeded before any block — match virtual_state_at's pre-capture path.
        if !self.base_captured {
            sim.accounts = self.accounts.clone();
            sim.minted_supply = self.minted_supply;
            sim.fees_burned = self.fees_burned;
            sim.treasury = self.treasury;
            sim.registry = self.registry.clone();
            sim.staked = self.staked.clone();
        }
        sim.base_captured = true;
        for h in &order {
            let block = self.dag.get(h)?;
            if let Some(gd) = self.ghostdag.get(h) {
                sim.ghostdag.insert(*h, gd.clone());
            }
            sim.apply_block_effects(block);
        }
        Some(sim.snapshot_ledger())
    }

    /// Build the pruning-point account ledger for cold-start IBD.
    /// Prefers a cached [`Self::pruning_ledger`]; otherwise archival nodes
    /// genesis-replay to the PP and verify against the header `state_root`.
    pub fn build_pruning_point_ledger(&self) -> Option<PruningPointLedger> {
        let pp = self.pruning_point?;
        let expected = self.dag.get(&pp)?.state_root;
        if let Some(ref cached) = self.pruning_ledger {
            if cached.merkle_root() == expected {
                return Some(PruningPointLedger {
                    pruning_point: pp,
                    ledger: cached.clone(),
                });
            }
        }
        if !self.archival {
            return None;
        }
        let ledger = self.ledger_via_genesis_replay(&pp)?;
        if ledger.merkle_root() != expected {
            return None;
        }
        Some(PruningPointLedger {
            pruning_point: pp,
            ledger,
        })
    }

    /// Adopt a verified pruning-point ledger after header import. Sets `base`,
    /// `base_frontier`, and live accounts to the PP post-state.
    pub fn adopt_pruning_point_ledger(&mut self, msg: &PruningPointLedger) -> Result<(), String> {
        let pp = self
            .pruning_point
            .ok_or_else(|| "no pruning point to adopt ledger for".to_string())?;
        if msg.pruning_point != pp {
            return Err("pruning-point ledger hash mismatch".into());
        }
        let expected = self
            .dag
            .get(&pp)
            .ok_or_else(|| "pruning point header missing".to_string())?
            .state_root;
        if msg.ledger.merkle_root() != expected {
            return Err("pruning-point ledger does not match state_root".into());
        }
        self.base = msg.ledger.clone();
        self.base_captured = true;
        self.base_frontier = Some(pp);
        self.pruning_ledger = Some(msg.ledger.clone());
        self.restore_ledger(&msg.ledger);
        Ok(())
    }

    /// Publish a serving pruning point on an archival node and cache its ledger.
    pub fn set_serving_pruning_point(&mut self, pp: Hash) -> Result<(), String> {
        if !self.dag.contains_key(&pp) {
            return Err("pruning point not in DAG".into());
        }
        self.pruning_point = Some(pp);
        let ledger = self
            .ledger_via_genesis_replay(&pp)
            .ok_or_else(|| "cannot replay ledger to pruning point".to_string())?;
        let expected = self.dag[&pp].state_root;
        if ledger.merkle_root() != expected {
            return Err("replayed ledger does not match PP state_root".into());
        }
        self.pruning_ledger = Some(ledger);
        Ok(())
    }

    /// Per-block difficulty for a child of `parents` at `timestamp_ms`.
    ///
    /// Blue-work weighted DAA: samples up to [`DAA_WINDOW`] blues from the past
    /// of the selected parent (mergeset blues along the selected-parent walk),
    /// scales work-weighted average difficulty toward `TARGET_BLOCK_TIME_MS`,
    /// clamps ±25%, then applies [`era_min_difficulty`].
    pub fn expected_difficulty(&self, parents: &[Hash]) -> u64 {
        let ts = parents
            .iter()
            .filter_map(|p| self.dag.get(p).map(|b| b.timestamp))
            .max()
            .unwrap_or(GENESIS_TIMESTAMP_MS)
            .saturating_add(TARGET_BLOCK_TIME_MS);
        self.expected_difficulty_at(parents, ts)
    }

    /// Same as [`Self::expected_difficulty`] but with an explicit block timestamp
    /// (consensus validation must use the block's claimed time).
    pub fn expected_difficulty_at(&self, parents: &[Hash], timestamp_ms: u64) -> u64 {
        let floor = era_min_difficulty(self.minted_supply, timestamp_ms);
        let selected_parent = match ghostdag::select_parent(&self.ghostdag, parents) {
            Some(sp) => sp,
            None => return floor,
        };
        let sp_difficulty = self
            .dag
            .get(&selected_parent)
            .map(|b| b.difficulty)
            .unwrap_or_else(effective_min_difficulty)
            .max(floor);

        let samples = self.collect_daa_blue_samples(selected_parent);
        let daa = if samples.len() < DAA_WINDOW {
            sp_difficulty
        } else {
            let newest = samples.iter().map(|s| s.0).max().unwrap_or(0);
            let oldest = samples.iter().map(|s| s.0).min().unwrap_or(0);
            let work: u128 = samples.iter().map(|s| s.1 as u128).sum();
            let avg_diff = ((work / samples.len() as u128) as u64).max(floor);
            // Scale the work-weighted average, then clamp ±25% vs the selected
            // parent's difficulty so a single parallel-blue burst cannot spike.
            let scaled = retarget_difficulty(avg_diff, newest, oldest, floor);
            let up = (sp_difficulty as u128 * 5 / 4).max(sp_difficulty as u128 + 1);
            let down = (sp_difficulty as u128 * 3 / 4).max(floor as u128);
            (scaled as u128).clamp(down, up) as u64
        };
        daa.max(floor)
    }

    /// Collect up to [`DAA_WINDOW`] `(timestamp, difficulty)` blue samples from
    /// the past of `selected_parent`: walk the selected-parent chain and, at
    /// each step, append that block's mergeset blues (newest-first). This is
    /// DAG-aware (spam reds are ignored) and work-weighted by the caller.
    fn collect_daa_blue_samples(&self, selected_parent: Hash) -> Vec<(u64, u64)> {
        let mut samples: Vec<(u64, u64)> = Vec::with_capacity(DAA_WINDOW);
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut cursor = Some(selected_parent);
        while let Some(h) = cursor {
            if samples.len() >= DAA_WINDOW {
                break;
            }
            let Some(gd) = self.ghostdag.get(&h) else {
                break;
            };
            // mergeset_blues[0] is the selected parent itself; include full set.
            for blue in &gd.mergeset_blues {
                if samples.len() >= DAA_WINDOW {
                    break;
                }
                if !seen.insert(*blue) {
                    continue;
                }
                if let Some(b) = self.dag.get(blue) {
                    samples.push((b.timestamp, b.difficulty.max(1)));
                }
            }
            // Solo chain: also count the cursor header if mergeset was empty.
            if gd.mergeset_blues.is_empty() && seen.insert(h) {
                if let Some(b) = self.dag.get(&h) {
                    samples.push((b.timestamp, b.difficulty.max(1)));
                }
            }
            cursor = gd.selected_parent;
        }
        samples
    }

    pub fn merkle_root(&self) -> Hash {
        self.snapshot_ledger().merkle_root()
    }

    /// Cheap checks suitable for a read-lock / pre-filter before taking the
    /// write lock for STARK + GHOSTDAG (anti-DoS). Does not mutate state.
    pub fn precheck_block(&self, block: &Block) -> Result<(), String> {
        if self.dag.contains_key(&block.hash()) {
            return Err("Block already known".into());
        }
        if !block.verify_size() {
            return Err("Block base exceeds 22KB limit".into());
        }
        if bincode::serialize(block).unwrap_or_default().len() > MAX_BLOCK_BYTES {
            return Err("Block (with witness) exceeds total size limit".into());
        }
        if block.parents.is_empty() {
            return Err("Block has no parents".into());
        }
        if block.parents.len() > MAX_BLOCK_PARENTS {
            return Err("Too many parents".into());
        }
        {
            let mut seen = HashSet::new();
            for parent in &block.parents {
                if !seen.insert(*parent) {
                    return Err("Duplicate parent in block".into());
                }
                if !self.dag.contains_key(parent) {
                    return Err("Unknown parent block".into());
                }
            }
        }
        let required_difficulty = self.expected_difficulty_at(&block.parents, block.timestamp);
        if block.difficulty != required_difficulty {
            return Err("Wrong difficulty".into());
        }
        let hash = block.hash();
        if !verify_pow(&hash, block.difficulty) {
            return Err("Invalid proof of work".into());
        }
        if block.stark_proof.is_empty() || block.birth_certificate.signature.is_empty() {
            return Err(
                "Header-only / empty-witness blocks are not consensus-admissible".into(),
            );
        }
        // Parse/size gate under the read lock so garbage proofs never take the
        // write lock or run winterfell verify.
        stark::precheck_format(&block.stark_proof)
            .map_err(|e| format!("Invalid STARK proof: {e}"))?;
        let selected_parent = ghostdag::select_parent(&self.ghostdag, &block.parents)
            .ok_or_else(|| "Cannot select parent".to_string())?;
        let expected_interlinks = self
            .dag
            .get(&selected_parent)
            .map(crate::superproof::compute_interlinks)
            .unwrap_or_default();
        if block.interlinks != expected_interlinks {
            return Err("interlinks do not match selected parent".into());
        }
        Ok(())
    }

    /// Cheap header admission gate for headers-first sync: parents, difficulty,
    /// PoW, interlinks — **without** requiring STARK / birth-certificate
    /// witnesses. Full blocks still go through [`Self::precheck_block`] +
    /// `add_block`. Used by P2P to reject junk headers before requesting bodies.
    pub fn precheck_header(&self, header: &Block) -> Result<(), String> {
        if self.dag.contains_key(&header.hash()) {
            return Err("Block already known".into());
        }
        if header.parents.is_empty() {
            return Err("Block has no parents".into());
        }
        if header.parents.len() > MAX_BLOCK_PARENTS {
            return Err("Too many parents".into());
        }
        {
            let mut seen = HashSet::new();
            for parent in &header.parents {
                if !seen.insert(*parent) {
                    return Err("Duplicate parent in block".into());
                }
                if !self.dag.contains_key(parent) {
                    return Err("Unknown parent block".into());
                }
            }
        }
        let required_difficulty = self.expected_difficulty_at(&header.parents, header.timestamp);
        if header.difficulty != required_difficulty {
            return Err("Wrong difficulty".into());
        }
        let hash = header.hash();
        if !verify_pow(&hash, header.difficulty) {
            return Err("Invalid proof of work".into());
        }
        let selected_parent = ghostdag::select_parent(&self.ghostdag, &header.parents)
            .ok_or_else(|| "Cannot select parent".to_string())?;
        let expected_interlinks = self
            .dag
            .get(&selected_parent)
            .map(crate::superproof::compute_interlinks)
            .unwrap_or_default();
        if header.interlinks != expected_interlinks {
            return Err("interlinks do not match selected parent".into());
        }
        Ok(())
    }

    /// Approximate work units for a header's difficulty (higher = more work).
    /// Used only for IBD body-fetch prioritization, not consensus fork choice.
    pub fn header_work_units(difficulty: u64) -> u128 {
        (difficulty as u128).saturating_add(1)
    }

    /// Apply a signed `TransparentTx`, mutating account balances only if the
    /// signature, chain id, nonce, fee, and balance all check out. This is a
    /// fully-authenticated state-transition path: it does real ML-DSA-87
    /// (post-quantum) signature verification plus nonce/balance checks.
    ///
    /// All validation happens before any mutation, and the recipient credit is
    /// overflow-checked *before* the sender is debited, so a rejected transfer
    /// never leaves balances partially updated. The fee leaves the sender; block
    /// admission credits it to the miner coinbase (v26+). Standalone / mempool
    /// callers must not treat the fee as burned.
    pub fn apply_transparent_tx(&mut self, tx: &TransparentTx) -> Result<(), String> {
        if !ACCOUNT_PEER_TRANSFERS {
            return Err(
                "Account peer transfers disabled (v27); use UTXO for value moves".into(),
            );
        }
        tx.validate_form()?;
        if tx.chain_id != self.chain_id {
            return Err("Wrong chain_id".into());
        }
        if !tx.verify() {
            return Err("Invalid signature".into());
        }

        let media_blue = self.selected_tip_blue_score();
        if tx.lock_blue_score > 0 && media_blue < tx.lock_blue_score {
            return Err(format!(
                "Absolute lock: media blue {media_blue} < lock {}",
                tx.lock_blue_score
            ));
        }
        let last_spend = self
            .accounts
            .get(&tx.from)
            .map(|a| a.last_spend_blue)
            .unwrap_or(0);
        if tx.relative_lock_blues > 0 {
            let unlock_at = last_spend.saturating_add(tx.relative_lock_blues as u64);
            if media_blue < unlock_at {
                return Err(format!(
                    "Relative lock: media blue {media_blue} < unlock {unlock_at}"
                ));
            }
        }
        if let Some(h) = &tx.hashlock {
            let commit = crate::predicate::hashlock_commitment(&tx.hashlock_preimage);
            if &commit != h {
                return Err("Hashlock preimage mismatch".into());
            }
        }

        let sender_nonce = self.accounts.get(&tx.from).map(|a| a.nonce).unwrap_or(0);
        if tx.nonce != sender_nonce {
            return Err(format!(
                "Bad nonce: expected {}, got {}",
                sender_nonce, tx.nonce
            ));
        }

        let total = tx.amount.checked_add(tx.fee).ok_or("amount+fee overflow")?;
        let sender_balance = self.accounts.get(&tx.from).map(|a| a.balance).unwrap_or(0);
        if sender_balance < total {
            return Err("Insufficient balance".into());
        }

        let recipient_balance = self.accounts.get(&tx.to).map(|a| a.balance).unwrap_or(0);
        let new_recipient_balance = recipient_balance
            .checked_add(tx.amount)
            .ok_or("Recipient balance overflow")?;

        {
            let sender = self.accounts.entry(tx.from.clone()).or_default();
            sender.balance -= total;
            sender.nonce = sender.nonce.saturating_add(1);
            sender.last_spend_blue = media_blue;
        }
        {
            let recipient = self.accounts.entry(tx.to.clone()).or_default();
            recipient.balance = new_recipient_balance;
        }
        // Fee is not burned here — block `apply_block_reward` pays it to the miner.

        Ok(())
    }

    /// Bridge account overlay value into a spendable UTXO (hybrid ledger).
    pub fn bridge_account_to_utxo(
        &mut self,
        address: &str,
        amount: u128,
        media_blue: u64,
    ) -> Result<utxo::OutPoint, String> {
        if amount < utxo::UTXO_DUST {
            return Err(format!("Bridge amount below dust ({})", utxo::UTXO_DUST));
        }
        if !security::is_valid_address(address) {
            return Err("Invalid address".into());
        }
        let acct = self.accounts.get_mut(address).ok_or("Account missing")?;
        if acct.balance < amount {
            return Err("Insufficient balance".into());
        }
        acct.balance -= amount;
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"hassan-bridge-utxo-v1");
        hasher.update(address.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(&media_blue.to_le_bytes());
        hasher.update(&acct.nonce.to_le_bytes());
        hasher.update(self.utxo.commitment().as_bytes());
        let mut txid = [0u8; HASH_SIZE];
        hasher.finalize_xof().fill(&mut txid);
        let op = utxo::OutPoint {
            txid: Hash(txid),
            vout: 0,
        };
        self.utxo.insert(
            op,
            utxo::TxOut {
                value: amount,
                predicate: predicate::Predicate::PayToAddress {
                    address: address.to_string(),
                },
                created_blue: media_blue,
            },
        );
        Ok(op)
    }

    fn account_balance(&self, addr: &str) -> u128 {
        self.accounts.get(addr).map(|a| a.balance).unwrap_or(0)
    }
    fn account_nonce(&self, addr: &str) -> u64 {
        self.accounts.get(addr).map(|a| a.nonce).unwrap_or(0)
    }

    /// Read-only validation of a *sequence* of transparent transfers as they
    /// would apply in order, WITHOUT mutating real state. Needed because two
    /// transfers from the same sender in one block must use consecutive nonces
    /// and the second sees the first's debit — a per-tx check against current
    /// state alone would wrongly accept or reject them. Mirrors
    /// Admit a transparent transfer to the mempool. Enforces a valid signature,
    /// matching chain id, a nonce at or ahead of the account's current nonce,
    /// package-depth / balance prechecks, and the mempool bound. Block assembly
    /// still re-validates the selected subset.
    ///
    /// REPLACE-BY-FEE (RBF): if a transfer at the same sender+nonce is already
    /// queued, the incoming one replaces it *only* if it raises the **package**
    /// total fee by at least [`MIN_TX_FEE`]. The package is that conflicting
    /// transfer plus any already-queued contiguous higher-nonce descendants
    /// from the same sender (CPFP children). With descendants kept in place
    /// this reduces to a BIP-125-style bump of the replaced tx alone, but the
    /// check is expressed over the package so a child paying for a parent is
    /// visible in the replacement floor / error path.
    pub fn admit_transparent_to_mempool(&mut self, tx: TransparentTx) -> Result<(), String> {
        if !ACCOUNT_PEER_TRANSFERS {
            return Err(
                "Account peer transfers disabled (v27); use UTXO for value moves".into(),
            );
        }
        let tx_hash = tx.tx_hash();
        tx.validate_form()?;
        if tx.chain_id != self.chain_id {
            return Err("Wrong chain_id".into());
        }
        if !tx.verify() {
            return Err("Invalid signature".into());
        }
        let tip = self.account_nonce(&tx.from);
        if tx.nonce < tip {
            return Err("Nonce already used".into());
        }
        let depth = (tx.nonce - tip + 1) as usize;
        if depth > MAX_MEMPOOL_PACKAGE_NONCES {
            return Err(format!(
                "Package nonce depth {depth} exceeds limit {MAX_MEMPOOL_PACKAGE_NONCES}"
            ));
        }
        // Congestion floor: once the mempool is full, refuse fees that cannot
        // beat the live min-relay (same units as fee estimator / FeeFilter).
        let relay_floor = self.current_min_relay_fee();
        if tx.fee < relay_floor && self.transparent_mempool.len() >= MAX_MEMPOOL_SIZE {
            return Err(format!(
                "Fee {0} below current min relay fee {relay_floor}",
                tx.fee
            ));
        }
        self.mempool_balance_precheck(&tx)?;
        let incoming_bytes = tx.relay_bytes();
        let mempool_bytes: usize = self
            .transparent_mempool
            .iter()
            .map(|t| t.relay_bytes())
            .sum();
        if mempool_bytes.saturating_add(incoming_bytes) > MAX_MEMPOOL_BYTES
            && self
                .transparent_mempool
                .iter()
                .position(|t| t.from == tx.from && t.nonce == tx.nonce)
                .is_none()
        {
            // Byte-budget eviction: drop lowest package-feerate until it fits,
            // or reject if incoming cannot outbid.
            let by_sender = mempool_index_by_sender(&self.transparent_mempool);
            let tip_nonce = tip;
            let (incoming_fee, incoming_len) =
                incoming_package_score(&tx, &self.transparent_mempool, tip_nonce);
            loop {
                let used: usize = self
                    .transparent_mempool
                    .iter()
                    .map(|t| t.relay_bytes())
                    .sum();
                if used.saturating_add(incoming_bytes) <= MAX_MEMPOOL_BYTES {
                    break;
                }
                if self.transparent_mempool.is_empty() {
                    return Err("Transparent mempool byte budget exceeded".into());
                }
                let (idx, lowest_fee, lowest_len) = self
                    .transparent_mempool
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        let (fee, len) = descendant_package_score(t, &by_sender);
                        (i, fee, len)
                    })
                    .min_by(|a, b| {
                        cmp_package_feerate(a.1, a.2, b.1, b.2)
                            .then_with(|| a.1.cmp(&b.1))
                            .then_with(|| a.0.cmp(&b.0))
                    })
                    .map(|(i, fee, len)| (i, fee, len))
                    .ok_or("Transparent mempool byte budget exceeded")?;
                let beats = matches!(
                    cmp_package_feerate(incoming_fee, incoming_len, lowest_fee, lowest_len),
                    Ordering::Greater
                ) || (cmp_package_feerate(
                    incoming_fee,
                    incoming_len,
                    lowest_fee,
                    lowest_len,
                ) == Ordering::Equal
                    && incoming_fee > lowest_fee);
                if !beats {
                    return Err("Transparent mempool byte budget exceeded".into());
                }
                self.transparent_mempool.remove(idx);
            }
        }
        if let Some(existing_idx) = self
            .transparent_mempool
            .iter()
            .position(|t| t.from == tx.from && t.nonce == tx.nonce)
        {
            let existing_fee = self.transparent_mempool[existing_idx].fee;
            let descendant_fees = self.descendant_package_fees(&tx.from, tx.nonce.saturating_add(1));
            let old_package_fee = existing_fee.saturating_add(descendant_fees);
            let new_package_fee = tx.fee.saturating_add(descendant_fees);
            let min_package_fee = old_package_fee.saturating_add(MIN_TX_FEE);
            if new_package_fee < min_package_fee {
                return Err(format!(
                    "Replacement (package RBF) must raise the package fee by at least {MIN_TX_FEE} \
                     (queued tx fee {existing_fee}, descendant fees {descendant_fees}, \
                     package {old_package_fee} → need package >= {min_package_fee}, got tx fee {} / package {new_package_fee})",
                    tx.fee
                ));
            }
            self.transparent_mempool.remove(existing_idx);
            self.transparent_mempool.push(tx);
            economics::record_first_seen(self, tx_hash);
            return Ok(());
        }
        if self.transparent_mempool.len() >= MAX_MEMPOOL_SIZE {
            // Evict the lowest *descendant-package* fee-rate entry if the
            // incoming *package* outbids it — so a low-fee parent paid for by a
            // high-fee child (CPFP) is not dropped out from under the child,
            // and an incoming CPFP child is scored with its ancestors.
            let by_sender = mempool_index_by_sender(&self.transparent_mempool);
            let (idx, lowest_rate_fee, lowest_rate_len) = self
                .transparent_mempool
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let (fee, len) = descendant_package_score(t, &by_sender);
                    (i, fee, len)
                })
                .min_by(|a, b| {
                    cmp_package_feerate(a.1, a.2, b.1, b.2)
                        .then_with(|| a.1.cmp(&b.1))
                        .then_with(|| a.0.cmp(&b.0))
                })
                .map(|(i, fee, len)| (i, fee, len))
                .ok_or("Transparent mempool is full")?;
            let (incoming_fee, incoming_len) =
                incoming_package_score(&tx, &self.transparent_mempool, tip);
            let incoming_beats = matches!(
                cmp_package_feerate(incoming_fee, incoming_len, lowest_rate_fee, lowest_rate_len),
                Ordering::Greater
            ) || (cmp_package_feerate(
                incoming_fee,
                incoming_len,
                lowest_rate_fee,
                lowest_rate_len,
            ) == Ordering::Equal
                && incoming_fee > lowest_rate_fee);
            if !incoming_beats {
                return Err("Transparent mempool is full".into());
            }
            self.transparent_mempool.remove(idx);
        }
        self.transparent_mempool.push(tx);
        economics::record_first_seen(self, tx_hash);
        Ok(())
    }

    /// Admit a signed UTXO spend to the mempool (v27 primary peer-value path).
    ///
    /// Policy (Bitcoin/Kaspa-class where applicable):
    /// - May spend confirmed UTXOs or outputs of already-queued mempool txs
    ///   (CPFP), subject to [`MAX_UTXO_PACKAGE_COUNT`] / [`MAX_UTXO_PACKAGE_BYTES`].
    /// - Conflicting inputs are replaced when the new tx pays at least
    ///   `conflict_fee + MIN_TX_FEE` absolute fee *and* a strictly higher
    ///   feerate; conflict set includes descendants that spend the conflicting
    ///   txs' outputs.
    /// - Under byte/count pressure, evict lowest ancestor-package feerate first.
    pub fn admit_utxo_to_mempool(&mut self, tx: utxo_tx::UtxoTx) -> Result<(), String> {
        tx.validate_form()?;
        if tx.chain_id != self.chain_id {
            return Err("Wrong chain_id".into());
        }
        if !tx.verify() {
            return Err("Invalid signature".into());
        }
        let media = self.selected_tip_blue_score();
        let txid = tx.txid();
        if self.utxo_mempool.iter().any(|t| t.txid() == txid) {
            return Err("UTXO tx already in mempool".into());
        }

        // Collect conflicting mempool txs (shared inputs) + their descendants.
        let mut conflict_idxs: Vec<usize> = Vec::new();
        for (i, queued) in self.utxo_mempool.iter().enumerate() {
            let conflicts = tx.inputs.iter().any(|tin| {
                queued.inputs.iter().any(|q| q.previous == tin.previous)
            });
            if conflicts {
                conflict_idxs.push(i);
            }
        }
        // Descendants of conflicts (spend conflict outputs) must leave too.
        if !conflict_idxs.is_empty() {
            let mut expanded = conflict_idxs.clone();
            let mut changed = true;
            while changed {
                changed = false;
                let conflict_txids: HashSet<Hash> = expanded
                    .iter()
                    .map(|&i| self.utxo_mempool[i].tx_hash())
                    .collect();
                for (i, queued) in self.utxo_mempool.iter().enumerate() {
                    if expanded.contains(&i) {
                        continue;
                    }
                    let spends_conflict = queued.inputs.iter().any(|tin| {
                        conflict_txids.contains(&tin.previous.txid)
                    });
                    if spends_conflict {
                        expanded.push(i);
                        changed = true;
                    }
                }
            }
            conflict_idxs = expanded;
        }

        // Preview UTXO set: confirmed + mempool outputs, minus conflicts.
        let skip: HashSet<usize> = conflict_idxs.iter().copied().collect();
        let (mut utxo, mut accounts) = self.utxo_mempool_preview(&skip);
        let mut fee = 0u128;
        utxo_tx::apply_utxo_tx(&mut utxo, &mut accounts, &tx, media, &mut fee)?;

        let incoming_bytes = tx.relay_bytes().max(1) as u128;
        let incoming_rate = tx.fee / incoming_bytes;

        // Ancestor package of the incoming tx (parents already in mempool).
        let parent_idxs = self.utxo_mempool_direct_parents(&tx, &skip);
        let mut package_idxs = parent_idxs;
        // Expand ancestors.
        let mut queue = package_idxs.clone();
        let mut qi = 0;
        while qi < queue.len() {
            let idx = queue[qi];
            qi += 1;
            let parents = self.utxo_mempool_direct_parents(&self.utxo_mempool[idx], &skip);
            for p in parents {
                if !package_idxs.contains(&p) {
                    package_idxs.push(p);
                    queue.push(p);
                }
            }
            if package_idxs.len() >= MAX_UTXO_PACKAGE_COUNT {
                break;
            }
        }
        let package_count = package_idxs.len().saturating_add(1); // + incoming
        if package_count > MAX_UTXO_PACKAGE_COUNT {
            return Err(format!(
                "UTXO ancestor package exceeds count limit {MAX_UTXO_PACKAGE_COUNT}"
            ));
        }
        let package_bytes: usize = package_idxs
            .iter()
            .map(|&i| self.utxo_mempool[i].relay_bytes())
            .sum::<usize>()
            .saturating_add(tx.relay_bytes());
        if package_bytes > MAX_UTXO_PACKAGE_BYTES {
            return Err(format!(
                "UTXO ancestor package exceeds byte limit {MAX_UTXO_PACKAGE_BYTES}"
            ));
        }
        let package_fee: u128 = package_idxs
            .iter()
            .map(|&i| self.utxo_mempool[i].fee)
            .sum::<u128>()
            .saturating_add(tx.fee);
        let incoming_pkg_rate = package_fee / (package_bytes.max(1) as u128);

        if !conflict_idxs.is_empty() {
            let conflict_fee: u128 = conflict_idxs
                .iter()
                .map(|&i| self.utxo_mempool[i].fee)
                .sum();
            let conflict_bytes: u128 = conflict_idxs
                .iter()
                .map(|&i| self.utxo_mempool[i].relay_bytes().max(1) as u128)
                .sum::<u128>()
                .max(1);
            let conflict_rate = conflict_fee / conflict_bytes;
            let min_bump = conflict_fee.saturating_add(crate::MIN_TX_FEE);
            if tx.fee < min_bump || incoming_rate <= conflict_rate {
                return Err("UTXO input conflicts with mempool".into());
            }
            conflict_idxs.sort_unstable_by(|a, b| b.cmp(a));
            for i in conflict_idxs {
                let old = self.utxo_mempool.remove(i);
                self.tx_first_seen_blue.remove(&old.txid());
                self.tx_first_seen_ms.remove(&old.txid());
            }
        }

        let used: usize = self.utxo_mempool.iter().map(|t| t.relay_bytes()).sum();
        let incoming_raw = tx.relay_bytes();
        if used.saturating_add(incoming_raw) > MAX_MEMPOOL_BYTES {
            let mut ranked: Vec<(usize, u128)> = self
                .utxo_mempool
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let (fee, bytes) = self.utxo_ancestor_package_score(i);
                    (i, fee / bytes.max(1))
                })
                .collect();
            ranked.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)));
            let mut used_now = used;
            let mut remove: Vec<usize> = Vec::new();
            for (i, rate) in ranked {
                if used_now.saturating_add(incoming_raw) <= MAX_MEMPOOL_BYTES {
                    break;
                }
                if rate >= incoming_pkg_rate {
                    break;
                }
                used_now = used_now.saturating_sub(self.utxo_mempool[i].relay_bytes());
                remove.push(i);
            }
            if used_now.saturating_add(incoming_raw) > MAX_MEMPOOL_BYTES {
                return Err("UTXO mempool byte budget exceeded".into());
            }
            remove.sort_unstable_by(|a, b| b.cmp(a));
            for i in remove {
                let old = self.utxo_mempool.remove(i);
                self.tx_first_seen_blue.remove(&old.txid());
                self.tx_first_seen_ms.remove(&old.txid());
            }
        }
        if self.utxo_mempool.len() >= MAX_MEMPOOL_SIZE {
            let worst = self
                .utxo_mempool
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let (fee, bytes) = self.utxo_ancestor_package_score(i);
                    (i, fee / bytes.max(1), fee)
                })
                .min_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
            match worst {
                Some((i, rate, fee))
                    if incoming_pkg_rate > rate
                        || (incoming_pkg_rate == rate && tx.fee > fee) =>
                {
                    let old = self.utxo_mempool.remove(i);
                    self.tx_first_seen_blue.remove(&old.txid());
                    self.tx_first_seen_ms.remove(&old.txid());
                }
                _ => return Err("UTXO mempool is full".into()),
            }
        }
        economics::record_first_seen(self, txid);
        self.utxo_mempool.push(tx);
        Ok(())
    }

    /// Confirmed UTXO set plus outputs of non-skipped mempool txs (topo apply).
    fn utxo_mempool_preview(
        &self,
        skip: &HashSet<usize>,
    ) -> (utxo::UtxoSet, HashMap<String, Account>) {
        let mut utxo = self.utxo.clone();
        let mut accounts = self.accounts.clone();
        let media = self.selected_tip_blue_score();
        let mut pending: Vec<&utxo_tx::UtxoTx> = self
            .utxo_mempool
            .iter()
            .enumerate()
            .filter(|(i, _)| !skip.contains(i))
            .map(|(_, t)| t)
            .collect();
        for _ in 0..pending.len().saturating_add(1) {
            let mut next = Vec::new();
            let mut progress = false;
            for tx in pending {
                let mut fee = 0u128;
                let mut u = utxo.clone();
                let mut a = accounts.clone();
                if utxo_tx::apply_utxo_tx(&mut u, &mut a, tx, media, &mut fee).is_ok() {
                    utxo = u;
                    accounts = a;
                    progress = true;
                } else {
                    next.push(tx);
                }
            }
            if !progress {
                break;
            }
            pending = next;
        }
        (utxo, accounts)
    }

    /// Mempool indices whose outputs are spent by `tx` (direct parents).
    fn utxo_mempool_direct_parents(
        &self,
        tx: &utxo_tx::UtxoTx,
        skip: &HashSet<usize>,
    ) -> Vec<usize> {
        let mut out = Vec::new();
        for (i, queued) in self.utxo_mempool.iter().enumerate() {
            if skip.contains(&i) {
                continue;
            }
            let qid = queued.tx_hash();
            let is_parent = tx.inputs.iter().any(|tin| tin.previous.txid == qid);
            if is_parent {
                out.push(i);
            }
        }
        out
    }

    /// Ancestor package fee/bytes for mempool index `idx` (inclusive).
    fn utxo_ancestor_package_score(&self, idx: usize) -> (u128, u128) {
        let skip = HashSet::new();
        let mut idxs = vec![idx];
        let mut queue = vec![idx];
        let mut qi = 0;
        while qi < queue.len() {
            let cur = queue[qi];
            qi += 1;
            for p in self.utxo_mempool_direct_parents(&self.utxo_mempool[cur], &skip) {
                if !idxs.contains(&p) {
                    idxs.push(p);
                    queue.push(p);
                }
            }
            if idxs.len() >= MAX_UTXO_PACKAGE_COUNT {
                break;
            }
        }
        let fee: u128 = idxs.iter().map(|&i| self.utxo_mempool[i].fee).sum();
        let bytes: u128 = idxs
            .iter()
            .map(|&i| self.utxo_mempool[i].relay_bytes().max(1) as u128)
            .sum();
        (fee, bytes.max(1))
    }

    /// Select a conflict-free UTXO subset for block templates (ancestor-package
    /// feerate descending — CPFP-aware).
    pub fn select_valid_utxo_txs(&self, candidates: &[utxo_tx::UtxoTx]) -> Vec<utxo_tx::UtxoTx> {
        let mut ranked: Vec<(usize, &utxo_tx::UtxoTx)> =
            candidates.iter().enumerate().map(|(i, t)| (i, t)).collect();
        // Score each candidate alone by feerate; full mempool ancestor score
        // applies when selecting from `utxo_mempool` (indices align).
        ranked.sort_by(|a, b| {
            let rate_a = a.1.fee / (a.1.relay_bytes().max(1) as u128);
            let rate_b = b.1.fee / (b.1.relay_bytes().max(1) as u128);
            rate_b
                .cmp(&rate_a)
                .then_with(|| b.1.fee.cmp(&a.1.fee))
                .then_with(|| a.1.txid().cmp(&b.1.txid()))
        });
        let mut utxo = self.utxo.clone();
        let mut accounts = self.accounts.clone();
        let media = self.selected_tip_blue_score();
        let mut out = Vec::new();
        for (_, tx) in ranked {
            let mut fee = 0u128;
            let mut u = utxo.clone();
            let mut a = accounts.clone();
            if utxo_tx::apply_utxo_tx(&mut u, &mut a, tx, media, &mut fee).is_ok() {
                utxo = u;
                accounts = a;
                out.push(tx.clone());
            }
        }
        out
    }

    /// Reject underfunded packages at admit time (DoS): if the sender's
    /// contiguous tip→nonce chain is present (after substituting `tx`), dry-run
    /// balances; otherwise require `amount+fee ≤` current free balance so a
    /// single gap orphan still cannot exceed the account.
    fn mempool_balance_precheck(&self, tx: &TransparentTx) -> Result<(), String> {
        let tip = self.account_nonce(&tx.from);
        let mut by_nonce: BTreeMap<u64, TransparentTx> = BTreeMap::new();
        for t in &self.transparent_mempool {
            if t.from == tx.from {
                by_nonce.insert(t.nonce, t.clone());
            }
        }
        by_nonce.insert(tx.nonce, tx.clone());

        if let Some(pkg) = ancestor_package(&by_nonce, tip, tx.nonce) {
            let mut bal = self.account_balance(&tx.from);
            // Debits to `from` only; credits to self are ignored (conservative).
            for t in pkg {
                let need = t
                    .amount
                    .checked_add(t.fee)
                    .ok_or_else(|| "amount+fee overflow".to_string())?;
                if bal < need {
                    return Err("Insufficient balance".into());
                }
                bal -= need;
            }
            return Ok(());
        }

        let need = tx
            .amount
            .checked_add(tx.fee)
            .ok_or_else(|| "amount+fee overflow".to_string())?;
        if self.account_balance(&tx.from) < need {
            return Err("Insufficient balance".into());
        }
        Ok(())
    }

    /// Sum of fees for the contiguous higher-nonce run from `start_nonce`
    /// upward for `from` (descendants in an account-nonce package). Used by
    /// package-aware RBF.
    fn descendant_package_fees(&self, from: &str, start_nonce: u64) -> u128 {
        let mut total = 0u128;
        let mut n = start_nonce;
        loop {
            match self
                .transparent_mempool
                .iter()
                .find(|t| t.from == from && t.nonce == n)
            {
                Some(t) => {
                    total = total.saturating_add(t.fee);
                    n = n.saturating_add(1);
                }
                None => break,
            }
        }
        total
    }

    /// Effective minimum fee to be admitted right now, given mempool
    /// congestion: the protocol floor normally; once either pool is ≥75% full
    /// it rises toward the lowest queued fee (strictly above the worst), and
    /// at 100% full it is whatever beats the lowest-fee entry — mirroring how
    /// Bitcoin's min relay fee rises under load.
    pub fn current_min_relay_fee(&self) -> u128 {
        let floor = typical_signed_tx_min_fee();
        let utxo_len = self.utxo_mempool.len();
        let acct_len = self.transparent_mempool.len();
        let utxo_full = utxo_len >= MAX_MEMPOOL_SIZE;
        let acct_full = acct_len >= MAX_MEMPOOL_SIZE;
        let utxo_hot = utxo_len * 4 >= MAX_MEMPOOL_SIZE * 3;
        let acct_hot = acct_len * 4 >= MAX_MEMPOOL_SIZE * 3;
        if !utxo_full && !acct_full && !utxo_hot && !acct_hot {
            return floor;
        }
        let mut min_fee = floor;
        if acct_hot || acct_full {
            if let Some(f) = self.transparent_mempool.iter().map(|t| t.fee).min() {
                min_fee = min_fee.max(if acct_full {
                    f.saturating_add(1)
                } else {
                    f
                });
            }
        }
        if utxo_hot || utxo_full {
            if let Some(f) = self.utxo_mempool.iter().map(|t| t.fee).min() {
                min_fee = min_fee.max(if utxo_full {
                    f.saturating_add(1)
                } else {
                    f
                });
            }
        }
        min_fee.max(floor)
    }

    /// Confirmation-target fee estimate (Bitcoin Core–style).
    ///
    /// For each target T ∈ {high≈6, medium≈20, low≈100} blues: prefer a
    /// success-rate walk over fee history (plus mempool waiters older than T
    /// counted as failures, like Core tracking unconfirmed samples); otherwise
    /// fall back to live mempool percentiles. Always floored at
    /// [`current_min_relay_fee`] for a typical signed transfer, and tiers are
    /// forced monotonic (`high ≥ medium ≥ low`) the way `estimateSmartFee`
    /// takes the max of its sub-estimates. Active path samples include UTXO
    /// mempool feerates (v27 primary value path).
    pub fn estimate_fee(&self) -> FeeEstimate {
        let floor = self.current_min_relay_fee();
        let typical_bytes =
            (PQ_PUBLIC_KEY_SIZE + PQ_SIGNATURE_SIZE + 512).max(1) as u128;
        let rate_to_fee = |rate: u128| -> u128 {
            rate.saturating_mul(typical_bytes).max(floor)
        };
        let (package_count, best_package_fee) = self.mempool_package_stats();
        let tip_blue = self.selected_tip_blue_score();

        let mempool_pick = |pct: usize| -> Option<u128> {
            let mut fees: Vec<u128> = self
                .transparent_mempool
                .iter()
                .map(|t| t.fee)
                .chain(self.utxo_mempool.iter().map(|t| t.fee))
                .collect();
            if fees.is_empty() {
                return None;
            }
            fees.sort_unstable();
            let idx = (fees.len().saturating_sub(1) * pct) / 100;
            Some(fees[idx].max(floor))
        };

        let tier = |target: u64, mempool_pct: usize| -> u128 {
            // Mempool txs waiting longer than `target` blues are failures for
            // their feerate (Bitcoin Core counts still-unconfirmed samples).
            let mut extra: Vec<(u128, bool)> = Vec::new();
            for tx in &self.transparent_mempool {
                let Some(seen) = self.tx_first_seen_blue.get(&tx.tx_hash()) else {
                    continue;
                };
                let lag = tip_blue.saturating_sub(*seen);
                if lag > target {
                    let bytes = tx.relay_bytes().max(1) as u128;
                    extra.push((tx.fee / bytes, false));
                }
            }
            for tx in &self.utxo_mempool {
                let Some(seen) = self.tx_first_seen_blue.get(&tx.txid()) else {
                    continue;
                };
                let lag = tip_blue.saturating_sub(*seen);
                if lag > target {
                    let bytes = tx.relay_bytes().max(1) as u128;
                    extra.push((tx.fee / bytes, false));
                }
            }
            if let Some(rate) = self
                .fee_history
                .estimate_for_target_with_extra(target, &extra)
            {
                return rate_to_fee(rate);
            }
            mempool_pick(mempool_pct).unwrap_or(floor)
        };

        let low = tier(FEE_TARGET_LOW_BLUES, 10);
        let mut medium = tier(FEE_TARGET_MEDIUM_BLUES, 50);
        let mut high = tier(FEE_TARGET_HIGH_BLUES, 90);
        if medium < low {
            medium = low;
        }
        if high < medium {
            high = medium;
        }

        FeeEstimate {
            low,
            medium,
            high,
            mempool_txs: self.transparent_mempool.len() + self.utxo_mempool.len(),
            package_count,
            best_package_fee,
            high_target_blues: FEE_TARGET_HIGH_BLUES,
            medium_target_blues: FEE_TARGET_MEDIUM_BLUES,
            low_target_blues: FEE_TARGET_LOW_BLUES,
        }
    }

    /// Count maximal includable ancestor packages (one per sender with a
    /// contiguous nonce run from the account tip) and the total fee of the
    /// best-scoring package prefix (highest fee-rate, then highest total fee).
    fn mempool_package_stats(&self) -> (usize, u128) {
        let by_sender = mempool_index_by_sender(&self.transparent_mempool);
        let mut package_count = 0usize;
        let mut best_fee = 0u128;
        let mut best_len = 1usize;
        for (from, by_nonce) in &by_sender {
            let tip = self.account_nonce(from);
            let chain = contiguous_nonce_chain(by_nonce, tip);
            if chain.is_empty() {
                continue;
            }
            package_count += 1;
            let mut running = 0u128;
            for (i, tx) in chain.iter().enumerate() {
                running = running.saturating_add(tx.fee);
                let len = i + 1;
                let better = match cmp_package_feerate(running, len, best_fee, best_len) {
                    Ordering::Greater => true,
                    Ordering::Equal => running > best_fee,
                    Ordering::Less => false,
                };
                if better {
                    best_fee = running;
                    best_len = len;
                }
            }
        }
        (package_count, best_fee)
    }

    /// Select a valid, mutually-consistent subset of candidate transfers for a
    /// block. Skips anything that would break the account nonce/balance sequence.
    ///
    /// Ancestor-package aware (account-nonce CPFP): candidates are ranked by
    /// *ancestor package fee-rate* `(sum of fees in the contiguous nonce chain
    /// from the account tip through this tx) / package length`. When a
    /// high-fee child is considered, its still-unconfirmed lower-nonce parents
    /// are pulled in as a package so the child can pay for them — the same
    /// role Bitcoin's ancestor packages play for UTXO CPFP.
    pub fn select_valid_block_txs(&self, transfers: &[TransparentTx]) -> Vec<TransparentTx> {
        if transfers.is_empty() {
            return Vec::new();
        }
        let by_sender = mempool_index_by_sender(transfers);

        #[derive(Clone)]
        struct Ranked {
            from: String,
            nonce: u64,
            pkg_fee: u128,
            pkg_len: usize,
            fee: u128,
            tx_hash: Hash,
        }

        let mut ranked: Vec<Ranked> = Vec::new();
        for (from, by_nonce) in &by_sender {
            let tip = self.account_nonce(from);
            for &n in by_nonce.keys() {
                let Some(pkg) = ancestor_package(by_nonce, tip, n) else {
                    continue;
                };
                let pkg_fee: u128 = pkg.iter().map(|t| t.fee).sum();
                let pkg_len: usize = pkg.iter().map(|t| t.relay_bytes()).sum::<usize>().max(1);
                let tx = by_nonce.get(&n).expect("key present");
                ranked.push(Ranked {
                    from: from.clone(),
                    nonce: n,
                    pkg_fee,
                    pkg_len,
                    fee: tx.fee,
                    tx_hash: tx.tx_hash(),
                });
            }
        }
        ranked.sort_by(|a, b| {
            cmp_package_feerate(a.pkg_fee, a.pkg_len, b.pkg_fee, b.pkg_len)
                .reverse()
                .then_with(|| b.pkg_fee.cmp(&a.pkg_fee))
                .then_with(|| b.fee.cmp(&a.fee))
                .then_with(|| a.tx_hash.cmp(&b.tx_hash))
        });

        let mut bal: HashMap<String, u128> = HashMap::new();
        let mut nonce_overlay: HashMap<String, u64> = HashMap::new();
        let mut selected: HashSet<(String, u64)> = HashSet::new();
        let mut good_transfers = Vec::new();

        for cand in &ranked {
            if selected.contains(&(cand.from.clone(), cand.nonce)) {
                continue;
            }
            let tip = *nonce_overlay
                .get(&cand.from)
                .unwrap_or(&self.account_nonce(&cand.from));
            if cand.nonce < tip {
                continue;
            }
            let Some(by_nonce) = by_sender.get(&cand.from) else {
                continue;
            };
            let Some(pkg) = ancestor_package(by_nonce, tip, cand.nonce) else {
                continue;
            };

            let mut tmp_bal = bal.clone();
            let mut tmp_nonce = nonce_overlay.clone();
            let mut batch = Vec::with_capacity(pkg.len());
            let mut ok = true;
            for tx in pkg {
                if selected.contains(&(tx.from.clone(), tx.nonce)) {
                    continue;
                }
                if tx.validate_form().is_err() || tx.chain_id != self.chain_id || !tx.verify() {
                    ok = false;
                    break;
                }
                let cur_nonce = *tmp_nonce
                    .get(&tx.from)
                    .unwrap_or(&self.account_nonce(&tx.from));
                if tx.nonce != cur_nonce {
                    ok = false;
                    break;
                }
                let Some(debit) = tx.amount.checked_add(tx.fee) else {
                    ok = false;
                    break;
                };
                let cur_bal = *tmp_bal
                    .get(&tx.from)
                    .unwrap_or(&self.account_balance(&tx.from));
                if cur_bal < debit {
                    ok = false;
                    break;
                }
                let cur_to = *tmp_bal.get(&tx.to).unwrap_or(&self.account_balance(&tx.to));
                let Some(new_to) = cur_to.checked_add(tx.amount) else {
                    ok = false;
                    break;
                };
                tmp_bal.insert(tx.from.clone(), cur_bal - debit);
                tmp_nonce.insert(tx.from.clone(), cur_nonce.saturating_add(1));
                tmp_bal.insert(tx.to.clone(), new_to);
                batch.push(tx.clone());
            }
            if !ok || batch.is_empty() {
                continue;
            }
            for tx in batch {
                selected.insert((tx.from.clone(), tx.nonce));
                good_transfers.push(tx);
            }
            bal = tmp_bal;
            nonce_overlay = tmp_nonce;
        }
        good_transfers
    }

    /// Admit a signed registry / escrow op to the mempool.
    pub fn admit_registry_to_mempool(&mut self, op: registry::RegistryOp) -> Result<(), String> {
        if op.chain_id() != self.chain_id {
            return Err("Wrong chain_id".into());
        }
        if !op.verify() {
            return Err("Invalid signature".into());
        }
        // Public mode: tiny fee-less mempool — CPU sig verify is the cost;
        // keep the queue small so API floods cannot pin megabytes + ML-DSA work.
        let cap = if crate::net_policy::policy().public_mode {
            256
        } else {
            10_000
        };
        if self.registry_mempool.len() >= cap {
            return Err("Registry mempool full".into());
        }
        let signer = op.signer_address();
        let want = self.account_nonce(&signer);
        if op.nonce() < want {
            return Err("Stale nonce".into());
        }
        if self
            .registry_mempool
            .iter()
            .any(|o| o.signer_address() == signer && o.nonce() == op.nonce())
        {
            return Err("Duplicate registry op".into());
        }
        self.registry_mempool.push(op);
        Ok(())
    }

    /// Select mutually-consistent registry ops for a block (nonce sequence +
    /// dry-run `apply_op` so invalid ownership/escrow ops never enter a block).
    pub fn select_valid_registry_ops(
        &self,
        ops: &[registry::RegistryOp],
    ) -> Vec<registry::RegistryOp> {
        let mut nonce: HashMap<String, u64> = HashMap::new();
        let mut accounts = self.accounts.clone();
        let mut registry = self.registry.clone();
        let mut good = Vec::new();
        // Dummy block shell for apply_op (only settlement string is used for history).
        let dummy = genesis_block();
        for op in ops {
            if op.chain_id() != self.chain_id || !op.verify() {
                continue;
            }
            let signer = op.signer_address();
            let cur = *nonce.get(&signer).unwrap_or(&self.account_nonce(&signer));
            if op.nonce() != cur {
                continue;
            }
            let mut trial_accounts = accounts.clone();
            let mut trial_registry = registry.clone();
            if trial_registry
                .apply_op(
                    &mut trial_accounts,
                    op,
                    &dummy,
                    "select-dry-run",
                    self.selected_tip_blue_score(),
                )
                .is_err()
            {
                continue;
            }
            accounts = trial_accounts;
            registry = trial_registry;
            nonce.insert(signer, cur.saturating_add(1));
            good.push(op.clone());
        }
        good
    }

    /// Admit a signed custody certificate to the mempool.
    pub fn admit_custody_to_mempool(
        &mut self,
        op: custody::CustodyCertificate,
    ) -> Result<(), String> {
        if matches!(
            op.kind,
            custody::CustodyKind::BridgeExit | custody::CustodyKind::BridgeEnter
        ) {
            return Err(
                "Bridge exit/enter disabled until a real cross-chain bridge ships".into(),
            );
        }
        if op.chain_id != self.chain_id {
            return Err("Wrong chain_id".into());
        }
        if op.amount == 0 {
            return Err("Custody amount must be > 0".into());
        }
        let sid: [u8; 64] = hex::decode(&op.settlement_id)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "bad settlement id".to_string())?;
        op.verify(&sid)?;
        // Same DAG-anchor binding as `validate_custody_ops` — mempool must not
        // accept forgeable self-consistent certificates.
        {
            let anchor = self
                .dag
                .get(&op.block_hash)
                .ok_or_else(|| "Custody: anchor block unknown".to_string())?;
            if anchor.stark_proof.is_empty() || anchor.birth_certificate.signature.is_empty() {
                return Err("Custody: anchor block has no consensus witnesses".into());
            }
            if op.settlement_id != anchor.settlement_id().to_hex() {
                return Err("Custody: settlement_id does not match anchor block".into());
            }
            if op.issuer_pubkey != anchor.creator_pubkey {
                return Err("Custody: issuer_pubkey does not match anchor block".into());
            }
            if op.birth_certificate != anchor.birth_certificate.signature {
                return Err("Custody: birth certificate does not match anchor block".into());
            }
        }
        if op.nonce < self.account_nonce(&op.owner) {
            return Err("Stale custody nonce".into());
        }
        if self
            .custody_mempool
            .iter()
            .any(|o| o.owner == op.owner && o.nonce == op.nonce && o.kind == op.kind)
        {
            return Err("Duplicate custody op".into());
        }
        let cap = if crate::net_policy::policy().public_mode {
            256
        } else {
            10_000
        };
        if self.custody_mempool.len() >= cap {
            return Err("Custody mempool full".into());
        }
        self.custody_mempool.push(op);
        Ok(())
    }

    /// Select mutually-consistent custody ops (nonce + balance dry-run).
    pub fn select_valid_custody_ops(
        &self,
        ops: &[custody::CustodyCertificate],
    ) -> Vec<custody::CustodyCertificate> {
        let mut overlay = ChainState {
            dag: HashMap::new(),
            tips: vec![],
            main_chain: vec![],
            accounts: self.accounts.clone(),
            utxo: self.utxo.clone(),
            total_supply: self.total_supply,
            minted_supply: self.minted_supply,
            block_reward: self.block_reward,
            difficulty: self.difficulty,
            chain_id: self.chain_id,
            transparent_mempool: vec![],
            utxo_mempool: vec![],
            registry_mempool: vec![],
            registry: Default::default(),
            custody_mempool: vec![],
            staked: self.staked.clone(),
            fees_burned: self.fees_burned,
            treasury: self.treasury,
            tor_nodes: HashSet::new(),
            ghostdag: HashMap::new(),
            reachability: reachability::Reachability::new(),
            archival: false,
            base: Ledger::default(),
            base_captured: true,
            base_frontier: None,
            pruning_point: None,
            pruning_ledger: None,
            pruned_selected_blocks: 0,
            tx_first_seen_ms: HashMap::new(),
            tx_first_seen_blue: HashMap::new(),
            fee_history: FeeRateHistory::default(),
        };
        let mut good = Vec::new();
        for op in ops {
            if overlay.apply_custody_op(op).is_ok() {
                good.push(op.clone());
            }
        }
        good
    }

    fn validate_custody_ops(&self, block: &Block) -> Result<(), String> {
        for op in &block.custody_ops {
            if matches!(
                op.kind,
                custody::CustodyKind::BridgeExit | custody::CustodyKind::BridgeEnter
            ) {
                return Err(
                    "Bridge exit/enter disabled until a real cross-chain bridge ships".into(),
                );
            }
            if op.chain_id != self.chain_id {
                return Err("Wrong chain_id on custody op".into());
            }
            if op.amount == 0 {
                return Err("Custody amount must be > 0".into());
            }
            if !security::is_valid_address(&op.owner) {
                return Err("Invalid custody owner address".into());
            }
            let sid: [u8; 64] = hex::decode(&op.settlement_id)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "bad settlement id".to_string())?;
            op.verify(&sid).map_err(|e| format!("Custody: {e}"))?;
            // Anchor must resolve to a real, full block in this node's DAG —
            // never accept attacker-invented settlement ids / birth certs.
            let anchor = self
                .dag
                .get(&op.block_hash)
                .ok_or_else(|| "Custody: anchor block unknown".to_string())?;
            if anchor.stark_proof.is_empty() || anchor.birth_certificate.signature.is_empty() {
                return Err("Custody: anchor block has no consensus witnesses".into());
            }
            if op.settlement_id != anchor.settlement_id().to_hex() {
                return Err("Custody: settlement_id does not match anchor block".into());
            }
            if op.issuer_pubkey != anchor.creator_pubkey {
                return Err("Custody: issuer_pubkey does not match anchor block".into());
            }
            if op.birth_certificate != anchor.birth_certificate.signature {
                return Err("Custody: birth certificate does not match anchor block".into());
            }
        }
        Ok(())
    }
}

/// Minimum fee for a transfer of `nbytes` on the wire (BTC density / Kaspa mass
/// spirit): `max(MIN_TX_FEE, nbytes × MIN_FEE_PER_BYTE)`.
pub fn min_relay_fee_for_bytes(nbytes: usize) -> u128 {
    let by_size = (nbytes as u128).saturating_mul(MIN_FEE_PER_BYTE);
    by_size.max(MIN_TX_FEE)
}

/// Conservative floor for a fully-signed ML-DSA-87 transfer (pubkey + sig +
/// addresses/amounts). Used when the mempool is empty so fee estimates are not
/// stuck at the tiny absolute floor.
pub fn typical_signed_tx_min_fee() -> u128 {
    min_relay_fee_for_bytes(PQ_PUBLIC_KEY_SIZE + PQ_SIGNATURE_SIZE + 512)
}

/// The easiest possible target: every 512-bit hash value is below it.
pub const MAX_TARGET: Hash = Hash::MAX;

/// Full 512-bit PoW target for a given difficulty (`MAX_TARGET / difficulty`).
/// A valid block hash, read as a big-endian 512-bit integer, must be strictly
/// less than this target.
pub fn pow_target(difficulty: u64) -> Hash {
    let max = BigUint::from_bytes_be(MAX_TARGET.as_slice());
    let target = max / BigUint::from(difficulty.max(1));
    let target_bytes = target.to_bytes_be();
    let mut result = [0u8; HASH_SIZE];
    let copy_len = target_bytes.len().min(HASH_SIZE);
    let start = target_bytes.len() - copy_len;
    result[HASH_SIZE - copy_len..].copy_from_slice(&target_bytes[start..]);
    Hash(result)
}

/// Cheap comparison against an already-computed target — this is what the
/// mining hot loop should call (millions of times per block), since
/// `pow_target` does a `BigUint` division that's only worth paying once per
/// block template, not once per nonce attempt.
pub fn hash_meets_target(hash: &Hash, target: &Hash) -> bool {
    hash.as_slice() < target.as_slice()
}

/// One-shot PoW check for validation call sites (block/share acceptance)
/// where recomputing the target once is negligible.
pub fn verify_pow(hash: &Hash, difficulty: u64) -> bool {
    hash_meets_target(hash, &pow_target(difficulty))
}

/// The DAA retarget formula, factored out so the live retarget
/// (`expected_difficulty_at`) and the pruning-proof verifier
/// (`expected_difficulty_linear`) compute an identical value and can never
/// drift. `new = base_difficulty * target_span / actual_span`, in u128 to avoid
/// overflow, then clamped to 5/4× up / 3/4× down. The `.max(base ± 1)` terms
/// matter: with integer difficulty, `1 * 5/4` rounds back to 1, so a pure
/// multiplicative clamp could never move difficulty off its floor — this
/// guarantees at least a ±1 step. Never drops below `floor` (era minimum).
pub fn retarget_difficulty(
    base_difficulty: u64,
    newest_ts: u64,
    oldest_ts: u64,
    floor: u64,
) -> u64 {
    let actual_span_ms = newest_ts.saturating_sub(oldest_ts).max(1);
    let target_span_ms = (DAA_WINDOW as u64) * TARGET_BLOCK_TIME_MS;
    let sp = base_difficulty.max(floor) as u128;
    let raw = sp.saturating_mul(target_span_ms as u128) / (actual_span_ms as u128);
    let up = (sp * 5 / 4).max(sp + 1);
    let down = (sp * 3 / 4).max(floor as u128);
    let clamped = raw.clamp(down, up);
    (clamped as u64).max(floor)
}

/// Difficulty bounds for an omitted-hop header given an older verified hop.
///
/// Applies the same ±25% per-[`DAA_WINDOW`] clamp the live DAA uses, once per
/// window of skipped height. Prevents a forger from claiming near-floor work
/// on tall skip-links while still allowing honest difficulty drift over long
/// compressed stretches. Returns `(lo, hi)` inclusive, both ≥ `floor`.
pub fn hop_difficulty_bounds(older_diff: u64, height_gap: u64, floor: u64) -> (u64, u64) {
    let base = older_diff.max(floor) as u128;
    let windows = ((height_gap as usize).saturating_sub(1) / DAA_WINDOW).saturating_add(1);
    // Cap iterations so adversarial huge gaps cannot spin verification.
    let windows = windows.min(64);
    let mut lo = base;
    let mut hi = base;
    for _ in 0..windows {
        hi = (hi * 5 / 4).max(hi + 1);
        lo = (lo * 3 / 4).max(floor as u128);
    }
    ((lo as u64).max(floor), hi as u64)
}

/// The one, deterministic genesis block. Every node builds the identical
/// genesis so its hash is a fixed, well-known anchor — the trust root a
/// pruning-point proof is verified against.
pub fn genesis_block() -> Block {
    Block {
        height: 0,
        timestamp: GENESIS_TIMESTAMP_MS,
        parents: vec![],
        interlinks: vec![],
        transparent_txs: vec![],
        utxo_txs: vec![],
        registry_ops: vec![],
        custody_ops: vec![],
        merkle_root: Hash::ZERO,
        state_root: Hash::ZERO,
        miner: Hash::ZERO,
        creator_pubkey: vec![],
        nonce: 0,
        difficulty: GENESIS_DIFFICULTY,
        version: crate::default_block_version(),
        coinbase_entropy: 0,
        stark_proof: vec![0u8; 64],
        birth_certificate: issuance::BirthCertificate::default(),
        size: 0,
    }
}

/// The fixed genesis hash — the anchor a pruning-point proof must chain back to.
pub fn genesis_hash() -> Hash {
    genesis_block().hash()
}

#[cfg(test)]
mod genesis_zero_tests {
    use super::*;

    #[test]
    fn chain_starts_at_genesis_height_zero() {
        let state = ChainState::new();
        assert_eq!(state.tip_height(), 0);
        assert_eq!(state.main_chain.len(), 1);
        assert_eq!(state.dag.len(), 1);
        let genesis = state.dag.get(&state.main_chain[0]).expect("genesis in dag");
        assert_eq!(genesis.height, 0);
        assert!(genesis.parents.is_empty());
        assert_eq!(genesis.hash(), genesis_hash());
        assert_eq!(state.minted_supply, 0);
        assert_eq!(state.difficulty, effective_min_difficulty());
    }

    #[test]
    fn chain_hash_is_stable_blake3_of_domain_id_and_genesis() {
        let h = chain_hash();
        let mut buf = Vec::new();
        buf.extend_from_slice(GENESIS_DOMAIN);
        buf.extend_from_slice(&CHAIN_ID.to_le_bytes());
        buf.extend_from_slice(genesis_hash().as_bytes());
        assert_eq!(h, Hash(abs_sig::digest512(b"chain-hash", &buf)));
        assert_eq!(chain_hash_hex().len(), HASH_SIZE * 2);
        assert_eq!(chain_hash(), chain_hash());
    }

    #[test]
    fn incompatible_state_format_is_rejected() {
        let dir = std::env::temp_dir().join(format!("hassan-fmt-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chainstate.bin");
        // Craft a file with valid magic but an old format version.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&STATE_MAGIC);
        bytes.extend_from_slice(&(STATE_FORMAT_VERSION.wrapping_sub(1)).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        std::fs::write(&path, &bytes).unwrap();
        let err = ChainState::load_from(&path).unwrap_err();
        assert!(
            err.contains("incompatible state format"),
            "expected version reject, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lean_persist_skips_mempool_and_keeps_hardcoded_genesis() {
        let dir = std::env::temp_dir().join(format!("hassan-lean-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chainstate.bin");

        let mut state = ChainState::new();
        let (_sk, pk) = generate_keypair();
        state.transparent_mempool.push(TransparentTx::new(
            pk,
            hash_to_address(&[9u8; 64]),
            1,
            0,
            CHAIN_ID,
        ));
        assert!(!state.transparent_mempool.is_empty());

        state.save_to(&path).unwrap();
        let loaded = ChainState::load_from(&path).unwrap();
        assert!(
            loaded.transparent_mempool.is_empty(),
            "mempool must not survive disk (lean persist)"
        );
        assert!(loaded.registry_mempool.is_empty());
        assert!(loaded.custody_mempool.is_empty());
        assert_eq!(loaded.chain_id, CHAIN_ID);
        assert!(loaded.dag.contains_key(&genesis_hash()));
        assert_eq!(loaded.tip_height(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chainstate_checksum_roundtrip_and_bitflip_rejected() {
        let dir = std::env::temp_dir().join(format!("hassan-cksum-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chainstate.bin");
        let mut state = ChainState::new();
        state.save_to(&path).unwrap();
        let loaded = ChainState::load_from(&path).unwrap();
        assert_eq!(loaded.tip_height(), 0);
        assert!(loaded.supply_invariant_ok());
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 12 + STATE_CHECKSUM_LEN);
        let flip = 20.min(bytes.len() - STATE_CHECKSUM_LEN - 1);
        bytes[flip] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        // Remove backup so load cannot silently recover a good snapshot.
        let _ = std::fs::remove_file(path.with_extension("bak"));
        let _ = std::fs::remove_file(path.with_extension("bak.1"));
        let err = ChainState::load_from(&path).unwrap_err();
        assert!(
            err.contains("integrity tag mismatch") || err.contains("deserialize"),
            "bit-flipped chainstate must not load, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chainstate_truncated_tag_is_rejected() {
        let dir = std::env::temp_dir().join(format!("hassan-trunc-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chainstate.bin");
        let mut state = ChainState::new();
        state.save_to(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > STATE_CHECKSUM_LEN);
        bytes.truncate(bytes.len() - STATE_CHECKSUM_LEN);
        std::fs::write(&path, &bytes).unwrap();
        let _ = std::fs::remove_file(path.with_extension("bak"));
        let _ = std::fs::remove_file(path.with_extension("bak.1"));
        let err = ChainState::load_from(&path).unwrap_err();
        assert!(
            err.contains("integrity tag") || err.contains("missing"),
            "truncated tag must refuse load, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v27_account_peer_transfers_are_disabled() {
        assert!(!ACCOUNT_PEER_TRANSFERS);
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let mut tx = TransparentTx::new(pk, test_address(1), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();
        let err = state.apply_transparent_tx(&tx).unwrap_err();
        assert!(err.contains("disabled"), "{err}");
        let err2 = state.admit_transparent_to_mempool(tx).unwrap_err();
        assert!(err2.contains("disabled"), "{err2}");
    }

    #[test]
    fn v27_coinbase_credits_utxo_not_accounts() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let parents = state.tips.clone();
        let ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let mut block = genesis_block();
        block.parents = parents;
        block.difficulty = difficulty;
        block.timestamp = ts;
        state.bind_parent_commitments(&mut block).unwrap();
        seal_block(&state, &mut block, &sk, &pk);
        state.add_block(block).unwrap();
        assert!(state.accounts.is_empty() || state.accounts.values().all(|a| a.balance == 0));
        assert!(state.utxo.total_value() > 0);
        assert!(state.supply_invariant_ok());
    }

    #[test]
    fn v27_utxo_mempool_admits_signed_payment() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let fund_op = utxo::OutPoint {
            txid: Hash([9u8; 64]),
            vout: 0,
        };
        state.utxo.insert(
            fund_op,
            utxo::TxOut {
                value: 5_000_000,
                predicate: predicate::Predicate::PayToAddress {
                    address: from.clone(),
                },
                created_blue: 0,
            },
        );
        // Advance media blue past coinbase maturity for non-coinbase outs (created_blue=0).
        let mut tx = utxo_tx::UtxoTx::payment(
            pk,
            fund_op,
            5_000_000,
            test_address(2),
            100_000,
            MIN_TX_FEE,
            state.chain_id,
            0,
            0,
        )
        .unwrap();
        tx.sign(&sk).unwrap();
        state.admit_utxo_to_mempool(tx.clone()).unwrap();
        assert_eq!(state.utxo_mempool.len(), 1);
        let selected = state.select_valid_utxo_txs(&state.utxo_mempool);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].txid(), tx.txid());
    }

    #[test]
    fn hop_difficulty_bounds_widen_per_window_and_respect_floor() {
        let floor = effective_min_difficulty();
        let (lo1, hi1) = hop_difficulty_bounds(floor, 1, floor);
        assert_eq!(lo1, (floor as u128 * 3 / 4).max(floor as u128) as u64);
        assert!(hi1 >= floor);
        let (lo_far, hi_far) = hop_difficulty_bounds(floor * 4, DAA_WINDOW as u64 * 3, floor);
        assert!(lo_far >= floor);
        assert!(hi_far > hi1);
        // A single-window drop cannot go below floor.
        let (lo_soft, _) = hop_difficulty_bounds(floor, 1, floor);
        assert_eq!(lo_soft, floor);
    }

    #[test]
    fn utxo_mempool_rejects_oversized_ancestor_package() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut fund_op = utxo::OutPoint {
            txid: Hash([4u8; 64]),
            vout: 0,
        };
        let mut fund_value = 50_000_000u128;
        state.utxo.insert(
            fund_op,
            utxo::TxOut {
                value: fund_value,
                predicate: predicate::Predicate::PayToAddress {
                    address: from.clone(),
                },
                created_blue: 0,
            },
        );
        // Chain MAX_UTXO_PACKAGE_COUNT parents, then one more child must fail.
        for i in 0..MAX_UTXO_PACKAGE_COUNT {
            let amount = 1_000;
            let mut tx = utxo_tx::UtxoTx::payment(
                pk.clone(),
                fund_op,
                fund_value,
                from.clone(),
                amount,
                MIN_TX_FEE,
                state.chain_id,
                0,
                0,
            )
            .unwrap();
            tx.sign(&sk).unwrap();
            let txid = tx.tx_hash();
            // Change output is vout 1 when amount leaves change.
            assert!(
                tx.outputs.len() > 1,
                "test expects a change output to chain packages"
            );
            let change_vout = 1u32;
            let change_val = tx.outputs[change_vout as usize].value;
            state.admit_utxo_to_mempool(tx).unwrap_or_else(|e| {
                panic!("package step {i} should admit: {e}");
            });
            fund_op = utxo::OutPoint {
                txid,
                vout: change_vout,
            };
            fund_value = change_val;
        }
        let mut over = utxo_tx::UtxoTx::payment(
            pk,
            fund_op,
            fund_value,
            from,
            1_000,
            MIN_TX_FEE,
            state.chain_id,
            0,
            0,
        )
        .unwrap();
        over.sign(&sk).unwrap();
        let err = state.admit_utxo_to_mempool(over).unwrap_err();
        assert!(
            err.contains("ancestor package exceeds count"),
            "expected package count reject, got: {err}"
        );
    }

    #[test]
    fn utxo_mempool_rbf_replaces_lower_feerate_conflict() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let fund_op = utxo::OutPoint {
            txid: Hash([9u8; 64]),
            vout: 0,
        };
        state.utxo.insert(
            fund_op,
            utxo::TxOut {
                value: 5_000_000,
                predicate: predicate::Predicate::PayToAddress {
                    address: from.clone(),
                },
                created_blue: 0,
            },
        );
        let mut low = utxo_tx::UtxoTx::payment(
            pk.clone(),
            fund_op,
            5_000_000,
            test_address(2),
            100_000,
            MIN_TX_FEE,
            state.chain_id,
            0,
            0,
        )
        .unwrap();
        low.sign(&sk).unwrap();
        let low_fee = low.fee;
        state.admit_utxo_to_mempool(low.clone()).unwrap();

        let hi_fee = low_fee.saturating_mul(4).max(low_fee.saturating_add(10_000));
        let mut high = utxo_tx::UtxoTx::payment(
            pk,
            fund_op,
            5_000_000,
            test_address(3),
            100_000,
            hi_fee,
            state.chain_id,
            0,
            0,
        )
        .unwrap();
        high.sign(&sk).unwrap();
        assert!(high.fee > low_fee, "replacement must pay more absolute fee");
        state.admit_utxo_to_mempool(high.clone()).unwrap();
        assert_eq!(state.utxo_mempool.len(), 1);
        assert_eq!(state.utxo_mempool[0].txid(), high.txid());
    }

    #[test]
    fn utxo_mempool_rbf_rejects_sub_min_fee_bump() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let fund_op = utxo::OutPoint {
            txid: Hash([7u8; 64]),
            vout: 0,
        };
        state.utxo.insert(
            fund_op,
            utxo::TxOut {
                value: 5_000_000,
                predicate: predicate::Predicate::PayToAddress {
                    address: from.clone(),
                },
                created_blue: 0,
            },
        );
        let mut low = utxo_tx::UtxoTx::payment(
            pk.clone(),
            fund_op,
            5_000_000,
            test_address(2),
            100_000,
            MIN_TX_FEE * 10,
            state.chain_id,
            0,
            0,
        )
        .unwrap();
        low.sign(&sk).unwrap();
        let low_fee = low.fee;
        state.admit_utxo_to_mempool(low.clone()).unwrap();

        // Absolute fee only +1 (below MIN_TX_FEE bump) — must be rejected.
        let mut tiny = utxo_tx::UtxoTx::payment(
            pk,
            fund_op,
            5_000_000,
            test_address(3),
            100_000,
            low_fee.saturating_add(1),
            state.chain_id,
            0,
            0,
        )
        .unwrap();
        tiny.sign(&sk).unwrap();
        let err = state.admit_utxo_to_mempool(tiny).unwrap_err();
        assert!(
            err.contains("conflicts"),
            "sub-MIN_TX_FEE RBF bump must fail: {err}"
        );
        assert_eq!(state.utxo_mempool.len(), 1);
        assert_eq!(state.utxo_mempool[0].txid(), low.txid());
    }

    #[test]
    fn drop_included_clears_utxo_mempool_and_prune_clears_utxo_bodies() {
        let mut state = ChainState::new();
        state.archival = false;
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let fund_op = utxo::OutPoint {
            txid: Hash([8u8; 64]),
            vout: 1,
        };
        state.utxo.insert(
            fund_op,
            utxo::TxOut {
                value: 5_000_000,
                predicate: predicate::Predicate::PayToAddress {
                    address: from,
                },
                created_blue: 0,
            },
        );
        let mut tx = utxo_tx::UtxoTx::payment(
            pk.clone(),
            fund_op,
            5_000_000,
            test_address(4),
            50_000,
            MIN_TX_FEE,
            state.chain_id,
            0,
            0,
        )
        .unwrap();
        tx.sign(&sk).unwrap();
        state.admit_utxo_to_mempool(tx.clone()).unwrap();
        assert_eq!(state.utxo_mempool.len(), 1);

        // Synthetic block carrying the UTXO tx — exercise mempool drop only.
        let tip = state.tips[0];
        let mut block = Block {
            height: 1,
            timestamp: now_ms(),
            parents: vec![tip],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![tx.clone()],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 0,
            difficulty: state.difficulty,
            version: default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: issuance::BirthCertificate::default(),
            size: 0,
        };
        block.merkle_root = block.merkle_root();
        state.drop_included_from_mempools(&block);
        assert!(
            state.utxo_mempool.is_empty(),
            "mined UTXO txs must leave the mempool"
        );

        // Body-prune must clear utxo_txs and report the body empty.
        let fake_hash = Hash([0xab; 64]);
        state.dag.insert(fake_hash, block.clone());
        state.ghostdag.insert(
            fake_hash,
            ghostdag::GhostdagData {
                blue_score: 0,
                selected_parent: Some(tip),
                mergeset_blues: vec![tip],
                mergeset_reds: vec![],
            },
        );
        // Force tip blue high enough that FINALITY_DEPTH buries score 0.
        let tip_h = state.tips[0];
        if let Some(gd) = state.ghostdag.get_mut(&tip_h) {
            gd.blue_score = FINALITY_DEPTH + 10;
        }
        state.prune_bodies();
        let pruned = state.dag.get(&fake_hash).expect("block retained as header");
        assert!(pruned.utxo_txs.is_empty());
        assert!(state.is_body_pruned(&fake_hash));
    }

    #[test]
    fn precheck_header_accepts_pow_without_witness() {
        let state = ChainState::new();
        let tip = state.tips[0];
        let difficulty = state.expected_difficulty_at(&[tip], now_ms());
        let (sk, pk) = test_miner_keys();
        let mut header = Block {
            height: 1,
            timestamp: now_ms(),
            parents: vec![tip],
            interlinks: crate::superproof::compute_interlinks(state.dag.get(&tip).unwrap()),
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: hash512(&pk),
            creator_pubkey: pk.clone(),
            nonce: 0,
            difficulty,
            version: default_block_version(),
            coinbase_entropy: 1,
            stark_proof: vec![],
            birth_certificate: issuance::BirthCertificate::default(),
            size: 0,
        };
        header.merkle_root = header.merkle_root();
        // Mine until PoW hits (bootstrap difficulty is low).
        let target = pow_target(difficulty);
        while !hash_meets_target(&header.hash(), &target) {
            header.nonce = header.nonce.wrapping_add(1);
        }
        assert!(state.precheck_header(&header).is_ok());
        assert!(state.precheck_block(&header).is_err());
        let _ = sk; // silence unused when keys are only for miner identity
    }

    #[test]
    fn blake3_pow_mineable_at_bootstrap_floor() {
        let floor = effective_min_difficulty();
        assert_eq!(floor, BOOTSTRAP_MIN_DIFFICULTY);
        let target = pow_target(floor);
        let mut hits = 0u32;
        for n in 0..250_000u64 {
            let mut hasher = Blake3Hasher::new();
            hasher.update(b"hassan-pow-probe");
            hasher.update(&n.to_le_bytes());
            let mut out = [0u8; HASH_SIZE];
            hasher.finalize_xof().fill(&mut out);
            if hash_meets_target(&Hash(out), &target) {
                hits += 1;
                if hits >= 2 {
                    break;
                }
            }
        }
        assert!(
            hits >= 1,
            "bootstrap floor {floor} should be CPU-mineable"
        );
        assert_eq!(MIN_DIFFICULTY, BOOTSTRAP_MIN_DIFFICULTY);
        assert_eq!(
            era_min_difficulty(0, GENESIS_TIMESTAMP_MS),
            BOOTSTRAP_MIN_DIFFICULTY
        );
        assert_eq!(
            era_min_difficulty(BOOTSTRAP_ERA_END, GENESIS_TIMESTAMP_MS),
            HARD_ERA_MIN_DIFFICULTY,
            "v29: hard floor after 1M HSN minted"
        );
    }
}

/// Finish a block draft for consensus acceptance: bind the creator's ML-DSA-87
/// identity into the PoW preimage, set post-mergeset `state_root` (depends on
/// miner + body), search for a valid nonce, issue the Birth Certificate over
/// the Settlement ID, and attach the block STARK. Call after setting height /
/// timestamp / parents / txs / difficulty.
pub fn seal_block(
    state: &ChainState,
    block: &mut Block,
    secret_key: &[u8],
    public_key: &[u8],
) {
    block.creator_pubkey = public_key.to_vec();
    block.miner = address_hash(public_key);
    block.merkle_root = block.merkle_root();
    state
        .bind_parent_commitments(block)
        .expect("bind post-mergeset commitments");
    let target = pow_target(block.difficulty);
    // Preserve any caller-chosen starting nonce; wrap on overflow.
    loop {
        if hash_meets_target(&block.hash(), &target) {
            break;
        }
        block.nonce = block.nonce.wrapping_add(1);
    }
    block
        .issue_birth_certificate(secret_key)
        .expect("ML-DSA-87 birth certificate");
    block.stark_proof = stark::prove(block.hash().as_slice());
    block.size = calculate_block_size(block);
}

/// Shared keypair for unit tests that mine blocks through `add_block`.
#[cfg(test)]
pub fn test_miner_keys() -> &'static (Vec<u8>, Vec<u8>) {
    use std::sync::OnceLock;
    static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEYS.get_or_init(generate_keypair)
}

/// A cold-start **pruning-point proof**: the header-only selected chain from
/// genesis to the pruning point. It lets a fresh node establish the pruning
/// point and its cumulative proof-of-work **without downloading any block
/// bodies or STARK proofs** — only headers, each independently PoW-checked and
/// its difficulty re-derived from the DAA.
///
/// HONEST SCOPE: this is a **linear, headers-first** proof (Bitcoin-style) — its
/// size is O(chain length). It is served by **archival** nodes (which retain all
/// headers); a body-pruned node cannot produce it. It is NOT Kaspa's *succinct*
/// (log-size) multi-level pruning-point proof — that construction proves the
/// same fact with a small subset of headers across difficulty levels and is a
/// substantially larger, separate effort. What this buys is real: a fresh node
/// downloads small headers (not ~50 KB-proof blocks) for the pruned history and
/// verifies the work trustlessly, then syncs bodies only from the pruning point
/// forward.
///
/// SECURITY CEILING (be honest): the proof certifies *cumulative difficulty*,
/// and its trust is only as strong as that difficulty is expensive to produce.
/// On a low-hashrate chain where difficulty sits near 1, PoW is nearly free
/// (`pow_target(1)` accepts every hash), so an attacker could mine a long
/// trivial chain and out-"work" the honest one. That is the same "needs real
/// hashrate" limitation that runs through this whole project — no code change
/// manufactures it. A verifying node treats a proof as *advisory* until
/// difficulty reflects meaningful work, only accepts one it explicitly
/// requested, and should cross-check multiple honest peers rather than trust the
/// first proof it sees.
///
/// Upper bound on headers in a pruning-point proof accepted by
/// `verify_pruning_proof` — a defence-in-depth cap on verification cost beyond
/// the P2P wire-size limit. Generous relative to any plausible chain length.
pub const MAX_PRUNING_PROOF_HEADERS: usize = 1_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningProof {
    /// Header-only blocks (bodies/proofs stripped), genesis-first, ending at the
    /// pruning point.
    pub headers: Vec<Block>,
}

/// What a verified pruning-point proof establishes.
#[derive(Clone, Debug, PartialEq)]
pub struct PruningProofSummary {
    /// The pruning-point block hash the fresh node may now trust as its base.
    pub pruning_point: Hash,
    /// Total proof-of-work (Σ difficulty) backing the chain to the pruning point.
    pub cumulative_work: u128,
    /// Number of headers in the proof.
    pub header_count: usize,
}

/// The DAA-expected difficulty for header `i` of a *linear* selected chain — the
/// pruning-proof twin of `ChainState::expected_difficulty_at`. Because the proof
/// IS the selected chain, header `i`'s DAA window is exactly
/// `headers[i-DAA_WINDOW..i]`. Simulated minted supply is the closed-form sum of
/// `block_subsidy(j)` for `j` in `0..i` (linear blue-score ≈ index assumption) —
/// `cumulative_issuance` computes this in O(halvings), not O(i); calling it once
/// per header keeps `verify_pruning_proof` O(n) instead of O(n²) (a proof up to
/// `MAX_PRUNING_PROOF_HEADERS` headers would otherwise be a verification-time DoS).
fn expected_difficulty_linear(headers: &[Block], i: usize) -> u64 {
    let simulated_minted = cumulative_issuance(i as u64);
    let ts = headers[i].timestamp;
    let floor = era_min_difficulty(simulated_minted, ts);
    let sp_difficulty = headers[i - 1].difficulty.max(floor);
    if i < DAA_WINDOW {
        return sp_difficulty.max(floor);
    }
    let newest = headers[i - 1].timestamp;
    let oldest = headers[i - DAA_WINDOW].timestamp;
    retarget_difficulty(sp_difficulty, newest, oldest, floor).max(floor)
}

/// Verify a pruning-point proof from scratch (no local chain needed). Checks:
/// genesis anchor, PoW on every header, chain linkage (each header names the
/// previous by hash in its PoW-committed `parents`), DAA-consistent difficulty
/// (so claimed work can't be faked cheap), and timestamp monotonicity. Returns
/// the trusted pruning point and its cumulative work, or an error. Never panics.
pub fn verify_pruning_proof(proof: &PruningProof) -> Result<PruningProofSummary, String> {
    let h = &proof.headers;
    if h.is_empty() {
        return Err("empty pruning proof".into());
    }
    // Bound verification cost against a hostile oversized proof (defence in
    // depth; the P2P layer also caps the message size on the wire).
    if h.len() > MAX_PRUNING_PROOF_HEADERS {
        return Err("pruning proof exceeds the header limit".into());
    }
    // 1. Anchor: the proof must start at the one true genesis.
    if h[0].hash() != genesis_hash() {
        return Err("pruning proof does not start at genesis".into());
    }
    if !h[0].parents.is_empty() {
        return Err("genesis header must have no parents".into());
    }

    let now = now_ms();
    let mut cumulative_work: u128 = h[0].difficulty as u128;
    for i in 1..h.len() {
        let cur = &h[i];
        let prev_hash = h[i - 1].hash();
        // 2. Linkage: the previous header is a parent of this one. `parents` is
        //    committed in `hash()`, so this can't be forged without redoing PoW.
        if !cur.parents.contains(&prev_hash) {
            return Err(format!("broken chain linkage at header {i}"));
        }
        // 3. Difficulty must equal what the DAA mandates for this position, so a
        //    forger can't claim an easy difficulty to fake cheap "work".
        if cur.difficulty != expected_difficulty_linear(h, i) {
            return Err(format!("header {i} claims a non-DAA difficulty"));
        }
        // 4. Real PoW: the header hash must meet its (now-verified) difficulty.
        if !verify_pow(&cur.hash(), cur.difficulty) {
            return Err(format!("header {i} fails its proof-of-work"));
        }
        // 5. Timestamp rules, mirroring consensus: monotonic vs the parent, and
        //    not implausibly far in the future (an unbounded future timestamp is
        //    one lever for gaming the DAA difficulty within the proof).
        if cur.timestamp < h[i - 1].timestamp {
            return Err(format!("header {i} timestamp predates its parent"));
        }
        if cur.timestamp > now.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(format!("header {i} timestamp is too far in the future"));
        }
        cumulative_work = cumulative_work.saturating_add(cur.difficulty as u128);
    }

    Ok(PruningProofSummary {
        pruning_point: h[h.len() - 1].hash(),
        cumulative_work,
        header_count: h.len(),
    })
}

/// Verifies `block.stark_proof` as a real winterfell-checked STARK proof
/// (see the `stark` module) that `stark::SEQUENTIAL_STEPS` steps of
/// sequential work were performed, seeded from this block's own hash.
///
/// SCOPE: this is a genuine, checked proof — not a byte-length stub — but it
/// proves sequential computation (a VDF-style companion to the PoW), not
/// transaction validity. See the `stark` module's doc comment for details.
pub fn verify_stark_proof(block: &Block) -> bool {
    stark::verify(block.hash().as_slice(), &block.stark_proof)
}

/// Generates a real post-quantum ML-DSA-87 (FIPS 204) keypair:
/// (signing_key_bytes, verifying_key_bytes). Highest Dilithium parameter set.
/// Every signature in Hassan is over a Blake3-512 prehash (512-bit).
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public_key, secret_key) = ml_dsa_87::try_keygen().expect("OS RNG failure during keygen");
    (
        secret_key.into_bytes().to_vec(),
        public_key.into_bytes().to_vec(),
    )
}

/// Deterministic ML-DSA-87 keypair from a 32-byte (or longer) seed.
pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if seed.len() < 32 {
        return Err("seed must be at least 32 bytes".into());
    }
    let mut xi = [0u8; 32];
    xi.copy_from_slice(&seed[..32]);
    let (public_key, secret_key) = ml_dsa_87::KG::keygen_from_seed(&xi);
    Ok((
        secret_key.into_bytes().to_vec(),
        public_key.into_bytes().to_vec(),
    ))
}

/// Sign an arbitrary message with an ML-DSA-87 secret key.
/// Callers that need the mandatory 512-bit prehash should use
/// `abs_sig::sign_pq512` instead; this signs the provided bytes directly
/// (used as the final step after prehashing).
pub fn sign_message(signing_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let bytes: [u8; PQ_SECRET_KEY_SIZE] = signing_key_bytes
        .try_into()
        .map_err(|_| format!("signing key must be exactly {} bytes", PQ_SECRET_KEY_SIZE))?;
    let secret_key = PrivateKey::try_from_bytes(bytes).map_err(|e| e.to_string())?;
    let signature = secret_key
        .try_sign(message, &[])
        .map_err(|e| e.to_string())?;
    Ok(signature.to_vec())
}

/// Verify a signature against an ML-DSA-87 public key and message.
/// Returns `false` (never panics) on malformed keys/signatures.
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk_bytes: [u8; PQ_PUBLIC_KEY_SIZE] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let verifying_key = match PublicKey::try_from_bytes(pk_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig_bytes: [u8; PQ_SIGNATURE_SIZE] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    verifying_key.verify(message, &sig_bytes, &[])
}

/// Blake3-512 digest — canonical 512-bit security hash for Hassan.
pub fn hash512(data: &[u8]) -> Hash {
    Hash(abs_sig::digest512(b"raw", data))
}

/// The raw 512-bit address digest behind `hash_to_address`.
pub fn address_hash(pubkey: &[u8]) -> Hash {
    Hash(abs_sig::digest512(b"address", pubkey))
}

/// Canonical wallet address: bech32m `hsn1…` encoding a 32-byte Blake3
/// fingerprint of the ML-DSA-87 public key (see [`address`]).
pub fn hash_to_address(pubkey: &[u8]) -> String {
    address::encode_address(pubkey)
}

/// True when `address` is the bech32m or legacy hex form of `pubkey`.
pub fn address_matches_pubkey(address: &str, pubkey: &[u8]) -> bool {
    address::address_matches_pubkey(address, pubkey)
}

/// Network / genesis identifier for wallets (“add network”).
///
/// Blake3-512 domain-separated digest of:
/// `GENESIS_DOMAIN ‖ CHAIN_ID (LE u64) ‖ genesis_block_hash (64 bytes)`.
/// Stable for a given genesis; hex via [`chain_hash_hex`].
pub fn chain_hash() -> Hash {
    let mut buf = Vec::with_capacity(GENESIS_DOMAIN.len() + 8 + HASH_SIZE);
    buf.extend_from_slice(GENESIS_DOMAIN);
    buf.extend_from_slice(&CHAIN_ID.to_le_bytes());
    buf.extend_from_slice(genesis_hash().as_bytes());
    Hash(abs_sig::digest512(b"chain-hash", &buf))
}

pub fn chain_hash_hex() -> String {
    hex::encode(chain_hash())
}

/// A valid bech32m `hsn1…` address from a fixed 512-bit seed (tests / fixtures).
pub fn test_address(seed: u8) -> String {
    crate::address::encode_hash(&Hash([seed; HASH_SIZE]))
}

/// Parse legacy `"hsn:<128 hex>"` to the full 512-bit digest (mining / PoW identity).
/// Bech32m forms are not invertible to 64 bytes — use [`address_hash`] from the pubkey.
pub fn address_to_bytes(address: &str) -> Option<Hash> {
    let hex_part = address.strip_prefix("hsn:")?;
    let bytes = hex::decode(hex_part).ok()?;
    Hash::try_from(bytes.as_slice()).ok()
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn calculate_block_size(block: &Block) -> usize {
    bincode::serialize(block).unwrap_or_default().len()
}

pub fn verify_tor_node(onion_address: &str) -> bool {
    // A Tor v3 onion is 56 base32 chars + ".onion" = 62 total (audit L-4: the
    // old `== 56` contradicted the `.onion` suffix and matched nothing valid).
    onion_address.ends_with(".onion") && onion_address.len() == 62
}

/// Verify a batch of transparent transfers' signatures in parallel.
pub fn parallel_execute(txs: Vec<TransparentTx>) -> Vec<Result<(), String>> {
    use rayon::prelude::*;
    txs.into_par_iter()
        .map(|tx| {
            if tx.verify() {
                Ok(())
            } else {
                Err("Invalid signature".into())
            }
        })
        .collect()
}

pub mod abs_sig;
pub mod ai_trace;
pub mod api;
pub mod consensus;
pub mod custody;
pub mod dual_sig;
pub mod economics;
pub mod ghostdag;
pub mod indexer;
pub mod issuance;
pub mod p2p;
pub mod reachability;
pub mod registry;
pub mod security;
pub mod stark;
pub mod tor;
pub mod wallet;

/// Fee-market snapshot returned by [`ChainState::estimate_fee`]. All values
/// are in base units (same as [`TransparentTx::fee`]), floored at the live
/// relay minimum. Tiers use a confirmation-target success-walk (or mempool
/// percentiles) and are forced monotonic (`high ≥ medium ≥ low`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Fee for ~100-blue confirmation (history or mempool 10th pct).
    pub low: u128,
    /// Fee for ~20-blue confirmation (history or mempool median).
    pub medium: u128,
    /// Fee for ~6-blue confirmation (history or mempool 90th pct).
    pub high: u128,
    /// Number of transfers the estimate was computed over (mempool size).
    pub mempool_txs: usize,
    /// Number of includable ancestor packages (one maximal contiguous nonce
    /// chain from each sender's account tip).
    #[serde(default)]
    pub package_count: usize,
    /// Total fee of the best-scoring ancestor package prefix (highest
    /// package fee-rate; tip of the CPFP-style queue).
    #[serde(default)]
    pub best_package_fee: u128,
    /// Blue-score confirmation target for `high`.
    #[serde(default = "default_high_target")]
    pub high_target_blues: u64,
    /// Blue-score confirmation target for `medium`.
    #[serde(default = "default_medium_target")]
    pub medium_target_blues: u64,
    /// Blue-score confirmation target for `low`.
    #[serde(default = "default_low_target")]
    pub low_target_blues: u64,
}

fn default_high_target() -> u64 {
    FEE_TARGET_HIGH_BLUES
}
fn default_medium_target() -> u64 {
    FEE_TARGET_MEDIUM_BLUES
}
fn default_low_target() -> u64 {
    FEE_TARGET_LOW_BLUES
}

/// Compare package fee-rates `fee_a/len_a` vs `fee_b/len_b` without floats.
fn cmp_package_feerate(fee_a: u128, len_a: usize, fee_b: u128, len_b: usize) -> Ordering {
    let len_a = len_a.max(1) as u128;
    let len_b = len_b.max(1) as u128;
    fee_a.saturating_mul(len_b).cmp(&fee_b.saturating_mul(len_a))
}

fn mempool_index_by_sender(transfers: &[TransparentTx]) -> HashMap<String, BTreeMap<u64, TransparentTx>> {
    let mut map: HashMap<String, BTreeMap<u64, TransparentTx>> = HashMap::new();
    for tx in transfers {
        map.entry(tx.from.clone())
            .or_default()
            .insert(tx.nonce, tx.clone());
    }
    map
}

/// Contiguous nonce chain starting at `tip_nonce` (account's next nonce).
fn contiguous_nonce_chain(
    by_nonce: &BTreeMap<u64, TransparentTx>,
    tip_nonce: u64,
) -> Vec<&TransparentTx> {
    let mut out = Vec::new();
    let mut n = tip_nonce;
    while let Some(tx) = by_nonce.get(&n) {
        out.push(tx);
        n = n.saturating_add(1);
    }
    out
}

/// Ancestor package from account `tip_nonce` through `target_nonce`, or
/// `None` if any nonce in between is missing.
fn ancestor_package(
    by_nonce: &BTreeMap<u64, TransparentTx>,
    tip_nonce: u64,
    target_nonce: u64,
) -> Option<Vec<&TransparentTx>> {
    if target_nonce < tip_nonce {
        return None;
    }
    let mut out = Vec::with_capacity((target_nonce - tip_nonce + 1) as usize);
    let mut n = tip_nonce;
    while n <= target_nonce {
        out.push(by_nonce.get(&n)?);
        n = n.saturating_add(1);
    }
    Some(out)
}

/// Descendant package score for eviction: this tx plus contiguous higher
/// nonces from the same sender (fee total, **relay bytes** for density).
fn descendant_package_score(
    tx: &TransparentTx,
    by_sender: &HashMap<String, BTreeMap<u64, TransparentTx>>,
) -> (u128, usize) {
    let Some(by_nonce) = by_sender.get(&tx.from) else {
        return (tx.fee, tx.relay_bytes().max(1));
    };
    let mut total = 0u128;
    let mut bytes = 0usize;
    let mut n = tx.nonce;
    while let Some(t) = by_nonce.get(&n) {
        total = total.saturating_add(t.fee);
        bytes = bytes.saturating_add(t.relay_bytes());
        n = n.saturating_add(1);
    }
    if bytes == 0 {
        (tx.fee, tx.relay_bytes().max(1))
    } else {
        (total, bytes)
    }
}

/// Score an incoming tx as it would sit in `mempool` (replacing same nonce):
/// contiguous ancestor package from `tip_nonce` through the tx, plus any
/// already-queued higher-nonce descendants. Used for full-mempool eviction.
fn incoming_package_score(
    tx: &TransparentTx,
    mempool: &[TransparentTx],
    tip_nonce: u64,
) -> (u128, usize) {
    let mut by_sender = mempool_index_by_sender(mempool);
    by_sender
        .entry(tx.from.clone())
        .or_default()
        .insert(tx.nonce, tx.clone());
    let by_nonce = by_sender
        .get(&tx.from)
        .expect("just inserted sender map");
    if let Some(pkg) = ancestor_package(by_nonce, tip_nonce, tx.nonce) {
        let mut total: u128 = pkg.iter().map(|t| t.fee).sum();
        let mut bytes: usize = pkg.iter().map(|t| t.relay_bytes()).sum();
        let mut n = tx.nonce.saturating_add(1);
        while let Some(t) = by_nonce.get(&n) {
            // Skip the tx itself if somehow re-hit; descendants only.
            if t.nonce == tx.nonce {
                n = n.saturating_add(1);
                continue;
            }
            total = total.saturating_add(t.fee);
            bytes = bytes.saturating_add(t.relay_bytes());
            n = n.saturating_add(1);
        }
        return (total, bytes.max(1));
    }
    descendant_package_score(tx, &by_sender)
}

/// A real, authenticated transfer: signed with ML-DSA-87 and checked against the
/// sender's actual balance and nonce in `ChainState::apply_transparent_tx`.
/// Hassan is fully transparent — every balance and transfer is visible on-chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparentTx {
    pub from: String,
    /// Full ML-DSA-87 public key — too large for `Hash`.
    pub from_pubkey: Vec<u8>,
    pub to: String,
    pub amount: u128,
    /// Burned fee (native units). Must be ≥ [`MIN_TX_FEE`].
    #[serde(default = "default_min_fee")]
    pub fee: u128,
    pub nonce: u64,
    pub chain_id: u64,
    /// Absolute lock (CLTV-class): selected tip blue must be ≥ this (`0` = none).
    #[serde(default)]
    pub lock_blue_score: u64,
    /// Relative lock (CSV-class): tip blue must be ≥ account.last_spend_blue + this.
    #[serde(default)]
    pub relative_lock_blues: u32,
    /// Optional hashlock covenant: if set, `hashlock_preimage` must commit to it.
    #[serde(default)]
    pub hashlock: Option<Hash>,
    /// Preimage unlocking `hashlock` (not signed; bound into tx_hash).
    #[serde(default)]
    pub hashlock_preimage: Vec<u8>,
    pub signature: Vec<u8>,
}

fn default_min_fee() -> u128 {
    MIN_TX_FEE
}

impl TransparentTx {
    /// Wire size used for density pricing. Unsigned drafts are priced as if
    /// they already carried a full ML-DSA-87 signature (wallets set fee before
    /// signing).
    pub fn relay_bytes(&self) -> usize {
        let mut priced = self.clone();
        if priced.signature.len() != PQ_SIGNATURE_SIZE {
            priced.signature = vec![0u8; PQ_SIGNATURE_SIZE];
        }
        bincode::serialize(&priced).map(|b| b.len()).unwrap_or_else(|_| {
            PQ_PUBLIC_KEY_SIZE
                .saturating_add(PQ_SIGNATURE_SIZE)
                .saturating_add(512)
        })
    }

    /// Consensus + mempool floor for this transfer: size density and absolute min.
    pub fn min_fee_required(&self) -> u128 {
        min_relay_fee_for_bytes(self.relay_bytes())
    }

    /// Build an unsigned tx with a size-priced fee. Call `.sign()` before submitting.
    pub fn new(from_pubkey: Vec<u8>, to: String, amount: u128, nonce: u64, chain_id: u64) -> Self {
        let mut tx = Self::new_with_fee(from_pubkey, to, amount, MIN_TX_FEE, nonce, chain_id);
        tx.fee = tx.min_fee_required();
        tx
    }

    pub fn new_with_fee(
        from_pubkey: Vec<u8>,
        to: String,
        amount: u128,
        fee: u128,
        nonce: u64,
        chain_id: u64,
    ) -> Self {
        Self {
            from: hash_to_address(&from_pubkey),
            from_pubkey,
            to,
            amount,
            fee,
            nonce,
            chain_id,
            lock_blue_score: 0,
            relative_lock_blues: 0,
            hashlock: None,
            hashlock_preimage: vec![],
            signature: vec![],
        }
    }

    /// Structural checks (address form, amounts, key/sig sizes) — no crypto.
    pub fn validate_form(&self) -> Result<(), String> {
        if !security::is_valid_address(&self.from) {
            return Err("Invalid from address".into());
        }
        if !security::is_valid_address(&self.to) {
            return Err("Invalid to address".into());
        }
        if self.amount == 0 {
            return Err("Amount must be > 0".into());
        }
        // Dust policy: amounts below DUST_THRESHOLD are rejected (BTC-like).
        if self.amount < DUST_THRESHOLD {
            return Err(format!(
                "Amount below dust threshold ({DUST_THRESHOLD} base units)"
            ));
        }
        let need = self.min_fee_required();
        if self.fee < need {
            return Err(format!(
                "Fee must be ≥ {need} (size {} B × {MIN_FEE_PER_BYTE}/B, floor {MIN_TX_FEE})",
                self.relay_bytes()
            ));
        }
        if self.amount.checked_add(self.fee).is_none() {
            return Err("amount+fee overflow".into());
        }
        if self.from_pubkey.len() != PQ_PUBLIC_KEY_SIZE {
            return Err("Invalid from_pubkey length".into());
        }
        if self.signature.len() != PQ_SIGNATURE_SIZE {
            // Unsigned drafts fail here; callers that build then sign should
            // validate after signing. Consensus only sees signed txs.
            if !self.signature.is_empty() {
                return Err("Invalid signature length".into());
            }
        }
        Ok(())
    }

    /// Canonical bytes that get signed and verified. Every field that affects
    /// the state transition must be included here, or an attacker could mutate
    /// an unsigned field (classic transaction-malleability bug).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.from.len() + self.to.len() + 80);
        buf.extend_from_slice(self.from.as_bytes());
        buf.extend_from_slice(self.to.as_bytes());
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.fee.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&self.lock_blue_score.to_le_bytes());
        buf.extend_from_slice(&self.relative_lock_blues.to_le_bytes());
        match &self.hashlock {
            Some(h) => {
                buf.push(1);
                buf.extend_from_slice(h.as_bytes());
            }
            None => buf.push(0),
        }
        buf
    }

    /// Sign with the private key matching `from_pubkey`.
    pub fn sign(&mut self, signing_key_bytes: &[u8]) -> Result<(), String> {
        self.signature =
            abs_sig::sign_pq512(b"transparent-tx", &self.signing_bytes(), signing_key_bytes)?;
        Ok(())
    }

    /// Full verification: confirms `from` is really the address derived from
    /// `from_pubkey` (bech32m or legacy hex), then checks the ML-DSA-87
    /// signature over the Blake3-512 prehash of the canonical transfer bytes.
    pub fn verify(&self) -> bool {
        if !address_matches_pubkey(&self.from, &self.from_pubkey) {
            return false;
        }
        abs_sig::verify_pq512(
            b"transparent-tx",
            &self.signing_bytes(),
            &self.from_pubkey,
            &self.signature,
        )
    }

    pub fn tx_hash(&self) -> Hash {
        let mut buf = self.signing_bytes();
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.hashlock_preimage);
        Hash(abs_sig::digest512(b"tx-hash", &buf))
    }

    /// Absolute Binding Signature view (number + type 87) for wallets / APIs.
    pub fn abs_signature(&self) -> abs_sig::AbsSignature {
        let digest = abs_sig::digest512(b"transparent-tx", &self.signing_bytes());
        abs_sig::AbsSignature::from_parts(&digest, &self.signature, &self.from_pubkey)
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;

    fn funded_state(address: &str, balance: u128) -> ChainState {
        let mut state = ChainState::new();
        state.accounts.insert(
            address.to_string(),
            Account {
                balance,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        state
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn valid_signed_tx_is_accepted_and_moves_balance() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut state = funded_state(&from, 1_000_000);

        let mut tx = TransparentTx::new(pk, test_address(1), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();

        state
            .apply_transparent_tx(&tx)
            .expect("valid tx should be accepted");
        assert_eq!(
            state.accounts.get(&from).unwrap().balance,
            1_000_000 - 1000 - tx.fee
        );
        assert_eq!(state.accounts.get(&test_address(1)).unwrap().balance, 1000);
        assert_eq!(state.accounts.get(&from).unwrap().nonce, 1);
        // Fee left the sender; without a block coinbase it is not yet credited
        // to a miner (standalone apply). Legacy burn counter stays 0 on v26+.
        assert_eq!(state.fees_burned, 0);
    }

    #[test]
    fn tampered_amount_after_signing_is_rejected() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut state = funded_state(&from, 1_000_000);

        let mut tx = TransparentTx::new(pk, test_address(1), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();
        tx.amount = 100_000; // attacker bumps the amount post-signature

        assert!(state.apply_transparent_tx(&tx).is_err());
    }

    #[test]
    fn forged_signature_from_random_bytes_is_rejected() {
        let (_sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut state = funded_state(&from, 1_000_000);

        let mut tx = TransparentTx::new(pk, test_address(1), 1000, 0, state.chain_id);
        tx.signature = vec![0u8; 64]; // no valid signature, just zero bytes

        assert!(state.apply_transparent_tx(&tx).is_err());
    }

    #[test]
    fn signing_with_a_different_key_than_from_pubkey_is_rejected() {
        let (sk_attacker, _pk_attacker) = generate_keypair();
        let (_sk_victim, pk_victim) = generate_keypair();
        let victim_addr = hash_to_address(&pk_victim);
        let mut state = funded_state(&victim_addr, 1_000_000);

        // Attacker claims to be the victim's address but signs with their own key.
        let mut tx = TransparentTx::new(pk_victim, test_address(2), 1000, 0, state.chain_id);
        tx.sign(&sk_attacker).unwrap();

        assert!(state.apply_transparent_tx(&tx).is_err());
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut state = funded_state(&from, 1_000_000);

        let mut tx = TransparentTx::new(pk, test_address(1), 1000, 5, state.chain_id); // should be 0
        tx.sign(&sk).unwrap();

        assert!(state.apply_transparent_tx(&tx).is_err());
    }

    #[test]
    fn insufficient_balance_is_rejected() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut state = funded_state(&from, 50);

        let mut tx = TransparentTx::new(pk, test_address(1), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();

        assert!(state.apply_transparent_tx(&tx).is_err());
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn replay_of_same_tx_twice_is_rejected_second_time() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut state = funded_state(&from, 1_000_000);

        let mut tx = TransparentTx::new(pk, test_address(1), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();

        state
            .apply_transparent_tx(&tx)
            .expect("first application should succeed");
        assert!(
            state.apply_transparent_tx(&tx).is_err(),
            "replaying the same tx must fail on nonce reuse"
        );
    }

    #[test]
    fn stake_lock_and_unlock_move_balance_on_ledger() {
        let (sk, pk) = generate_keypair();
        let owner = hash_to_address(&pk);
        let mut state = funded_state(&owner, 10_000);

        let parents = state.tips.clone();
        let ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let mut anchor = genesis_block();
        anchor.parents = parents;
        anchor.difficulty = difficulty;
        anchor.state_root = state.merkle_root();
        anchor.timestamp = ts;
        let (miner_sk, miner_pk) = generate_keypair();
        seal_block(&state, &mut anchor, &miner_sk, &miner_pk);

        let lock = custody::issue_custody(custody::CustodyRequest {
            kind: custody::CustodyKind::StakeLock,
            block: &anchor,
            foreign_chain_id: 0,
            amount: 2_500,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 0,
            chain_id: state.chain_id,
            dual_sig_keypair: None,
        })
        .unwrap();
        state.apply_custody_op(&lock).expect("stake lock");
        assert_eq!(state.account_balance(&owner), 7_500);
        assert_eq!(state.staked.get(&owner).copied().unwrap_or(0), 2_500);
        assert_eq!(state.account_nonce(&owner), 1);

        let unlock = custody::issue_custody(custody::CustodyRequest {
            kind: custody::CustodyKind::StakeUnlock,
            block: &anchor,
            foreign_chain_id: 0,
            amount: 2_500,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 1,
            chain_id: state.chain_id,
            dual_sig_keypair: None,
        })
        .unwrap();
        state.apply_custody_op(&unlock).expect("stake unlock");
        assert_eq!(state.account_balance(&owner), 10_000);
        assert_eq!(state.staked.get(&owner).copied().unwrap_or(0), 0);
        assert_eq!(state.account_nonce(&owner), 2);
    }

    #[test]
    fn attack_bridge_enter_cannot_mint_without_real_bridge() {
        // Critical: a self-consistent BridgeEnter (forged birth cert, no exit)
        // previously reminted up to MAX_SUPPLY. Must stay disabled.
        let (sk, pk) = generate_keypair();
        let owner = hash_to_address(&pk);
        let mut state = funded_state(&owner, 0);
        let before = state.minted_supply;

        let mut fake = genesis_block();
        fake.parents = state.tips.clone();
        fake.timestamp = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
        fake.difficulty = state.expected_difficulty_at(&fake.parents, fake.timestamp);
        fake.state_root = state.merkle_root();
        let (msk, mpk) = generate_keypair();
        seal_block(&state, &mut fake, &msk, &mpk);
        // Deliberately NOT add_block — attacker invents an off-DAG "anchor".

        let enter = custody::issue_custody(custody::CustodyRequest {
            kind: custody::CustodyKind::BridgeEnter,
            block: &fake,
            foreign_chain_id: 99,
            amount: 1_000_000,
            title_id: None,
            owner_sk: &sk,
            owner_pk: &pk,
            nonce: 0,
            chain_id: state.chain_id,
            dual_sig_keypair: None,
        })
        .unwrap();

        let err = state.apply_custody_op(&enter).unwrap_err();
        assert!(err.contains("disabled"), "got: {err}");
        assert_eq!(state.minted_supply, before);
        assert_eq!(state.account_balance(&owner), 0);

        let err = state.admit_custody_to_mempool(enter).unwrap_err();
        assert!(err.contains("disabled"), "got: {err}");
    }

    #[test]
    fn attack_header_only_stub_is_not_consensus_admissible() {
        // Critical: empty-witness stubs previously skipped STARK/birth, paid
        // subsidy, and permanently blocked the full body under the same hash.
        let mut state = ChainState::new();
        let parents = state.tips.clone();
        let ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let mut block = Block {
            height: 1,
            timestamp: ts,
            parents,
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: state.merkle_root(),
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        // PoW only — no seal_block (no STARK / birth).
        let target = pow_target(block.difficulty);
        while !hash_meets_target(&block.hash(), &target) {
            block.nonce = block.nonce.wrapping_add(1);
        }
        let err = state.add_block(block).unwrap_err();
        assert!(
            err.contains("Header-only") || err.contains("empty-witness"),
            "got: {err}"
        );
    }
}

#[cfg(test)]
mod pow_tests {
    use super::*;

    fn draft_block(state: &ChainState, parent: Hash, difficulty: u64) -> Block {
        let timestamp = now_ms();
        let mut block = Block {
            height: 1,
            timestamp,
            parents: vec![parent],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        block
    }

    #[test]
    fn block_claiming_a_different_difficulty_than_the_chain_requires_is_rejected() {
        // Before this check existed, a miner could stamp any difficulty
        // (e.g. 1) on a block regardless of what the chain actually
        // requires, and verify_pow would validate it against that
        // self-declared value instead of the chain's real target.
        let mut state = ChainState::new();
        let parent = state.tips[0];
        let ts = now_ms();
        let required = state.expected_difficulty_at(&[parent], ts);

        let mut wrong = draft_block(&state, parent, required.saturating_add(1000));
        wrong.timestamp = ts;
        assert!(state.add_block(wrong).is_err());

        let mut correct = draft_block(&state, parent, required);
        correct.timestamp = ts;
        // Re-seal after fixing timestamp so PoW/birth match.
        let (sk, pk) = test_miner_keys();
        correct.difficulty = required;
        seal_block(&state, &mut correct, sk, pk);
        assert!(state.add_block(correct).is_ok());
    }

    #[test]
    fn block_with_a_fake_stark_proof_is_rejected() {
        // The old `verify_stark_proof` was a byte-length stub: any blob of
        // a plausible size passed. This block's proof is real STARK-shaped
        // (right size range) but not an actual valid proof — it must now be
        // rejected by a real verifier instead of waved through.
        let mut state = ChainState::new();
        let parent = state.tips[0];
        let ts = now_ms();
        let required = state.expected_difficulty_at(&[parent], ts);
        let mut block = draft_block(&state, parent, required);
        block.timestamp = ts;
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        block.stark_proof = vec![0u8; 64];

        assert!(state.add_block(block).is_err());
    }

    #[test]
    fn verify_pow_does_not_panic_on_zero_difficulty() {
        // u32::MAX / 0 used to panic here; a block with a miner-supplied
        // difficulty of 0 could reach this before the fix.
        let hash = Hash::ZERO;
        assert!(verify_pow(&hash, 0));
    }

    #[test]
    fn pow_target_shrinks_as_difficulty_increases() {
        let easy = pow_target(1);
        let hard = pow_target(1_000_000);
        assert!(hard.as_slice() < easy.as_slice());
    }

    #[test]
    fn high_difficulty_rejects_a_large_hash_and_accepts_a_small_one() {
        // The old check only ever compared the first 4 bytes as a u32 and
        // capped `difficulty` itself at u32::MAX. This difficulty (2^40)
        // couldn't even be expressed in the old type, and at this scale the
        // target's first 4 bytes are all zero — so a hash that's large only
        // in the bytes the old truncated comparison would have looked at
        // (byte 4 onward) must now correctly fail, while a hash small
        // across the full 512 bits must pass.
        let difficulty = 1u64 << 40;
        let mut large_hash = Hash::ZERO;
        large_hash[4] = 0xff; // zero in the first 4 bytes, large right after
        let small_hash = Hash::ZERO;

        assert!(!verify_pow(&large_hash, difficulty));
        assert!(verify_pow(&small_hash, difficulty));
    }
}

/// Adversarial ("hack test") suite: each test drives an input an attacker
/// could actually supply and asserts the node rejects it *gracefully* rather
/// than panicking. Under `panic = "abort"` (this crate's release profile) a
/// panic is a full process death — so every one of these, before its fix,
/// was a trivial remote denial-of-service that could halt a node.
#[cfg(test)]
mod adversarial_tests {
    use super::*;

    /// A block with a valid PoW (trivial at genesis difficulty 1) and a real
    /// per-block STARK proof, so it clears every check up to the one under test.
    fn mined_block(state: &ChainState, timestamp: u64) -> Block {
        let parent = state.tips[0];
        let parents = vec![parent];
        let difficulty = state.expected_difficulty_at(&parents, timestamp);
        let mut block = Block {
            height: 1,
            timestamp,
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
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        block
    }

    #[test]
    fn a_corrupt_state_file_recovers_from_the_rolling_backup() {
        // Durability: a torn/corrupt primary state file must NOT reset the chain
        // to genesis — it recovers the previous good state from the `.bak` backup.
        let dir = std::env::temp_dir().join(format!("hassan-persist-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chainstate.bin");

        // Mine one real block so the persisted DAG is distinguishable from a
        // fresh genesis (state is recomputed from the DAG on load).
        let mut state = ChainState::new();
        let parents = state.tips.clone();
        let ts = now_ms();
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let mut block = Block {
            height: 0,
            timestamp: ts,
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
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        state.add_block(block).unwrap();
        assert_eq!(state.main_chain.len(), 2, "genesis + 1 mined block");

        state.save_to(&path).unwrap(); // primary: 2-block chain (no .bak yet)
        state.save_to(&path).unwrap(); // primary: 2-block, .bak: 2-block

        // Simulate a corrupt/torn primary write.
        std::fs::write(&path, b"garbage-not-a-valid-state-file").unwrap();

        let loaded = ChainState::load_from(&path).expect("must recover, not fail to genesis");
        assert_eq!(
            loaded.main_chain.len(),
            2,
            "recovered the 2-block backup, not a fresh genesis (1)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn attack_backwards_timestamp_is_a_graceful_rejection_not_a_node_crash() {
        // A timestamp earlier than the parent used to underflow the
        // `current - past` subtraction in difficulty retargeting → panic.
        let mut state = ChainState::new();
        let parent_ts = state.dag.get(&state.tips[0]).unwrap().timestamp;
        let block = mined_block(&state, parent_ts.saturating_sub(1));
        assert!(
            state.add_block(block).is_err(),
            "a backwards timestamp must be rejected"
        );
    }

    #[test]
    fn attack_far_future_timestamp_is_rejected() {
        let mut state = ChainState::new();
        let block = mined_block(
            &state,
            now_ms().saturating_add(MAX_FUTURE_DRIFT_MS + 10_000),
        );
        assert!(
            state.add_block(block).is_err(),
            "a far-future timestamp must be rejected"
        );
    }

    #[test]
    fn attack_recipient_balance_overflow_is_rejected_and_does_not_debit_sender() {
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let mut state = ChainState::new();
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        // Recipient pre-loaded to the max — any credit overflows u128.
        state.accounts.insert(
            test_address(3),
            Account {
                balance: u128::MAX,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );

        let mut tx = TransparentTx::new(pk, test_address(3), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();

        assert!(
            state.apply_transparent_tx(&tx).is_err(),
            "recipient overflow must be rejected"
        );
        assert_eq!(
            state.accounts.get(&from).unwrap().balance,
            1_000_000,
            "a rejected transfer must not debit the sender",
        );
    }

    fn bare_block(parents: Vec<Hash>) -> Block {
        Block {
            height: 1,
            timestamp: now_ms(),
            parents,
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: ChainState::new().merkle_root(),
            miner: Hash([7u8; HASH_SIZE]),
            creator_pubkey: vec![],
            nonce: 0,
            difficulty: effective_min_difficulty(),
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        }
    }

    #[test]
    fn attack_too_many_parents_is_rejected() {
        // A tiny block citing more than MAX_BLOCK_PARENTS parents is an
        // amplification-DoS vector (each parent drives GHOSTDAG BFS work). The
        // cap fires before any expensive processing.
        let mut state = ChainState::new();
        let parents: Vec<Hash> = (0..(MAX_BLOCK_PARENTS as u8 + 1))
            .map(|i| Hash([i; HASH_SIZE]))
            .collect();
        let err = state.add_block(bare_block(parents)).unwrap_err();
        assert!(err.contains("Too many parents"), "got: {err}");
    }

    #[test]
    fn attack_duplicate_parents_is_rejected() {
        let mut state = ChainState::new();
        let genesis = state.tips[0];
        let err = state
            .add_block(bare_block(vec![genesis, genesis]))
            .unwrap_err();
        assert!(err.contains("Duplicate parent"), "got: {err}");
    }

    #[test]
    fn attack_empty_parents_is_rejected() {
        let mut state = ChainState::new();
        let err = state.add_block(bare_block(vec![])).unwrap_err();
        assert!(err.contains("no parents"), "got: {err}");
    }
}

/// End-to-end GHOSTDAG tests through the real `add_block` path (real PoW —
/// trivial at genesis difficulty 1 — and real per-block STARK proofs), as
/// opposed to `ghostdag`'s own unit tests which drive the algorithm on bare
/// DAG shapes.
#[cfg(test)]
mod ghostdag_integration_tests {
    use super::*;

    fn valid_child(state: &ChainState, parents: Vec<Hash>, tag: u8) -> Block {
        let timestamp = now_ms();
        let difficulty = state.expected_difficulty_at(&parents, timestamp);
        let mut block = Block {
            height: state.main_chain.len() as u64,
            timestamp,
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
            // Starting nonce carries `tag` so siblings mined off the same
            // parents/timestamp still land on distinct hashes (PoW at these
            // test difficulties accepts the first nonce it tries).
            nonce: tag as u64,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: tag as u64,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        block
    }

    #[test]
    fn add_block_builds_a_ghostdag_selected_chain_with_growing_blue_score() {
        let mut state = ChainState::new();
        assert_eq!(state.selected_tip_blue_score(), 0);
        let genesis = state.tips[0];

        let b1 = valid_child(&state, vec![genesis], 1);
        let h1 = b1.hash();
        state.add_block(b1).expect("valid child of genesis");
        assert_eq!(state.selected_tip_blue_score(), 1);
        assert_eq!(*state.main_chain.last().unwrap(), h1);

        let b2 = valid_child(&state, vec![h1], 2);
        let h2 = b2.hash();
        state.add_block(b2).expect("valid child of b1");
        assert_eq!(state.selected_tip_blue_score(), 2);
        assert_eq!(state.main_chain, vec![genesis, h1, h2]);
    }

    #[test]
    fn a_merge_block_selects_the_heavier_branch_and_raises_blue_score() {
        let mut state = ChainState::new();
        let genesis = state.tips[0];

        // Two parallel children of genesis (different miner tags => different hashes).
        let a = valid_child(&state, vec![genesis], 1);
        let ha = a.hash();
        state.add_block(a).unwrap();
        let b = valid_child(&state, vec![genesis], 2);
        let hb = b.hash();
        state.add_block(b).unwrap();

        // Now both a and b are tips. A block merging them is a real DAG merge.
        let merge = valid_child(&state, vec![ha, hb], 3);
        let hm = merge.hash();
        state.add_block(merge).expect("merge of two tips");

        // The merge is the selected tip, and its blue score exceeds either
        // single branch's (it merged the other branch's blue block too).
        assert_eq!(*state.main_chain.last().unwrap(), hm);
        assert!(state.selected_tip_blue_score() >= 2);
        // Only one tip remains after the merge.
        assert_eq!(state.tips, vec![hm]);
    }

    #[test]
    fn parallel_siblings_commit_post_mergeset_state_root() {
        // Empty siblings each commit a post-mergeset root that includes their
        // UTXO coinbase (≠ SP pre-state). Distinct coinbase entropy (tag) means
        // roots may differ; both remain admissible against the shared SP.
        let mut state = ChainState::new();
        let genesis = state.tips[0];
        let parent_pre = state.merkle_root_at(&genesis);

        let a = valid_child(&state, vec![genesis], 1);
        assert_ne!(
            a.state_root, parent_pre,
            "post-mergeset root includes this block's subsidy"
        );
        state.add_block(a.clone()).unwrap();
        assert_ne!(
            state.merkle_root(),
            parent_pre,
            "live tip must move after subsidy"
        );

        let b = valid_child(&state, vec![genesis], 2);
        assert_ne!(
            b.state_root, parent_pre,
            "sibling also commits subsidy in post-mergeset root"
        );
        state
            .add_block(b)
            .expect("parallel sibling with post-mergeset state_root must be admitted");
        assert!(state.supply_invariant_ok());
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn parallel_siblings_with_different_bodies_have_different_state_roots() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let genesis = state.tips[0];
        let mut tx = TransparentTx::new(pk, test_address(0xb), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();

        let empty = valid_child(&state, vec![genesis], 1);
        let with_tx = {
            let timestamp = now_ms();
            let difficulty = state.expected_difficulty_at(&[genesis], timestamp);
            let mut block = Block {
                height: 1,
                timestamp,
                parents: vec![genesis],
                interlinks: vec![],
                transparent_txs: vec![tx],
                utxo_txs: vec![],
                registry_ops: vec![],
                custody_ops: vec![],
                merkle_root: Hash::ZERO,
                state_root: Hash::ZERO,
                miner: Hash::ZERO,
                creator_pubkey: vec![],
                nonce: 2,
                difficulty,
                version: crate::default_block_version(),
                coinbase_entropy: 0,
                stark_proof: vec![],
                birth_certificate: Default::default(),
                size: 0,
            };
            let (skm, pkm) = test_miner_keys();
            seal_block(&state, &mut block, skm, pkm);
            block
        };
        assert_ne!(
            empty.state_root, with_tx.state_root,
            "different bodies → different post-mergeset state_roots"
        );
        state.add_block(empty).unwrap();
        // Second sibling still admits (parallel) with its own root.
        state
            .add_block(with_tx)
            .expect("funded parallel sibling must admit");
    }
}

/// Windowed difficulty-adjustment (DAA) tests.
#[cfg(test)]
mod daa_tests {
    use super::*;

    /// Mine one valid block on the current selected tip. Uses `timestamp = t`
    /// so the test can control the block-time spacing the DAA sees. Performs a
    /// real (small) PoW search, since once the DAA raises difficulty above the floor a
    /// fixed nonce no longer satisfies the target.
    fn mine_at(state: &mut ChainState, t: u64) {
        let parents = state.tips.clone();
        let difficulty = state.expected_difficulty_at(&parents, t);
        let mut block = Block {
            height: state.main_chain.len() as u64,
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
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        state.add_block(block).expect("mined block must be valid");
    }

    /// Mine a block on explicit `parents` (with a distinguishing `tag` so
    /// sibling blocks off the same parent get different hashes). Returns its
    /// hash. Lets a test build a *wide* DAG (forks/merges), not just a chain.
    fn mine_with_parents(state: &mut ChainState, t: u64, parents: Vec<Hash>, tag: u8) -> Hash {
        let difficulty = state.expected_difficulty_at(&parents, t);
        let mut block = Block {
            height: 0,
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
            // Starting nonce carries `tag` so siblings mined off the same
            // parents/timestamp still land on distinct hashes.
            nonce: tag as u64,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        let h = block.hash();
        state.add_block(block).expect("mined block must be valid");
        h
    }

    /// Mine a block carrying transparent transfers, computing the canonical
    /// merkle_root (so it passes the PoW-binding check).
    fn mine_block_with_transparent(
        state: &mut ChainState,
        t: u64,
        transparent_txs: Vec<TransparentTx>,
    ) -> Result<(), String> {
        let parents = state.tips.clone();
        let difficulty = state.expected_difficulty_at(&parents, t);
        let mut block = Block {
            height: 0,
            timestamp: t,
            parents,
            interlinks: vec![],
            transparent_txs,
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state.bind_parent_commitments(&mut block)?;
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        state.add_block(block)
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn the_block_builder_skips_a_future_nonce_transfer_instead_of_halting() {
        // Liveness: a future-nonce transfer is admitted to the mempool (gaps are
        // allowed for queuing) but breaks strict block validation. If the
        // builder included it blindly, EVERY block would be rejected and the
        // chain would halt. `select_valid_block_txs` must skip it and keep the
        // good one, so a valid block can still be built.
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );

        let mut good = TransparentTx::new(pk.clone(), test_address(0xb), 1000, 0, state.chain_id);
        good.sign(&sk).unwrap();
        let mut future = TransparentTx::new(pk, test_address(0xc), 1000, 5, state.chain_id); // nonce gap
        future.sign(&sk).unwrap();

        let selected = state.select_valid_block_txs(&[good.clone(), future.clone()]);
        assert_eq!(
            selected.len(),
            1,
            "only the valid-sequence transfer is selected"
        );
        assert_eq!(selected[0].nonce, 0, "the future-nonce one is skipped");
        // And the selected set really is block-valid.
        mine_block_with_transparent(
            &mut state,
            GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS,
            selected,
        )
        .expect("a block with only the valid transfer must be accepted");
        assert_eq!(state.account_balance(&test_address(0xb)), 1000);
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn a_transparent_transfer_flows_through_mempool_into_a_block_and_moves_value() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        // Fund the sender (as if from a prior mining reward).
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );

        let mut tx = TransparentTx::new(pk, test_address(0xb), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();
        state
            .admit_transparent_to_mempool(tx.clone())
            .expect("valid transfer admitted");
        assert_eq!(state.transparent_mempool.len(), 1);

        let queued = state.transparent_mempool.clone();
        mine_block_with_transparent(
            &mut state,
            GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS,
            queued,
        )
        .expect("block with a valid transfer must be accepted");

        assert_eq!(
            state.account_balance(&from),
            1_000_000 - 1000 - tx.fee,
            "sender debited (amount + fee)"
        );
        assert_eq!(
            state.account_balance(&test_address(0xb)),
            1000,
            "recipient credited"
        );
        assert_eq!(state.account_nonce(&from), 1, "nonce advanced");
        assert!(
            state.transparent_mempool.is_empty(),
            "included transfer left the mempool"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn a_confirmed_transfer_has_a_full_economic_entity_and_journey() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );

        let mut tx = TransparentTx::new(pk, test_address(0xb), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();
        let tx_hash = tx.tx_hash();
        state
            .admit_transparent_to_mempool(tx.clone())
            .expect("valid transfer admitted");

        let queued = state.transparent_mempool.clone();
        mine_block_with_transparent(
            &mut state,
            GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS,
            queued,
        )
        .expect("block with a valid transfer must be accepted");

        let mined_hash = *state.main_chain.last().unwrap();
        let block_entity = crate::economics::EconomicEntity::for_block(&state, &mined_hash)
            .expect("mined block has an economic entity");
        assert_eq!(block_entity.transaction_count, 1);
        assert!(
            block_entity.provenance.issuance_verified,
            "mined block's birth certificate must verify"
        );
        assert!(block_entity.finality.is_on_selected_chain);
        assert!(block_entity.cost_basis.is_estimate);

        let bio = crate::economics::EconomicBiography::for_block(&state, &mined_hash)
            .expect("mined block has a biography");
        assert!(bio.origin.contains("Issued at"));

        let tx_entity = crate::economics::TransactionEconomicEntity::for_tx(&state, &tx_hash)
            .expect("confirmed transfer is findable");
        match tx_entity.lineage {
            crate::economics::TransactionLineage::Confirmed {
                containing_block, ..
            } => {
                assert_eq!(containing_block, hex::encode(mined_hash));
            }
            crate::economics::TransactionLineage::Pending => {
                panic!("transfer was mined, must not read as pending")
            }
        }
        assert!(tx_entity.journey.first_seen_ms.is_some());
        assert!(tx_entity.journey.confirmed_at_ms.is_some());
        assert!(tx_entity.journey.mempool_dwell_ms.is_some());
    }

    #[test]
    fn a_block_with_an_underfunded_transfer_is_rejected_at_admission() {
        // Strict SP+mergeset virtual body validation: an underfunded transfer in
        // the block body rejects the whole block. Conflict-skip remains only
        // for historical mergeset replay across parallel/red conflicts.
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 100,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );

        let mut tx = TransparentTx::new(pk, test_address(0xb), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();

        let dag_before = state.dag.len();
        let err = mine_block_with_transparent(
            &mut state,
            GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS,
            vec![tx],
        )
        .expect_err("underfunded body must reject the block");
        assert!(
            err.contains("does not apply") || err.contains("underfund") || err.contains("balance"),
            "expected apply failure, got: {err}"
        );
        assert_eq!(state.dag.len(), dag_before, "rejected block must not enter DAG");
        assert_eq!(state.account_balance(&from), 100);
        assert_eq!(state.account_balance(&test_address(0xb)), 0);
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn an_honest_funded_transfer_in_a_block_still_applies() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let to = test_address(0xc);
        let fee = typical_signed_tx_min_fee();
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000 + fee,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let mut tx = TransparentTx::new_with_fee(pk, to.clone(), 1000, fee, 0, state.chain_id);
        tx.sign(&sk).unwrap();
        let paid_fee = tx.fee;
        mine_block_with_transparent(
            &mut state,
            GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS,
            vec![tx],
        )
        .expect("honest funded body must be admitted");
        assert_eq!(state.account_balance(&from), 1_000_000 + fee - 1000 - paid_fee);
        assert_eq!(state.account_balance(&to), 1000);
        assert_eq!(state.fees_burned, 0, "v26+ fees go to miner coinbase, not burn");
        // Tip coinbase must include subsidy + the body's fee.
        let tip = *state.tips.last().expect("tip");
        let tip_block = state.dag.get(&tip).expect("tip block");
        let cb = utxo::OutPoint::coinbase(utxo::coinbase_txid(tip_block));
        let cb_out = state.utxo.get(&cb).expect("coinbase utxo");
        let blue = state.ghostdag.get(&tip).map(|d| d.blue_score).unwrap_or(0);
        let subsidy = block_subsidy(blue);
        assert_eq!(cb_out.value, subsidy.saturating_add(paid_fee));
        assert!(
            !state.fee_history.samples.is_empty(),
            "selected-chain fee samples must be recorded"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn parallel_siblings_with_shared_selected_parent_are_both_admissible_when_self_consistent() {
        // Two parallel children of the same tip, each carrying a self-consistent
        // transfer from a different funded account. Both must be admitted
        // (state_root = SP pre-state; each body validates against SP virtual).
        // Live balances reflect both only after a merge cites both parents.
        let mut state = ChainState::new();
        let (sk_a, pk_a) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let from_a = hash_to_address(&pk_a);
        let from_b = hash_to_address(&pk_b);
        let fee = typical_signed_tx_min_fee();
        for addr in [&from_a, &from_b] {
            state.accounts.insert(
                addr.clone(),
                Account {
                    balance: 500_000 + fee,
                    nonce: 0,
                last_spend_blue: 0,
                    code_hash: None,
                    storage_root: Hash::ZERO,
                },
            );
        }
        let parent = *state.tips.last().unwrap();
        let t = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;

        let mut tx_a =
            TransparentTx::new_with_fee(pk_a, test_address(0xa), 1000, fee, 0, state.chain_id);
        tx_a.sign(&sk_a).unwrap();
        let mut tx_b =
            TransparentTx::new_with_fee(pk_b, test_address(0xb), 1000, fee, 0, state.chain_id);
        tx_b.sign(&sk_b).unwrap();

        let mine_sibling = |state: &mut ChainState,
                            parents: Vec<Hash>,
                            tag: u8,
                            ts: u64,
                            txs: Vec<TransparentTx>|
         -> Hash {
            let difficulty = state.expected_difficulty_at(&parents, ts);
            let mut block = Block {
                height: 0,
                timestamp: ts,
                parents,
                interlinks: vec![],
                transparent_txs: txs,
                utxo_txs: vec![],
                registry_ops: vec![],
                custody_ops: vec![],
                merkle_root: Hash::ZERO,
                state_root: Hash::ZERO,
                miner: Hash::ZERO,
                creator_pubkey: vec![],
                nonce: tag as u64,
                difficulty,
                version: crate::default_block_version(),
                coinbase_entropy: 0,
                stark_proof: vec![],
                birth_certificate: Default::default(),
                size: 0,
            };
            state
                .bind_parent_commitments(&mut block)
                .expect("selected parent");
            let (sk, pk) = test_miner_keys();
            seal_block(&state, &mut block, sk, pk);
            let h = block.hash();
            state.add_block(block).expect("self-consistent sibling must admit");
            h
        };

        let h_a = mine_sibling(&mut state, vec![parent], 1, t, vec![tx_a]);
        let h_b = mine_sibling(&mut state, vec![parent], 2, t, vec![tx_b]);
        assert!(state.dag.contains_key(&h_a));
        assert!(state.dag.contains_key(&h_b));

        // Merge both tips so both bodies enter the selected-chain mergeset.
        let _merge = mine_sibling(
            &mut state,
            vec![h_a, h_b],
            3,
            t + TARGET_BLOCK_TIME_MS,
            vec![],
        );
        assert_eq!(state.account_balance(&test_address(0xa)), 1000);
        assert_eq!(state.account_balance(&test_address(0xb)), 1000);
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn merge_block_may_spend_output_created_in_its_mergeset() {
        // Kaspa-shaped: after applying mergeset (conflict-skip), *this* block's
        // body must apply on that virtual. A transfer funded only by a parallel
        // sibling in the mergeset is valid here (would fail on SP-only).
        let mut state = ChainState::new();
        let (sk_a, pk_a) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let from_a = hash_to_address(&pk_a);
        let fee = typical_signed_tx_min_fee();
        state.accounts.insert(
            from_a.clone(),
            Account {
                balance: 500_000 + fee * 2,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        // Bob starts empty — funded only via sibling A's transfer.
        let from_b = hash_to_address(&pk_b);
        let parent = *state.tips.last().unwrap();
        let t = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;

        let mut tx_fund =
            TransparentTx::new_with_fee(pk_a, from_b.clone(), 50_000 + fee, fee, 0, state.chain_id);
        tx_fund.sign(&sk_a).unwrap();

        let mine_sibling = |state: &mut ChainState,
                            parents: Vec<Hash>,
                            tag: u8,
                            ts: u64,
                            txs: Vec<TransparentTx>|
         -> Hash {
            let difficulty = state.expected_difficulty_at(&parents, ts);
            let mut block = Block {
                height: 0,
                timestamp: ts,
                parents,
                interlinks: vec![],
                transparent_txs: txs,
                utxo_txs: vec![],
                registry_ops: vec![],
                custody_ops: vec![],
                merkle_root: Hash::ZERO,
                state_root: Hash::ZERO,
                miner: Hash::ZERO,
                creator_pubkey: vec![],
                nonce: tag as u64,
                difficulty,
                version: crate::default_block_version(),
                coinbase_entropy: 0,
                stark_proof: vec![],
                birth_certificate: Default::default(),
                size: 0,
            };
            state
                .bind_parent_commitments(&mut block)
                .expect("selected parent");
            let (skm, pkm) = test_miner_keys();
            seal_block(&state, &mut block, skm, pkm);
            let h = block.hash();
            state.add_block(block).expect("sibling must admit");
            h
        };

        let h_a = mine_sibling(&mut state, vec![parent], 1, t, vec![tx_fund]);
        // Empty parallel sibling so the merge has a non-trivial mergeset that
        // still includes A's funding transfer when A is not the selected parent,
        // or is a blue in the mergeset.
        let h_empty = mine_sibling(&mut state, vec![parent], 2, t, vec![]);

        let mut tx_spend =
            TransparentTx::new_with_fee(pk_b, test_address(0xc), 1000, fee, 0, state.chain_id);
        tx_spend.sign(&sk_b).unwrap();

        let h_merge = mine_sibling(
            &mut state,
            vec![h_a, h_empty],
            3,
            t + TARGET_BLOCK_TIME_MS,
            vec![tx_spend],
        );
        assert!(state.dag.contains_key(&h_merge));
        assert_eq!(state.account_balance(&test_address(0xc)), 1000);
        assert_eq!(state.account_balance(&from_b), 50_000 - 1000);
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn merge_block_rejecting_stale_nonce_already_consumed_in_mergeset() {
        // After mergeset applies Alice's nonce-0 spend, a merge body reusing
        // nonce 0 must be rejected at admission (strict on mergeset virtual).
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let fee = typical_signed_tx_min_fee();
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 500_000 + fee * 2,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let parent = *state.tips.last().unwrap();
        let t = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;

        let mut tx0 =
            TransparentTx::new_with_fee(pk.clone(), test_address(0xa), 1000, fee, 0, state.chain_id);
        tx0.sign(&sk).unwrap();
        let mut tx_stale =
            TransparentTx::new_with_fee(pk, test_address(0xb), 1000, fee, 0, state.chain_id);
        tx_stale.sign(&sk).unwrap();

        let mine_sibling = |state: &mut ChainState,
                            parents: Vec<Hash>,
                            tag: u8,
                            ts: u64,
                            txs: Vec<TransparentTx>|
         -> Result<Hash, String> {
            let difficulty = state.expected_difficulty_at(&parents, ts);
            let mut block = Block {
                height: 0,
                timestamp: ts,
                parents,
                interlinks: vec![],
                transparent_txs: txs,
                utxo_txs: vec![],
                registry_ops: vec![],
                custody_ops: vec![],
                merkle_root: Hash::ZERO,
                state_root: Hash::ZERO,
                miner: Hash::ZERO,
                creator_pubkey: vec![],
                nonce: tag as u64,
                difficulty,
                version: crate::default_block_version(),
                coinbase_entropy: 0,
                stark_proof: vec![],
                birth_certificate: Default::default(),
                size: 0,
            };
            state.bind_parent_commitments(&mut block)?;
            let (skm, pkm) = test_miner_keys();
            seal_block(&state, &mut block, skm, pkm);
            let h = block.hash();
            state.add_block(block)?;
            Ok(h)
        };

        let h_a = mine_sibling(&mut state, vec![parent], 1, t, vec![tx0]).unwrap();
        let h_empty = mine_sibling(&mut state, vec![parent], 2, t, vec![]).unwrap();
        let err = mine_sibling(
            &mut state,
            vec![h_a, h_empty],
            3,
            t + TARGET_BLOCK_TIME_MS,
            vec![tx_stale],
        )
        .expect_err("stale nonce vs mergeset virtual must reject");
        assert!(
            err.contains("does not apply") || err.contains("nonce") || err.contains("Bad nonce"),
            "expected nonce failure, got: {err}"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn parallel_same_nonce_siblings_both_admit_but_mergeset_replay_keeps_one() {
        // Kaspa-style mergeset conflict: two parallel children of the same SP
        // each spend the same account nonce. Both bodies are self-consistent
        // against the SP virtual → both admit. Canonical mergeset replay
        // conflict-skips the loser (only one debit applies).
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        let fee = typical_signed_tx_min_fee();
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 500_000 + fee,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let parent = *state.tips.last().unwrap();
        let t = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
        let bal_before = state.account_balance(&from);

        let mut tx_a =
            TransparentTx::new_with_fee(pk.clone(), test_address(0xa), 1000, fee, 0, state.chain_id);
        tx_a.sign(&sk).unwrap();
        let mut tx_b =
            TransparentTx::new_with_fee(pk, test_address(0xb), 1000, fee, 0, state.chain_id);
        tx_b.sign(&sk).unwrap();

        let mine_sibling = |state: &mut ChainState,
                            parents: Vec<Hash>,
                            tag: u8,
                            ts: u64,
                            txs: Vec<TransparentTx>|
         -> Hash {
            let difficulty = state.expected_difficulty_at(&parents, ts);
            let mut block = Block {
                height: 0,
                timestamp: ts,
                parents,
                interlinks: vec![],
                transparent_txs: txs,
                utxo_txs: vec![],
                registry_ops: vec![],
                custody_ops: vec![],
                merkle_root: Hash::ZERO,
                state_root: Hash::ZERO,
                miner: Hash::ZERO,
                creator_pubkey: vec![],
                nonce: tag as u64,
                difficulty,
                version: crate::default_block_version(),
                coinbase_entropy: 0,
                stark_proof: vec![],
                birth_certificate: Default::default(),
                size: 0,
            };
            state
                .bind_parent_commitments(&mut block)
                .expect("selected parent");
            let (skm, pkm) = test_miner_keys();
            seal_block(&state, &mut block, skm, pkm);
            let h = block.hash();
            state
                .add_block(block)
                .expect("SP-consistent conflicting sibling must admit");
            h
        };

        let h_a = mine_sibling(&mut state, vec![parent], 1, t, vec![tx_a]);
        let h_b = mine_sibling(&mut state, vec![parent], 2, t, vec![tx_b]);
        assert!(state.dag.contains_key(&h_a));
        assert!(state.dag.contains_key(&h_b));

        let _merge = mine_sibling(
            &mut state,
            vec![h_a, h_b],
            3,
            t + TARGET_BLOCK_TIME_MS,
            vec![],
        );

        let to_a = state.account_balance(&test_address(0xa));
        let to_b = state.account_balance(&test_address(0xb));
        assert!(
            (to_a == 1000 && to_b == 0) || (to_a == 0 && to_b == 1000),
            "exactly one conflicting transfer must apply; got a={to_a} b={to_b}"
        );
        let winner_debit = 1000 + fee;
        assert_eq!(
            state.account_balance(&from),
            bal_before - winner_debit,
            "sender debited once"
        );
        assert_eq!(state.account_nonce(&from), 1, "nonce advanced once");
    }

    #[test]
    fn chain_state_persists_and_reloads_and_keeps_advancing() {
        let mut state = ChainState::new();
        // A small wide-ish DAG so reachability rebuild has real structure.
        let mut prev = *state.tips.last().unwrap();
        let mut t = GENESIS_TIMESTAMP_MS + 1;
        for i in 0..12u8 {
            let c1 = mine_with_parents(&mut state, t, vec![prev], i * 3 + 1);
            t += TARGET_BLOCK_TIME_MS;
            let c2 = mine_with_parents(&mut state, t, vec![prev], i * 3 + 2);
            t += TARGET_BLOCK_TIME_MS;
            prev = mine_with_parents(&mut state, t, vec![c1, c2], i * 3 + 3);
            t += TARGET_BLOCK_TIME_MS;
        }
        let dag_len = state.dag.len();
        let score = state.selected_tip_blue_score();
        let tip = *state.main_chain.last().unwrap();
        let genesis = state.main_chain[0];

        // Round-trip through disk.
        let path = std::env::temp_dir().join(format!("hassan-persist-{}.bin", std::process::id()));
        state.save_to(&path).expect("save");
        let mut loaded = ChainState::load_from(&path).expect("load");
        let _ = std::fs::remove_file(&path);

        // Consensus state survived.
        assert_eq!(loaded.dag.len(), dag_len, "DAG size preserved");
        assert_eq!(
            loaded.selected_tip_blue_score(),
            score,
            "blue score preserved"
        );
        assert_eq!(
            *loaded.main_chain.last().unwrap(),
            tip,
            "selected tip preserved"
        );

        // The REBUILT reachability oracle is correct: it agrees with BFS, and
        // (crucially) the loaded node can keep mining — which drives GHOSTDAG
        // coloring through the rebuilt oracle.
        assert!(
            loaded.reachability.is_ancestor(&genesis, &tip, &loaded.dag),
            "genesis reaches tip"
        );
        assert!(
            !loaded.reachability.is_ancestor(&tip, &genesis, &loaded.dag),
            "tip does not reach genesis"
        );
        let before = loaded.selected_tip_blue_score();
        for _ in 0..5 {
            mine_at(&mut loaded, t);
            t += TARGET_BLOCK_TIME_MS;
        }
        assert!(
            loaded.selected_tip_blue_score() > before,
            "loaded chain keeps advancing correctly"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn a_block_whose_merkle_root_lies_about_its_transactions_is_rejected() {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        state.accounts.insert(
            from.clone(),
            Account {
                balance: 1_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let mut tx = TransparentTx::new(pk, test_address(0xb), 1000, 0, state.chain_id);
        tx.sign(&sk).unwrap();

        let parents = state.tips.clone();
        let ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let target = pow_target(difficulty);
        let (miner_sk, miner_pk) = test_miner_keys();
        let mut block = Block {
            height: 0,
            timestamp: ts,
            parents,
            interlinks: vec![],
            transparent_txs: vec![tx],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO, // WRONG: claims no txs while carrying one
            state_root: Hash::ZERO,
            miner: address_hash(miner_pk),
            nonce: 0,
            difficulty,
            version: default_block_version(),
            coinbase_entropy: 0,
            creator_pubkey: miner_pk.clone(),
            stark_proof: vec![],
            size: 0,
            birth_certificate: Default::default(),
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        // Keep the lying body merkle commitment (bind only sets state/interlinks).
        block.merkle_root = Hash::ZERO;
        // Seal issuance/PoW by hand (not via `seal_block`) so the lying
        // `merkle_root` above survives sealing instead of being recomputed to
        // the correct value — that's the exact fault this test is checking for.
        while !hash_meets_target(&block.hash(), &target) {
            block.nonce += 1;
        }
        block
            .issue_birth_certificate(miner_sk)
            .expect("ML-DSA-87 birth certificate");
        block.stark_proof = stark::prove(block.hash().as_slice());
        let err = state.add_block(block).unwrap_err();
        assert!(err.contains("merkle_root does not commit"), "got: {err}");
    }

    #[test]
    fn difficulty_stays_at_floor_until_the_window_is_full() {
        let mut state = ChainState::new();
        // The window for the *next* block includes genesis, so it fills once
        // the chain reaches DAA_WINDOW blocks. Mine two fewer than that so the
        // next block's window is still short and difficulty stays at the floor.
        for i in 0..(DAA_WINDOW as u64 - 2) {
            mine_at(&mut state, GENESIS_TIMESTAMP_MS + 1 + i);
        }
        assert_eq!(
            state.difficulty, effective_min_difficulty(),
            "difficulty must stay at era floor before the window fills"
        );
    }

    #[test]
    fn difficulty_rises_when_blocks_come_faster_than_target() {
        let mut state = ChainState::new();
        // Mine well past the window with tight 1ms spacing — far faster than
        // the 100ms target — so the DAA must raise difficulty above the floor.
        for i in 0..(DAA_WINDOW as u64 + 10) {
            mine_at(&mut state, GENESIS_TIMESTAMP_MS + 1 + i);
        }
        assert!(
            state.difficulty > effective_min_difficulty(),
            "difficulty should rise above era floor when blocks are mined faster than target (got {})",
            state.difficulty
        );
    }

    #[test]
    fn expected_difficulty_is_deterministic_and_never_below_one() {
        let mut state = ChainState::new();
        for i in 0..(DAA_WINDOW as u64 + 5) {
            mine_at(&mut state, GENESIS_TIMESTAMP_MS + 1 + i * TARGET_BLOCK_TIME_MS); // on-target blocks
        }
        let a = state.expected_difficulty(&state.tips);
        let b = state.expected_difficulty(&state.tips);
        assert_eq!(
            a, b,
            "expected_difficulty must be a deterministic function of the block's past"
        );
        assert!(
            a >= effective_min_difficulty(),
            "difficulty must never drop below era floor"
        );
    }

    #[test]
    fn daa_never_admits_below_era_pow_floor() {
        // Bootstrap-era floor at genesis supply; blocks below it are rejected.
        assert_eq!(MIN_DIFFICULTY, BOOTSTRAP_MIN_DIFFICULTY);
        let mut state = ChainState::new();
        let parent = state.tips[0];
        let ts = GENESIS_TIMESTAMP_MS + TARGET_BLOCK_TIME_MS;
        let floor = effective_min_difficulty();
        let required = state.expected_difficulty_at(&[parent], ts);
        assert!(
            required >= floor,
            "required difficulty {required} below effective floor {floor}"
        );

        let mut soft = Block {
            height: 1,
            timestamp: ts,
            parents: vec![parent],
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: Hash::ZERO,
            miner: Hash::ZERO,
            creator_pubkey: vec![],
            nonce: 0,
            difficulty: floor.saturating_sub(1).max(1),
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut soft)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut soft, sk, pk);
        let err = state.add_block(soft).unwrap_err();
        assert!(
            err.contains("Wrong difficulty"),
            "below-floor claim must be rejected, got: {err}"
        );
    }

    #[test]
    fn per_block_difficulty_change_is_clamped() {
        let mut state = ChainState::new();
        // Fill the window with tight spacing so the DAA is active and pushing up.
        for i in 0..(DAA_WINDOW as u64 + 2) {
            mine_at(&mut state, GENESIS_TIMESTAMP_MS + 1 + i);
        }
        let before = state.difficulty.max(effective_min_difficulty());
        // The next block's required difficulty must not jump by more than the
        // clamp (5/4×, or +1 at low values) — no single-block spike that could
        // stall the chain.
        let next = state.expected_difficulty(&state.tips);
        let ceiling = (before as u128 * 5 / 4).max(before as u128 + 1) as u64;
        assert!(
            next <= ceiling,
            "difficulty jumped from {before} to {next}, past clamp {ceiling}"
        );
    }

    #[test]
    fn old_block_bodies_are_pruned_but_consensus_data_is_kept() {
        let mut state = ChainState::new();
        // Space blocks exactly at the target so difficulty stays at the floor and the PoW
        // search stays cheap — this test is about pruning, not the DAA.
        for i in 0..(FINALITY_DEPTH + 10) {
            mine_at(
                &mut state,
                GENESIS_TIMESTAMP_MS + 1 + i * TARGET_BLOCK_TIME_MS,
            );
        }

        let tip_score = state.selected_tip_blue_score();
        assert_eq!(tip_score, FINALITY_DEPTH + 10);

        let old_hash = state.main_chain[5]; // blue_score ~5, far below the finality threshold
        let recent_hash = *state.main_chain.last().unwrap();

        // Old body is pruned; recent body is intact.
        assert!(
            state.is_body_pruned(&old_hash),
            "an old block's body must be pruned"
        );
        assert!(
            !state.is_body_pruned(&recent_hash),
            "the tip's body must be intact"
        );
        let old = state.dag.get(&old_hash).unwrap();
        assert!(
            old.stark_proof.is_empty() && old.transparent_txs.is_empty(),
            "old body must be cleared"
        );

        // But every consensus-relevant thing about the old block is retained.
        assert!(
            !old.parents.is_empty(),
            "pruned block must keep its parent links"
        );
        assert!(
            state.ghostdag.contains_key(&old_hash),
            "pruned block must keep its GHOSTDAG data"
        );

        // Pruning must not have disturbed the chain or scores.
        assert_eq!(state.main_chain.len() as u64, FINALITY_DEPTH + 10 + 1); // + genesis
        assert_eq!(state.selected_tip_blue_score(), FINALITY_DEPTH + 10);
    }

    #[test]
    fn block_subsidy_halves_on_schedule_and_reaches_zero() {
        assert_eq!(
            block_subsidy(0),
            BLOCK_REWARD,
            "genesis-era subsidy is the full reward"
        );
        assert_eq!(
            block_subsidy(HALVING_INTERVAL - 1),
            BLOCK_REWARD,
            "no halving before the interval"
        );
        assert_eq!(
            block_subsidy(HALVING_INTERVAL),
            BLOCK_REWARD / 2,
            "first halving"
        );
        assert_eq!(
            block_subsidy(HALVING_INTERVAL * 2),
            BLOCK_REWARD / 4,
            "second halving"
        );
        assert_eq!(
            block_subsidy(HALVING_INTERVAL * 200),
            0,
            "subsidy eventually reaches zero"
        );
    }

    #[test]
    fn mining_increments_circulating_supply_by_the_subsidy() {
        let mut state = ChainState::new();
        assert_eq!(state.minted_supply, 0, "nothing minted at genesis");
        for i in 0..5 {
            mine_at(
                &mut state,
                GENESIS_TIMESTAMP_MS + 1 + i * TARGET_BLOCK_TIME_MS,
            );
        }
        assert_eq!(
            state.minted_supply,
            5 * BLOCK_REWARD,
            "5 blocks mint 5 full subsidies"
        );
    }

    #[test]
    fn issuance_is_hard_capped_at_max_supply() {
        // Do not mine here: setting minted near MAX_SUPPLY puts the chain past
        // the hard-era floor (2^24), which is expensive for a CPU unit test.
        // Exercise the same clamp `apply_block_effects` uses.
        let mut minted = MAX_SUPPLY - 10;
        let subsidy = block_subsidy(0).min(MAX_SUPPLY.saturating_sub(minted));
        assert_eq!(subsidy, 10);
        minted = minted.saturating_add(subsidy);
        assert_eq!(minted, MAX_SUPPLY);
        let at_cap = minted;
        let subsidy2 = block_subsidy(1).min(MAX_SUPPLY.saturating_sub(minted));
        assert_eq!(subsidy2, 0);
        minted = minted.saturating_add(subsidy2);
        assert_eq!(minted, at_cap, "no coins are minted past MAX_SUPPLY");
    }

    #[test]
    fn folded_base_matches_a_fresh_recompute_across_finality() {
        // Guards the determinism fix: build a chain PAST the finality depth (so
        // the base is incrementally folded), then save + reload. The reload does
        // a fresh recompute from `base`, which must produce state IDENTICAL to
        // the incrementally-folded live state. If the fold used a blue-score
        // cutoff instead of the canonical-order prefix, these could differ.
        let mut state = ChainState::new();
        for i in 0..(FINALITY_DEPTH + 20) {
            mine_at(
                &mut state,
                GENESIS_TIMESTAMP_MS + 1 + i * TARGET_BLOCK_TIME_MS,
            );
        }
        assert!(
            state.base_frontier.is_some(),
            "a chain past finality must have folded its base"
        );
        let accounts_before = state.accounts.clone();
        let minted_before = state.minted_supply;

        let path = std::env::temp_dir().join(format!("hassan-fold-{}.bin", std::process::id()));
        state.save_to(&path).unwrap();
        let loaded = ChainState::load_from(&path).unwrap(); // fresh recompute from base
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            loaded.accounts, accounts_before,
            "fresh-recompute accounts must equal the incrementally-folded ones"
        );
        assert_eq!(loaded.minted_supply, minted_before, "issuance must match");
        assert!(
            loaded.base_frontier.is_some(),
            "loaded state keeps its folded base"
        );
    }

    #[test]
    fn a_deep_reorg_below_the_finality_point_is_rejected() {
        // Build a chain past the finality depth, then try to fork from a block
        // far below the finality point (a deep-reorg / double-spend attempt).
        // It must be rejected; a normal block on the tip must still be accepted.
        let mut state = ChainState::new();
        let n = FINALITY_DEPTH + 10;
        for i in 0..n {
            mine_at(
                &mut state,
                GENESIS_TIMESTAMP_MS + 1 + i * TARGET_BLOCK_TIME_MS,
            );
        }
        assert!(
            state.finality_point().is_some(),
            "chain past finality depth must have a finality point"
        );

        // A block that forks from an early block (blue score ~5, well below the
        // finality point) — a deep reorg.
        let old = state.main_chain[5];
        let parents = vec![old];
        let ts = GENESIS_TIMESTAMP_MS + 1 + n * TARGET_BLOCK_TIME_MS;
        let difficulty = state.expected_difficulty_at(&parents, ts);
        let target = pow_target(difficulty);
        let mut attack = Block {
            height: 0,
            timestamp: ts,
            parents,
            interlinks: vec![],
            transparent_txs: vec![],
            utxo_txs: vec![],
            registry_ops: vec![],
            custody_ops: vec![],
            merkle_root: Hash::ZERO,
            state_root: state.merkle_root(),
            miner: Hash([7u8; HASH_SIZE]),
            creator_pubkey: vec![],
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        attack.merkle_root = attack.merkle_root();
        while !hash_meets_target(&attack.hash(), &target) {
            attack.nonce += 1;
        }
        attack.stark_proof = stark::prove(attack.hash().as_slice());
        let dag_before = state.dag.len();
        let err = state.add_block(attack).unwrap_err();
        assert!(
            err.contains("Finality violation"),
            "deep reorg must be a finality violation; got: {err}"
        );
        assert_eq!(
            state.dag.len(),
            dag_before,
            "rejected reorg block must not be committed"
        );

        // A normal block extending the tip is still accepted (shallow additions
        // within the finality window are fine).
        mine_at(
            &mut state,
            GENESIS_TIMESTAMP_MS + 1 + (n + 1) * TARGET_BLOCK_TIME_MS,
        );
        assert_eq!(
            state.selected_tip_blue_score(),
            n + 1,
            "honest extension still advances the chain"
        );
    }

    #[test]
    fn full_pruning_keeps_the_chain_correct_on_a_wide_dag() {
        // A WIDE DAG (chained diamonds), not a straight chain — so the pruning
        // boundary contains *side* blocks whose selected parent lands below the
        // pruning point. A straight-chain test hides the dangling-selected_parent
        // bug; this one exercises it.
        let mut state = ChainState::new();
        let mut prev = *state.tips.last().unwrap(); // genesis
        let mut t = GENESIS_TIMESTAMP_MS + 1;
        let mut tag: u8 = 1;
        let bump = |tag: &mut u8| {
            *tag = tag.wrapping_add(1);
            if *tag == 0 {
                *tag = 1
            }
            *tag
        };
        while state.selected_tip_blue_score() < PRUNING_DEPTH + 40 {
            // prev → c1, prev → c2 (siblings), {c1, c2} → m. c2 (or c1) is a
            // merged side block whose selected parent is `prev`.
            let c1 = mine_with_parents(&mut state, t, vec![prev], bump(&mut tag));
            t += TARGET_BLOCK_TIME_MS;
            let c2 = mine_with_parents(&mut state, t, vec![prev], bump(&mut tag));
            t += TARGET_BLOCK_TIME_MS;
            let m = mine_with_parents(&mut state, t, vec![c1, c2], bump(&mut tag));
            t += TARGET_BLOCK_TIME_MS;
            prev = m;
        }

        // The pruning point advanced and old headers are gone.
        let pp = state
            .pruning_point
            .expect("chain past PRUNING_DEPTH must have a pruning point");
        assert!(
            state.ghostdag.contains_key(&pp),
            "pruning point header is retained"
        );
        assert!(
            state.pruned_selected_blocks > 0,
            "some selected-chain blocks were dropped"
        );
        assert_eq!(
            state.ghostdag[&pp].selected_parent, None,
            "the retained DAG is rooted at the pruning point"
        );
        // Width really was retained (side blocks, not just the selected chain).
        assert!(
            state.dag.len() > state.main_chain.len(),
            "a wide DAG must retain side blocks"
        );

        // THE BUG THIS TEST EXISTS FOR: after pruning, no retained block may have
        // a selected parent pointing at a removed block. A dangling link would
        // corrupt `selected_chain`/`main_chain` and desync GHOSTDAG from the
        // reachability tree (whose `retain` nulls exactly these).
        for (h, d) in &state.ghostdag {
            if let Some(sp) = d.selected_parent {
                assert!(
                    state.ghostdag.contains_key(&sp),
                    "retained block {} has a dangling selected_parent after pruning",
                    hex::encode(h)
                );
            }
        }
        // main_chain contains only live hashes and is contiguous.
        for w in state.main_chain.windows(2) {
            assert!(
                state.dag.contains_key(&w[0]) && state.dag.contains_key(&w[1]),
                "main_chain hash must be live"
            );
            assert_eq!(
                state.ghostdag[&w[1]].selected_parent,
                Some(w[0]),
                "main chain must be contiguous"
            );
        }

        // The chain keeps advancing correctly after pruning, height absolute.
        let height_before = state.pruned_selected_blocks + state.main_chain.len() as u64;
        let score_before = state.selected_tip_blue_score();
        for _ in 0..15 {
            let c1 = mine_with_parents(&mut state, t, vec![prev], bump(&mut tag));
            t += TARGET_BLOCK_TIME_MS;
            let c2 = mine_with_parents(&mut state, t, vec![prev], bump(&mut tag));
            t += TARGET_BLOCK_TIME_MS;
            let m = mine_with_parents(&mut state, t, vec![c1, c2], bump(&mut tag));
            t += TARGET_BLOCK_TIME_MS;
            prev = m;
        }
        assert!(
            state.pruned_selected_blocks + state.main_chain.len() as u64 > height_before,
            "height must keep rising"
        );
        assert!(
            state.selected_tip_blue_score() > score_before,
            "blue score must keep rising"
        );

        // Reachability among retained blocks still matches ground-truth BFS.
        let retained: Vec<_> = state.dag.keys().copied().collect();
        for a in retained.iter().take(25) {
            for b in retained.iter().take(25) {
                assert_eq!(
                    state.reachability.is_ancestor(a, b, &state.dag),
                    reachability::bfs_is_ancestor(&state.dag, a, b),
                    "post-prune reachability must match BFS",
                );
            }
        }
    }
}

#[cfg(test)]
mod pruning_proof_tests {
    use super::*;

    /// Mine and add one valid block on the current selected tip.
    fn mine_next(state: &mut ChainState, t: u64) {
        let parents = state.tips.clone();
        let difficulty = state.expected_difficulty_at(&parents, t);
        let mut block = Block {
            // Match solo-miner / consensus: selected-chain index of the next
            // block. Multi-level pruning-proof structural checks (and era
            // floors keyed off height) require this field to be monotonic.
            height: state.main_chain.len() as u64,
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
            nonce: 0,
            difficulty,
            version: crate::default_block_version(),
            coinbase_entropy: 0,
            stark_proof: vec![],
            birth_certificate: Default::default(),
            size: 0,
        };
        state
            .bind_parent_commitments(&mut block)
            .expect("selected parent");
        let (sk, pk) = test_miner_keys();
        seal_block(&state, &mut block, sk, pk);
        state
            .add_block(block)
            .expect("mined block must be accepted");
    }

    fn chain_headers(state: &ChainState) -> Vec<Block> {
        let tip = ghostdag::selected_tip(&state.ghostdag, &state.tips).unwrap();
        ghostdag::selected_chain(&state.ghostdag, &tip)
            .iter()
            .map(|h| state.dag.get(h).unwrap().header_only())
            .collect()
    }

    #[test]
    fn a_pruning_proof_over_a_real_chain_verifies_with_correct_cumulative_work() {
        let mut state = ChainState::new();
        state.archival = true;
        for i in 1..=6u64 {
            mine_next(&mut state, GENESIS_TIMESTAMP_MS + i * TARGET_BLOCK_TIME_MS);
        }
        let headers = chain_headers(&state);
        let tip_hash = headers.last().unwrap().hash();
        let expected_work: u128 = headers.iter().map(|b| b.difficulty as u128).sum();

        let proof = PruningProof {
            headers: headers.iter().map(|b| b.header_only()).collect(),
        };
        let summary = verify_pruning_proof(&proof).expect("a genuine proof must verify");
        assert_eq!(summary.pruning_point, tip_hash);
        assert_eq!(summary.header_count, 7, "genesis + 6 mined blocks");
        assert_eq!(summary.cumulative_work, expected_work);
    }

    #[test]
    fn build_pruning_proof_walks_genesis_to_the_pruning_point() {
        let mut state = ChainState::new();
        state.archival = true;
        for i in 1..=5u64 {
            mine_next(&mut state, GENESIS_TIMESTAMP_MS + i * TARGET_BLOCK_TIME_MS);
        }
        // No pruning point yet -> no proof.
        assert!(
            state.build_pruning_proof().is_none(),
            "no proof before a pruning point exists"
        );

        // Simulate a pruning point at the 3rd block along the selected chain.
        let tip = ghostdag::selected_tip(&state.ghostdag, &state.tips).unwrap();
        let chain = ghostdag::selected_chain(&state.ghostdag, &tip);
        let pp = chain[3];
        state.pruning_point = Some(pp);

        let proof = state
            .build_pruning_proof()
            .expect("archival node builds a proof");
        assert_eq!(proof.headers.first().unwrap().hash(), genesis_hash());
        assert_eq!(
            proof.headers.last().unwrap().hash(),
            pp,
            "proof ends at the pruning point"
        );
        let summary = verify_pruning_proof(&proof).unwrap();
        assert_eq!(summary.pruning_point, pp);

        // Same chain, through the succinct multi-level proof builder — the
        // ChainState-level wiring for `superproof`, not just its own unit
        // tests. `recent_window` of 2 is smaller than the 4-header chain up
        // to `pp`, exercising a real (if tiny) hop chain.
        let ml_proof = state
            .build_multilevel_pruning_proof(2)
            .expect("archival node builds a multi-level proof too");
        let ml_summary = crate::superproof::verify_multilevel_pruning_proof(&ml_proof)
            .expect("the multi-level proof must independently verify");
        assert_eq!(ml_summary.pruning_point, pp);
    }

    #[test]
    fn import_verified_pruning_headers_puts_pp_in_dag_without_minting() {
        let mut archival = ChainState::new();
        archival.archival = true;
        for i in 1..=5u64 {
            mine_next(
                &mut archival,
                GENESIS_TIMESTAMP_MS + i * TARGET_BLOCK_TIME_MS,
            );
        }
        let tip = ghostdag::selected_tip(&archival.ghostdag, &archival.tips).unwrap();
        let chain = ghostdag::selected_chain(&archival.ghostdag, &tip);
        let pp = chain[3];
        archival.pruning_point = Some(pp);
        let proof = archival.build_pruning_proof().expect("proof");
        let minted_on_source = archival.minted_supply;

        let mut fresh = ChainState::new();
        let minted_before = fresh.minted_supply;
        let imported = fresh
            .import_verified_pruning_headers(&proof.headers)
            .expect("import");
        assert_eq!(imported, pp);
        assert!(fresh.dag.contains_key(&pp));
        assert_eq!(fresh.pruning_point, Some(pp));
        assert_eq!(fresh.tips, vec![pp]);
        assert_eq!(
            fresh.minted_supply, minted_before,
            "empty-body import must not mint subsidies (source had {minted_on_source})"
        );
        assert!(fresh.reachability.is_ancestor(&genesis_hash(), &pp, &fresh.dag));

        // Archival publishes PP ledger; fresh adopts and matches balances.
        archival
            .set_serving_pruning_point(pp)
            .expect("archival can cache PP ledger");
        let pp_ledger = archival
            .build_pruning_point_ledger()
            .expect("archival serves PP ledger");
        assert!(
            !pp_ledger.ledger.accounts.is_empty() || pp_ledger.ledger.minted_supply > 0,
            "PP ledger must reflect post-PP mining, not empty genesis"
        );
        fresh
            .adopt_pruning_point_ledger(&pp_ledger)
            .expect("ledger must verify against PP state_root");
        assert_eq!(fresh.minted_supply, pp_ledger.ledger.minted_supply);
        assert_eq!(fresh.accounts, pp_ledger.ledger.accounts);
        assert_eq!(fresh.base_frontier, Some(pp));
    }

    #[test]
    fn a_proof_not_anchored_at_genesis_is_rejected() {
        let mut state = ChainState::new();
        state.archival = true;
        for i in 1..=4u64 {
            mine_next(&mut state, GENESIS_TIMESTAMP_MS + i * TARGET_BLOCK_TIME_MS);
        }
        let mut headers: Vec<Block> = chain_headers(&state);
        headers.remove(0); // drop genesis
        let proof = PruningProof { headers };
        assert!(
            verify_pruning_proof(&proof).is_err(),
            "must start at genesis"
        );
        assert!(
            verify_pruning_proof(&PruningProof { headers: vec![] }).is_err(),
            "empty is rejected"
        );
    }

    #[test]
    fn a_broken_link_or_forged_difficulty_is_rejected() {
        let mut state = ChainState::new();
        state.archival = true;
        for i in 1..=5u64 {
            mine_next(&mut state, GENESIS_TIMESTAMP_MS + i * TARGET_BLOCK_TIME_MS);
        }
        let base = chain_headers(&state);

        // Corrupting a middle header's nonce changes its hash, breaking the
        // linkage the next header commits to.
        let mut broken = base.clone();
        broken[2].nonce ^= 0xdead_beef;
        assert!(
            verify_pruning_proof(&PruningProof { headers: broken }).is_err(),
            "broken linkage rejected"
        );

        // Claiming a difficulty the DAA never mandated is rejected (this is what
        // stops a forger from faking cheap "work").
        let mut forged = base.clone();
        forged[3].difficulty = 1_000_000;
        assert!(
            verify_pruning_proof(&PruningProof { headers: forged }).is_err(),
            "forged difficulty rejected"
        );
    }

    #[test]
    fn expected_difficulty_linear_scales_linearly_not_quadratically() {
        // Regression test: `expected_difficulty_linear` used to recompute
        // cumulative issuance with an O(i) loop on every call. Since
        // `verify_pruning_proof` calls it once per header in an O(n) loop, that
        // made verification O(n^2) — with MAX_PRUNING_PROOF_HEADERS = 1,000,000
        // a maximal proof would need ~10^12 operations (a verification-time
        // DoS). The fixed version uses the O(halvings) closed-form
        // `cumulative_issuance`, so total cost across all headers is O(n).
        // With the bug this loop takes minutes; fixed, it's sub-second.
        let n: u64 = 300_000;
        let mut headers = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut b = genesis_block();
            b.timestamp = GENESIS_TIMESTAMP_MS + i * TARGET_BLOCK_TIME_MS;
            b.difficulty = effective_min_difficulty();
            headers.push(b);
        }
        let start = std::time::Instant::now();
        for i in 1..(n as usize) {
            let _ = expected_difficulty_linear(&headers, i);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "expected_difficulty_linear over {n} headers must stay near-linear, took {:?}",
            start.elapsed()
        );
    }
}

#[cfg(test)]
mod fee_market_tests {
    use super::*;

    fn funded_state(balance: u128) -> (ChainState, Vec<u8>, Vec<u8>, String) {
        let mut state = ChainState::new();
        let (sk, pk) = generate_keypair();
        let from = hash_to_address(&pk);
        state.accounts.insert(
            from.clone(),
            Account {
                balance,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        (state, sk, pk, from)
    }

    fn signed_tx(
        pk: Vec<u8>,
        sk: &[u8],
        to: &str,
        amount: u128,
        fee: u128,
        nonce: u64,
        chain_id: u64,
    ) -> TransparentTx {
        let mut tx = TransparentTx::new_with_fee(pk, to.to_string(), amount, fee, nonce, chain_id);
        let need = tx.min_fee_required();
        if tx.fee < need {
            tx.fee = need;
        }
        tx.sign(sk).unwrap();
        tx
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn a_higher_fee_replacement_at_the_same_nonce_replaces_the_queued_transfer() {
        let (mut state, sk, pk, from) = funded_state(10_000_000);
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();
        let original = signed_tx(
            pk.clone(),
            &sk,
            &test_address(1) ,
            1000,
            floor,
            0,
            chain_id,
        );
        state
            .admit_transparent_to_mempool(original)
            .expect("first transfer admitted");
        assert_eq!(state.transparent_mempool.len(), 1);

        // Same sender+nonce, fee bumped by exactly one MIN_TX_FEE increment.
        let replacement =
            signed_tx(pk, &sk, &test_address(1), 1000, floor + MIN_TX_FEE, 0, chain_id);
        state
            .admit_transparent_to_mempool(replacement.clone())
            .expect("RBF replacement admitted");

        assert_eq!(
            state.transparent_mempool.len(),
            1,
            "replacement must not grow the mempool"
        );
        assert_eq!(state.transparent_mempool[0].fee, floor + MIN_TX_FEE);
        assert_eq!(
            state.transparent_mempool[0].tx_hash(),
            replacement.tx_hash()
        );
        let _ = from;
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn a_replacement_that_does_not_clear_the_minimum_fee_bump_is_rejected() {
        let (mut state, sk, pk, _from) = funded_state(10_000_000);
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();
        let base = floor + MIN_TX_FEE * 5;
        let original = signed_tx(
            pk.clone(),
            &sk,
            &test_address(1),
            1000,
            base,
            0,
            chain_id,
        );
        state
            .admit_transparent_to_mempool(original)
            .expect("first transfer admitted");

        // Same fee: not a real bump, must be rejected (prevents free replacement spam).
        let same_fee = signed_tx(
            pk.clone(),
            &sk,
            &test_address(1),
            1000,
            base,
            0,
            chain_id,
        );
        assert!(
            state.admit_transparent_to_mempool(same_fee).is_err(),
            "equal-fee replacement rejected"
        );

        // A tiny bump below one full MIN_TX_FEE increment: also rejected.
        let tiny_bump = signed_tx(
            pk,
            &sk,
            &test_address(1) ,
            1000,
            base + MIN_TX_FEE - 1,
            0,
            chain_id,
        );
        assert!(
            state.admit_transparent_to_mempool(tiny_bump).is_err(),
            "sub-increment bump rejected"
        );
        assert_eq!(
            state.transparent_mempool.len(),
            1,
            "the original queued transfer must be untouched"
        );
        assert_eq!(state.transparent_mempool[0].fee, base);
    }

    #[test]
    fn fee_estimate_on_an_empty_mempool_returns_the_protocol_floor() {
        let state = ChainState::new();
        let floor = typical_signed_tx_min_fee();
        let est = state.estimate_fee();
        assert_eq!(est.low, floor);
        assert_eq!(est.medium, floor);
        assert_eq!(est.high, floor);
        assert_eq!(est.mempool_txs, 0);
        assert_eq!(est.package_count, 0);
        assert_eq!(est.best_package_fee, 0);
        assert_eq!(est.high_target_blues, FEE_TARGET_HIGH_BLUES);
        assert_eq!(est.medium_target_blues, FEE_TARGET_MEDIUM_BLUES);
        assert_eq!(est.low_target_blues, FEE_TARGET_LOW_BLUES);
    }

    #[test]
    fn fee_estimate_confirmation_targets_prefer_history_over_mempool() {
        // Seed fee history with a high feerate that confirmed within 6 blues;
        // estimate_fee must surface it for the high tier (converted to absolute
        // fee for a typical signed transfer), floored at the relay minimum.
        let mut state = ChainState::new();
        let floor = typical_signed_tx_min_fee();
        let typical_bytes = (PQ_PUBLIC_KEY_SIZE + PQ_SIGNATURE_SIZE + 512) as u128;
        let hist_rate = (floor / typical_bytes).saturating_add(50);
        state.fee_history.record(
            10,
            vec![hist_rate],
            vec![3], // confirmed within high target (6)
        );
        let est = state.estimate_fee();
        let expected = hist_rate.saturating_mul(typical_bytes).max(floor);
        assert_eq!(est.high, expected);
        assert_eq!(est.high_target_blues, 6);
        assert_eq!(est.medium_target_blues, 20);
        assert_eq!(est.low_target_blues, 100);
    }

    #[test]
    fn fee_history_success_walk_picks_minimum_rate_that_clears_target() {
        // Fast high-rate + slow low-rate: target=6 must require the high rate;
        // target=100 may accept the low rate (both succeeded in-window).
        let mut hist = FeeRateHistory::default();
        hist.record(10, vec![100, 10], vec![2, 50]);
        assert_eq!(hist.estimate_for_target(6), Some(100));
        assert_eq!(hist.estimate_for_target(100), Some(10));
        // No in-window successes → None (do not ignore the target).
        let mut thin = FeeRateHistory::default();
        thin.record(10, vec![5], vec![80]);
        assert_eq!(thin.estimate_for_target(6), None);
    }

    #[test]
    fn fee_estimate_tiers_are_monotonic_high_ge_medium_ge_low() {
        let mut state = ChainState::new();
        // Deliberately awkward history that could invert naive percentiles:
        // a cheap tx confirmed very fast (lucky) and expensive txs confirmed slowly.
        state.fee_history.record(1, vec![1], vec![0]);
        state.fee_history.record(2, vec![1000, 1000], vec![90, 90]);
        let est = state.estimate_fee();
        assert!(
            est.high >= est.medium && est.medium >= est.low,
            "tiers must be monotonic: high={} medium={} low={}",
            est.high,
            est.medium,
            est.low
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn cpfp_package_selects_low_fee_parent_with_high_fee_child_before_medium_unrelated() {
        // Account-nonce CPFP: parent (nonce 0, low fee) + child (nonce 1, high
        // fee) must outrank an unrelated medium-fee transfer when ranked by
        // ancestor package fee-rate — otherwise the child is skipped (wrong
        // nonce) and the medium tx fills the block first.
        let (mut state, sk_a, pk_a, _from_a) = funded_state(50_000_000);
        let (sk_b, pk_b) = generate_keypair();
        let from_b = hash_to_address(&pk_b);
        state.accounts.insert(
            from_b,
            Account {
                balance: 50_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: Hash::ZERO,
            },
        );
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();

        let parent = signed_tx(
            pk_a.clone(),
            &sk_a,
            &test_address(1) ,
            1000,
            floor, // low
            0,
            chain_id,
        );
        let child = signed_tx(
            pk_a,
            &sk_a,
            &test_address(2) ,
            1000,
            floor * 100, // high — pays for the parent
            1,
            chain_id,
        );
        let medium = signed_tx(
            pk_b,
            &sk_b,
            &test_address(3) ,
            1000,
            floor * 10, // medium individual fee (between parent and child)
            0,
            chain_id,
        );

        // Admit in an order that would fool naive highest-individual-fee-first
        // selection if packages were ignored (medium between child and parent).
        state.admit_transparent_to_mempool(medium.clone()).unwrap();
        state.admit_transparent_to_mempool(parent.clone()).unwrap();
        state.admit_transparent_to_mempool(child.clone()).unwrap();

        let selected = state.select_valid_block_txs(&state.transparent_mempool);
        assert_eq!(selected.len(), 3, "all three transfers are includable");

        let parent_pos = selected
            .iter()
            .position(|t| t.tx_hash() == parent.tx_hash())
            .expect("parent selected");
        let child_pos = selected
            .iter()
            .position(|t| t.tx_hash() == child.tx_hash())
            .expect("child selected");
        let medium_pos = selected
            .iter()
            .position(|t| t.tx_hash() == medium.tx_hash())
            .expect("medium selected");

        assert!(
            parent_pos < child_pos,
            "parent must precede child (nonce order inside the package)"
        );
        assert!(
            child_pos < medium_pos,
            "CPFP package (parent+child) must be selected before the unrelated medium-fee tx; \
             positions parent={parent_pos} child={child_pos} medium={medium_pos}"
        );

        let est = state.estimate_fee();
        assert_eq!(est.package_count, 2, "two sender packages");
        assert_eq!(
            est.best_package_fee,
            floor + floor * 100,
            "best package total is parent+child fees"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn package_rbf_requires_a_bump_over_the_queued_package_total() {
        let (mut state, sk, pk, _from) = funded_state(50_000_000);
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();
        let parent_fee = floor + MIN_TX_FEE * 5;
        let child_fee = floor + MIN_TX_FEE * 20;
        let parent = signed_tx(
            pk.clone(),
            &sk,
            &test_address(1),
            1000,
            parent_fee,
            0,
            chain_id,
        );
        let child = signed_tx(
            pk.clone(),
            &sk,
            &test_address(2),
            1000,
            child_fee,
            1,
            chain_id,
        );
        state.admit_transparent_to_mempool(parent).unwrap();
        state.admit_transparent_to_mempool(child).unwrap();

        // Same fee on the parent: package total unchanged → reject.
        let same = signed_tx(
            pk.clone(),
            &sk,
            &test_address(1),
            1000,
            parent_fee,
            0,
            chain_id,
        );
        let err = state
            .admit_transparent_to_mempool(same)
            .expect_err("equal-fee package RBF rejected");
        assert!(
            err.contains("package RBF") || err.contains("package fee"),
            "error should mention package RBF, got: {err}"
        );

        // Bump parent by MIN_TX_FEE: package total rises → accept; child stays.
        let bumped = signed_tx(
            pk,
            &sk,
            &test_address(1),
            1000,
            parent_fee + MIN_TX_FEE,
            0,
            chain_id,
        );
        state
            .admit_transparent_to_mempool(bumped.clone())
            .expect("package-aware RBF bump admitted");
        assert_eq!(state.transparent_mempool.len(), 2, "descendant child retained");
        assert!(state
            .transparent_mempool
            .iter()
            .any(|t| t.tx_hash() == bumped.tx_hash()));
        assert!(state
            .transparent_mempool
            .iter()
            .any(|t| t.nonce == 1 && t.fee == child_fee));
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn mempool_rejects_underfunded_tip_nonce_at_admit() {
        let (mut state, sk, pk, _from) = funded_state(5_000);
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();
        // amount + fee exceeds the 5_000 balance.
        let tx = signed_tx(
            pk,
            &sk,
            &test_address(1),
            4_000,
            floor.saturating_add(2_000),
            0,
            chain_id,
        );
        let err = state
            .admit_transparent_to_mempool(tx)
            .expect_err("underfunded tip nonce rejected at admit");
        assert!(
            err.contains("Insufficient balance"),
            "got: {err}"
        );
        assert!(state.transparent_mempool.is_empty());
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn mempool_rejects_package_deeper_than_max_nonce_depth() {
        let (mut state, sk, pk, _from) = funded_state(50_000_000);
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();
        let deep = tip_nonce_depth_tx(
            &mut state,
            pk,
            &sk,
            floor,
            MAX_MEMPOOL_PACKAGE_NONCES as u64,
            chain_id,
        );
        let err = state
            .admit_transparent_to_mempool(deep)
            .expect_err("over-depth package rejected");
        assert!(
            err.contains("Package nonce depth"),
            "got: {err}"
        );
    }

    fn tip_nonce_depth_tx(
        state: &mut ChainState,
        pk: Vec<u8>,
        sk: &[u8],
        fee: u128,
        depth_zero_based: u64,
        chain_id: u64,
    ) -> TransparentTx {
        let tip = state.account_nonce(&hash_to_address(&pk));
        signed_tx(
            pk,
            sk,
            &test_address(9),
            1000,
            fee,
            tip + depth_zero_based,
            chain_id,
        )
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn fee_estimate_percentiles_track_the_live_mempool_fee_distribution() {
        let (mut state, sk, pk, _from) = funded_state(50_000_000);
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();
        // Ten transfers with fees floor*(1..=10) at increasing nonces.
        for n in 0..10u64 {
            let tx = signed_tx(
                pk.clone(),
                &sk,
                &test_address(2),
                1000,
                floor * (n as u128 + 1),
                n,
                chain_id,
            );
            state.admit_transparent_to_mempool(tx).unwrap();
        }
        let est = state.estimate_fee();
        assert_eq!(est.mempool_txs, 10);
        assert!(est.low <= est.medium, "low must not exceed medium");
        assert!(est.medium <= est.high, "medium must not exceed high");
        assert!(est.low >= floor);
        assert!(est.high <= floor * 10);
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn current_min_relay_fee_rises_once_the_mempool_is_full_of_higher_fees() {
        let (mut state, sk, pk, _from) = funded_state(50_000_000);
        let chain_id = state.chain_id;
        let floor = typical_signed_tx_min_fee();
        assert_eq!(
            state.current_min_relay_fee(),
            floor,
            "empty mempool charges the size-priced protocol floor"
        );

        for n in 0..5u64 {
            let tx = signed_tx(
                pk.clone(),
                &sk,
                &test_address(3),
                1000,
                floor * 3,
                n,
                chain_id,
            );
            state.admit_transparent_to_mempool(tx).unwrap();
        }
        assert_eq!(
            state.current_min_relay_fee(),
            floor,
            "below MAX_MEMPOOL_SIZE the floor stays the protocol minimum"
        );
    }
}
