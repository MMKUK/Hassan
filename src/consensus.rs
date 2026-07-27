use crate::{
    address_hash, address_matches_pubkey, hash_meets_target, now_ms, pow_target, verify_pow, Block,
    ChainState, Hash, Miner, MiningWork, StratumShare, BLOCK_TIME_MS,
};
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

/// How long one mining template is searched before the producer refreshes.
///
/// Release/runtime uses [`BLOCK_TIME_MS`] (100) so search misses and template
/// refresh stay on the per-chain cadence. A previous floor of 15s made solo
/// intervals ~15s whenever PoW did not finish instantly. Unit tests keep a
/// longer budget because debug builds hash ML-DSA-sized headers slowly.
pub fn mining_search_budget_ms() -> u64 {
    #[cfg(test)]
    {
        BLOCK_TIME_MS.max(15_000)
    }
    #[cfg(not(test))]
    {
        BLOCK_TIME_MS
    }
}

/// BlockDAG Consensus Engine
pub struct BlockDAGConsensus {
    state: Arc<RwLock<ChainState>>,
    miners: Arc<Mutex<Vec<Miner>>>,
    pool_shares: Arc<Mutex<Vec<StratumShare>>>,
    running: Arc<Mutex<bool>>,
}

impl BlockDAGConsensus {
    pub fn new(state: Arc<RwLock<ChainState>>) -> Self {
        Self {
            state,
            miners: Arc::new(Mutex::new(vec![])),
            pool_shares: Arc::new(Mutex::new(vec![])),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Start block production at the target block interval.
    pub fn start(&self) {
        let mut running = self.running.lock().unwrap();
        *running = true;
        drop(running);

        let state = self.state.clone();
        let running = self.running.clone();
        let miners = self.miners.clone();

        thread::spawn(move || {
            while *running.lock().unwrap() {
                let start = now_ms();

                // Template cites up to MAX_BLOCK_PARENTS tips so a found block
                // merges concurrent siblings (DAG width). Parallel peers mining
                // the same tips raise aggregate accepted blocks/sec; this loop
                // only paces *this* node's solo producer near BLOCK_TIME_MS.
                let template = create_block_template(&state);

                let shares = check_miner_shares(&state, &miners, &template);

                if let Some(winning_share) = shares {
                    if let Ok(block) = assemble_block(&state, &miners, &template, &winning_share) {
                        let mut s = state.write().unwrap();
                        if let Err(e) = s.add_block(block) {
                            eprintln!("Block rejected: {}", e);
                        }
                    }
                }

                // Pace this node's producer to ~TARGET_BLOCK_TIME_MS when PoW
                // finishes early (lab-easy). Does not cap network-wide DAG
                // throughput — other honest nodes keep admitting parallel tips.
                // `saturating_sub` guards clock skew (NTP / VM pause).
                let elapsed = now_ms().saturating_sub(start);
                if elapsed < BLOCK_TIME_MS {
                    thread::sleep(Duration::from_millis(BLOCK_TIME_MS - elapsed));
                }
            }
        });
    }

    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }

    /// Register a new miner
    pub fn register_miner(&self, miner: Miner) {
        let mut miners = self.miners.lock().unwrap();
        miners.push(miner);
    }

    /// Submit mining share (Stratum protocol)
    pub fn submit_share(&self, share: StratumShare) -> Result<(), String> {
        // Verify share
        if !verify_pow(&share.result, self.get_difficulty()) {
            return Err("Share below target".into());
        }

        let mut shares = self.pool_shares.lock().unwrap();
        shares.push(share);
        Ok(())
    }

    fn get_difficulty(&self) -> u64 {
        let state = self.state.read().unwrap();
        state.difficulty
    }
}

/// Create block template for miners
fn create_block_template(state: &Arc<RwLock<ChainState>>) -> MiningWork {
    let s = state.read().unwrap();

    // Reference up to MAX_BLOCK_PARENTS tips, highest blue score first — a
    // block that cited every tip on a busy DAG could exceed the parent cap and
    // be rejected by our own `add_block`, so we bound it here the same way.
    let mut parents = s.tips.clone();
    parents.sort_by(|a, b| {
        let sa = s.ghostdag.get(a).map(|d| d.blue_score).unwrap_or(0);
        let sb = s.ghostdag.get(b).map(|d| d.blue_score).unwrap_or(0);
        sb.cmp(&sa).then_with(|| b.cmp(a))
    });
    parents.truncate(crate::MAX_BLOCK_PARENTS);

    // Difficulty this block must claim is a deterministic function of its
    // parents' past (per-block DAA) + supply-era floor at the template time.
    let timestamp = now_ms();
    let difficulty = s.expected_difficulty_at(&parents, timestamp);

    // Pull pending transfers from the mempool, then select a valid,
    // mutually-consistent subset with ancestor-package ranking (account-nonce
    // CPFP: a high-fee child can pay for its unconfirmed lower-nonce parents).
    // Truncating the *selected* prefix is safe — packages are emitted in nonce
    // order, so a cut never leaves a child without its parent.
    let mut transparent_txs = s.select_valid_block_txs(&s.transparent_mempool);
    transparent_txs.truncate(1000);
    let mut utxo_txs = s.select_valid_utxo_txs(&s.utxo_mempool);
    utxo_txs.truncate(1000);
    let cand_ops: Vec<crate::registry::RegistryOp> =
        s.registry_mempool.iter().take(500).cloned().collect();
    let registry_ops = s.select_valid_registry_ops(&cand_ops);
    let cand_custody: Vec<crate::custody::CustodyCertificate> =
        s.custody_mempool.iter().take(200).cloned().collect();
    let custody_ops = s.select_valid_custody_ops(&cand_custody);

    let mut template = Block {
        height: s.pruned_selected_blocks + s.main_chain.len() as u64,
        timestamp,
        parents,
        interlinks: vec![],
        transparent_txs,
        utxo_txs,
        registry_ops,
        custody_ops,
        merkle_root: Hash::ZERO, // set canonically just below
        state_root: Hash::ZERO,
        miner: Hash::ZERO, // To be filled by miner
        creator_pubkey: vec![],
        nonce: 0,
        difficulty,
        version: crate::versionbits::miner_version(&[0, 1, 2]),
        coinbase_entropy: crate::now_ms(),
        stark_proof: vec![0u8; 64],
        birth_certificate: crate::issuance::BirthCertificate::default(),
        size: 0,
    };
    // Provisional interlinks + state_root (miner still zero). After trim and
    // after the real miner identity is set, mining rebinds post-mergeset root.
    s.bind_parent_commitments(&mut template)
        .expect("template parents must yield a selected parent");
    // Trim body until the block fits BOTH the 22KB consensus base AND the
    // total on-wire cap (`MAX_BLOCK_BYTES`, base + witness proof).
    let too_big = |b: &Block| {
        !b.verify_size()
            || bincode::serialize(b).map(|s| s.len()).unwrap_or(usize::MAX) > crate::MAX_BLOCK_BYTES
    };
    while too_big(&template) {
        // Drop lowest-fee transfer first; then UTXO; then registry ops.
        if let Some((i, _)) = template
            .transparent_txs
            .iter()
            .enumerate()
            .min_by_key(|(_, t)| t.fee)
        {
            template.transparent_txs.remove(i);
            continue;
        }
        if let Some((i, _)) = template
            .utxo_txs
            .iter()
            .enumerate()
            .min_by_key(|(_, t)| t.fee)
        {
            template.utxo_txs.remove(i);
            continue;
        }
        if template.registry_ops.pop().is_some() || template.custody_ops.pop().is_some() {
            continue;
        }
        break;
    }
    template.merkle_root = template.merkle_root();
    // Rebind after trim so state_root matches the final body (still pre-miner).
    s.bind_parent_commitments(&mut template)
        .expect("post-trim commitments");

    // Calculate the real target once per template — the mining hot
    // loop reuses this via `hash_meets_target` instead of recomputing it
    // per nonce attempt.
    let target = pow_target(difficulty);

    MiningWork {
        block_template: template,
        target,
        job_id: format!("job_{}", now_ms()),
        extranonce: vec![0u8; 4],
    }
}

/// Search for a winning nonce across all available cores, bounded by the
/// block-time deadline.
///
/// The previous implementation gave up after **11 nonces** (`if nonce > 10 {
/// break; }`), which is why blocks only ever appeared to mine successfully:
/// difficulty stayed at 1 (the easiest possible target) and even then an
/// 11-attempt search only wins by luck. Against any real difficulty this
/// made mining non-functional. There is no shortcut around real PoW search —
/// this now searches the full nonce space in parallel (via `rayon`, already
/// a project dependency) until either a solution is found or the block-time
/// deadline passes, at which point it's normal and expected to return `None`
/// (not every interval produces a block; that's what makes it proof-of-*work*).
///
/// Block rewards must be credited to a real, registered miner's address, so
/// if nobody has registered there is no legitimate recipient and thus no
/// point searching for a block — the old code used a hardcoded
/// `"solo_miner"` placeholder that decoded to no real address, so every
/// block reward was silently credited to an address nobody controls
/// (see the `hex::encode(block.miner)` lookup in `process_block_transactions`).
fn check_miner_shares(
    state: &Arc<RwLock<ChainState>>,
    miners: &Arc<Mutex<Vec<Miner>>>,
    work: &MiningWork,
) -> Option<StratumShare> {
    let (miner_address, creator_pubkey) = {
        let guard = miners.lock().unwrap();
        let m = guard.first()?;
        (m.address.clone(), m.public_key.clone())
    };

    // The miner address AND creator pubkey are part of `block.hash()` / the
    // Settlement ID, so they MUST be set before searching — otherwise the winning nonce would be
    // invalidated when `assemble_block` fills them in. Post-mergeset state_root
    // also credits subsidy to miner, so rebind after identity is set.
    // block.miner is the full 512-bit address digest (not bech32m-invertible).
    if !address_matches_pubkey(&miner_address, &creator_pubkey) {
        return None;
    }
    let miner_bytes = address_hash(&creator_pubkey);
    let deadline = now_ms() + mining_search_budget_ms();
    let target = work.target;
    let mut template = work.block_template.clone();
    template.miner = miner_bytes;
    template.creator_pubkey = creator_pubkey;
    template.merkle_root = template.merkle_root();
    state
        .read()
        .unwrap()
        .bind_parent_commitments(&mut template)
        .ok()?;
    let template = &template;
    let num_lanes = rayon::current_num_threads().max(1) as u64;

    (0..num_lanes).into_par_iter().find_map_any(|lane| {
        let mut block = template.clone();
        let mut nonce = lane;
        loop {
            if now_ms() >= deadline {
                return None;
            }
            block.nonce = nonce;
            let hash = block.hash();
            if hash_meets_target(&hash, &target) {
                return Some(StratumShare {
                    job_id: work.job_id.clone(),
                    nonce,
                    miner: miner_address.clone(),
                    result: hash,
                    tor_proof: None,
                });
            }
            nonce += num_lanes;
        }
    })
}

/// Assemble final block from winning share: restore creator identity baked into
/// the PoW search, issue the Birth Certificate over the Settlement ID, then attach the STARK.
fn assemble_block(
    state: &Arc<RwLock<ChainState>>,
    miners: &Arc<Mutex<Vec<Miner>>>,
    work: &MiningWork,
    share: &StratumShare,
) -> Result<Block, String> {
    let mut block = work.block_template.clone();
    block.nonce = share.nonce;

    let (creator_pubkey, signing_key) = {
        let guard = miners.lock().unwrap();
        let m = guard
            .iter()
            .find(|m| m.address == share.miner)
            .ok_or_else(|| format!("No registered miner for share address {}", share.miner))?;
        (
            m.public_key.clone(),
            m.signing_key
                .clone()
                .ok_or_else(|| "Miner has no signing key for birth certificate".to_string())?,
        )
    };

    block.creator_pubkey = creator_pubkey.clone();
    if !address_matches_pubkey(&share.miner, &creator_pubkey) {
        return Err(format!(
            "Share miner address does not match creator pubkey: {}",
            share.miner
        ));
    }
    block.miner = address_hash(&creator_pubkey);
    block.merkle_root = block.merkle_root();
    state
        .read()
        .map_err(|e| e.to_string())?
        .bind_parent_commitments(&mut block)?;

    // Birth certificate is witness data (not in the PoW hash), so signing after
    // the nonce is found is safe — the Settlement ID already commits to
    // height/parents/miner/creator/nonce/difficulty.
    block.issue_birth_certificate(&signing_key)?;

    // NOTE: no trimming here. The template was already trimmed to fit the 22KB
    // base in `create_block_template`, and its `merkle_root` (part of the PoW
    // hash) commits to exactly that transaction set — changing the set now would
    // invalidate both the PoW and the merkle_root binding. The STARK proof is
    // witness data (not in the base size, not in the hash), so adding it here is
    // safe.
    block.stark_proof = generate_block_stark_proof(&block);
    block.size = crate::calculate_block_size(&block);

    Ok(block)
}

/// Generate a real STARK proof (see the `stark` module) that
/// `stark::SEQUENTIAL_STEPS` steps of sequential work were performed,
/// seeded from this block's own hash.
fn generate_block_stark_proof(block: &Block) -> Vec<u8> {
    crate::stark::prove(block.hash().as_slice())
}

/// Solo mining worker
pub struct SoloMiner {
    pub address: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub running: bool,
    pub hashes_per_second: u64,
}

impl Default for SoloMiner {
    fn default() -> Self {
        Self::new()
    }
}

impl SoloMiner {
    pub fn new() -> Self {
        let (sk, pk) = crate::generate_keypair();
        Self {
            address: crate::hash_to_address(&pk),
            public_key: pk,
            secret_key: sk,
            running: false,
            hashes_per_second: 0,
        }
    }

    pub fn start_mining(&mut self, work: MiningWork) -> Option<StratumShare> {
        self.running = true;
        let start = now_ms();
        let mut nonce = 0u64;
        let mut block = work.block_template.clone();
        block.miner = crate::address_hash(&self.public_key);
        block.creator_pubkey = self.public_key.clone();
        let target = work.target;

        while self.running && nonce < u64::MAX {
            block.nonce = nonce;
            let hash = block.hash();

            if hash_meets_target(&hash, &target) {
                let elapsed = now_ms().saturating_sub(start).max(1);
                self.hashes_per_second = (nonce / elapsed).saturating_mul(1000);

                return Some(StratumShare {
                    job_id: work.job_id,
                    nonce,
                    miner: self.address.clone(),
                    result: hash,
                    tor_proof: None,
                });
            }

            nonce += 1;

            // Refresh after one search budget (block time in release).
            if now_ms().saturating_sub(start) > mining_search_budget_ms() {
                break;
            }
        }

        None
    }

    pub fn stop(&mut self) {
        self.running = false;
    }
}

/// Mining Pool (Stratum server)
pub struct MiningPool {
    pub name: String,
    pub fee_percent: f64,
    pub miners: Vec<String>,
    pub total_shares: u64,
    pub reward_distribution: HashMap<String, u128>,
}

impl MiningPool {
    pub fn new(name: &str, fee: f64) -> Self {
        Self {
            name: name.into(),
            fee_percent: fee,
            miners: vec![],
            total_shares: 0,
            reward_distribution: HashMap::new(),
        }
    }

    pub fn distribute_rewards(&mut self, total_reward: u128) {
        let pool_fee = (total_reward as f64 * self.fee_percent / 100.0) as u128;
        let miner_reward = total_reward - pool_fee;

        if self.total_shares == 0 {
            return;
        }

        let reward_per_share = miner_reward / self.total_shares as u128;

        for (miner, shares) in &self.reward_distribution {
            let reward = reward_per_share * *shares;
            // In production: Transfer reward to miner address
            println!("Pool {}: Paid {} to {}", self.name, reward, miner);
        }
    }
}

#[cfg(test)]
mod mining_tests {
    use super::*;
    use crate::ChainState;
    use std::sync::{Arc, RwLock};

    #[test]
    fn target_block_time_is_100ms_and_test_search_budget_covers_debug_pow() {
        assert_eq!(BLOCK_TIME_MS, 100);
        assert_eq!(crate::TARGET_BLOCK_TIME_MS, 100);
        // cfg(test) keeps the long budget so debug PoW unit tests stay practical.
        assert_eq!(mining_search_budget_ms(), 15_000);
    }

    #[test]
    fn no_registered_miner_means_no_block_is_produced() {
        // Before this fix, mining used a hardcoded "solo_miner" placeholder
        // and produced a block regardless of whether anyone was registered
        // to receive its reward. There's no legitimate recipient here, so
        // there should be no block.
        let state = Arc::new(RwLock::new(ChainState::new()));
        let work = create_block_template(&state);
        let miners: Arc<Mutex<Vec<Miner>>> = Arc::new(Mutex::new(vec![]));

        assert!(check_miner_shares(&state, &miners, &work).is_none());
    }

    #[test]
    fn registered_miner_wins_the_share_and_the_assembled_block_credits_their_real_address() {
        let state = Arc::new(RwLock::new(ChainState::new()));
        let work = create_block_template(&state);

        let (sk, pk) = crate::generate_keypair();
        let address = crate::hash_to_address(&pk);
        let miners: Arc<Mutex<Vec<Miner>>> = Arc::new(Mutex::new(vec![Miner {
            address: address.clone(),
            public_key: pk.clone(),
            signing_key: Some(sk),
            stake: 0,
            hashrate: 0,
            tor_address: None,
            is_pool: false,
        }]));

        // Lab-easy floor under cfg(test) — still cheap enough for unit tests.
        let share = check_miner_shares(&state, &miners, &work)
            .expect("bootstrap difficulty must mine quickly");
        assert_eq!(share.miner, address);

        let block =
            assemble_block(&state, &miners, &work, &share).expect("valid share must assemble");
        // block.miner is the full Blake3-512 address digest of the creator pk.
        assert_eq!(block.miner, crate::address_hash(&pk));
        assert_ne!(
            block.miner, share.result,
            "reward must not be credited to the PoW hash"
        );
        assert!(
            block.verify_issuance().is_ok(),
            "assembled block must carry a valid birth certificate"
        );
    }

    #[test]
    #[ignore = "v27: ACCOUNT_PEER_TRANSFERS=false — retained for re-enable"]
    fn block_template_orders_transfers_highest_fee_first() {
        let (sk_lo, pk_lo) = crate::generate_keypair();
        let (sk_hi, pk_hi) = crate::generate_keypair();
        let from_lo = crate::hash_to_address(&pk_lo);
        let from_hi = crate::hash_to_address(&pk_hi);
        let mut state = ChainState::new();
        state.accounts.insert(
            from_lo.clone(),
            crate::Account {
                balance: 10_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: crate::Hash::ZERO,
            },
        );
        state.accounts.insert(
            from_hi.clone(),
            crate::Account {
                balance: 10_000_000,
                nonce: 0,
                last_spend_blue: 0,
                code_hash: None,
                storage_root: crate::Hash::ZERO,
            },
        );

        let mut lo =
            crate::TransparentTx::new(pk_lo, crate::test_address(9), 1000, 0, state.chain_id);
        lo.sign(&sk_lo).unwrap();

        let mut hi =
            crate::TransparentTx::new(pk_hi, crate::test_address(8), 1000, 0, state.chain_id);
        hi.fee = hi.min_fee_required().saturating_mul(50);
        hi.sign(&sk_hi).unwrap();

        // Admit low fee first so insertion order is opposite of priority.
        state.admit_transparent_to_mempool(lo).unwrap();
        state.admit_transparent_to_mempool(hi.clone()).unwrap();

        let shared = Arc::new(RwLock::new(state));
        let work = create_block_template(&shared);
        assert_eq!(
            work.block_template.transparent_txs.first().map(|t| t.fee),
            Some(hi.fee),
            "highest-fee transfer must lead the block body"
        );
    }
}
