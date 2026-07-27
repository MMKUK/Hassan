//! A genuine, winterfell-verified STARK proof of *sequential work*: a proof
//! that `SEQUENTIAL_STEPS` steps of a fixed transition function were really
//! executed, starting from a seed derived from the block header, without
//! the verifier re-executing those steps itself.
//!
//! This replaces the previous placeholder `stark_proof` handling
//! (`verify_stark_proof` used to just check the proof blob's byte length —
//! any bytes of the right size passed). `stark_proof` is now a real,
//! checked proof for a well-defined statement.
//!
//! SCOPE, stated honestly: this proves *sequential computation was
//! performed* (a VDF-style companion to the PoW, similar in spirit to the
//! block hash search itself). Hassan is fully transparent — there is no
//! shielded transaction path.
//!
//! Encoding: `stark_proof` bytes are `result(16 bytes, big-endian u128) ||
//! serialized winterfell Proof`. `result` must travel with the proof
//! because it's the whole point of a succinct proof: the verifier is
//! handed a *claimed* result and the STARK confirms that result is really
//! reachable via `SEQUENTIAL_STEPS` correct steps from the seed — it does
//! not (and, for a large step count, should not need to) recompute the
//! result itself by iterating.

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions,
    Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

/// Number of sequential steps proved per block. Small enough that proving
/// stays well under a second (this runs once per mined block, after the PoW
/// nonce search already succeeded — not in the search's hot loop), while
/// still exercising a real AIR, trace, and FRI-based proof/verify cycle.
/// Bump this in a real deployment where proving time is less constrained —
/// the succinctness benefit (verification cost independent of step count)
/// only starts to matter once direct re-execution would be slow.
pub const SEQUENTIAL_STEPS: usize = 128;

const RESULT_HEADER_LEN: usize = 16;

/// Hard cap on `stark_proof` wire size. Honest proofs for `SEQUENTIAL_STEPS`
/// are well under 20 KB; anything larger is treated as garbage before the
/// expensive winterfell verify path runs (P2P CPU-DoS mitigation).
pub const MAX_STARK_PROOF_BYTES: usize = 24 * 1024;

/// STARK parameters for the per-block sequential-work proof: ~80-bit
/// conjectured security (28 queries, 8x blowup, 16 bits grinding, 128-bit
/// f128 field). This is a COMPANION to the PoW — the block's primary security —
/// generated on EVERY block at the 100ms target, so it is tuned for fast
/// proving over maximal security; ~80 bits is ample for a work-attestation
/// companion. It's witness data (see `Block::base_size`), so
/// its size no longer competes with the 22KB base budget (audit CRITICAL 1).
fn proof_options() -> ProofOptions {
    ProofOptions::new(
        28,                   // number of queries
        8,                    // blowup factor
        16,                   // grinding factor
        FieldExtension::None, // f128 field is already 128-bit
        8,                    // FRI folding factor
        31,                   // FRI max remainder polynomial degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn seed_from_bytes(bytes: &[u8]) -> BaseElement {
    let mut buf = [0u8; 16];
    let n = bytes.len().min(16);
    buf[..n].copy_from_slice(&bytes[..n]);
    BaseElement::new(u128::from_be_bytes(buf))
}

fn step(state: BaseElement) -> BaseElement {
    state.exp(3u32.into()) + BaseElement::new(42)
}

fn build_trace(seed: BaseElement, steps: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(1, steps);
    trace.fill(
        |state| {
            state[0] = seed;
        },
        |_, state| {
            state[0] = step(state[0]);
        },
    );
    trace
}

pub struct PublicInputs {
    pub seed: BaseElement,
    pub result: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.seed, self.result]
    }
}

pub struct SequentialWorkAir {
    context: AirContext<BaseElement>,
    seed: BaseElement,
    result: BaseElement,
}

impl Air for SequentialWorkAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(3)];
        let num_assertions = 2;
        SequentialWorkAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            seed: pub_inputs.seed,
            result: pub_inputs.result,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_state = frame.current()[0];
        let next_state = current_state.exp(3u32.into()) + E::from(BaseElement::new(42));
        result[0] = frame.next()[0] - next_state;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.seed),
            Assertion::single(0, last_step, self.result),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct SequentialWorkProver {
    options: ProofOptions,
}

impl SequentialWorkProver {
    fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for SequentialWorkProver {
    type BaseField = BaseElement;
    type Air = SequentialWorkAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            seed: trace.get(0, 0),
            result: trace.get(0, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Generate a real STARK proof that `SEQUENTIAL_STEPS` steps of the fixed
/// transition function were executed starting from a seed derived from
/// `header_bytes` (the block hash). Returns `result || proof`, both needed
/// by `verify`.
pub fn prove(header_bytes: &[u8]) -> Vec<u8> {
    let seed = seed_from_bytes(header_bytes);
    let trace = build_trace(seed, SEQUENTIAL_STEPS);
    let result = trace.get(0, SEQUENTIAL_STEPS - 1);

    let prover = SequentialWorkProver::new(proof_options());
    let proof = prover
        .prove(trace)
        .expect("proving a freshly-built, correct trace cannot fail");

    let mut out = Vec::with_capacity(RESULT_HEADER_LEN + proof.to_bytes().len());
    out.extend_from_slice(&result.as_int().to_be_bytes());
    out.extend_from_slice(&proof.to_bytes());
    out
}

/// Cheap size/parse gate used by `precheck_block` / `add_block` before the
/// full winterfell verify. Rejects truncated, oversized, or unparseable
/// blobs without running FRI verification.
pub fn precheck_format(stark_proof: &[u8]) -> Result<(), &'static str> {
    if stark_proof.len() <= RESULT_HEADER_LEN {
        return Err("too short");
    }
    if stark_proof.len() > MAX_STARK_PROOF_BYTES {
        return Err("too large");
    }
    let proof_bytes = &stark_proof[RESULT_HEADER_LEN..];
    Proof::from_bytes(proof_bytes).map_err(|_| "malformed")?;
    Ok(())
}

/// Verify a proof produced by `prove` against the same header bytes used to
/// generate it. Returns `false` (never panics) for malformed, truncated, or
/// invalid proofs.
pub fn verify(header_bytes: &[u8], stark_proof: &[u8]) -> bool {
    if precheck_format(stark_proof).is_err() {
        return false;
    }
    let (result_bytes, proof_bytes) = stark_proof.split_at(RESULT_HEADER_LEN);
    let result_int = match result_bytes.try_into() {
        Ok(b) => u128::from_be_bytes(b),
        Err(_) => return false,
    };
    let result = BaseElement::new(result_int);

    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let seed = seed_from_bytes(header_bytes);
    let pub_inputs = PublicInputs { seed, result };

    // Matches the reduced-security parameters in `proof_options` (see its
    // doc comment for why this is far below cryptographic strength).
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(80);
    winterfell::verify::<
        SequentialWorkAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_genuine_proof_verifies_against_its_own_header() {
        let header = b"block header bytes go here, e.g. a block hash";
        let proof = prove(header);
        assert!(verify(header, &proof));
    }

    #[test]
    fn a_proof_generated_for_one_header_is_rejected_against_a_different_one() {
        let proof = prove(b"header A");
        assert!(!verify(b"header B", &proof));
    }

    #[test]
    fn corrupted_proof_bytes_are_rejected_not_panicked_on() {
        let header = b"some header";
        let mut proof = prove(header);
        let last = proof.len() - 1;
        proof[last] ^= 0xff;
        assert!(!verify(header, &proof));
    }

    #[test]
    fn truncated_or_empty_proof_bytes_are_rejected_not_panicked_on() {
        assert!(!verify(b"h", &[]));
        assert!(!verify(b"h", &[0u8; 8]));
    }

    #[test]
    fn precheck_format_rejects_garbage_before_full_verify() {
        assert!(precheck_format(&[]).is_err());
        assert!(precheck_format(&[0u8; 8]).is_err());
        assert!(precheck_format(&[0u8; 64]).is_err());
        let mut huge = vec![0u8; MAX_STARK_PROOF_BYTES + 1];
        huge[0] = 1;
        assert!(precheck_format(&huge).is_err());
        let ok = prove(b"precheck header");
        assert!(precheck_format(&ok).is_ok());
    }

    #[test]
    fn proof_size_leaves_real_room_for_transactions_in_a_22kb_block() {
        let proof = prove(b"size check header");
        assert!(
            proof.len() < 20 * 1024,
            "stark_proof is {} bytes, too large for a 22KiB block alongside any transactions",
            proof.len()
        );
    }
}
