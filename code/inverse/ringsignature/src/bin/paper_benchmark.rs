use ark_ec::CurveGroup;
use ark_ff::{One, Zero};
use ark_secp256k1::{Fr, Projective};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use ringsignature::commitment::pedersen::PedersenCommitmentScheme;
use ringsignature::ringsig::protocol_compressed::RingSignatureScheme;
use ringsignature::ringsig::structs::{LogarithmicRingSignature, RingSignatureParams};
use std::time::Instant;
use toolbox::sigma::SigmaProtocol;

const SCHEME: &str = "inverse_constraint";
const PARAMETER_SETS: usize = 3;
const WARMUPS: usize = 3;
const REPETITIONS: usize = 30;
const CASES: &[(usize, usize)] = &[
    (128, 16),
    (256, 16),
    (512, 16),
    (1024, 1),
    (1024, 2),
    (1024, 4),
    (1024, 8),
    (1024, 16),
];
const MAIN_K4_CASES: &[(usize, usize)] = &[(128, 4), (256, 4), (512, 4)];
const SECURE_MAIN_CASES: &[(usize, usize)] = &[(16, 4), (32, 4), (64, 4), (128, 4)];
const SMOKE_CASES: &[(usize, usize)] = &[(128, 1)];

type Ring = RingSignatureScheme<Projective>;

fn main() {
    // Fixed-seed randomness makes the benchmark reproducible. It is not a
    // deployment setup and must never be used to instantiate public parameters
    // for a security-sensitive system.
    let mut rng = StdRng::from_seed([0x49; 32]);
    let arguments: Vec<_> = std::env::args().collect();
    let smoke = arguments.iter().any(|argument| argument == "--smoke");
    let main_k4 = arguments.iter().any(|argument| argument == "--main-k4");
    let secure_main = arguments.iter().any(|argument| argument == "--secure-main");
    let cases = if smoke {
        SMOKE_CASES
    } else if secure_main {
        SECURE_MAIN_CASES
    } else if main_k4 {
        MAIN_K4_CASES
    } else {
        CASES
    };
    let warmups = if smoke { 1 } else { WARMUPS };
    let repetitions = if smoke { 1 } else { REPETITIONS };
    println!("scheme,ring_size,k,iteration,prove_ms,verify_ms,paper_size_bytes,implementation_size_bytes");

    for &(ring_size, signer_count) in cases {
        let message = format!("{SCHEME}:N={ring_size}:k={signer_count}");
        let (params, witness) = build_case(&mut rng, ring_size, signer_count, message);

        for _ in 0..warmups {
            let proof = Ring::prove(&mut rng, &params, &witness).unwrap();
            assert!(Ring::verify(&params, &proof).unwrap());
        }

        for iteration in 0..repetitions {
            let prove_start = Instant::now();
            let proof = Ring::prove(&mut rng, &params, &witness).unwrap();
            let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

            let verify_start = Instant::now();
            assert!(Ring::verify(&params, &proof).unwrap());
            let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

            println!(
                "{SCHEME},{ring_size},{signer_count},{iteration},{prove_ms:.6},{verify_ms:.6},{},{}",
                paper_size_bytes(ring_size),
                implementation_size_bytes(&proof),
            );
        }
    }
}

fn build_case(
    rng: &mut StdRng,
    ring_size: usize,
    signer_count: usize,
    message: String,
) -> (RingSignatureParams<Projective>, Vec<Fr>) {
    assert!(ring_size.is_power_of_two());
    assert!((1..=ring_size).contains(&signer_count));

    let mut com_parameters = Vec::with_capacity(PARAMETER_SETS);
    for index in 0..PARAMETER_SETS {
        let supported_size = if index + 1 == PARAMETER_SETS {
            1
        } else {
            ring_size
        };
        com_parameters
            .push(PedersenCommitmentScheme::<Projective>::setup(rng, supported_size).unwrap());
    }
    let key_params = com_parameters.last().unwrap().clone();
    let mut ring_entries = (0..ring_size)
        .map(|_| (Projective::rand(rng).into_affine(), None))
        .collect::<Vec<_>>();

    for signer in 0..signer_count {
        let ring_index = signer * ring_size / signer_count;
        let secret_key = Fr::rand(rng);
        let public_key = PedersenCommitmentScheme::commit(
            &key_params,
            &vec![secret_key],
            &Fr::zero(),
            "benchmark public key",
        )
        .unwrap()
        .into_affine();
        ring_entries[ring_index] = (public_key, Some(secret_key));
    }

    let mut encoded_entries = ring_entries
        .into_iter()
        .map(|(public_key, secret_key)| {
            let mut encoding = Vec::new();
            public_key.serialize_compressed(&mut encoding).unwrap();
            (encoding, public_key, secret_key)
        })
        .collect::<Vec<_>>();
    encoded_entries.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(encoded_entries.windows(2).all(|pair| pair[0].0 < pair[1].0));

    let mut public_keys = Vec::with_capacity(ring_size);
    let mut selection = Vec::with_capacity(ring_size);
    let mut secret_keys = Vec::with_capacity(signer_count);
    for (_, public_key, secret_key) in encoded_entries {
        public_keys.push(public_key);
        if let Some(secret_key) = secret_key {
            selection.push(Fr::one());
            secret_keys.push(secret_key);
        } else {
            selection.push(Fr::zero());
        }
    }

    let mut witness = secret_keys;
    witness.extend(selection);
    let params = RingSignatureParams {
        num_witness: witness.len(),
        num_pub_inputs: ring_size,
        com_parameters,
        message,
        vec_pk: public_keys,
    };
    (params, witness)
}

fn paper_size_bytes(ring_size: usize) -> usize {
    let log_n = ring_size.ilog2() as usize;
    (2 * log_n + 5) * 33 + 7 * 32
}

fn implementation_size_bytes(proof: &LogarithmicRingSignature<Projective>) -> usize {
    let group_elements = proof.commitments.len()
        + proof.compression_proof.vec_L.len()
        + proof.compression_proof.vec_R.len();
    let scalars = 5 + 2;
    group_elements * 33 + scalars * 32
}
