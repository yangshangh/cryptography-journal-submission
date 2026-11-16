//! Minimal non-interactive implementation of Section 3 of Groth--Kohlweiss
//! (EUROCRYPT 2015), specialized to powers-of-two ring sizes.
//!
//! The proved relation is knowledge of an opening to zero of one Pedersen
//! commitment in a public list.  Fiat--Shamir additionally binds a message,
//! making the benchmark representative of the paper's ring-signature use.

use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField, Zero};
use ark_secp256k1::{Fr, Projective};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::{CryptoRng, RngCore, SeedableRng},
    UniformRand,
};
use merlin::Transcript;
use std::{ops::Mul, time::Instant};

#[derive(Clone)]
struct GroupParams {
    /// Message generator in Com(m; r) = m*A + r*B.
    a: Projective,
    /// Blinding generator.
    b: Projective,
    /// Independent padding commitment used when N is not a power of two.
    y: Projective,
}

#[derive(Clone)]
struct Witness {
    index: usize,
    opening: Fr,
}

#[derive(Clone)]
struct FirstMessage {
    c_l: Vec<Projective>,
    c_a: Vec<Projective>,
    c_b: Vec<Projective>,
    c_d: Vec<Projective>,
}

struct ProverState {
    r: Vec<Fr>,
    a: Vec<Fr>,
    s: Vec<Fr>,
    t: Vec<Fr>,
    rho: Vec<Fr>,
    witness: Witness,
}

#[derive(Clone)]
struct Response {
    f: Vec<Fr>,
    z_a: Vec<Fr>,
    z_b: Vec<Fr>,
    z_d: Fr,
}

#[derive(Clone)]
struct OneOutOfManyProof {
    first: FirstMessage,
    response: Response,
}

fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

fn random_nonzero_point<R: RngCore + CryptoRng>(rng: &mut R) -> Projective {
    loop {
        let value = Projective::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

#[cfg(test)]
fn setup_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    ring_size: usize,
) -> (GroupParams, Vec<Projective>, Witness) {
    assert!(ring_size >= 2 && ring_size.is_power_of_two());
    let params = GroupParams {
        a: random_nonzero_point(rng),
        b: random_nonzero_point(rng),
        y: random_nonzero_point(rng),
    };
    let witness = Witness {
        // A non-boundary index exercises both zero and one bits.
        index: ring_size / 3,
        opening: random_nonzero_scalar(rng),
    };
    let mut commitments: Vec<Projective> =
        (0..ring_size).map(|_| random_nonzero_point(rng)).collect();
    // This list element is Com(0; opening) = opening*B.
    commitments[witness.index] = params.b.mul(witness.opening);
    (params, commitments, witness)
}

fn setup_batch_statement<R: RngCore + CryptoRng>(
    rng: &mut R,
    ring_size: usize,
    signer_count: usize,
) -> (GroupParams, Vec<Projective>, Vec<Witness>) {
    assert!(ring_size >= 2 && ring_size.is_power_of_two());
    assert!(signer_count > 0 && signer_count <= ring_size);
    let params = GroupParams {
        a: random_nonzero_point(rng),
        b: random_nonzero_point(rng),
        y: random_nonzero_point(rng),
    };
    let mut commitments: Vec<Projective> =
        (0..ring_size).map(|_| random_nonzero_point(rng)).collect();
    let mut witnesses = Vec::with_capacity(signer_count);
    for signer in 0..signer_count {
        let witness = Witness {
            index: signer * ring_size / signer_count,
            opening: random_nonzero_scalar(rng),
        };
        commitments[witness.index] = params.b.mul(witness.opening);
        witnesses.push(witness);
    }
    (params, commitments, witnesses)
}

fn polynomial_mul_scalar(poly: &mut [Fr], scalar: Fr) {
    for coefficient in poly {
        *coefficient *= scalar;
    }
}

/// Multiply a polynomial in coefficient form by (X + constant).
fn polynomial_mul_x_plus(poly: &mut [Fr], constant: Fr) {
    assert!(poly.last().unwrap().is_zero());
    for degree in (1..poly.len()).rev() {
        poly[degree] = poly[degree] * constant + poly[degree - 1];
    }
    poly[0] *= constant;
}

fn first_step<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &GroupParams,
    commitments: &[Projective],
    witness: &Witness,
) -> (FirstMessage, ProverState) {
    let ring_size = commitments.len();
    assert!(ring_size >= 2 && ring_size.is_power_of_two());
    assert!(witness.index < ring_size);
    let n = ring_size.trailing_zeros() as usize;

    let r: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
    let a: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
    let s: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
    let t: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
    let rho: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();

    let mut c_l = Vec::with_capacity(n);
    let mut c_a = Vec::with_capacity(n);
    let mut c_b = Vec::with_capacity(n);
    let mut c_d = Vec::with_capacity(n);

    for j in 0..n {
        let witness_bit_is_one = ((witness.index >> j) & 1) == 1;
        c_l.push(
            params.b.mul(r[j])
                + if witness_bit_is_one {
                    params.a
                } else {
                    Projective::zero()
                },
        );
        c_a.push(params.a.mul(a[j]) + params.b.mul(s[j]));
        c_b.push(
            params.b.mul(t[j])
                + if witness_bit_is_one {
                    params.a.mul(a[j])
                } else {
                    Projective::zero()
                },
        );
        c_d.push(params.b.mul(rho[j]));
    }

    for i in 0..ring_size {
        // Coefficients of p_i(X) from GK15 Section 3.
        let mut p_i = vec![Fr::zero(); n + 1];
        p_i[0] = Fr::one();
        for j in 0..n {
            let i_bit_is_one = ((i >> j) & 1) == 1;
            let witness_bit_is_one = ((witness.index >> j) & 1) == 1;
            match (i_bit_is_one, witness_bit_is_one) {
                (true, true) => polynomial_mul_x_plus(&mut p_i, a[j]),
                (true, false) => polynomial_mul_scalar(&mut p_i, a[j]),
                (false, true) => polynomial_mul_scalar(&mut p_i, -a[j]),
                (false, false) => polynomial_mul_x_plus(&mut p_i, -a[j]),
            }
        }
        debug_assert_eq!(
            p_i[n],
            if i == witness.index {
                Fr::one()
            } else {
                Fr::zero()
            }
        );
        for k in 0..n {
            c_d[k] += commitments[i].mul(p_i[k]);
        }
    }

    (
        FirstMessage { c_l, c_a, c_b, c_d },
        ProverState {
            r,
            a,
            s,
            t,
            rho,
            witness: witness.clone(),
        },
    )
}

fn append_point(transcript: &mut Transcript, label: &'static [u8], point: &Projective) {
    let mut encoded = Vec::new();
    point
        .clone()
        .into_affine()
        .serialize_compressed(&mut encoded)
        .unwrap();
    transcript.append_message(label, &encoded);
}

fn fiat_shamir_challenge(
    params: &GroupParams,
    commitments: &[Projective],
    message: &[u8],
    first: &FirstMessage,
) -> Fr {
    let mut transcript = Transcript::new(b"GK15-One-out-of-Many-v1");
    transcript.append_u64(b"ring size", commitments.len() as u64);
    transcript.append_message(b"message", message);
    append_point(&mut transcript, b"generator A", &params.a);
    append_point(&mut transcript, b"generator B", &params.b);
    append_point(&mut transcript, b"padding Y", &params.y);
    for point in commitments {
        append_point(&mut transcript, b"ring commitment", point);
    }
    for point in &first.c_l {
        append_point(&mut transcript, b"C_l", point);
    }
    for point in &first.c_a {
        append_point(&mut transcript, b"C_a", point);
    }
    for point in &first.c_b {
        append_point(&mut transcript, b"C_b", point);
    }
    for point in &first.c_d {
        append_point(&mut transcript, b"C_d", point);
    }
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"challenge x", &mut challenge_bytes);
    let challenge = Fr::from_le_bytes_mod_order(&challenge_bytes);
    if challenge.is_zero() {
        Fr::one()
    } else {
        challenge
    }
}

fn second_step(state: ProverState, challenge: Fr) -> Response {
    let n = state.rho.len();
    let mut f = Vec::with_capacity(n);
    let mut z_a = Vec::with_capacity(n);
    let mut z_b = Vec::with_capacity(n);
    for j in 0..n {
        let witness_bit_is_one = ((state.witness.index >> j) & 1) == 1;
        let f_j = state.a[j]
            + if witness_bit_is_one {
                challenge
            } else {
                Fr::zero()
            };
        f.push(f_j);
        z_a.push(challenge * state.r[j] + state.s[j]);
        z_b.push((challenge - f_j) * state.r[j] + state.t[j]);
    }

    let mut z_d = Fr::zero();
    let mut challenge_power = Fr::one();
    for rho_k in &state.rho {
        z_d -= *rho_k * challenge_power;
        challenge_power *= challenge;
    }
    // challenge_power is x^n here.
    z_d += state.witness.opening * challenge_power;
    Response { f, z_a, z_b, z_d }
}

fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &GroupParams,
    commitments: &[Projective],
    witness: &Witness,
    message: &[u8],
) -> OneOutOfManyProof {
    let (first, state) = first_step(rng, params, commitments, witness);
    let challenge = fiat_shamir_challenge(params, commitments, message, &first);
    let response = second_step(state, challenge);
    OneOutOfManyProof { first, response }
}

fn verify(
    params: &GroupParams,
    commitments: &[Projective],
    message: &[u8],
    proof: &OneOutOfManyProof,
) -> bool {
    let ring_size = commitments.len();
    if ring_size < 2 || !ring_size.is_power_of_two() {
        return false;
    }
    let n = ring_size.trailing_zeros() as usize;
    if proof.first.c_l.len() != n
        || proof.first.c_a.len() != n
        || proof.first.c_b.len() != n
        || proof.first.c_d.len() != n
        || proof.response.f.len() != n
        || proof.response.z_a.len() != n
        || proof.response.z_b.len() != n
    {
        return false;
    }
    let challenge = fiat_shamir_challenge(params, commitments, message, &proof.first);

    for j in 0..n {
        let lhs_1 = proof.first.c_l[j].mul(challenge) + proof.first.c_a[j];
        let rhs_1 = params.a.mul(proof.response.f[j]) + params.b.mul(proof.response.z_a[j]);
        if lhs_1 != rhs_1 {
            return false;
        }

        let lhs_2 = proof.first.c_l[j].mul(challenge - proof.response.f[j]) + proof.first.c_b[j];
        let rhs_2 = params.b.mul(proof.response.z_b[j]);
        if lhs_2 != rhs_2 {
            return false;
        }
    }

    let mut lhs = Projective::zero();
    for (i, commitment) in commitments.iter().enumerate() {
        let mut selector = Fr::one();
        for j in 0..n {
            selector *= if ((i >> j) & 1) == 1 {
                proof.response.f[j]
            } else {
                challenge - proof.response.f[j]
            };
        }
        lhs += commitment.mul(selector);
    }

    let mut rhs = params.b.mul(proof.response.z_d);
    let mut challenge_power = Fr::one();
    for c_d_k in &proof.first.c_d {
        rhs += c_d_k.mul(challenge_power);
        challenge_power *= challenge;
    }
    lhs == rhs
}

fn proof_size_bytes(proof: &OneOutOfManyProof) -> usize {
    let mut encoded = Vec::new();
    for points in [
        &proof.first.c_l,
        &proof.first.c_a,
        &proof.first.c_b,
        &proof.first.c_d,
    ] {
        for point in points {
            point
                .clone()
                .into_affine()
                .serialize_compressed(&mut encoded)
                .unwrap();
        }
    }
    for scalars in [&proof.response.f, &proof.response.z_a, &proof.response.z_b] {
        for scalar in scalars {
            scalar.serialize_compressed(&mut encoded).unwrap();
        }
    }
    proof
        .response
        .z_d
        .serialize_compressed(&mut encoded)
        .unwrap();
    encoded.len()
}

fn main() {
    let mut rng = ark_std::rand::rngs::StdRng::from_seed([0x47; 32]);
    let formal_cases = [
        (128usize, 16usize),
        (256, 16),
        (512, 16),
        (1024, 1),
        (1024, 2),
        (1024, 4),
        (1024, 8),
        (1024, 16),
    ];
    let main_k4_cases = [(128usize, 4usize), (256, 4), (512, 4)];
    let secure_main_cases = [(16usize, 4usize), (32, 4), (64, 4), (128, 4)];
    let smoke_cases = [(128usize, 1usize)];
    let arguments: Vec<_> = std::env::args().collect();
    let smoke = arguments.iter().any(|argument| argument == "--smoke");
    let main_k4 = arguments.iter().any(|argument| argument == "--main-k4");
    let secure_main = arguments.iter().any(|argument| argument == "--secure-main");
    let cases = if smoke {
        &smoke_cases[..]
    } else if secure_main {
        &secure_main_cases[..]
    } else if main_k4 {
        &main_k4_cases[..]
    } else {
        &formal_cases[..]
    };
    let warmups = if smoke { 1usize } else { 3usize };
    let repetitions = if smoke { 1usize } else { 30usize };

    println!("scheme,ring_size,k,iteration,prove_ms,verify_ms,paper_size_bytes,implementation_size_bytes");
    for &(ring_size, signer_count) in cases {
        let (params, commitments, witnesses) =
            setup_batch_statement(&mut rng, ring_size, signer_count);
        let message = format!("GK15 benchmark N={ring_size}, k={signer_count}");

        for _ in 0..warmups {
            let proofs: Vec<_> = witnesses
                .iter()
                .map(|witness| prove(&mut rng, &params, &commitments, witness, message.as_bytes()))
                .collect();
            for proof in &proofs {
                assert!(verify(&params, &commitments, message.as_bytes(), proof));
            }
        }

        for iteration in 0..repetitions {
            let prove_start = Instant::now();
            let proofs: Vec<_> = witnesses
                .iter()
                .map(|witness| prove(&mut rng, &params, &commitments, witness, message.as_bytes()))
                .collect();
            let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

            let verify_start = Instant::now();
            for proof in &proofs {
                assert!(verify(&params, &commitments, message.as_bytes(), proof));
            }
            let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
            let implementation_size: usize = proofs.iter().map(proof_size_bytes).sum();
            let log_n = ring_size.ilog2() as usize;
            let paper_size =
                signer_count * (4 * log_n * 33 + (3 * log_n + 1) * 32);
            assert_eq!(paper_size, implementation_size);

            println!(
                "gk15_oom_kfold,{ring_size},{signer_count},{iteration},{prove_ms:.6},{verify_ms:.6},{paper_size},{implementation_size}",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_proof_verifies_and_has_gk15_size() {
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([7u8; 32]);
        let (params, commitments, witness) = setup_statement(&mut rng, 128);
        let proof = prove(&mut rng, &params, &commitments, &witness, b"test message");
        assert!(verify(&params, &commitments, b"test message", &proof));
        // 4*log2(N) compressed points + (3*log2(N)+1) scalars.
        assert_eq!(proof_size_bytes(&proof), 4 * 7 * 33 + (3 * 7 + 1) * 32);
    }

    #[test]
    fn tampered_response_is_rejected() {
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([9u8; 32]);
        let (params, commitments, witness) = setup_statement(&mut rng, 128);
        let mut proof = prove(&mut rng, &params, &commitments, &witness, b"test message");
        proof.response.f[0] += Fr::one();
        assert!(!verify(&params, &commitments, b"test message", &proof));
    }

    #[test]
    fn proof_is_bound_to_message() {
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([11u8; 32]);
        let (params, commitments, witness) = setup_statement(&mut rng, 128);
        let proof = prove(&mut rng, &params, &commitments, &witness, b"message A");
        assert!(!verify(&params, &commitments, b"message B", &proof));
    }
}
