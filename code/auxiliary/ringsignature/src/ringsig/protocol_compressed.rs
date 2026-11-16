use std::io::Write;
use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_std::{end_timer, rand::Rng, start_timer, One, UniformRand, Zero};
use sha256::digest;

use crate::commitment::pedersen::PedersenCommitmentScheme;
use crate::commitment::PedersenParams;
use crate::ringsig::structs::{LogarithmicRingSignature, Openings, RingSignatureParams};
use bulletproofs::ipa::*;
use bulletproofs::structs::*;
use toolbox::errors::SigmaErrors;
use toolbox::sigma::{transcript::ProofTranscript, SigmaProtocol};
use toolbox::vec::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingSignatureScheme<C>
where
    C: CurveGroup,
{
    phantom: PhantomData<C>,
}

/// Subtract one from a little-endian binary vector.
///
/// Together with the power vector `(1, 2, ..., 2^(N-1))`, this constructs the
/// auxiliary witness b2 satisfying <b0, 2^N> - 1 = <b2, 2^N>. `None` means
/// that the input was zero or was not binary.
fn binary_minus_one<F: PrimeField>(bits: &[F]) -> Option<Vec<F>> {
    let mut result = bits.to_vec();
    for bit in &mut result {
        if bit.is_one() {
            *bit = F::zero();
            return Some(result);
        }
        if bit.is_zero() {
            *bit = F::one();
        } else {
            return None;
        }
    }
    None
}

fn concat<F: PrimeField>(left: &[F], right: &[F]) -> Vec<F> {
    let mut result = Vec::with_capacity(left.len() + right.len());
    result.extend_from_slice(left);
    result.extend_from_slice(right);
    result
}

/// The original auxiliary-vector protocol from the supplied paper.
///
/// It proves b0 is binary and non-zero by introducing the binary vector b2
/// that encodes <b0, 2^N> - 1. The pairs (b0,b1) and (b2,b3), together with
/// four independent masks, are concatenated into a length-2N IPA witness.
impl<C> SigmaProtocol<C> for RingSignatureScheme<C>
where
    C: CurveGroup,
{
    type PublicParams = RingSignatureParams<C>;
    type Witness = Vec<C::ScalarField>;
    type Commitments = Vec<C::Affine>;
    type Challenge = Vec<C::ScalarField>;
    type Proof = LogarithmicRingSignature<C>;

    fn setup<R: Rng>(
        rng: &mut R,
        wit: &mut Self::Witness,
        msg: &String,
        supported_size: usize,
    ) -> Result<Self::PublicParams, SigmaErrors> {
        if supported_size == 0 || !supported_size.is_power_of_two() {
            return Err(SigmaErrors::InvalidParameters(
                "compressed ring size must be a non-zero power of two".to_string(),
            ));
        }

        // (g1,u1), (h1,v), (g2,u2), h2, and the public-key base g.
        let param_g1_u1 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let param_h1_v = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let param_g2_u2 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let param_h2 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let param_key = PedersenCommitmentScheme::<C>::setup(rng, 1)?;

        let pk =
            PedersenCommitmentScheme::commit(&param_key, wit, &C::ScalarField::zero(), "as pk")?
                .into_affine();
        let mut vec_pk = vec![C::Affine::rand(rng); supported_size - 1];
        vec_pk.push(pk);
        let vec_b = shuffle::<C>(&mut vec_pk, pk);
        wit.extend(vec_b);

        Ok(RingSignatureParams {
            num_witness: wit.len(),
            num_pub_inputs: supported_size,
            com_parameters: vec![param_g1_u1, param_h1_v, param_g2_u2, param_h2, param_key],
            message: msg.clone(),
            vec_pk,
        })
    }

    fn prove<R: Rng>(
        rng: &mut R,
        params: &Self::PublicParams,
        wit: &Self::Witness,
    ) -> Result<Self::Proof, SigmaErrors> {
        let start = start_timer!(|| "running 2N auxiliary-vector ring signature prover...");
        let n = params.num_pub_inputs;
        if n == 0
            || !n.is_power_of_two()
            || params.vec_pk.len() != n
            || params.com_parameters.len() != 5
            || wit.len() < n
        {
            return Err(SigmaErrors::InvalidParameters(
                "invalid auxiliary-vector ring parameters or witness length".to_string(),
            ));
        }

        let param_g1_u1 = &params.com_parameters[0];
        let param_h1_v = &params.com_parameters[1];
        let param_g2_u2 = &params.com_parameters[2];
        let param_h2 = &params.com_parameters[3];
        let param_key = &params.com_parameters[4];
        let vec_sk = wit[..wit.len() - n].to_vec();
        let vec_b0 = wit[wit.len() - n..].to_vec();
        if vec_b0.iter().any(|&bit| !bit.is_zero() && !bit.is_one()) {
            return Err(SigmaErrors::InvalidProver(
                "selection vector must be binary".to_string(),
            ));
        }

        // b2 is the binary encoding of the selected-position number minus one.
        // It exists exactly when b0 is non-zero.
        let vec_b2 = binary_minus_one(&vec_b0).ok_or_else(|| {
            SigmaErrors::InvalidProver(
                "selection vector must be non-empty (auxiliary witness does not exist)".to_string(),
            )
        })?;
        let vec_b1: Vec<C::ScalarField> = vec_b0
            .iter()
            .map(|&bit| C::ScalarField::one() - bit)
            .collect();
        let vec_b3: Vec<C::ScalarField> = vec_b2
            .iter()
            .map(|&bit| C::ScalarField::one() - bit)
            .collect();
        let selected_count = vec_b0.iter().filter(|&&bit| bit.is_one()).count();
        if selected_count != vec_sk.len() {
            return Err(SigmaErrors::InvalidProver(
                "secret-key count does not match selected positions".to_string(),
            ));
        }

        let powers_two = generate_powers(C::ScalarField::from(2u64), n);
        if inner_product(&vec_b0, &powers_two) - C::ScalarField::one()
            != inner_product(&vec_b2, &powers_two)
        {
            return Err(SigmaErrors::InvalidProver(
                "auxiliary non-zero relation is not satisfied".to_string(),
            ));
        }

        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"RingSignature-2N");
        transcript.append_serializable_element(b"public list", &params.vec_pk)?;

        let alpha1 = C::ScalarField::rand(rng);
        let alpha2 = C::ScalarField::rand(rng);
        let alpha3 = C::ScalarField::rand(rng);
        let alpha4 = C::ScalarField::rand(rng);
        let vec_r0: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let vec_r1: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let vec_r2: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let vec_r3: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();

        // Paper steps (4): A, B, C, D.
        let com_a = PedersenCommitmentScheme::commit(param_g1_u1, &vec_b0, &alpha1, "A/b0")?
            + PedersenCommitmentScheme::commit(
                param_h1_v,
                &vec_b1,
                &C::ScalarField::zero(),
                "A/b1",
            )?;
        let com_b = PedersenCommitmentScheme::commit(param_g1_u1, &vec_r0, &alpha2, "B/r0")?
            + PedersenCommitmentScheme::commit(
                param_h1_v,
                &vec_r1,
                &C::ScalarField::zero(),
                "B/r1",
            )?;
        let com_c = PedersenCommitmentScheme::commit(param_g2_u2, &vec_b2, &alpha3, "C/b2")?
            + PedersenCommitmentScheme::commit(param_h2, &vec_b3, &C::ScalarField::zero(), "C/b3")?;
        let com_d = PedersenCommitmentScheme::commit(param_g2_u2, &vec_r2, &alpha4, "D/r2")?
            + PedersenCommitmentScheme::commit(param_h2, &vec_r3, &C::ScalarField::zero(), "D/r3")?;

        transcript
            .append_serializable_element(b"commitments A,B,C,D", &[com_a, com_b, com_c, com_d])?;
        let y = transcript.get_and_append_challenge(b"challenge y")?;
        let z = transcript.get_and_append_challenge(b"challenge z")?;
        let y_inverse = y
            .inverse()
            .ok_or_else(|| SigmaErrors::InvalidProver("zero y challenge".to_string()))?;

        let z2 = z * z;
        let z3 = z2 * z;
        let z5 = z3 * z2;
        let z6 = z3 * z3;
        let z7 = z6 * z;
        let z8 = z7 * z;
        let ones = vec![C::ScalarField::one(); n];
        let powers_y = generate_powers(y, n);
        let gamma = C::ScalarField::from(2u64) * y_inverse;
        let powers_gamma = generate_powers(gamma, n);
        let weights_2n = concat(&powers_y, &powers_y);

        // Equations (4.8)-(4.9), at X=0.
        let left_first = vec_add(&vec_b0, &scalar_product(&ones, &z));
        let left_second = vec_add(&scalar_product(&vec_b2, &z2), &scalar_product(&ones, &z3));
        let left_base = hadamard_product(&concat(&left_first, &left_second), &weights_2n);

        let right_first = vec_add(
            &vec_add(&vec_b1, &scalar_product(&ones, &z)),
            &scalar_product(&powers_gamma, &z7),
        );
        let right_second = vec_add(
            &vec_add(&scalar_product(&vec_b3, &z2), &scalar_product(&ones, &z3)),
            &scalar_product(&powers_gamma, &(-z5)),
        );
        let right_base = concat(&right_first, &right_second);

        let left_mask = hadamard_product(&concat(&vec_r0, &vec_r2), &weights_2n);
        let right_mask = concat(&vec_r1, &vec_r3);
        let t1 = inner_product(&left_mask, &right_base) + inner_product(&left_base, &right_mask);
        let t2 = inner_product(&left_mask, &right_mask);

        let q_2n = concat(
            &powers_two,
            &scalar_product(&powers_two, &(-C::ScalarField::one())),
        );
        let ones_2n = vec![C::ScalarField::one(); 2 * n];
        let delta = (z + z2 + z5 + z6) * inner_product(&ones, &powers_y)
            + z7
            + z8 * inner_product(&ones_2n, &q_2n);

        let r_s = C::ScalarField::rand(rng);
        let tau1 = C::ScalarField::rand(rng);
        let tau2 = C::ScalarField::rand(rng);
        let com_e = C::msm(&params.vec_pk, &hadamard_product(&powers_y, &vec_r0)).unwrap()
            + PedersenCommitmentScheme::commit(
                param_key,
                &vec![-r_s],
                &C::ScalarField::zero(),
                "E",
            )?;
        let param_u1_v = PedersenParams {
            generator: param_g1_u1.generator,
            vec_gen: vec![param_h1_v.generator.into_affine()],
        };
        let com_t1 = PedersenCommitmentScheme::commit(&param_u1_v, &vec![t1], &tau1, "T1")?;
        let com_t2 = PedersenCommitmentScheme::commit(&param_u1_v, &vec![t2], &tau2, "T2")?;

        transcript.append_serializable_element(b"commitments E,T1,T2", &[com_e, com_t1, com_t2])?;
        let h = digest(&params.message);
        let mut h_msg: &mut [u8] = &mut [0; 32];
        h_msg.write(h.as_bytes()).unwrap();
        transcript.append_message(b"message digest", &h_msg)?;
        let x = transcript.get_and_append_challenge(b"challenge x")?;

        let zeta = vec_add(&left_base, &scalar_product(&left_mask, &x));
        let eta = vec_add(&right_base, &scalar_product(&right_mask, &x));
        let hat_t = inner_product(&zeta, &eta);
        let taux = tau1 * x + tau2 * x * x;
        let mu1 = alpha1 + alpha2 * x;
        let mu2 = alpha3 * z2 + alpha4 * x;

        let mut sk_index = 0;
        let mut fs = C::ScalarField::zero();
        for i in 0..n {
            if vec_b0[i].is_one() {
                fs += powers_y[i] * vec_sk[sk_index];
                sk_index += 1;
            }
        }
        fs += r_s * x;

        // Section 4.4: combine checks (21)-(23) into a length-2N IPA.
        let powers_y_inverse = generate_powers(y_inverse, n);
        let mut vec_g = Vec::with_capacity(2 * n);
        for i in 0..n {
            vec_g.push(
                ((param_g1_u1.vec_gen[i] * powers_y_inverse[i]) + params.vec_pk[i]).into_affine(),
            );
        }
        for i in 0..n {
            vec_g.push((param_g2_u2.vec_gen[i] * powers_y_inverse[i]).into_affine());
        }
        let mut vec_h = param_h1_v.vec_gen.clone();
        vec_h.extend(param_h2.vec_gen.clone());
        let ipa_param = InnerProductParam {
            factors_G: vec![C::ScalarField::one(); 2 * n],
            factors_H: vec![C::ScalarField::one(); 2 * n],
            u: param_h1_v.generator.into_affine(),
            vec_G: vec_g,
            vec_H: vec_h,
        };
        let compression_proof = InnerProductProtocol::<C>::prove(&ipa_param, zeta, eta)?;

        // The polynomial constant term is checked again here to catch formula
        // regressions before returning a proof.
        if hat_t != delta + t1 * x + t2 * x * x {
            return Err(SigmaErrors::InvalidProver(
                "auxiliary constraint polynomial is inconsistent".to_string(),
            ));
        }

        end_timer!(start);
        Ok(LogarithmicRingSignature {
            commitments: vec![com_a, com_b, com_c, com_d, com_e, com_t1, com_t2],
            openings: Openings {
                zeta: vec![compression_proof.a],
                eta: vec![compression_proof.b],
                hat_t,
                taux,
                mu_1: mu1,
                mu_2: mu2,
                fs,
            },
            compression_proof,
            challenges: vec![y, z, x],
            digest: h,
        })
    }

    fn verify(params: &Self::PublicParams, proof: &Self::Proof) -> Result<bool, SigmaErrors> {
        let start = start_timer!(|| "running 2N auxiliary-vector ring signature verifier...");
        let n = params.num_pub_inputs;
        if n == 0
            || !n.is_power_of_two()
            || params.vec_pk.len() != n
            || params.com_parameters.len() != 5
            || proof.commitments.len() != 7
            || proof.challenges.len() != 3
        {
            return Err(SigmaErrors::InvalidProof(
                "invalid auxiliary-vector proof shape".to_string(),
            ));
        }

        let param_g1_u1 = &params.com_parameters[0];
        let param_h1_v = &params.com_parameters[1];
        let param_g2_u2 = &params.com_parameters[2];
        let param_h2 = &params.com_parameters[3];
        let param_key = &params.com_parameters[4];
        let (com_a, com_b, com_c, com_d, com_e, com_t1, com_t2) = (
            proof.commitments[0],
            proof.commitments[1],
            proof.commitments[2],
            proof.commitments[3],
            proof.commitments[4],
            proof.commitments[5],
            proof.commitments[6],
        );
        let (y, z, x) = (
            proof.challenges[0],
            proof.challenges[1],
            proof.challenges[2],
        );
        let y_inverse = y
            .inverse()
            .ok_or_else(|| SigmaErrors::InvalidProof("zero y challenge".to_string()))?;

        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"RingSignature-2N");
        transcript.append_serializable_element(b"public list", &params.vec_pk)?;
        transcript
            .append_serializable_element(b"commitments A,B,C,D", &[com_a, com_b, com_c, com_d])?;
        let y_check = transcript.get_and_append_challenge(b"challenge y")?;
        let z_check = transcript.get_and_append_challenge(b"challenge z")?;
        transcript.append_serializable_element(b"commitments E,T1,T2", &[com_e, com_t1, com_t2])?;
        let h = digest(&params.message);
        if h != proof.digest {
            return Err(SigmaErrors::InvalidProof(
                "message digest mismatch".to_string(),
            ));
        }
        let mut h_msg: &mut [u8] = &mut [0; 32];
        h_msg.write(h.as_bytes()).unwrap();
        transcript.append_message(b"message digest", &h_msg)?;
        let x_check = transcript.get_and_append_challenge(b"challenge x")?;
        if (y_check, z_check, x_check) != (y, z, x) {
            return Err(SigmaErrors::InvalidProof(
                "invalid Fiat-Shamir challenge".to_string(),
            ));
        }

        let z2 = z * z;
        let z3 = z2 * z;
        let z5 = z3 * z2;
        let z6 = z3 * z3;
        let z7 = z6 * z;
        let z8 = z7 * z;
        let ones = vec![C::ScalarField::one(); n];
        let powers_y = generate_powers(y, n);
        let powers_y_inverse = generate_powers(y_inverse, n);
        let powers_gamma = generate_powers(C::ScalarField::from(2u64) * y_inverse, n);
        let powers_two = generate_powers(C::ScalarField::from(2u64), n);
        let q_2n = concat(
            &powers_two,
            &scalar_product(&powers_two, &(-C::ScalarField::one())),
        );
        let ones_2n = vec![C::ScalarField::one(); 2 * n];
        let delta = (z + z2 + z5 + z6) * inner_product(&ones, &powers_y)
            + z7
            + z8 * inner_product(&ones_2n, &q_2n);

        // Check (20), rearranged so rhs_step1 equals v^hat_t.
        let zero_n = vec![C::ScalarField::zero(); n];
        let rhs_step1 = PedersenCommitmentScheme::commit(param_h1_v, &zero_n, &delta, "delta")?
            + com_t1.mul(x)
            + com_t2.mul(x * x)
            - PedersenCommitmentScheme::commit(
                param_g1_u1,
                &zero_n,
                &proof.openings.taux,
                "tau_x",
            )?;

        // Check (21), moved to the public target of the IPA.
        let g1_shift = scalar_product(&ones, &z);
        let g2_shift = scalar_product(&ones, &z3);
        let h1_shift = vec_add(
            &scalar_product(&ones, &z),
            &scalar_product(&powers_gamma, &z7),
        );
        let h2_shift = vec_add(
            &scalar_product(&ones, &z3),
            &scalar_product(&powers_gamma, &(-z5)),
        );
        let rhs_step2 = com_a
            + com_b.mul(x)
            + com_c.mul(z2)
            + com_d.mul(x)
            + C::msm(&param_g1_u1.vec_gen, &g1_shift).unwrap()
            + C::msm(&param_g2_u2.vec_gen, &g2_shift).unwrap()
            + C::msm(&param_h1_v.vec_gen, &h1_shift).unwrap()
            + C::msm(&param_h2.vec_gen, &h2_shift).unwrap()
            - param_g1_u1.generator.mul(proof.openings.mu_1)
            - param_g2_u2.generator.mul(proof.openings.mu_2);

        // Check (22), with the identity vector in the second half implicit.
        let rhs_step3 = PedersenCommitmentScheme::commit(
            param_key,
            &vec![proof.openings.fs],
            &C::ScalarField::zero(),
            "fs",
        )? + com_e.mul(x)
            + C::msm(&params.vec_pk, &scalar_product(&powers_y, &z)).unwrap();

        let mut vec_g = Vec::with_capacity(2 * n);
        for i in 0..n {
            vec_g.push(
                ((param_g1_u1.vec_gen[i] * powers_y_inverse[i]) + params.vec_pk[i]).into_affine(),
            );
        }
        for i in 0..n {
            vec_g.push((param_g2_u2.vec_gen[i] * powers_y_inverse[i]).into_affine());
        }
        let mut vec_h = param_h1_v.vec_gen.clone();
        vec_h.extend(param_h2.vec_gen.clone());
        let ipa_param = InnerProductParam {
            factors_G: vec![C::ScalarField::one(); 2 * n],
            factors_H: vec![C::ScalarField::one(); 2 * n],
            u: param_h1_v.generator.into_affine(),
            vec_G: vec_g,
            vec_H: vec_h,
        };
        InnerProductProtocol::<C>::verify(
            2 * n,
            rhs_step1 + rhs_step2 + rhs_step3,
            &ipa_param,
            &proof.compression_proof,
        )?;

        end_timer!(start);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256k1::{Fr, Projective};
    use ark_std::UniformRand;
    use std::time::Instant;

    type Ring = RingSignatureScheme<Projective>;

    fn manual_params(
        rng: &mut impl Rng,
        ring_size: usize,
        message: String,
    ) -> RingSignatureParams<Projective> {
        RingSignatureParams {
            num_witness: ring_size,
            num_pub_inputs: ring_size,
            com_parameters: vec![
                PedersenCommitmentScheme::<Projective>::setup(rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(rng, 1).unwrap(),
            ],
            message,
            vec_pk: vec![Projective::rand(rng).into_affine(); ring_size],
        }
    }

    #[test]
    fn test_auxiliary_vector_ring_signature() {
        let mut rng = ark_std::test_rng();
        let ring_size = 16;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        let message = String::from("Welcome to the world of Zero Knowledge!");
        let params = Ring::setup(&mut rng, &mut wit, &message, ring_size).unwrap();
        let proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        assert_eq!(proof.compression_proof.vec_L.len(), 5); // log2(2N)
        assert!(Ring::verify(&params, &proof).unwrap());
    }

    #[test]
    fn rejects_empty_selection_vector() {
        let mut rng = ark_std::test_rng();
        let ring_size = 8;
        let params = manual_params(&mut rng, ring_size, "empty selection".to_string());
        let wit = vec![Fr::zero(); ring_size];
        assert!(Ring::prove(&mut rng, &params, &wit).is_err());
    }

    #[test]
    fn test_multiple_hidden_signers() {
        let mut rng = ark_std::test_rng();
        let ring_size = 16;
        let signer_indices = [1usize, 5, 11];
        let mut params = manual_params(&mut rng, ring_size, "three hidden signers".to_string());
        let key_params = params.com_parameters[4].clone();
        let mut vec_b = vec![Fr::zero(); ring_size];
        let mut vec_sk = Vec::new();
        for &i in &signer_indices {
            let sk = Fr::rand(&mut rng);
            params.vec_pk[i] =
                PedersenCommitmentScheme::commit(&key_params, &vec![sk], &Fr::zero(), "as pk")
                    .unwrap()
                    .into_affine();
            vec_b[i] = Fr::one();
            vec_sk.push(sk);
        }
        params.num_witness = vec_sk.len() + ring_size;
        let mut wit = vec_sk;
        wit.extend(vec_b);
        let proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        assert!(Ring::verify(&params, &proof).unwrap());
    }

    #[test]
    #[ignore]
    fn benchmark_large_ring_sizes() {
        let ring_sizes = [128usize, 256, 512, 1024];
        println!();
        println!("| Ring size N | Sign time (ms) | Verify time (ms) | Signature size (bytes, estimated) |");
        println!("|---:|---:|---:|---:|");
        for ring_size in ring_sizes {
            let mut rng = ark_std::test_rng();
            let sk = Fr::rand(&mut rng);
            let mut wit = vec![sk];
            let message = format!("Large ring benchmark N={}", ring_size);
            let params = Ring::setup(&mut rng, &mut wit, &message, ring_size).unwrap();
            let start_sign = Instant::now();
            let proof = Ring::prove(&mut rng, &params, &wit).unwrap();
            let sign_time_ms = start_sign.elapsed().as_secs_f64() * 1000.0;
            let start_verify = Instant::now();
            assert!(Ring::verify(&params, &proof).unwrap());
            let verify_time_ms = start_verify.elapsed().as_secs_f64() * 1000.0;
            println!(
                "| {} | {:.3} | {:.3} | {} |",
                ring_size,
                sign_time_ms,
                verify_time_ms,
                estimate_signature_size_bytes(&proof),
            );
        }
    }

    fn estimate_signature_size_bytes(proof: &LogarithmicRingSignature<Projective>) -> usize {
        const SCALAR_BYTES: usize = 32;
        const COMPRESSED_POINT_BYTES: usize = 33;
        const DIGEST_BYTES: usize = 32;
        let commitment_bytes = proof.commitments.len() * COMPRESSED_POINT_BYTES;
        let opening_bytes =
            (proof.openings.zeta.len() + proof.openings.eta.len() + 5) * SCALAR_BYTES;
        let challenge_bytes = proof.challenges.len() * SCALAR_BYTES;
        let ipa_bytes = (proof.compression_proof.vec_L.len() + proof.compression_proof.vec_R.len())
            * COMPRESSED_POINT_BYTES
            + (2 + proof.compression_proof.challenges.len()) * SCALAR_BYTES;
        commitment_bytes + opening_bytes + challenge_bytes + ipa_bytes + DIGEST_BYTES
    }
}
