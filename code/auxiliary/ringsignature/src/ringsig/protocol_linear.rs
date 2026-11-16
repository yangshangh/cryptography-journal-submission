use std::io::Write;
use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_std::{end_timer, rand::Rng, start_timer, One, UniformRand, Zero};
use sha256::digest;

use crate::commitment::pedersen::PedersenCommitmentScheme;
use crate::commitment::PedersenParams;
use crate::ringsig::structs::{LinearRingSignature, Openings, RingSignatureParams};
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

/// Uncompressed form of the paper's auxiliary-vector protocol. The verifier
/// checks equations (20)-(23) directly on the length-2N responses.
impl<C> SigmaProtocol<C> for RingSignatureScheme<C>
where
    C: CurveGroup,
{
    type PublicParams = RingSignatureParams<C>;
    type Witness = Vec<C::ScalarField>;
    type Commitments = Vec<C::Affine>;
    type Challenge = Vec<C::ScalarField>;
    type Proof = LinearRingSignature<C>;

    fn setup<R: Rng>(
        rng: &mut R,
        wit: &mut Self::Witness,
        msg: &String,
        supported_size: usize,
    ) -> Result<Self::PublicParams, SigmaErrors> {
        if supported_size == 0 {
            return Err(SigmaErrors::InvalidParameters(
                "ring size must be non-zero".to_string(),
            ));
        }
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
        let start = start_timer!(|| "running 2N auxiliary-vector linear prover...");
        let n = params.num_pub_inputs;
        if n == 0 || params.vec_pk.len() != n || params.com_parameters.len() != 5 || wit.len() < n {
            return Err(SigmaErrors::InvalidParameters(
                "invalid auxiliary-vector parameters or witness".to_string(),
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
        if vec_b0.iter().filter(|&&bit| bit.is_one()).count() != vec_sk.len() {
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

        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"RingSignature-2N-linear");
        transcript.append_serializable_element(b"public list", &params.vec_pk)?;
        let alpha1 = C::ScalarField::rand(rng);
        let alpha2 = C::ScalarField::rand(rng);
        let alpha3 = C::ScalarField::rand(rng);
        let alpha4 = C::ScalarField::rand(rng);
        let vec_r0: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let vec_r1: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let vec_r2: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let vec_r3: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
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
        let powers_gamma = generate_powers(C::ScalarField::from(2u64) * y_inverse, n);
        let weights_2n = concat(&powers_y, &powers_y);
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
        let delta = (z + z2 + z5 + z6) * inner_product(&ones, &powers_y)
            + z7
            + z8 * inner_product(&vec![C::ScalarField::one(); 2 * n], &q_2n);

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
        if hat_t != delta + t1 * x + t2 * x * x {
            return Err(SigmaErrors::InvalidProver(
                "auxiliary constraint polynomial is inconsistent".to_string(),
            ));
        }
        let taux = tau1 * x + tau2 * x * x;
        let mu1 = alpha1 + alpha2 * x;
        let mu2 = alpha3 * z2 + alpha4 * x;
        let mut fs = C::ScalarField::zero();
        let mut sk_index = 0;
        for i in 0..n {
            if vec_b0[i].is_one() {
                fs += powers_y[i] * vec_sk[sk_index];
                sk_index += 1;
            }
        }
        fs += r_s * x;

        end_timer!(start);
        Ok(LinearRingSignature {
            commitments: vec![com_a, com_b, com_c, com_d, com_e, com_t1, com_t2],
            openings: Openings {
                zeta,
                eta,
                hat_t,
                taux,
                mu_1: mu1,
                mu_2: mu2,
                fs,
            },
            challenges: vec![y, z, x],
            digest: h,
        })
    }

    fn verify(params: &Self::PublicParams, proof: &Self::Proof) -> Result<bool, SigmaErrors> {
        let start = start_timer!(|| "running 2N auxiliary-vector linear verifier...");
        let n = params.num_pub_inputs;
        if n == 0
            || params.vec_pk.len() != n
            || params.com_parameters.len() != 5
            || proof.commitments.len() != 7
            || proof.challenges.len() != 3
            || proof.openings.zeta.len() != 2 * n
            || proof.openings.eta.len() != 2 * n
        {
            return Err(SigmaErrors::InvalidProof(
                "invalid auxiliary-vector linear proof shape".to_string(),
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
        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"RingSignature-2N-linear");
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
        let delta = (z + z2 + z5 + z6) * inner_product(&ones, &powers_y)
            + z7
            + z8 * inner_product(&vec![C::ScalarField::one(); 2 * n], &q_2n);

        // Equation (20).
        let v1_lhs = param_h1_v.generator.mul(proof.openings.hat_t)
            + param_g1_u1.generator.mul(proof.openings.taux);
        let v1_rhs = param_h1_v.generator.mul(delta) + com_t1.mul(x) + com_t2.mul(x * x);
        if v1_lhs != v1_rhs {
            return Err(SigmaErrors::InvalidProof(
                "equation (20) failed".to_string(),
            ));
        }

        // Equation (21).
        let zeta_first = proof.openings.zeta[..n].to_vec();
        let zeta_second = proof.openings.zeta[n..].to_vec();
        let eta_first = proof.openings.eta[..n].to_vec();
        let eta_second = proof.openings.eta[n..].to_vec();
        let mut g1_prime = Vec::with_capacity(n);
        let mut g2_prime = Vec::with_capacity(n);
        for i in 0..n {
            g1_prime.push((param_g1_u1.vec_gen[i] * powers_y_inverse[i]).into_affine());
            g2_prime.push((param_g2_u2.vec_gen[i] * powers_y_inverse[i]).into_affine());
        }
        let v2_lhs = C::msm(&g1_prime, &zeta_first).unwrap()
            + C::msm(&g2_prime, &zeta_second).unwrap()
            + C::msm(&param_h1_v.vec_gen, &eta_first).unwrap()
            + C::msm(&param_h2.vec_gen, &eta_second).unwrap()
            + param_g1_u1.generator.mul(proof.openings.mu_1)
            + param_g2_u2.generator.mul(proof.openings.mu_2);
        let v2_rhs = com_a
            + com_b.mul(x)
            + com_c.mul(z2)
            + com_d.mul(x)
            + C::msm(&param_g1_u1.vec_gen, &scalar_product(&ones, &z)).unwrap()
            + C::msm(&param_g2_u2.vec_gen, &scalar_product(&ones, &z3)).unwrap()
            + C::msm(
                &param_h1_v.vec_gen,
                &vec_add(
                    &scalar_product(&ones, &z),
                    &scalar_product(&powers_gamma, &z7),
                ),
            )
            .unwrap()
            + C::msm(
                &param_h2.vec_gen,
                &vec_add(
                    &scalar_product(&ones, &z3),
                    &scalar_product(&powers_gamma, &(-z5)),
                ),
            )
            .unwrap();
        if v2_lhs != v2_rhs {
            return Err(SigmaErrors::InvalidProof(
                "equation (21) failed".to_string(),
            ));
        }

        // Equation (22).
        let v3_lhs = C::msm(&params.vec_pk, &zeta_first).unwrap();
        let v3_rhs = PedersenCommitmentScheme::commit(
            param_key,
            &vec![proof.openings.fs],
            &C::ScalarField::zero(),
            "fs",
        )? + com_e.mul(x)
            + C::msm(&params.vec_pk, &scalar_product(&powers_y, &z)).unwrap();
        if v3_lhs != v3_rhs {
            return Err(SigmaErrors::InvalidProof(
                "equation (22) failed".to_string(),
            ));
        }

        // Equation (23).
        if proof.openings.hat_t != inner_product(&proof.openings.zeta, &proof.openings.eta) {
            return Err(SigmaErrors::InvalidProof(
                "equation (23) failed".to_string(),
            ));
        }
        end_timer!(start);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256k1::{Fr, Projective};
    use ark_std::UniformRand;

    type Ring = RingSignatureScheme<Projective>;

    #[test]
    fn test_auxiliary_vector_linear_signature() {
        let mut rng = ark_std::test_rng();
        let ring_size = 10;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        let message = String::from("Welcome to the world of Zero Knowledge!");
        let params = Ring::setup(&mut rng, &mut wit, &message, ring_size).unwrap();
        let proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        assert_eq!(proof.openings.zeta.len(), 2 * ring_size);
        assert!(Ring::verify(&params, &proof).unwrap());
    }

    #[test]
    fn rejects_empty_selection_vector() {
        let mut rng = ark_std::test_rng();
        let ring_size = 8;
        let params = RingSignatureParams {
            num_witness: ring_size,
            num_pub_inputs: ring_size,
            com_parameters: vec![
                PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap(),
                PedersenCommitmentScheme::<Projective>::setup(&mut rng, 1).unwrap(),
            ],
            message: "empty selection".to_string(),
            vec_pk: vec![Projective::rand(&mut rng).into_affine(); ring_size],
        };
        let wit = vec![Fr::zero(); ring_size];
        assert!(Ring::prove(&mut rng, &params, &wit).is_err());
    }
}
