use std::marker::PhantomData;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{end_timer, rand::Rng, start_timer, One, UniformRand, Zero};

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

fn compressed_encoding<C: CurveGroup>(point: &C::Affine) -> Result<Vec<u8>, SigmaErrors> {
    let mut encoded = Vec::new();
    point.serialize_compressed(&mut encoded)?;
    Ok(encoded)
}

fn validate_canonical_ring<C: CurveGroup>(ring: &[C::Affine]) -> Result<(), SigmaErrors> {
    let mut previous: Option<Vec<u8>> = None;
    for point in ring {
        if point.is_zero() {
            return Err(SigmaErrors::InvalidParameters(
                "public ring contains the identity element".to_string(),
            ));
        }
        let encoded = compressed_encoding::<C>(point)?;
        if previous.as_ref().is_some_and(|value| value >= &encoded) {
            return Err(SigmaErrors::InvalidParameters(
                "public ring must be strictly sorted by compressed encoding and contain no duplicates"
                    .to_string(),
            ));
        }
        previous = Some(encoded);
    }
    Ok(())
}

fn initialize_transcript<C: CurveGroup>(
    params: &RingSignatureParams<C>,
) -> Result<ProofTranscript<C::ScalarField>, SigmaErrors> {
    let mut transcript = ProofTranscript::<C::ScalarField>::new(b"SEU-AMRS-v2-linear");
    transcript.append_message(b"ring size", &params.num_pub_inputs.to_le_bytes())?;
    for parameter in &params.com_parameters {
        transcript.append_serializable_element(b"parameter blinding base", &parameter.generator)?;
        transcript.append_serializable_element(b"parameter vector bases", &parameter.vec_gen)?;
    }
    transcript.append_serializable_element(b"canonical public ring", &params.vec_pk)?;
    transcript.append_message(b"message", params.message.as_bytes())?;
    Ok(transcript)
}

fn first_layer_challenges<F: PrimeField>(
    transcript: &mut ProofTranscript<F>,
) -> Result<(F, F, F), SigmaErrors> {
    let prefix = transcript.clone();
    let mut y_transcript = prefix.clone();
    let y = y_transcript.get_and_append_nonzero_challenge(b"challenge omega seed")?;
    let mut z_transcript = prefix.clone();
    let z = loop {
        let candidate = z_transcript.get_and_append_challenge(b"challenge z")?;
        if !candidate.is_zero() && !candidate.is_one() {
            break candidate;
        }
    };
    let mut lambda_transcript = prefix;
    let lambda = lambda_transcript.get_and_append_nonzero_challenge(b"challenge lambda")?;
    transcript.append_field_element(b"accepted omega seed", &y)?;
    transcript.append_field_element(b"accepted z", &z)?;
    transcript.append_field_element(b"accepted lambda", &lambda)?;
    Ok((y, z, lambda))
}

/// Uncompressed form of the inverse-constrained any-out-of-many proof.
/// This exposes the two length-N responses directly instead of
/// compressing them with an IPA.
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
        if supported_size == 0 || !supported_size.is_power_of_two() {
            return Err(SigmaErrors::InvalidParameters(
                "ring size must be a non-zero power of two".to_string(),
            ));
        }
        let com_params_1 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let com_params_2 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let key_params = PedersenCommitmentScheme::<C>::setup(rng, 1)?;
        let pk =
            PedersenCommitmentScheme::commit(&key_params, wit, &C::ScalarField::zero(), "as pk")?
                .into_affine();
        if pk.is_zero() {
            return Err(SigmaErrors::InvalidParameters(
                "secret key must produce a non-identity public key".to_string(),
            ));
        }
        let mut vec_pk = Vec::with_capacity(supported_size);
        while vec_pk.len() + 1 < supported_size {
            let candidate = C::Affine::rand(rng);
            if !candidate.is_zero() && candidate != pk && !vec_pk.contains(&candidate) {
                vec_pk.push(candidate);
            }
        }
        vec_pk.push(pk);
        let mut encoded_ring = vec_pk
            .into_iter()
            .map(|point| Ok((compressed_encoding::<C>(&point)?, point)))
            .collect::<Result<Vec<_>, SigmaErrors>>()?;
        encoded_ring.sort_by(|left, right| left.0.cmp(&right.0));
        let vec_pk = encoded_ring
            .into_iter()
            .map(|(_, point)| point)
            .collect::<Vec<_>>();
        validate_canonical_ring::<C>(&vec_pk)?;
        let vec_b = vec_pk
            .iter()
            .map(|point| {
                if point == &pk {
                    C::ScalarField::one()
                } else {
                    C::ScalarField::zero()
                }
            })
            .collect::<Vec<_>>();
        wit.extend(vec_b);
        Ok(RingSignatureParams {
            num_witness: wit.len(),
            num_pub_inputs: supported_size,
            com_parameters: vec![com_params_1, com_params_2, key_params],
            message: msg.clone(),
            vec_pk,
        })
    }

    fn prove<R: Rng>(
        rng: &mut R,
        params: &Self::PublicParams,
        wit: &Self::Witness,
    ) -> Result<Self::Proof, SigmaErrors> {
        let start = start_timer!(|| "running inverse-constrained linear prover...");
        let n = params.num_pub_inputs;
        if n == 0
            || !n.is_power_of_two()
            || params.vec_pk.len() != n
            || params.com_parameters.len() != 3
            || wit.len() < n
        {
            return Err(SigmaErrors::InvalidParameters(
                "invalid public parameters or witness length".to_string(),
            ));
        }
        validate_canonical_ring::<C>(&params.vec_pk)?;
        let param_g_u = &params.com_parameters[0];
        let param_h_v = &params.com_parameters[1];
        let param_key = &params.com_parameters[2];
        let vec_sk = wit[..wit.len() - n].to_vec();
        let vec_b0 = wit[wit.len() - n..].to_vec();
        if vec_b0
            .iter()
            .any(|&b_i| b_i != C::ScalarField::zero() && b_i != C::ScalarField::one())
        {
            return Err(SigmaErrors::InvalidProver(
                "selection vector must be binary".to_string(),
            ));
        }
        let vec_b1: Vec<C::ScalarField> = vec_b0
            .iter()
            .map(|&b_i| C::ScalarField::one() - b_i)
            .collect();
        let signer_count = vec_b0
            .iter()
            .fold(C::ScalarField::zero(), |acc, &b_i| acc + b_i);
        let xi = signer_count.inverse().ok_or_else(|| {
            SigmaErrors::InvalidProver(
                "selection vector must be non-empty (inverse constraint has no witness)"
                    .to_string(),
            )
        })?;
        if vec_b0.iter().filter(|&&b_i| b_i.is_one()).count() != vec_sk.len() {
            return Err(SigmaErrors::InvalidProver(
                "secret-key count does not match selected positions".to_string(),
            ));
        }

        let mut transcript = initialize_transcript::<C>(params)?;
        let alpha = C::ScalarField::rand(rng);
        let com_a = PedersenCommitmentScheme::commit(param_g_u, &vec_b0, &alpha, "A/b0")?
            + PedersenCommitmentScheme::commit(
                param_h_v,
                &vec_b1,
                &C::ScalarField::zero(),
                "A/b1",
            )?
            + param_key.generator.mul(xi);

        transcript.append_serializable_element(b"commitment A", &[com_a])?;
        let (y, z, lambda) = first_layer_challenges(&mut transcript)?;

        let omega = generate_powers(y, n);
        let ones = vec![C::ScalarField::one(); n];
        let z_ones = vec![z; n];
        let a0 = vec_add(&vec_b0, &scalar_product(&ones, &(-z)));
        let c0 = vec_add(&z_ones, &scalar_product(&vec_b1, &(-C::ScalarField::one())));
        let d0 = hadamard_product(&omega, &c0);
        let vec_r0: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let vec_r1: Vec<C::ScalarField> = (0..n).map(|_| C::ScalarField::rand(rng)).collect();
        let r_xi = C::ScalarField::rand(rng);
        let r_s = C::ScalarField::rand(rng);
        let beta = C::ScalarField::rand(rng);
        let tau1 = C::ScalarField::rand(rng);
        let tau2 = C::ScalarField::rand(rng);
        let r_sum = inner_product(&vec_r0, &ones);
        let omega_r1 = hadamard_product(&omega, &vec_r1);
        let t1 = inner_product(&vec_r0, &d0) - inner_product(&a0, &omega_r1)
            + lambda * (xi * r_sum + r_xi * signer_count);
        let t2 = -inner_product(&vec_r0, &omega_r1) + lambda * r_xi * r_sum;
        let delta = (z - z * z) * inner_product(&omega, &ones) + lambda;

        let com_s = PedersenCommitmentScheme::commit(param_g_u, &vec_r0, &beta, "S/r0")?
            + PedersenCommitmentScheme::commit(
                param_h_v,
                &vec_r1,
                &C::ScalarField::zero(),
                "S/r1",
            )?
            + param_key.generator.mul(r_xi);
        let com_e = C::msm(&params.vec_pk, &hadamard_product(&omega, &vec_r0)).unwrap()
            + PedersenCommitmentScheme::commit(
                param_key,
                &vec![-r_s],
                &C::ScalarField::zero(),
                "E",
            )?;
        let param_u1_v = PedersenParams {
            generator: param_g_u.generator,
            vec_gen: vec![param_h_v.generator.into_affine()],
        };
        let com_t1 = PedersenCommitmentScheme::commit(&param_u1_v, &vec![t1], &tau1, "T1")?;
        let com_t2 = PedersenCommitmentScheme::commit(&param_u1_v, &vec![t2], &tau2, "T2")?;

        transcript.append_serializable_element(
            b"commitments S,E,T1,T2",
            &[com_s, com_e, com_t1, com_t2],
        )?;
        let x = transcript.get_and_append_nonzero_challenge(b"challenge x")?;

        let ell = vec_add(&a0, &scalar_product(&vec_r0, &x));
        let r = hadamard_product(&omega, &vec_add(&c0, &scalar_product(&vec_r1, &(-x))));
        let hat_xi = xi + x * r_xi;
        let hat_t = delta + x * t1 + x * x * t2;
        let taux = x * tau1 + x * x * tau2;
        let mu = alpha + x * beta;
        let mut sk_index = 0;
        let mut f = C::ScalarField::zero();
        for i in 0..n {
            if vec_b0[i].is_one() {
                f += omega[i] * vec_sk[sk_index];
                sk_index += 1;
            }
        }
        f += x * r_s;

        end_timer!(start);
        Ok(LinearRingSignature {
            commitments: vec![com_a, com_s, com_e, com_t1, com_t2],
            openings: Openings {
                zeta: ell,
                eta: r,
                hat_t,
                taux,
                mu_1: mu,
                mu_2: hat_xi,
                fs: f,
            },
        })
    }

    fn verify(params: &Self::PublicParams, proof: &Self::Proof) -> Result<bool, SigmaErrors> {
        let start = start_timer!(|| "running inverse-constrained linear verifier...");
        let n = params.num_pub_inputs;
        if n == 0
            || !n.is_power_of_two()
            || params.vec_pk.len() != n
            || params.com_parameters.len() != 3
            || proof.commitments.len() != 5
            || proof.openings.zeta.len() != n
            || proof.openings.eta.len() != n
        {
            return Err(SigmaErrors::InvalidProof(
                "invalid parameters or linear proof shape".to_string(),
            ));
        }
        validate_canonical_ring::<C>(&params.vec_pk)?;
        let param_g_u = &params.com_parameters[0];
        let param_h_v = &params.com_parameters[1];
        let param_key = &params.com_parameters[2];
        let com_a = proof.commitments[0];
        let com_s = proof.commitments[1];
        let com_e = proof.commitments[2];
        let com_t1 = proof.commitments[3];
        let com_t2 = proof.commitments[4];
        let o = &proof.openings;

        let mut transcript = initialize_transcript::<C>(params)?;
        transcript.append_serializable_element(b"commitment A", &[com_a])?;
        let (y, z, lambda) = first_layer_challenges(&mut transcript)?;
        transcript.append_serializable_element(
            b"commitments S,E,T1,T2",
            &[com_s, com_e, com_t1, com_t2],
        )?;
        let x = transcript.get_and_append_nonzero_challenge(b"challenge x")?;

        let omega = generate_powers(y, n);
        let ones = vec![C::ScalarField::one(); n];
        let z_ones = vec![z; n];
        let delta = (z - z * z) * inner_product(&omega, &ones) + lambda;

        let v1_lhs = param_h_v.generator.mul(o.hat_t - delta) + param_g_u.generator.mul(o.taux);
        let v1_rhs = com_t1.mul(x) + com_t2.mul(x * x);
        if v1_lhs != v1_rhs {
            return Err(SigmaErrors::InvalidProof("V1 failed".to_string()));
        }

        let omega_inverse: Vec<C::ScalarField> = omega
            .iter()
            .map(|omega_i| omega_i.inverse().unwrap())
            .collect();
        let ell_plus_z = vec_add(&o.zeta, &z_ones);
        let z_minus_scaled_r = vec_add(
            &z_ones,
            &scalar_product(
                &hadamard_product(&omega_inverse, &o.eta),
                &(-C::ScalarField::one()),
            ),
        );
        let v2_lhs = com_a + com_s.mul(x);
        let v2_rhs = PedersenCommitmentScheme::commit(param_g_u, &ell_plus_z, &o.mu_1, "V2/g")?
            + PedersenCommitmentScheme::commit(
                param_h_v,
                &z_minus_scaled_r,
                &C::ScalarField::zero(),
                "V2/h",
            )?
            + param_key.generator.mul(o.mu_2);
        if v2_lhs != v2_rhs {
            return Err(SigmaErrors::InvalidProof("V2 failed".to_string()));
        }

        let v3_lhs = com_e.mul(x)
            + PedersenCommitmentScheme::commit(
                param_key,
                &vec![o.fs],
                &C::ScalarField::zero(),
                "V3/f",
            )?;
        let v3_rhs = C::msm(&params.vec_pk, &hadamard_product(&omega, &ell_plus_z)).unwrap();
        if v3_lhs != v3_rhs {
            return Err(SigmaErrors::InvalidProof("V3 failed".to_string()));
        }

        let n_scalar = C::ScalarField::from(n as u128);
        let v4_rhs = inner_product(&o.zeta, &o.eta)
            + lambda * o.mu_2 * (inner_product(&o.zeta, &ones) + z * n_scalar);
        if o.hat_t != v4_rhs {
            return Err(SigmaErrors::InvalidProof("V4 failed".to_string()));
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

    #[test]
    fn test_inverse_constrained_linear_signature() {
        let mut rng = ark_std::test_rng();
        let ring_size = 16;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        type Ring = RingSignatureScheme<Projective>;
        let message = String::from("Welcome to the world of Zero Knowledge!");
        let params = Ring::setup(&mut rng, &mut wit, &message, ring_size).unwrap();
        let proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        assert!(Ring::verify(&params, &proof).unwrap());
    }
}
