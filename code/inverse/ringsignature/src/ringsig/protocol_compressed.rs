use std::marker::PhantomData;
use std::ops::Mul;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{end_timer, rand::Rng, start_timer, One, UniformRand, Zero};

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
    let mut transcript = ProofTranscript::<C::ScalarField>::new(b"SEU-AMRS-v2");
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
    // Derive y, z and lambda from independent, domain-separated clones of the
    // same (ctx, A) prefix. This supports the structured rewinding used in the
    // proof: one challenge can change while the other two stay fixed.
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

/// Logarithmic any-out-of-many ring signature using the inverse non-zero constraint
/// The non-zero relation is `xi * inner_product(b, 1) = 1`.
/// The scalar witness `xi` replaces the old N-dimensional auxiliary-vector
/// construction. The two length-N response vectors are compressed by the IPA.
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

        let com_params_1 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let com_params_2 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        let key_params = PedersenCommitmentScheme::<C>::setup(rng, 1)?;

        let pk: C::Affine =
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
        let start = start_timer!(|| "running optimized ring signature prover...");
        let n = params.num_pub_inputs;
        if n == 0 || !n.is_power_of_two() || params.vec_pk.len() != n {
            return Err(SigmaErrors::InvalidParameters(
                "ring size must be a non-zero power of two and match the public-key vector"
                    .to_string(),
            ));
        }
        if params.com_parameters.len() != 3 || wit.len() < n {
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
        let vec_b1: Vec<C::ScalarField> = vec_b0
            .iter()
            .map(|&b_i| C::ScalarField::one() - b_i)
            .collect();

        if vec_b0
            .iter()
            .any(|&b_i| b_i != C::ScalarField::zero() && b_i != C::ScalarField::one())
        {
            return Err(SigmaErrors::InvalidProver(
                "selection vector must be binary".to_string(),
            ));
        }
        let signer_count = vec_b0
            .iter()
            .fold(C::ScalarField::zero(), |acc, &b_i| acc + b_i);
        let xi = signer_count.inverse().ok_or_else(|| {
            SigmaErrors::InvalidProver(
                "selection vector must be non-empty (inverse constraint has no witness)"
                    .to_string(),
            )
        })?;
        let selected_count = vec_b0
            .iter()
            .filter(|&&b_i| b_i == C::ScalarField::one())
            .count();
        if selected_count != vec_sk.len() {
            return Err(SigmaErrors::InvalidProver(
                "the number of secret keys must equal the Hamming weight of the selection vector"
                    .to_string(),
            ));
        }

        let mut transcript = initialize_transcript::<C>(params)?;

        // A = g^b0 h^b1 u2^xi u1^alpha.
        let alpha = C::ScalarField::rand(rng);
        let com_a = PedersenCommitmentScheme::commit(param_g_u, &vec_b0, &alpha, "A/b0")?
            + PedersenCommitmentScheme::commit(
                param_h_v,
                &vec_b1,
                &C::ScalarField::zero(),
                "A/b1",
            )?
            + param_key.generator.mul(xi);

        // Independent domain-separated challenges Hy, Hz and Hlambda share the
        // same (ctx, A) prefix. The power vector needs only the seed y.
        transcript.append_serializable_element(b"commitment A", &[com_a])?;
        let (y, z, lambda) = first_layer_challenges(&mut transcript)?;
        let omega = generate_powers(y, n);
        let ones = vec![C::ScalarField::one(); n];
        let z_ones = vec![z; n];
        let a0 = vec_add(&vec_b0, &scalar_product(&ones, &(-z)));
        let c0 = vec_add(&z_ones, &scalar_product(&vec_b1, &(-C::ScalarField::one())));
        let d0 = hadamard_product(&omega, &c0);

        // All masks are independently sampled. `vec![rand; n]` would repeat one
        // mask instead of providing independent coordinate masks.
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

        // S and E are transmitted separately. The folding challenge is sampled
        // only after both commitments and all outer responses are fixed.
        let com_s = PedersenCommitmentScheme::commit(param_g_u, &vec_r0, &beta, "S/r0")?
            + PedersenCommitmentScheme::commit(
                param_h_v,
                &vec_r1,
                &C::ScalarField::zero(),
                "S/r1",
            )?
            + param_key.generator.mul(r_xi);
        let omega_r0 = hadamard_product(&omega, &vec_r0);
        let com_e = C::msm(&params.vec_pk, &omega_r0).unwrap()
            + PedersenCommitmentScheme::commit(
                param_key,
                &vec![-r_s],
                &C::ScalarField::zero(),
                "E",
            )?;
        // T_j = v^t_j u1^tau_j.
        let param_u1_v = PedersenParams {
            generator: param_g_u.generator,
            vec_gen: vec![param_h_v.generator.into_affine()],
        };
        let com_t1 = PedersenCommitmentScheme::commit(&param_u1_v, &vec![t1], &tau1, "T1")?;
        let com_t2 = PedersenCommitmentScheme::commit(&param_u1_v, &vec![t2], &tau2, "T2")?;

        transcript
            .append_serializable_element(b"outer commitments", &[com_s, com_e, com_t1, com_t2])?;
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
            if vec_b0[i] == C::ScalarField::one() {
                f += omega[i] * vec_sk[sk_index];
                sk_index += 1;
            }
        }
        f += x * r_s;

        transcript
            .append_serializable_element(b"outer responses", &[hat_xi, f, hat_t, taux, mu])?;
        let kappa = transcript.get_and_append_nonzero_challenge(b"challenge kappa")?;
        let ipa_binding = transcript.get_and_append_challenge(b"IPA transcript binding")?;

        // Derived bases fold V2, V3 and the inverse-aware V4 into one IPA.
        let omega_inverse: Vec<C::ScalarField> = omega
            .iter()
            .map(|omega_i| omega_i.inverse().unwrap())
            .collect();
        let mut vec_g_bar = Vec::with_capacity(n);
        let inverse_constraint_base = param_h_v.generator.mul(lambda * hat_xi);
        for i in 0..n {
            vec_g_bar.push(
                (param_g_u.vec_gen[i].into_group()
                    + params.vec_pk[i].mul(kappa * omega[i])
                    + inverse_constraint_base)
                    .into_affine(),
            );
        }
        let ipa_param = InnerProductParam {
            factors_G: vec![C::ScalarField::one(); n],
            factors_H: omega_inverse.iter().map(|&value| -value).collect(),
            u: param_h_v.generator.into_affine(),
            vec_G: vec_g_bar,
            vec_H: param_h_v.vec_gen.clone(),
        };
        let compression_proof =
            InnerProductProtocol::<C>::prove_with_context(&ipa_param, ell, r, ipa_binding)?;

        end_timer!(start);
        Ok(LogarithmicRingSignature {
            commitments: vec![com_a, com_s, com_e, com_t1, com_t2],
            openings: Openings {
                // The terminal IPA scalars already live in compression_proof.
                zeta: Vec::new(),
                eta: Vec::new(),
                hat_t,
                taux,
                mu_1: mu,
                mu_2: hat_xi,
                fs: f,
            },
            compression_proof,
        })
    }

    fn verify(params: &Self::PublicParams, proof: &Self::Proof) -> Result<bool, SigmaErrors> {
        let start = start_timer!(|| "running optimized ring signature verifier...");
        let n = params.num_pub_inputs;
        if n == 0
            || !n.is_power_of_two()
            || params.vec_pk.len() != n
            || params.com_parameters.len() != 3
            || proof.commitments.len() != 5
        {
            return Err(SigmaErrors::InvalidProof(
                "invalid ring parameters or optimized proof shape".to_string(),
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
        let openings = &proof.openings;

        let mut transcript = initialize_transcript::<C>(params)?;
        transcript.append_serializable_element(b"commitment A", &[com_a])?;
        let (y, z, lambda) = first_layer_challenges(&mut transcript)?;
        transcript
            .append_serializable_element(b"outer commitments", &[com_s, com_e, com_t1, com_t2])?;
        let x = transcript.get_and_append_nonzero_challenge(b"challenge x")?;
        transcript.append_serializable_element(
            b"outer responses",
            &[
                openings.mu_2,
                openings.fs,
                openings.hat_t,
                openings.taux,
                openings.mu_1,
            ],
        )?;
        let kappa = transcript.get_and_append_nonzero_challenge(b"challenge kappa")?;
        let ipa_binding = transcript.get_and_append_challenge(b"IPA transcript binding")?;

        let omega = generate_powers(y, n);
        let ones = vec![C::ScalarField::one(); n];
        let delta = (z - z * z) * inner_product(&omega, &ones) + lambda;

        // V1: v^(hat_t-delta) u1^taux = T1^x T2^(x^2).
        let polynomial_lhs = param_h_v.generator.mul(openings.hat_t - delta)
            + param_g_u.generator.mul(openings.taux);
        let polynomial_rhs = com_t1.mul(x) + com_t2.mul(x * x);
        if polynomial_lhs != polynomial_rhs {
            return Err(SigmaErrors::InvalidProof(
                "inverse-aware constraint polynomial check failed".to_string(),
            ));
        }

        let omega_inverse: Vec<C::ScalarField> = omega
            .iter()
            .map(|omega_i| omega_i.inverse().unwrap())
            .collect();
        let mut vec_g_bar = Vec::with_capacity(n);
        let inverse_constraint_base = param_h_v.generator.mul(lambda * openings.mu_2);
        for i in 0..n {
            vec_g_bar.push(
                (param_g_u.vec_gen[i].into_group()
                    + params.vec_pk[i].mul(kappa * omega[i])
                    + inverse_constraint_base)
                    .into_affine(),
            );
        }
        let ipa_param = InnerProductParam {
            factors_G: vec![C::ScalarField::one(); n],
            factors_H: omega_inverse.iter().map(|&value| -value).collect(),
            u: param_h_v.generator.into_affine(),
            vec_G: vec_g_bar,
            vec_H: param_h_v.vec_gen.clone(),
        };

        // Consistency commitment P_cons^(0), in additive notation.
        let neg_z = vec![-z; n];
        let neg_kappa_z_omega = scalar_product(&omega, &(-kappa * z));
        let n_scalar = C::ScalarField::from(n as u128);
        let target = com_a
            + com_s.mul(x)
            + com_e.mul(kappa * x)
            + C::msm(&param_g_u.vec_gen, &neg_z).unwrap()
            + C::msm(&param_h_v.vec_gen, &neg_z).unwrap()
            + param_key.vec_gen[0].mul(kappa * openings.fs)
            + C::msm(&params.vec_pk, &neg_kappa_z_omega).unwrap()
            + param_key.generator.mul(-openings.mu_2)
            + param_g_u.generator.mul(-openings.mu_1)
            + param_h_v
                .generator
                .mul(openings.hat_t - lambda * z * n_scalar * openings.mu_2);

        InnerProductProtocol::<C>::verify_with_context(
            n,
            target,
            &ipa_param,
            &proof.compression_proof,
            ipa_binding,
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

    #[test]
    fn test_inverse_constrained_ring_signature() {
        let mut rng = ark_std::test_rng();
        let ring_size = 16;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        type Ring = RingSignatureScheme<Projective>;
        let message = String::from("Welcome to the world of Zero Knowledge!");
        let ring_params = Ring::setup(&mut rng, &mut wit, &message, ring_size).unwrap();
        let proof = Ring::prove(&mut rng, &ring_params, &wit).unwrap();
        assert_eq!(proof.commitments.len(), 5);
        assert_eq!(estimate_signature_size_bytes(&proof), 653);
        assert!(Ring::verify(&ring_params, &proof).unwrap());
    }

    #[test]
    fn rejects_empty_selection_vector() {
        let mut rng = ark_std::test_rng();
        let ring_size = 8;
        let com_params_1 =
            PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap();
        let com_params_2 =
            PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap();
        let key_params = PedersenCommitmentScheme::<Projective>::setup(&mut rng, 1).unwrap();
        let params = RingSignatureParams {
            num_witness: ring_size,
            num_pub_inputs: ring_size,
            com_parameters: vec![com_params_1, com_params_2, key_params],
            message: "empty selection".to_string(),
            vec_pk: vec![Projective::rand(&mut rng).into_affine(); ring_size],
        };
        let wit = vec![Fr::zero(); ring_size];
        type Ring = RingSignatureScheme<Projective>;
        assert!(Ring::prove(&mut rng, &params, &wit).is_err());
    }

    #[test]
    fn test_multiple_hidden_signers() {
        let mut rng = ark_std::test_rng();
        let ring_size = 16;
        let signer_indices = [1usize, 5, 11];
        let com_params_1 =
            PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap();
        let com_params_2 =
            PedersenCommitmentScheme::<Projective>::setup(&mut rng, ring_size).unwrap();
        let key_params = PedersenCommitmentScheme::<Projective>::setup(&mut rng, 1).unwrap();
        let mut ring_entries = (0..ring_size)
            .map(|_| (Projective::rand(&mut rng).into_affine(), None))
            .collect::<Vec<_>>();
        for &i in &signer_indices {
            let sk = Fr::rand(&mut rng);
            let pk = PedersenCommitmentScheme::commit(&key_params, &vec![sk], &Fr::zero(), "as pk")
                .unwrap()
                .into_affine();
            ring_entries[i] = (pk, Some(sk));
        }
        let mut ring_entries = ring_entries
            .into_iter()
            .map(|(point, secret)| {
                let mut encoding = Vec::new();
                point.serialize_compressed(&mut encoding).unwrap();
                (encoding, point, secret)
            })
            .collect::<Vec<_>>();
        ring_entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut vec_pk = Vec::with_capacity(ring_size);
        let mut vec_b = Vec::with_capacity(ring_size);
        let mut vec_sk = Vec::new();
        for (_, point, secret) in ring_entries {
            vec_pk.push(point);
            if let Some(secret) = secret {
                vec_b.push(Fr::one());
                vec_sk.push(secret);
            } else {
                vec_b.push(Fr::zero());
            }
        }
        let params = RingSignatureParams {
            num_witness: vec_sk.len() + ring_size,
            num_pub_inputs: ring_size,
            com_parameters: vec![com_params_1, com_params_2, key_params],
            message: "three hidden signers".to_string(),
            vec_pk,
        };
        let mut wit = vec_sk;
        wit.extend(vec_b);
        type Ring = RingSignatureScheme<Projective>;
        let proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        assert!(Ring::verify(&params, &proof).unwrap());
    }

    #[test]
    fn rejects_tampered_inverse_response() {
        let mut rng = ark_std::test_rng();
        let ring_size = 8;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        type Ring = RingSignatureScheme<Projective>;
        let params =
            Ring::setup(&mut rng, &mut wit, &"tamper test".to_string(), ring_size).unwrap();
        let mut proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        proof.openings.mu_2 += Fr::one();
        assert!(Ring::verify(&params, &proof).is_err());
    }

    #[test]
    fn rejects_tampered_key_binding_commitment() {
        let mut rng = ark_std::test_rng();
        let ring_size = 8;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        type Ring = RingSignatureScheme<Projective>;
        let params = Ring::setup(
            &mut rng,
            &mut wit,
            &"folding challenge test".to_string(),
            ring_size,
        )
        .unwrap();
        let mut proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        proof.commitments[2] += Projective::rand(&mut rng);
        assert!(Ring::verify(&params, &proof).is_err());
    }

    #[test]
    fn rejects_changed_message_or_parameters() {
        let mut rng = ark_std::test_rng();
        let ring_size = 8;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        type Ring = RingSignatureScheme<Projective>;
        let params = Ring::setup(
            &mut rng,
            &mut wit,
            &"context binding test".to_string(),
            ring_size,
        )
        .unwrap();
        let proof = Ring::prove(&mut rng, &params, &wit).unwrap();

        let mut changed_message = params.clone();
        changed_message.message.push('!');
        assert!(Ring::verify(&changed_message, &proof).is_err());

        let mut changed_parameters = params.clone();
        changed_parameters.com_parameters[0].generator += Projective::rand(&mut rng);
        assert!(Ring::verify(&changed_parameters, &proof).is_err());
    }

    #[test]
    fn rejects_noncanonical_ring_order() {
        let mut rng = ark_std::test_rng();
        let ring_size = 8;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        type Ring = RingSignatureScheme<Projective>;
        let params = Ring::setup(
            &mut rng,
            &mut wit,
            &"ring order test".to_string(),
            ring_size,
        )
        .unwrap();
        let proof = Ring::prove(&mut rng, &params, &wit).unwrap();
        let mut noncanonical = params.clone();
        noncanonical.vec_pk.swap(0, 1);
        assert!(Ring::verify(&noncanonical, &proof).is_err());
    }

    #[test]
    #[ignore]
    fn benchmark_large_ring_sizes() {
        let ring_sizes = [128usize, 256, 512, 1024];
        type Ring = RingSignatureScheme<Projective>;

        println!();
        println!("| Ring size N | Sign time (ms) | Verify time (ms) | Signature size (bytes, estimated) |");
        println!("|---:|---:|---:|---:|");

        for ring_size in ring_sizes {
            let mut rng = ark_std::test_rng();
            let sk = Fr::rand(&mut rng);
            let mut wit = vec![sk];
            let message = format!("Large ring benchmark N={}", ring_size);
            let ring_params = Ring::setup(&mut rng, &mut wit, &message, ring_size).unwrap();
            let start_sign = Instant::now();
            let proof = Ring::prove(&mut rng, &ring_params, &wit).unwrap();
            let sign_time_ms = start_sign.elapsed().as_secs_f64() * 1000.0;
            let start_verify = Instant::now();
            assert!(Ring::verify(&ring_params, &proof).unwrap());
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
        let outer_group_elements = proof.commitments.len();
        let ipa_group_elements =
            proof.compression_proof.vec_L.len() + proof.compression_proof.vec_R.len();
        let outer_scalars = 5;
        let ipa_terminal_scalars = 2;
        (outer_group_elements + ipa_group_elements) * COMPRESSED_POINT_BYTES
            + (outer_scalars + ipa_terminal_scalars) * SCALAR_BYTES
    }
}
