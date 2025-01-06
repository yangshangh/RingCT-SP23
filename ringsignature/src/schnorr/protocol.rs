use ark_ec::CurveGroup;
use ark_std::{end_timer, rand::Rng, start_timer, UniformRand};
use sha256::digest;
use std::{fmt::Debug, io::Write, marker::PhantomData};

use crate::commitment::CommitmentScheme;
use crate::errors::SigmaErrors;
use crate::schnorr::structs::{SchnorrParams, SchnorrProof};
use crate::sigma::{transcript::ProofTranscript, SigmaProtocol};

// todo: turn it into a signature scheme

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchnorrProtocol<C, COM>
where
    C: CurveGroup,
    COM: CommitmentScheme<C>,
{
    phantom1: PhantomData<C>,
    phantom2: PhantomData<COM>,
}

/// Implement sigma protocol by:
/// write the protocol step by step
/// calling the commitment to generate elements
/// calling transcript for appending message and generate challenge
impl<C, COM> SigmaProtocol<C, COM> for SchnorrProtocol<C, COM>
where
    C: CurveGroup,
    COM:
        CommitmentScheme<C, Message = Vec<C::ScalarField>, Random = C::ScalarField, Commitment = C>,
{
    /// public parameters
    type PublicParams = SchnorrParams<C, COM>;
    /// Witness
    type Witness = Vec<C::ScalarField>;
    // challenge
    type Challenge = Vec<C::ScalarField>;
    /// proof
    type Proof = SchnorrProof<C, COM>;

    /// Setup algorithm with
    /// Inputs:
    /// - rng: RngCore palys a role as the random tape
    /// - max: the maximum length of the witness supported
    /// Outputs:
    /// - Params<C>: Pedersen commitment parameter as a tuple (h, generators)
    ///
    fn setup<R: Rng>(
        rng: &mut R,
        witness: &Self::Witness,
        msg: &String,
        supported_size: usize,
    ) -> Result<Self::PublicParams, SigmaErrors> {
        let commitment_params = COM::setup(rng, supported_size)?;
        let schnorr_params = SchnorrParams {
            num_witness: witness.len(),
            num_pub_inputs: 1,
            public_parameters: commitment_params,
            message: msg.clone(),
        };
        Ok(schnorr_params)
    }

    /// Prover algorithm
    /// Inputs:
    /// - params: commitment parameter
    /// - pub_inputs: the commitment vector for witness
    /// - witness: the witness vector
    fn prove<R: Rng>(
        rng: &mut R,
        params: &Self::PublicParams,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, SigmaErrors> {
        // initialization
        let start = start_timer!(|| "running sigma protocol prove algorithm...");
        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"SchnorrSignature");

        // Compute the witness commitment
        let r_wit = C::ScalarField::rand(rng);
        let com_wit = COM::commit(&params.public_parameters, witness, &r_wit)?;
        transcript.append_serializable_element(b"witness commitment", &com_wit)?;

        // sample the masking vector and compute its commitment
        let masking = vec![C::ScalarField::rand(rng); params.num_witness];
        let r_mask = C::ScalarField::rand(rng);
        let com_mask = COM::commit(&params.public_parameters, &masking, &r_mask)?;
        transcript.append_serializable_element(b"masking commitment", &com_mask)?;

        // append the message digest to the transcript
        let h = digest(&params.message);
        let mut h_msg: &mut [u8] = &mut [0; 32];
        h_msg.write(h.as_bytes()).unwrap();
        transcript.append_message(b"message digest", &h_msg)?;

        // generate the challenge c
        let c = transcript.get_and_append_challenge(b"challenge")?;

        // compute opening vector
        let z: Vec<C::ScalarField> = witness
            .iter()
            .zip(masking.iter())
            .map(|(wi, mi)| c * wi + mi)
            .collect();
        let z_r = c * r_wit + r_mask;
        let mut open = z.clone();
        open.push(z_r);

        // proving ends
        end_timer!(start);

        Ok(SchnorrProof {
            commitments: vec![com_wit, com_mask],
            opening: open,
            challenge: vec![c],
            digest: h.clone(),
        })
    }

    fn verify(params: &Self::PublicParams, proof: &Self::Proof) -> Result<bool, SigmaErrors> {
        // initialization
        let start = start_timer!(|| "running sigma protocol verify algorithm...");
        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"SchnorrSignature");

        // append commitments and messages
        transcript.append_serializable_element(b"witness commitment", &proof.commitments[0])?;
        transcript.append_serializable_element(b"masking commitment", &proof.commitments[1])?;

        // append the message digest to the transcript
        let h = digest(&params.message);
        assert_eq!(h, proof.digest);
        let mut h_msg: &mut [u8] = &mut [0; 32];
        h_msg.write(h.as_bytes()).unwrap();
        transcript.append_message(b"message digest", &h_msg)?;

        // generate the challenge
        let c = transcript.get_and_append_challenge(b"challenge")?;
        if c != proof.challenge[0] {
            return Err(SigmaErrors::InvalidProof(
                "invalid challenge value".to_string(),
            ));
        }

        // check the validity of opening
        let lhs = proof.commitments[0].mul(c) + proof.commitments[1].clone();

        let z = proof.opening[0..params.num_witness].to_vec();
        let zr = proof.opening[params.num_witness];
        let rhs = COM::commit(&params.public_parameters, &z, &zr)?;
        if lhs != rhs {
            return Err(SigmaErrors::InvalidProof("verification failed".to_string()));
        }

        // verifying ends
        end_timer!(start);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::pedersen::PedersenCommitmentScheme;
    use ark_secp256k1::{Fr, Projective};
    use ark_std::UniformRand;

    #[test]
    fn test_sigma() {
        let mut rng = ark_std::test_rng();
        let supported_size = 10;
        let wit = vec![Fr::rand(&mut rng); supported_size];

        type Schnorr = SchnorrProtocol<Projective, PedersenCommitmentScheme<Projective>>;
        // setup algorithm
        let message = String::from("Welcome to the world of Zero Knowledge!");
        let params = Schnorr::setup(&mut rng, &wit, &message, supported_size).unwrap();
        // prove algorithm
        let proof = Schnorr::prove(&mut rng, &params, &wit).unwrap();
        // verify algorithm
        let result = Schnorr::verify(&params, &proof).unwrap();

        assert_eq!(result, true);
    }
}
