use ark_ec::CurveGroup;
use ark_std::{end_timer, rand::Rng, start_timer, UniformRand};
use sha256::digest;
use std::{fmt::Debug, io::Write, marker::PhantomData};
use crate::commitment::CommitmentScheme;
use crate::errors::SigmaErrors;
use crate::schnorr::structs::{SchnorrParams, SchnorrProof};
use crate::sigma::{transcript::ProofTranscript, SigmaProtocol};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchnorrProtocol<C, COM>
where
    C: CurveGroup,
    COM: CommitmentScheme<C>,
{
    phantom1: PhantomData<C>,
    phantom2: PhantomData<COM>,
}

/// Implement a sigma protocol as a schnorr protocol, including 3-move:
/// Relation: P knows a wit to com(wit)
/// P->V: commitment com(mask)
/// V->P: challenge c
/// P->V: openings z = wit + c*mask, z_r = r_wit + c*r_mask
impl<C, COM> SigmaProtocol<C, COM> for SchnorrProtocol<C, COM>
where
    C: CurveGroup,
    COM:
        CommitmentScheme<C, Message = Vec<C::ScalarField>, Random = C::ScalarField, Commitment = C>,
{
    /// public parameters
    type PublicParams = SchnorrParams<C, COM>;
    /// witness
    type Witness = Vec<C::ScalarField>;
    /// witness commitments
    type Commitments = Vec<C>;
    /// challenge
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
        wit: &mut Self::Witness,
        msg: &String,
        supported_size: usize,
    ) -> Result<Self::PublicParams, SigmaErrors> {
        let com_params = COM::setup(rng, supported_size)?;
        // compute the witness commitment
        let r_wit = C::ScalarField::rand(rng);
        let com_wit = vec![COM::commit(&com_params, wit, &r_wit, "on witness")?];
        wit.push(r_wit);
        // outputs
        let schnorr_params = SchnorrParams {
            com_witness: com_wit,
            num_witness: wit.len(),
            num_pub_inputs: 1,
            com_parameters: com_params,
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
        transcript.append_serializable_element(b"witness commitment", &params.com_witness[0])?;

        // parse the witness vector into wit and r_wit
        let wit = witness[..witness.len()-1].to_vec();
        let r_wit = witness[witness.len()-1];

        // sample the masking vector and compute its commitment
        let mask = vec![C::ScalarField::rand(rng); params.num_witness-1];
        let r_mask = C::ScalarField::rand(rng);
        let com_mask = COM::commit(&params.com_parameters, &mask, &r_mask, "on masking")?;
        transcript.append_serializable_element(b"masking commitment", &com_mask)?;

        // append the message digest to the transcript
        let h = digest(&params.message);
        let mut h_msg: &mut [u8] = &mut [0; 32];
        h_msg.write(h.as_bytes()).unwrap();
        transcript.append_message(b"message digest", &h_msg)?;

        // generate the challenge c
        let c = transcript.get_and_append_challenge(b"challenge")?;

        // compute opening vector
        let z: Vec<C::ScalarField> = wit
            .iter()
            .zip(mask.iter())
            .map(|(wi, mi)| c * wi + mi)
            .collect();
        let z_r = c * r_wit + r_mask;
        let mut open = z.clone();
        open.push(z_r);

        // proving ends
        end_timer!(start);

        Ok(SchnorrProof {
            commitments: vec![com_mask],
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
        transcript.append_serializable_element(b"witness commitment", &params.com_witness[0])?;
        transcript.append_serializable_element(b"masking commitment", &proof.commitments[0])?;

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
        let lhs = params.com_witness[0].mul(c) + proof.commitments[0].clone();

        let z = proof.opening[0..params.num_witness-1].to_vec();
        let zr = proof.opening[params.num_witness-1];
        let rhs = COM::commit(&params.com_parameters, &z, &zr, "on opening")?;
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
    fn test_schnorr() {
        let mut rng = ark_std::test_rng();
        let supported_size = 10;
        let mut wit = vec![Fr::rand(&mut rng); supported_size];

        type Schnorr = SchnorrProtocol<Projective, PedersenCommitmentScheme<Projective>>;
        // setup algorithm
        let message = String::from("Welcome to the world of Zero Knowledge!");
        let params = Schnorr::setup(&mut rng, &mut wit, &message, supported_size).unwrap();
        // prove algorithm
        let proof = Schnorr::prove(&mut rng, &params, &wit).unwrap();
        // verify algorithm
        let result = Schnorr::verify(&params, &proof).unwrap();

        assert_eq!(result, true);
    }
}
