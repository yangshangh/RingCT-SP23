use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_std::{end_timer, rand::Rng, start_timer, UniformRand};
use ark_std::iterable::Iterable;

use crate::commitment::CommitmentScheme;
use crate::ringsig::structs::{RingSignature, RingSignatureParams};
use crate::sigma::{transcript::ProofTranscript, SigmaProtocol};
use crate::SigmaErrors;
use crate::utils::vec::shuffle;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingSignatureScheme<C, COM>
where
    C: CurveGroup,
    COM: CommitmentScheme<C>,
{
    phantom1: PhantomData<C>,
    phantom2: PhantomData<COM>,
}

/// Implement a sigma protocol as a ring signature scheme, including 3-move:
/// Relation: P knows a sk to a pk among the vector vec_pk
/// Formalized Relation: P knows a sk satisfying <vec_pk, vec_b> = com(sk)
/// P->V: commitment com(mask)
/// V->P: challenge c
/// P->V: openings z = wit + c*mask, z_r = r_wit + c*r_mask
impl<C, COM> SigmaProtocol<C, COM> for RingSignatureScheme<C, COM>
where
    C: CurveGroup,
    COM:
    CommitmentScheme<C, Message = Vec<C::ScalarField>, Random = C::ScalarField, Commitment = C>,
{
    /// public parameters
    type PublicParams = RingSignatureParams<C, COM>;
    /// witness
    type Witness = Vec<C::ScalarField>;
    /// witness commitments
    type Commitments = Vec<C::Affine>;
    // challenge
    type Challenge = Vec<C::ScalarField>;
    /// proof
    type Proof = RingSignature<C, COM>;

    fn setup<R: Rng>(
        rng: &mut R,
        wit: &mut Self::Witness, // secret key
        msg: &String,
        supported_size: usize, // ring size
    ) -> Result<Self::PublicParams, SigmaErrors> {
        // generate commitment scheme parameters (vec_g, h)
        let com_params = COM::setup(rng, supported_size)?;
        // generate public key parameters (g)
        let key_params = COM::setup(rng, 1)?;

        // generate pk vectors
        let pk:C::Affine = COM::commit(key_params, wit, None).into_affine();
        let mut vec_pk = vec![C::Affine::rand(rng); supported_size-1];
        // add pk to the vector and shuffle it
        vec_pk.push(pk);
        let vec_b = shuffle(&mut vec_pk, pk);
        wit.extend(vec_b);

        Ok(RingSignatureParams {
            num_witness: wit.len(),
            num_pub_inputs: supported_size,
            com_parameters: com_params,
            message: msg.clone(),
            vec_pk,
        })
    }

    fn prove<R: Rng>(
        rng: &mut R,
        params: &Self::PublicParams,
        wit: &Self::Witness,
    ) -> Result<Self::Proof, SigmaErrors> {

    }

    fn verify(
        params: &Self::PublicParams,
        proof: &Self::Proof
    ) -> Result<bool, SigmaErrors> {

    }
}

pub fn sign<R: Rng, C: CurveGroup, COM: CommitmentScheme<C>>(
    ring_size: usize,
    rng: &mut R,
    msg: &String,
) {
    let sk = C::ScalarField::rand(rng);
    let mut wit = vec![sk];
    let ring_params = RingSignatureScheme::setup(rng, &mut wit, msg, ring_size).unwrap();

}