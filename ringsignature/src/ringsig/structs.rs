use crate::commitment::{PedersenParams};
use ark_ec::CurveGroup;
use bulletproofs::structs::InnerProductProof;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Openings<C: CurveGroup> {
    pub zeta: Vec<C::ScalarField>,
    pub eta: Vec<C::ScalarField>,
    pub hat_t: C::ScalarField,
    pub taux: C::ScalarField,
    pub mu: C::ScalarField,
    pub fs: C::ScalarField,
}

// Linear-size Ring Signature tuple without Bulletproofs Compression
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinearRingSignature<C: CurveGroup> {
    // the intermediate commitment vector generated along the proving
    pub commitments: Vec<C>,
    // the opening vector generated along the proving
    pub openings: Openings<C>,
    // the challenge vector generated by merlin transcript
    pub challenges: Vec<C::ScalarField>,
    // the digest of the message
    pub digest: String,
}

// Logarithmic-size Ring Signature tuple with Bulletproofs Compression
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LogarithmicRingSignature<C: CurveGroup> {
    // the intermediate commitment vector generated along the proving
    pub commitments: Vec<C>,
    // the opening vector generated along the proving
    pub openings: Openings<C>,
    // the challenge vector generated by merlin transcript
    pub challenges: Vec<C::ScalarField>,
    // the Bulletproofs compression proof
    pub compression_proof: InnerProductProof<C>,
    // the digest of the message
    pub digest: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RingSignatureParams<C: CurveGroup> {
    // the number of witness elements
    pub num_witness: usize,
    // the number of public inputs (commitments)
    pub num_pub_inputs: usize,
    // the generators for commitments
    pub com_parameters: Vec<PedersenParams<C>>,
    // the signed message
    pub message: String,
    // public key vector
    pub vec_pk: Vec<C::Affine>,
}