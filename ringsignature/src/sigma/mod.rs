use crate::commitment::CommitmentScheme;
use crate::errors::SigmaErrors;
use ark_ec::CurveGroup;
use ark_std::rand::Rng;

pub mod transcript;

pub trait SigmaProtocol<C, COM>
where
    C: CurveGroup,
    COM: CommitmentScheme<C>,
{
    /// public parameters
    type PublicParams;
    /// witness vector
    type Witness;
    // challenge
    type Challenge;
    /// opening
    type Proof;

    /// Setup algorithm does the following work
    /// 1. generates the public parameter with given size
    /// 2. commit the witness based on the public params
    fn setup<R: Rng>(
        rng: &mut R,
        wit: &Self::Witness,
        msg: &String,
        supported_size: usize,
    ) -> Result<Self::PublicParams, SigmaErrors>;

    /// Prove algorithm generates the proof with inputs
    /// - PublicParams
    /// - witness
    /// - masking
    fn prove<R: Rng>(
        rng: &mut R,
        params: &Self::PublicParams,
        wit: &Self::Witness,
    ) -> Result<Self::Proof, SigmaErrors>;

    /// Verify algorithm checks the validity of the proof
    /// outputs either 1 (pass) or 0 (fail)
    fn verify(params: &Self::PublicParams, proof: &Self::Proof) -> Result<bool, SigmaErrors>;
}
