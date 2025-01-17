pub mod pedersen;
pub mod structs;

use crate::errors::CommitmentErrors;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use std::fmt::Debug;

/// This trait defines APIs for (vector) commitment schemes with hiding property.
pub trait CommitmentScheme<C: CurveGroup> {
    /// public parameters
    type PublicParams: Clone + Debug;
    /// message
    type Message: Clone + Debug + PartialEq + Eq;
    /// random
    type Random: Clone + Debug + Eq;
    /// commitment
    type Commitment: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + Eq;
    /// opening
    type Opening: Clone + Debug + PartialEq + Eq;

    /// Setup algorithm generates the public parameter with given size
    fn setup<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::PublicParams, CommitmentErrors>;

    /// Commit algorithm generates the (hiding) commitment with inputs
    /// - PublicParams
    /// - message
    /// - random
    fn commit(
        params: &Self::PublicParams,
        m: &Self::Message,
        r: &Self::Random,
        info: &str,
    ) -> Result<Self::Commitment, CommitmentErrors>;

    /// Open algorithm outputs the corresponding message and random
    /// for the given commitment
    fn open(
        m: &Self::Message,
        r: &Self::Random,
    ) -> Result<Self::Opening, CommitmentErrors>;

    /// Verify algorithm checks the validity of the opening
    /// outputs either 1 (pass) or 0 (fail)
    fn verify(
        params: &Self::PublicParams,
        cm: &Self::Commitment,
        open: &Self::Opening,
    ) -> Result<bool, CommitmentErrors>;
}
