use ark_ec::CurveGroup;
use ark_std::{end_timer, marker::PhantomData, rand::Rng, start_timer, UniformRand};

use std::fmt::Debug;

use crate::commitment::{
    structs::{PedersenOpening, PedersenParams},
    CommitmentScheme,
};
use crate::CommitmentErrors;

// Pedersen (Vector) Commitment
#[derive(Clone, Debug)]
pub struct PedersenCommitmentScheme<C: CurveGroup> {
    phantom: PhantomData<C>,
}

impl<C: CurveGroup> CommitmentScheme<C> for PedersenCommitmentScheme<C> {
    // Parameters
    type PublicParams = PedersenParams<C>;
    // witnesses including message vector and random
    type Message = Vec<C::ScalarField>;
    type Random = C::ScalarField;
    // commitment and opening
    type Commitment = C;
    type Opening = PedersenOpening<C>;

    /// Setup algorithm generates public parameters for Pedersen Commitment includes
    /// - h: a generator
    /// - vec_g: a vector of generators in length of supported_size
    fn setup<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::PublicParams, CommitmentErrors> {
        let h_scalar = C::ScalarField::rand(rng);
        let g = C::generator();
        let generators = vec![C::Affine::rand(rng); supported_size];
        let pp = Self::PublicParams {
            h: g.mul(h_scalar),
            vec_g: generators,
        };
        Ok(pp)
    }

    /// Commit algorithm takes inputs as
    /// - PublicParams
    /// - m: message vector
    /// - r: random element for hiding
    /// then outputs
    /// - cm: a pedersen vector commitment
    fn commit(
        params: &Self::PublicParams,
        m: &Self::Message,
        r: &Self::Random,
    ) -> Result<Self::Commitment, CommitmentErrors> {
        let start = start_timer!(|| "generating pedersen commitment...");
        let params = params;
        if m.len() != params.vec_g.len() {
            return Err(CommitmentErrors::InvalidParameters(
                "message length should equal to the generator length".to_string(),
            ));
        }
        let msm = C::msm(&params.vec_g, m).unwrap();

        let cm = params.h.mul(r) + msm;
        end_timer!(start);
        Ok(cm)
    }

    /// Open algorithm outputs the following as the opening of commitment
    /// - m: message vector
    /// - r: random element for hiding
    fn open(m: &Self::Message, r: &Self::Random) -> Result<Self::Opening, CommitmentErrors> {
        // TODO: maybe we can convert m, r in Vec<usize> to Vec<F> here?
        Ok(Self::Opening {
            message: m.clone(),
            random: r.clone(),
        })
    }

    /// Verify algorithm takes inputs as
    /// - PublicParams
    /// - cm: commitment
    /// - open: opening includes m and r
    /// then outputs
    /// - cm: a pedersen vector commitment
    fn verify(
        params: &Self::PublicParams,
        cm: &Self::Commitment,
        open: &Self::Opening,
    ) -> Result<bool, CommitmentErrors> {
        let start = start_timer!(|| "checking pedersen commitment...");
        let params = params;
        let msm = C::msm(&params.vec_g, &open.message).unwrap();
        let cm_prime = params.h.mul(&open.random) + msm;
        end_timer!(start);
        Ok(&cm_prime == cm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::vec::convert;
    use ark_bls12_381::{Fr as G1Fr, G1Projective};
    use ark_secp256k1::{Fr, Projective};
    use test::Bencher;

    #[test]
    fn test_pedersen() {
        let mut rng = ark_std::test_rng();
        let supported_size = 10;
        let params =
            PedersenCommitmentScheme::<Projective>::setup(&mut rng, supported_size).unwrap();
        let m: [u64; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let field_m: Vec<Fr> = convert(&m);
        let r = Fr::rand(&mut rng);

        let cm = PedersenCommitmentScheme::<Projective>::commit(&params, &field_m, &r).unwrap();

        let opening = PedersenCommitmentScheme::<Projective>::open(&field_m, &r).unwrap();

        assert_eq!(
            PedersenCommitmentScheme::<Projective>::verify(&params, &cm, &opening).unwrap(),
            true
        );
    }

    #[bench]
    fn bench_group(b: &mut Bencher) {
        let mut rng = ark_std::test_rng();
        let supported_size = 4096;
        let params =
            PedersenCommitmentScheme::<G1Projective>::setup(&mut rng, supported_size).unwrap();

        let m: Vec<G1Fr> = vec![G1Fr::rand(&mut rng); supported_size];
        let r = G1Fr::rand(&mut rng);

        b.iter(|| PedersenCommitmentScheme::<G1Projective>::commit(&params, &m, &r));
    }
}
