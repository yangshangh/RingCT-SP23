use ark_ec::CurveGroup;
use ark_std::{rand::Rng, UniformRand, marker::PhantomData};
use derivative::Derivative;
use crate::CommitmentErrors;
use crate::commitment::{Commitment, structs::{PedersenParams, PedersenOpening}};

// Pedersen (Vector) Commitment
#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
)]
pub struct PedersenCommitment<C: CurveGroup> {
    phantom: PhantomData<C>,
}

impl<C: CurveGroup> Commitment<C> for PedersenCommitment<C> {
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
            vec_g: generators
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
    ) -> Result<C, CommitmentErrors> {
        if m.len() != params.vec_g.len() {
            return Err(CommitmentErrors::InvalidParameters("message length should equal to the generator length".to_string()));
        }
        let msm = C::msm(&params.vec_g, m).unwrap();

        let cm = params.h.mul(r) + msm;
        Ok(cm)
    }

    /// Open algorithm outputs the following as the opening of commitment
    /// - m: message vector
    /// - r: random element for hiding
    fn open(
        m: &Self::Message,
        r: &Self::Random,
    ) -> Result<Self::Opening, CommitmentErrors> {
        Ok((Self::Opening{
            m,
            r
        }))
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
        let msm = C::msm(&params.vec_g, &open.message).unwrap();
        let cm_prime = params.h.mul(&open.random) + msm;
        Ok(cm_prime == cm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
    use ark_secp256k1::{Fr, Projective};
    use ark_bls12_381::{Fr as G1Fr, G1Projective};

    #[test]
    fn test_pedersen() {
        let mut rng = ark_std::test_rng();
        let supported_size = 1;
        let params = PedersenCommitment::<Projective>::setup(&mut rng, supported_size).unwrap();
        
        let m = vec![Fr::from(1)];
        let r = Fr::rand(&mut rng);

        let cm = PedersenCommitment::<Projective>::commit(&params, &m, &r).unwrap();
        
        let opening = PedersenCommitment::<Projective>::open(&m, &r).unwrap();

        assert_eq!(PedersenCommitment::<Projective>::verify(&params, &cm, &opening).unwrap(), true);
    }

    #[bench]
    fn bench_group(b: &mut Bencher) {
        let mut rng = ark_std::test_rng();
        let supported_size = 4096;
        let params = PedersenCommitment::<G1Projective>::setup(&mut rng, supported_size).unwrap();
        
        let m: Vec<G1Fr> = vec![G1Fr::rand(&mut rng); supported_size];
        let r = G1Fr::rand(&mut rng);

        b.iter(|| PedersenCommitment::<G1Projective>::commit(&params, &m, &r));
    }
 }
