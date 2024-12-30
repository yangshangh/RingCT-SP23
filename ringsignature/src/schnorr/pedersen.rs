use ark_ec::CurveGroup;
use ark_std::{rand::Rng, UniformRand};
use std::{marker::PhantomData};
use crate::PedersenErrors;

#[derive(Clone, Debug)]
pub struct PedersenParams<C: CurveGroup> {
    pub h: C,
    // the `GAffine` type is used here for more efficient MSM.
    pub generators: Vec<C::Affine>,
}

#[derive(Clone, Debug)]
pub struct Pedersen<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup> Pedersen<C> {
    pub fn setup<R: Rng>(
        rng: &mut R, 
        max: usize
    ) -> Result<PedersenParams<C>, PedersenErrors> {
        let h_scalar = C::ScalarField::rand(rng);
        let g: C = C::generator();
        let generators = vec![C::Affine::rand(rng); max];

        Ok(PedersenParams {
            h: g.mul(h_scalar), 
            generators 
        })
    }

    pub fn commit(
        params: &PedersenParams<C>,
        m: &[C::ScalarField],
        r: &C::ScalarField,
    ) -> Result<C, PedersenErrors> {
        if m.len() != params.generators.len() {
            panic!("Invalid message length");
        }
        let msm = C::msm(&params.generators, m).unwrap();

        let cm = params.h.mul(r) + msm;
        Ok(cm)
    }

    pub fn open(
        params: &PedersenParams<C>,
        cm: &C,
        m: &Vec<C::ScalarField>,
        r: &C::ScalarField,
    ) -> Result<(&Vec<C::ScalarField>, C::ScalarField), PedersenErrors> {
        todo!();
        Ok((m, r))
    }

    pub fn verify(
        params: &PedersenParams<C>,
        cm: &C,
        m: &Vec<C::ScalarField>,
        r: &C::ScalarField,
    ) -> Result<bool, PedersenErrors> {
        let msm = C::msm(&params.generators, &m).unwrap();
        let cm_prime = params.h.mul(&r) + msm;
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
        let max = 1;
        let params = Pedersen::<Projective>::setup(&mut rng, max);
        
        let m = vec![Fr::from(1)];
        let r = Fr::rand(&mut rng);

        let cm = Pedersen::<Projective>::commit(&params, &m, &r);
        
        let proof = Pedersen::<Projective>::open(&params, &cm, &m, &r);

        assert_eq!(Pedersen::<Projective>::verify(&params, &cm, &proof), true);
    }

    #[bench]
    fn bench_group(b: &mut Bencher) {
        let mut rng = ark_std::test_rng();
        let max = 4096;
        let params = Pedersen::<G1Projective>::setup(&mut rng, max);
        
        let m: Vec<G1Fr> = vec![G1Fr::rand(&mut rng); max];
        let r = G1Fr::rand(&mut rng);

        b.iter(|| Pedersen::<G1Projective>::commit(&params, &m, &r));
    }
 }
