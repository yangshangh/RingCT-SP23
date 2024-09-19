use ark_ec::CurveGroup;
use ark_std::{rand::Rng, UniformRand};
use std::{marker::PhantomData};

#[derive(Clone, Debug)]
pub struct Params<C: CurveGroup> {
    pub h: C,
    pub generators: Vec<C::Affine>, // we're using the `GAffine` type here for more efficient MSM.
}

pub struct Proof<C: CurveGroup> {
    pub message: Vec<C::ScalarField>,
    pub random: C::ScalarField,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment<C: CurveGroup>(pub C);

#[derive(Clone, Debug)]
pub struct Pedersen<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup> Pedersen<C> {
    pub fn new_params<R: Rng>(
        rng: &mut R, 
        max: usize
    ) -> Params<C> {
        let h_scalar = C::ScalarField::rand(rng);
        let g: C = C::generator();
        let generators = vec![C::Affine::rand(rng); max]; 

        Params { 
            h: g.mul(h_scalar), 
            generators 
        }
    }

    pub fn commit(
        params: &Params<C>,
        m: &[C::ScalarField],
        r: &C::ScalarField,
    ) -> Commitment<C> {
        if m.len() != params.generators.len() {
            panic!("Invalid message length");
        }
        let msm = C::msm(&params.generators, m).unwrap();

        let cm = params.h.mul(r) + msm;
        Commitment(cm)
    }

    pub fn open(
        params: &Params<C>,
        cm: &Commitment<C>,
        m: &Vec<C::ScalarField>,
        r: &C::ScalarField,
    ) -> Proof<C> {
        Proof {
            message: m.clone(),
            random: r.clone(),
        }
    }

    pub fn verify(
        params: &Params<C>,
        cm: &Commitment<C>,
        proof: &Proof<C>,
    ) -> bool {
        let msm = C::msm(&params.generators, &proof.message).unwrap();
        let cm_prime = params.h.mul(&proof.random) + msm;
        cm_prime == cm.0
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
        let params = Pedersen::<Projective>::new_params(&mut rng, max);
        
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
        let params = Pedersen::<G1Projective>::new_params(&mut rng, max);
        
        let m: Vec<G1Fr> = vec![G1Fr::rand(&mut rng); max];
        let r = G1Fr::rand(&mut rng);

        b.iter(|| Pedersen::<G1Projective>::commit(&params, &m, &r));
    }
 }
