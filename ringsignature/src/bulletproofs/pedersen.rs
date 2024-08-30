use ark_ec::CurveGroup;
use ark_std::{rand::Rng, UniformRand};


#[derive(Clone, Debug)]
pub struct Params<C: CurveGroup> {
    pub g: C,
    pub h: C,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pedersen<C: CurveGroup> {
    pub commitment : C,
    message: C::ScalarField,
    randnom: C::ScalarField,
}

impl<C: CurveGroup> Pedersen<C> {
    pub fn setup<R: Rng>(rng: &mut R) -> Params<C> {
        // let h_r = C::ScalarField::rand(rng);
        let g = C::rand(rng);
        let h = C::rand(rng);
        Params {
            g,
            h,
        }
    }

    pub fn commit(
        params: &Params<C>,
        message: &C::ScalarField,
        random: &C::ScalarField,
    ) -> C {
        let gm = params.g.mul(message);
        let hr = params.h.mul(random);

        gm + hr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256k1::{Fr, Projective};

    #[test]
    fn tets_pedersen() {
        let mut rng = ark_std::test_rng();

        let params = Pedersen::setup(&mut rng);
        
        let m: Fr= Fr::rand(&mut rng);
        let r: Fr= Fr::rand(&mut rng);
        let cm = Pedersen::<Projective>::commit(&params, &m, &r);
        println!("cm: {:?}", cm);
    }
 }
