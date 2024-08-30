use ark_ec::CurveGroup;
use ark_std::{rand::Rng, UniformRand, Zero};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Params<C: CurveGroup> {
    pub g: C,
    pub h: C,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pedersen<C: CurveGroup> {
    pub params: Params<C>,
    pub commitment : C,
    message: C::ScalarField,
    random: C::ScalarField,
}

impl<C: CurveGroup> Pedersen<C> {
    pub fn new() -> Self {
        Self {
            params: Params {
                g: C::generator(),
                h: C::generator(),
            },
            commitment: C::generator(),
            message: C::ScalarField::zero(),
            random: C::ScalarField::zero(),
        }
    }

    pub fn setup<R: Rng>(&mut self, rng: &mut R) {
        let g = C::rand(rng);
        let h = C::rand(rng);
        self.params.g = g;
        self.params.h = h;
    }

    pub fn commit<R: Rng>(
        &mut self,
        message: &C::ScalarField,
        rng: &mut R,
    ) {
        self.message = message.clone();
        self.random = C::ScalarField::rand(rng);
        let gm = self.params.g.mul(self.message);
        let hr = self.params.h.mul(self.random);

        self.commitment = gm + hr;
    }

    pub fn open(&self) -> (&C::ScalarField, &C::ScalarField) {
        (&self.message, &self.random)
    }
}

fn verify<C: CurveGroup>(pedcom: &Pedersen::<C>, message: &C::ScalarField, random: &C::ScalarField) {
    let gm = pedcom.params.g.mul(message);
    let hr = pedcom.params.h.mul(random);

    assert_eq!(pedcom.commitment, gm + hr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256k1::{Fr, Projective};

    #[test]
    fn tets_pedersen() {
        let mut rng = ark_std::test_rng();
        let mut pedcom = Pedersen::<Projective>::new();
        
        pedcom.setup(&mut rng);
        
        let m: Fr= Fr::from(114514);
        pedcom.commit(&m, &mut rng);
        
        let (mprime, rprime) = pedcom.open();
        verify(&pedcom, &mprime, &rprime);
    }
 }
