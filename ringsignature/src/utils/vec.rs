use ark_ff::PrimeField;
use ark_ec::CurveGroup;
use rand::{seq::SliceRandom, thread_rng};


pub fn convert<F: PrimeField>(m: &[u64]) -> Vec<F> {
    let mut vec_field: Vec<F> = Vec::new();
    for i in m.iter() {
        vec_field.push(F::from(*i));
    }
    vec_field
}

pub fn shuffle<C: CurveGroup>(vec_pk: & mut Vec<C::Affine>, pk: C::Affine) -> Vec<C::ScalarField>{
    let mut rng = thread_rng();
    vec_pk.shuffle(&mut rng);
    let mut vec_b:Vec<C::ScalarField> = Vec::new();
    for i in 0..vec_pk.len() {
        if pk == vec_pk[i] {
            vec_b.push(C::ScalarField::from(1u64));
        } else {
            vec_b.push(C::ScalarField::from(0u64));
        }
    }
    vec_b
}

#[cfg(test)]
mod tests {
    use ark_ec::{CurveGroup};
    use super::*;
    use ark_secp256k1::{Fr, Projective, Affine};
    use ark_std::{UniformRand};

    #[test]
    fn test_convert() {
        let msg: [u64; 4] = [1, 2, 3, 4];
        let msg_field: Vec<Fr> = convert(&msg);
        assert_eq!(msg_field, vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]);
    }

    #[test]
    fn test_shuffle() {
        let mut rng = ark_std::test_rng();
        let scalar = Fr::from(1u64);
        let g = Projective::rand(&mut rng);
        let pk = g*scalar;
        let mut vec_pk = vec![Affine::rand(&mut rng); 3usize];
        let vec_b = shuffle::<Projective>(&mut vec_pk, pk.into_affine());
        for i in 0..vec_b.len() {
            if vec_b[i] == Fr::from(1u64) {
                assert_eq!(pk, vec_pk[i]);
            }
        }
    }
}
