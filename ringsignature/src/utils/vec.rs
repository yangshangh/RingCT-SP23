use ark_ff::PrimeField;

pub fn convert<F: PrimeField>(m: &[u64]) -> Vec<F> {
    let mut vec_field: Vec<F> = Vec::new();
    for i in m.iter() {
        vec_field.push(F::from(*i));
    }
    vec_field
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256k1::Fr;
    #[test]
    fn test_convert() {
        let msg: [u64; 4] = [1, 2, 3, 4];
        let msg_field: Vec<Fr> = convert(&msg);
        assert_eq!(msg_field, vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]);
    }
}
