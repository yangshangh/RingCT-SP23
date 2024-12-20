use ark_std::rand::Rng;
use ark_ec::CurveGroup;
use transcript::IOPTranscript;

use std::marker::PhantomData;

use super::pedersen::{Params, Commitment, Pedersen};

#[derive(Clone, Debug)]
pub struct Proof<C: CurveGroup> {
    cm: Commitment<C>,
    U: C,
    z: Vec<C::ScalarField>,
    rz: C::ScalarField,
}

#[derive(Clone, Debug)]
pub struct Schnorr<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup> Schnorr<C> {
    pub fn new_params<R: Rng>(
        rng: &mut R, 
        max: usize
    ) -> Params<C> {
        Pedersen::new_params(rng, max)
    }

    pub fn prove(
        params: &Params<C>, 
        transcript: &mut IOPTranscript<C::ScalarField>,
        m: &Vec<C::ScalarField>,
        r: &C::ScalarField,
    ) -> Proof<C> {
        // z = m*r + u 
        let cm = Pedersen::commit(params, m, r);
        let u = transcript.get_and_append_challenge_vectors(b"u", m.len()).unwrap();
        let ru = transcript.get_and_append_challenge(b"ru").unwrap();

        let msm = C::msm(&params.generators, &u).unwrap();
        let U = params.h.mul(ru) + msm;

        transcript.append_serializable_element(b"cm", &cm.0).unwrap();
        transcript.append_serializable_element(b"U", &U).unwrap();
        let c = transcript.get_and_append_challenge(b"c").unwrap();

        let z = m.iter().zip(u.iter()).map(|(mi, ui)| c * mi + ui).collect();
        let rz = c * r + ru;
        Proof {cm, U, z, rz }
    }

    pub fn verify(
        params: &Params<C>,
        transcript: &mut IOPTranscript<C::ScalarField>,
        proof: &Proof<C>,
    ) -> bool {
        // 这里不对，verifier不应该知道 u 和 ru
        transcript.get_and_append_challenge_vectors(b"u", proof.z.len()).unwrap();
        transcript.get_and_append_challenge(b"ru").unwrap();

        transcript.append_serializable_element(b"cm", &proof.cm.0).unwrap();
        transcript.append_serializable_element(b"U", &proof.U);
        let c = transcript.get_and_append_challenge(b"c").unwrap();

        let lhs = proof.U + proof.cm.0.mul(c);
        let msm = C::msm(&params.generators, &proof.z).unwrap();
        let rhs = params.h.mul(proof.rz) + msm;
        if lhs != rhs {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use ark_secp256k1::{Fr, Projective}; 

    #[test]
    fn test_schnorr() {
        let mut rng = ark_std::test_rng();

        let max = 10;
        let params = Schnorr::new_params(&mut rng, max);

        let mut transcript_p = IOPTranscript::<Fr>::new(b"schnorr_test");
        transcript_p.append_message(b"init", b"init").unwrap();

        let mut transcript_v = IOPTranscript::<Fr>::new(b"schnorr_test");
        transcript_v.append_message(b"init", b"init").unwrap();

        let m = vec![Fr::rand(&mut rng); max];
        let r = Fr::rand(&mut rng);

        let proof = Schnorr::<Projective>::prove(&params, &mut transcript_p, &m, &r);
        assert!(Schnorr::<Projective>::verify(&params, &mut transcript_v, &proof));
    }
}