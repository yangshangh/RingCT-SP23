use std::fs::Permissions;
use std::io::Write;
use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_std::{end_timer, rand::Rng, start_timer, UniformRand, Zero, One};
use sha256::digest;

use bulletproofs::ipa::*;
use bulletproofs::structs::*;
use crate::commitment::pedersen::PedersenCommitmentScheme;
use crate::commitment::PedersenParams;
use crate::ringsig::structs::{LogarithmicRingSignature, RingSignatureParams, Openings};
use toolbox::sigma::{transcript::ProofTranscript, SigmaProtocol};
use toolbox::errors::SigmaErrors;
use toolbox::vec::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingSignatureScheme<C>
where
    C: CurveGroup,
{
    phantom: PhantomData<C>,
}

/// Implement a sigma protocol as a ring signature scheme (without compression), including 5-move:
/// Relation: P knows a sk to a pk among the vector vec_pk
/// Formalized Relation: P knows a sk satisfying <vec_pk, vec_b> = com(sk)
impl<C> SigmaProtocol<C> for RingSignatureScheme<C>
where
    C: CurveGroup,
{
    /// public parameters
    type PublicParams = RingSignatureParams<C>;
    /// witness
    type Witness = Vec<C::ScalarField>;
    /// witness commitments
    type Commitments = Vec<C::Affine>;
    // challenge
    type Challenge = Vec<C::ScalarField>;
    /// proof
    type Proof = LogarithmicRingSignature<C>;

    fn setup<R: Rng>(
        rng: &mut R,
        wit: &mut Self::Witness, // secret key
        msg: &String,
        supported_size: usize, // ring size
    ) -> Result<Self::PublicParams, SigmaErrors> {
        // generate commitment scheme parameters (vec_g, u)
        let com_params_1 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        // generate commitment scheme parameters (vec_h, v)
        let com_params_2 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;

        //生成(vec_g_2,u_2)
        let com_params_3 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        //生成(vec_h_2,v_2)
        let com_params_4 = PedersenCommitmentScheme::<C>::setup(rng, supported_size)?;
        
        // generate public key parameters (g)
        let key_params = PedersenCommitmentScheme::<C>::setup(rng, 1)?;

        // generate pk vectors
        let pk:C::Affine = PedersenCommitmentScheme::commit(&key_params, wit, &C::ScalarField::zero(), "as pk")?.into_affine();
        let mut vec_pk = vec![C::Affine::rand(rng); 2*supported_size-1];
        // add pk to the vector and shuffle it
        vec_pk.push(pk);
        let vec_b = shuffle::<C>(&mut vec_pk, pk);
        wit.extend(vec_b);

        Ok(RingSignatureParams {
            num_witness: wit.len(),
            num_pub_inputs: supported_size,
            com_parameters: vec![com_params_1, com_params_2, com_params_3,com_params_4,key_params],
            message: msg.clone(),
            vec_pk,
        })
    }

    fn prove<R: Rng>(
        rng: &mut R,
        params: &Self::PublicParams,
        wit: &Self::Witness,
    ) -> Result<Self::Proof, SigmaErrors> {
        // initialization
        let start = start_timer!(|| "running sigma protocol prove algorithm...");
        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"RingSignature");
        transcript.append_serializable_element(b"public list", &params.vec_pk)?;
        // parse commitment parameters
        let param_g_1_u_1 = &params.com_parameters[0];
        let param_h_1_v_1 = &params.com_parameters[1];
        let param_g_2_u_2=&params.com_parameters[2];
        let param_h_2_v_2=&params.com_parameters[3];
        let param_key = &params.com_parameters[4];
        // parse wit as vec_sk and vec_b
        let vec_sk = wit[0..wit.len()-params.num_pub_inputs].to_vec();
        let vec_b = wit[wit.len()-params.num_pub_inputs..].to_vec();
         // 定义 b' = b - bits(1)，其中 bits(1) 是第一个元素为 1，其余为 0 的向量
        let vec_b_prime: Vec<C::ScalarField> = {
        let n = vec_b.len();
        // 构造 bits(1) 向量：第一个元素为 1，其余为 0
        let mut bits = vec![C::ScalarField::zero(); n];
        if n > 0 {
            bits[0] = C::ScalarField::one();
        }
        // 逐元素相减得到 b'
        vec_b
            .iter()
            .zip(bits.iter())
            .map(|(&b_i, &bit_i)| b_i - bit_i)
            .collect()
        };
        // denote b_0 = b, b_1 = 1^n - b_0
        let vec_b0 = vec_b.clone();
        let vec_b1: Vec<C::ScalarField> = vec_b.iter()
            .map(|&b_i| C::ScalarField::one() - b_i)
            .collect();
        // 定义 b_2 = b'，b_3 = 1^n - b'
        let (vec_b2, vec_b3): (Vec<C::ScalarField>, Vec<C::ScalarField>) = {
            //let n = vec_b_prime.len();
            // 生成全 1 向量 1^n
            let ones = vec![C::ScalarField::one(); params.num_pub_inputs];
            // 计算 b_3 = 1^n - b'
            let vec_b3: Vec<C::ScalarField> = ones
                .into_iter()
                .zip(vec_b_prime.iter())
                .map(|(one_i, &b_prime_i)| one_i - b_prime_i)
                .collect();
            // b_2 直接等于 b'
            let vec_b2 = vec_b_prime.clone();
            (vec_b2, vec_b3)
        };
        // sanity check
        // b_0 + b_1 = 1^n
        // b_0 \circ b_1 = 0^n
        let constraint_1 = vec_b0.iter()
            .zip(vec_b1.iter())
            .all(|(&b0_i, &b1_i)| b0_i + b1_i == C::ScalarField::one());
        let constraint_2 = vec_b0.iter()
            .zip(vec_b1.iter())
            .all(|(&b0_i, &b1_i)| b0_i * b1_i == C::ScalarField::zero());
        assert!(constraint_1 && constraint_2);


        //check b_2 b_3
        // 约束检查：b_2 + b_3 = 1^n 且 b_2 ◦ b_3 = 0^n
        //let check_sum = vec_b2.iter()
        // .zip(vec_b3.iter())
        // .all(|(&b2_i, &b3_i)| b2_i + b3_i == C::ScalarField::one());

        // let check_product = vec_b2.iter()
        // .zip(vec_b3.iter())
        // .all(|(&b2_i, &b3_i)| b2_i * b3_i == C::ScalarField::zero());

        // assert!(check_sum && check_product, "b_2/b_3 constraints failed");

        // computes A = g^{b_0}h^{b_1}u^{alpha}, B = g^{r_0}h^{r_1}u^{beta},C D
        let alpha_1 = C::ScalarField::rand(rng);
        let alpha_2 = C::ScalarField::rand(rng);
        let alpha_3 = C::ScalarField::rand(rng);
        let alpha_4 = C::ScalarField::rand(rng);
        //let beta = C::ScalarField::rand(rng);
        let vec_r0 = vec![C::ScalarField::rand(rng); vec_b0.len()];
        let vec_r1 = vec![C::ScalarField::rand(rng); vec_b1.len()];
        let vec_r2 = vec![C::ScalarField::rand(rng); vec_b1.len()];
        let vec_r3 = vec![C::ScalarField::rand(rng); vec_b1.len()];
        let com_A = PedersenCommitmentScheme::commit(&param_g_1_u_1, &vec_b0, &alpha_1, "on b0")?
            + PedersenCommitmentScheme::commit(&param_h_1_v_1, &vec_b1, &C::ScalarField::zero(), "on b1")?;
        let com_B = PedersenCommitmentScheme::commit(&param_g_1_u_1, &vec_r0, &alpha_2, "on r0")?
            + PedersenCommitmentScheme::commit(&param_h_1_v_1, &vec_r1, &C::ScalarField::zero(), "on r1")?;
        let com_C = PedersenCommitmentScheme::commit(&param_g_2_u_2, &vec_b2, &alpha_3, "on b2")?
        + PedersenCommitmentScheme::commit(&param_h_2_v_2, &vec_b3, &C::ScalarField::zero(), "on b3")?;
        let com_D = PedersenCommitmentScheme::commit(&param_g_2_u_2, &vec_r2, &alpha_4, "on r2")?
        + PedersenCommitmentScheme::commit(&param_h_2_v_2, &vec_r3, &C::ScalarField::zero(), "on r3")?;

        // P->V: A,B
        transcript.append_serializable_element(b"commitments A,B,C,D", &[com_A, com_B,com_C,com_D])?;

        // V->P: challenges y,z
        let y = transcript.get_and_append_challenge(b"challenge y")?;
        let z = transcript.get_and_append_challenge(b"challenge z")?;

        // t1 = <r_0 \circ y^n, z*1^n + b_1> + <(b0 + z*1^n) \circ y^n, r_1>
        let powers_yn = generate_powers(y, params.num_pub_inputs);
        let vec_z1n = vec![z; params.num_pub_inputs];
        let vec_r0_yn = hadamard_product(&vec_r0, &powers_yn);
        let mut vec_r0_yn_expanded=vec_r0_yn.clone();
        vec_r0_yn_expanded.extend(vec![C::ScalarField::zero();vec_r0_yn.len()]);
        //let vec_z1n_b1 = vec_add(&vec_z1n, &vec_b1);
        //let vec_b0_z1n_yn = hadamard_product(&vec_add(&vec_z1n, &vec_b0), &powers_yn);
        //let t1 = inner_product(&vec_r0_yn, &vec_z1n_b1) + inner_product(&vec_b0_z1n_yn, &vec_r1);
        // t2 = <r0 \circ y^n, r_1>
        //let t2 = inner_product(&vec_r0_yn, &vec_r1);
        let z2=z.pow(&[2]);
        // 计算 z^3
        let z3 = z.pow(&[3]); // z^3
        // 计算 z^5
        let z5 = z.pow(&[5]); // z^5
        // 计算 z^7
        let z7 = z.pow(&[7]); // z^7
        //let two_power_n = vec![C::ScalarField::from(2u64); params.num_pub_inputs];
        let two_power_n=generate_powers(C::ScalarField::from(2u64), params.num_pub_inputs);
        let z2_b3: Vec<_>=vec_b3.iter().map(|&x| x * z2).collect(); 
        let z3_1n= vec![z3; params.num_pub_inputs];
        let z7_2n: Vec<_> = two_power_n.iter().map(|&x| z7 * x).collect();
        let z5_2n: Vec<_> = two_power_n.iter().map(|&x| z5 * x).collect();
        let b1_z2_b3=[vec_b1, z2_b3].concat();
        let z_1n_z3_1n=[vec_z1n,z3_1n].concat();
        let z7_2n_z5_2n=[z7_2n,z5_2n].concat();
        let z2_b2:Vec<_>=vec_b2.iter().map(|&x| x*z2).collect();
        let b0_z2_b2=[vec_b0,z2_b2].concat();
        let yn_yn=[powers_yn.clone(),powers_yn.clone()].concat();
        let t1_part11=hadamard_product(&([vec_r0.clone(), vec_r2.clone()].concat()),&([powers_yn.clone(),powers_yn.clone()].concat()));
        let t1_part12:Vec<_>=b1_z2_b3.iter()
            .zip(z_1n_z3_1n.iter())
            .zip(z7_2n_z5_2n.iter())
            .map(|((&x1,&x2),&x3)| x1+x2+x3)
            .collect();
        let t1_part1=inner_product(&t1_part11,&t1_part12);
        let t1_part211:Vec<_>=b0_z2_b2.iter()
            .zip(z_1n_z3_1n.iter())
            .map(|(&x1,&x2)| x1+x2)
            .collect();
        let t1_part21:Vec<_>=hadamard_product(&t1_part211, &yn_yn);
        let t1_part22:Vec<_>=[vec_r1.clone(),vec_r3.clone()].concat();
        let t1_part2=inner_product(&t1_part21, &t1_part22);
        let t1=t1_part1+t1_part2;

        let t2_part11:Vec<_>=[vec_r0.clone(),vec_r2.clone()].concat();
        let t2_part1:Vec<_>=hadamard_product(&t2_part11, &yn_yn);
        let t2_part2:Vec<_>=[vec_r1.clone(),vec_r3.clone()].concat();
        let t2=inner_product(&t2_part1, &t2_part2);
        // computes
        // E = P^{y^n \circ r_0} Com_{ck}(0; -r_s)
        // T1 = v^{t1}u^{tau1}
        // T2 = v^{t2}u^{tau2}
        let rs = C::ScalarField::rand(rng);
        let neg_rs = -rs.clone();
        let tau1 = C::ScalarField::rand(rng);
        let tau2 = C::ScalarField::rand(rng);

        let com_E = C::msm(&params.vec_pk, &vec_r0_yn_expanded).unwrap() + PedersenCommitmentScheme::commit(&param_key, &vec![neg_rs], &C::ScalarField::zero(), "E")?;
        
        let param_u_v = PedersenParams {
            generator: param_h_1_v_1.generator.clone(),
            vec_gen: vec![param_g_1_u_1.generator.into_affine().clone()],
        };
        let com_T1 = PedersenCommitmentScheme::commit(&param_u_v, &vec![tau1], &t1, "T1")?;
        let com_T2 = PedersenCommitmentScheme::commit(&param_u_v, &vec![tau2], &t2, "T2")?;
        // P->V: E, T1, T2
        transcript.append_serializable_element(b"commitments E,T1,T2", &[com_E, com_T1, com_T2])?;

        // append the message digest to the transcript
        let h = digest(&params.message);
        let mut h_msg: &mut [u8] = &mut [0; 32];
        h_msg.write(h.as_bytes()).unwrap();
        
        transcript.append_message(b"message digest", &h_msg)?;
        // V->P: challenges x
        let x = transcript.get_and_append_challenge(b"challenge x")?;

        // computes zeta = (b_0 + z*1^n + r_0*x) \circ y^n, eta = b_1 + z*1^n + r_1*x
        //let b0_z1n_r0x = vec_add(&vec_b0, &vec_add(&vec_z1n, &scalar_product(&vec_r0, &x)));
        //let zeta = hadamard_product(&b0_z1n_r0x, &powers_yn);
        //let eta = vec_add(&vec_b1, &vec_add(&vec_z1n, &scalar_product(&vec_r1, &x)));

        let r1_r3=[vec_r1,vec_r3].concat();
        let r0_r2=[vec_r0,vec_r2].concat();
        let r0_r2_x:Vec<_>=r0_r2.iter().map(|&a| a*x).collect();
        let r1_r3_x:Vec<_>=r1_r3.iter().map(|&a| a*x).collect();
        let zeta_1=vec_add(&vec_add(&b0_z2_b2, &z_1n_z3_1n),&r0_r2_x);
        let zeta=hadamard_product(&zeta_1, &yn_yn);
        
        let eta_1=vec_add(&b1_z2_b3, &z_1n_z3_1n);
        let eta_2=vec_add(&z7_2n_z5_2n, &r1_r3_x);
        let eta=vec_add(&eta_1, &eta_2);
        // computes hat_t = <zeta, eta>
        let hat_t = inner_product(&zeta, &eta);
        // // sanity check
        // let vec_1n = vec![C::ScalarField::one(); params.num_pub_inputs];
        // let delta = inner_product(&vec_1n, &powers_yn) * (z+z*z);
        // let t_prime = delta + t1*x + t2*x*x;
        // if t_prime == hat_t {println!("delta equality passes")}
        // else {println!("delta equality fails")}

        // tau_x = tau1*x + tau2*x^2
        let taux = tau1*x + tau2*x*x;
        // mu = alpha + beta*x
        let mu_1 = alpha_1 + alpha_2*x;
        let mu_2=alpha_2*z*z+alpha_4*x;
        // fs = \sum_{j=1}^k y^{i_j} s_j + r_s*x
        let mut j = 1;
        let mut sum = C::ScalarField::zero();
        for i in 0..params.num_pub_inputs {
            let term = powers_yn[i]*vec_b[i];
            if term != C::ScalarField::zero() {
                sum += term*vec_sk[j];
            
            }
            j += 1;
        }
        let fs = sum + rs*x;

        // Bulletproofs Compression
        let powers_yn_inverse = generate_powers(y.inverse().unwrap(), params.num_pub_inputs);
        let mut vec_g1_yn = Vec::with_capacity(param_g_1_u_1.vec_gen.len());
        let mut vec_g2_yn = Vec::with_capacity(param_g_2_u_2.vec_gen.len());
        for i in 0..param_g_1_u_1.vec_gen.len() {
            vec_g1_yn.push((param_g_1_u_1.vec_gen[i]*powers_yn_inverse[i]).into_affine());
        }
        for i in 0..param_g_2_u_2.vec_gen.len() {
            vec_g2_yn.push((param_g_2_u_2.vec_gen[i]*powers_yn_inverse[i]).into_affine());
        }
        let vec_g_yn=[vec_g1_yn.clone(),vec_g2_yn.clone()].concat();
        let n = vec_g_yn.len();
        let mut vec_G:Vec<C::Affine> = Vec::with_capacity(n);
        for i in 0..n {
            vec_G.push((vec_g_yn[i] + params.vec_pk[i]).into_affine());
        }
        let vec_H = [param_h_1_v_1.vec_gen.clone(),param_h_2_v_2.vec_gen.clone()].concat();
        let v = param_h_1_v_1.generator.clone().into_affine();
        let factors_G = vec![C::ScalarField::from(1u64); n];
        let factors_H = vec![C::ScalarField::from(1u64); n];
        let param = InnerProductParam {
            factors_G,
            factors_H,
            u: v,
            vec_G,
            vec_H,
        };

        let proof = InnerProductProtocol::<C>::prove(&param, zeta.clone(), eta.clone())?;

        let openings = Openings {
            zeta: vec![proof.a],
            eta: vec![proof.b],
            hat_t,
            taux,
            mu_1,
            mu_2,
            fs,
        };
        assert_eq!(j, vec_sk.len());

        // proving ends
        end_timer!(start);
        Ok(LogarithmicRingSignature {
            commitments: vec![com_A, com_B,com_C,com_D, com_E, com_T1, com_T2],
            openings,
            compression_proof: proof,
            challenges: vec![y,z,x],
            digest: h.clone(),
        })
    }

    fn verify(
        params: &Self::PublicParams,
        proof: &Self::Proof
    ) -> Result<bool, SigmaErrors> {
        // initialization
        let start = start_timer!(|| "preprocessing sigma protocol verify algorithm...");
        let mut transcript = ProofTranscript::<C::ScalarField>::new(b"RingSignature");
        transcript.append_serializable_element(b"public list", &params.vec_pk)?;
        // parse commitment parameters
        let param_g_1_u_1 = &params.com_parameters[0];
        let param_h_1_v_1 = &params.com_parameters[1];
        let param_g_2_u_2=&params.com_parameters[2];
        let param_h_2_v_2=&params.com_parameters[3];
        let param_key = &params.com_parameters[4];

        // parse proof
        let commitments = &proof.commitments;
        let (com_A, com_B,com_C ,com_D,com_E, com_T1, com_T2) = (commitments[0], commitments[1], commitments[2], commitments[3], commitments[4],commitments[5],commitments[6]);
        let openings = &proof.openings;
        let challenges = &proof.challenges;
        let digest = &proof.digest;

        let (y,z,x) = (challenges[0],challenges[1],challenges[2]);

        let vec_0n = vec![C::ScalarField::zero(); params.num_pub_inputs];
        let vec_1n = vec![C::ScalarField::one(); params.num_pub_inputs];
        let vec_12n = vec![C::ScalarField::one(); 2*params.num_pub_inputs];
        let powers_yn = generate_powers(y, params.num_pub_inputs);

        // check validity of T1 T2
        // v^{hat_t} = v^delta T1^x T2^{x^2} y^{-taux}
        // where hat_t = <zeta, eta>
        // let t = inner_product(&openings.zeta, &openings.eta);
        // assert_eq!(openings.hat_t, t, "step 1: hat_t check fails");
        let z2=z.pow(&[2]);
        // 计算 z^3
        let z3 = z.pow(&[3]); // z^3
        // 计算 z^5
        let z5 = z.pow(&[5]); // z^5
        // 计算 z^7
        let z7 = z.pow(&[7]); // z^7
        let z6=z.pow(&[6]);
        let z8=z.pow(&[8]);
        let two_power_n = vec![C::ScalarField::from(2u64); params.num_pub_inputs];
        let yn_yn=[powers_yn.clone(),powers_yn.clone()].concat();
        let delta_1=(z+z2+z5+z6+z7)*inner_product(&vec_1n, &powers_yn.clone());
        let delta_21=hadamard_product(&vec_12n, &yn_yn);
        let delta_22=[two_power_n.clone(),two_power_n.clone()].concat();
        let delta_2=z8*inner_product(&delta_21, &delta_22);
        let delta=delta_1+delta_2;
        //let delta = inner_product(&vec_1n, &powers_yn) * (z+z*z);

        //let lhs_step1 = PedersenCommitmentScheme::commit(param_h_1_v_1, &vec_0n, &openings.hat_t, "on hat_t")?;
        let rhs_step1 = PedersenCommitmentScheme::commit(param_h_1_v_1, &vec_0n, &delta, "on delta")?
            + com_T1.mul(x) + com_T2.mul(x*x) - PedersenCommitmentScheme::commit(&param_g_1_u_1, &vec_0n, &openings.taux, "on tau_x")?;
        //assert_eq!(lhs_step1, rhs_step1, "step 1: T1, T2 checks fail");

        // check validity of A B
        // {vec_g'}^{zeta} vec_h^eta = A B^x vec_g^{z1^n} vec_h^{z1^n} u^{-mu}
        let powers_yn_inverse = generate_powers(y.inverse().unwrap(), params.num_pub_inputs);
        let mut vec_g1_yn = Vec::with_capacity(param_g_1_u_1.vec_gen.len());
        for i in 0..param_g_1_u_1.vec_gen.len() {
            vec_g1_yn.push((param_g_1_u_1.vec_gen[i]*powers_yn_inverse[i]).into_affine());
        }
        let mut vec_g2_yn = Vec::with_capacity(param_g_2_u_2.vec_gen.len());
        for i in 0..param_g_2_u_2.vec_gen.len() {
            vec_g2_yn.push((param_g_2_u_2.vec_gen[i]*powers_yn_inverse[i]).into_affine());
        }
        let vec_g1_g2=[vec_g1_yn.clone(),vec_g2_yn.clone()].concat();
        let vec_g12=vec_g1_g2.clone();
        let vec_h1=param_h_1_v_1.vec_gen.clone();
        let vec_h2=param_h_2_v_2.vec_gen.clone();
        let vec_h1_h2=[vec_h1,vec_h2].concat();
        let vec_z1n = vec![z; params.num_pub_inputs];
        let vec_z3_1n=vec![z3;params.num_pub_inputs];
        let vec_z7_2n: Vec<_> = two_power_n.iter().map(|&x| z7 * x).collect();
        let vec_z1n_z72n=vec_add(&vec_z1n, &vec_z7_2n);
        let vec_z5_2n:Vec<_>=two_power_n.iter().map(|&x| z5 * x).collect();
        let vec_z3n_z52n=vec_add(&vec_z3_1n, &vec_z5_2n);
        //generate zero vector
        let zeros = vec![C::ScalarField::zero(); vec_g1_g2.len()];
        let param_g1_yn_u1 = PedersenParams {
            generator: param_g_1_u_1.generator.clone(),
            vec_gen: vec_g1_g2,
        };
        // let param_g2_yn_u2 = PedersenParams {
        //     generator: param_g_2_u_2.generator.clone(),
        //     vec_gen:vec_g12,
        // };
        let param_h12_v1 = PedersenParams {
            generator: param_h_1_v_1.generator.clone(),
            vec_gen: vec_h1_h2,
        };
        // let lhs_step2 = PedersenCommitmentScheme::commit(&param_g_yn_u, &openings.zeta, &C::ScalarField::zero(), "on zeta")?
        //    + PedersenCommitmentScheme::commit(&param_h_v, &openings.eta, &C::ScalarField::zero(), "on eta")?;
        //


        // let lhs_step2=PedersenCommitmentScheme::commit(&param_g2_yn_u2, &zeros, &openings.mu_2, "on zeros")?
        //     +PedersenCommitmentScheme::commit(&param_g1_yn_u1, &openings.zeta, &openings.mu_1, "on zeta")?
        //     +PedersenCommitmentScheme::commit(&param_h12_v1, &openings.eta,&C::ScalarField::zero(),"on eta")?;
        
        
        // let rhs_step2 = com_A + com_B.mul(x)
        //     + PedersenCommitmentScheme::commit(&param_g_u, &vec_z1n, &(-openings.mu), "on z1n")?
        //     + PedersenCommitmentScheme::commit(&param_h_v, &vec_z1n, &C::ScalarField::zero(), "on z1n")?;
        let rhs_step2=com_A+com_B.mul(x)+com_C.mul(z2)+com_D.mul(x)
            +PedersenCommitmentScheme::commit(&param_g_1_u_1,&vec_z1n,&C::ScalarField::zero() , "on vec_z1n")?
            +PedersenCommitmentScheme::commit(&param_g_2_u_2, &vec_z3_1n,&C::ScalarField::zero() , "on vec_z3_1n")?
            +PedersenCommitmentScheme::commit(&param_h_1_v_1,&vec_z1n_z72n , &C::ScalarField::zero(), "on vec_z1n_z7n")?
            +PedersenCommitmentScheme::commit(&param_h_2_v_2, &vec_z3n_z52n, &C::ScalarField::zero(), "on vec_z3n_z52n")?;
        //assert_eq!(lhs_step2, rhs_step2, "step 2: A,B checks fail");

        // check pk
        // P^zeta = g^fs E^x P^{z y^n}
        let vec_z_yn = scalar_product(&powers_yn, &z);
        let vec_z_yn_2=vec_z_yn.clone();
        let vec_z_yn_expanded=[vec_z_yn.clone(),vec_z_yn_2.clone()].concat();
        // let lhs_step3 = C::msm(&params.vec_pk, &openings.zeta).unwrap();



        let rhs_step3 = PedersenCommitmentScheme::commit(&param_key, &vec![openings.fs], &C::ScalarField::zero(), "on fs")?
            + com_E.mul(x) + C::msm(&params.vec_pk, &vec_z_yn_expanded).unwrap();
        // assert_eq!(lhs_step3, rhs_step3, "step 3: pk check fails");

        end_timer!(start);

        let start = start_timer!(|| "running sigma protocol verify algorithm...");
        // check the challenges
        transcript.append_serializable_element(b"commitments A,B,C,D", &[com_A, com_B,com_C,com_D])?;
        let y = transcript.get_and_append_challenge(b"challenge y")?;
        let z = transcript.get_and_append_challenge(b"challenge z")?;
        transcript.append_serializable_element(b"commitments E,T1,T2", &[com_E, com_T1, com_T2])?;
        let h = sha256::digest(&params.message);
        assert_eq!(&h, digest);
        let mut h_msg: &mut [u8] = &mut [0; 32];
        h_msg.write(h.as_bytes()).unwrap();
        transcript.append_message(b"message digest", &h_msg)?;
        let x = transcript.get_and_append_challenge(b"challenge x")?;

        if (y,z,x) != (challenges[0],challenges[1],challenges[2])  {
            return Err(SigmaErrors::InvalidProof(
                "invalid challenge value".to_string(),
            ));
        }

        // run Bulletproofs Compression
        // consider aggregating the following three equation into one
        // v^{hat_t} = v^delta T1^x T2^{x^2} y^{-taux}
        // {vec_g'}^{zeta} vec_h^eta = A B^x vec_g^{z1^n} vec_h^{z1^n} u^{-mu}
        // P^zeta = g^fs E^x P^{z y^n}
        let RHS = rhs_step1 + rhs_step2 + rhs_step3;
        let n = param_g1_yn_u1.vec_gen.len();
        let mut vec_G:Vec<C::Affine> = Vec::with_capacity(n);
        let vec_g=vec_g12.clone();
        for i in 0..n {
            vec_G.push((vec_g[i] + params.vec_pk[i]).into_affine());
        }
        let vec_H = param_h12_v1.vec_gen.clone();
        let v = param_h12_v1.generator.clone().into_affine();
        let factors_G = vec![C::ScalarField::from(1u64); n];
        let factors_H = vec![C::ScalarField::from(1u64); n];
        let param = InnerProductParam {
            factors_G,
            factors_H,
            u: v,
            vec_G,
            vec_H,
        };

        // call Bulletproofs prover
        InnerProductProtocol::<C>::verify(n, RHS, &param, &proof.compression_proof)?;
        let result = true;
        end_timer!(start);
        Ok(result)
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256k1::{Fr, Projective};
    use ark_std::UniformRand;

    #[test]
    fn test_ringsignature() {
        // parameter setting
        let mut rng = ark_std::test_rng();
        let ring_size = 256;
        let sk = Fr::rand(&mut rng);
        let mut wit = vec![sk];
        type Ring = RingSignatureScheme<Projective>;
        let message = String::from("Welcome to the world of Zero Knowledge!");
        // setup algorithm
        let ring_params = Ring::setup(&mut rng, &mut wit, &message, ring_size).unwrap();
        // prove algorithm
        let proof = Ring::prove(&mut rng, &ring_params, &wit).unwrap();
        // verify algorithm
        let result = Ring::verify(&ring_params, &proof).unwrap();
        assert_eq!(result, true);
    }
}