//! Validation gate for the ceremony machinery (setup_mpc). Three decisive checks, on a small circuit
//! where we can hold a KNOWN tau and compare to arkworks element-for-element:
//!   A. iFFT identity: domain.ifft([tau^i G]) == [L_i(tau) G]  (the in-exponent Lagrange derivation).
//!   B. derive_pk matches ark-groth16's QAP (instance_map_with_evaluation) element-wise, gamma=delta=1.
//!   C. full run_ceremony (PoT + phase-2) -> prove -> arkworks verify == true.
//! If these pass, the in-exponent key derivation is exactly arkworks', and the ceremony pipeline is sound.
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, UniformRand};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_groth16::Groth16;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError, SynthesisMode};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ckb_consensus_circuit::setup_mpc::{self, Phase1};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};

#[derive(Clone)]
struct Cube { x: Option<Fr>, y: Fr }
impl ConstraintSynthesizer<Fr> for Cube {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = FpVar::new_witness(cs.clone(), || self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = FpVar::new_input(cs.clone(), || Ok(self.y))?;
        let x3 = &x * &x * &x;
        (x3 + &x + FpVar::constant(Fr::from(5u64))).enforce_equal(&y)
    }
}

fn g1(s: Fr) -> G1Affine { (G1Affine::generator().into_group() * s).into_affine() }
fn g2(s: Fr) -> G2Affine { (G2Affine::generator().into_group() * s).into_affine() }

fn main() {
    // ---- A. iFFT identity ----------------------------------------------------------------------
    {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let tau = Fr::rand(&mut rng);
        for k in [3usize, 5, 8] {
            let n = 1usize << k;
            let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
            assert_eq!(domain.size(), n);
            // powers in the exponent
            let mut pts: Vec<G1Projective> = Vec::with_capacity(n);
            let mut p = Fr::one();
            for _ in 0..n { pts.push(G1Affine::generator().into_group() * p); p *= tau; }
            domain.ifft_in_place(&mut pts);
            let lag = domain.evaluate_all_lagrange_coefficients(tau);
            for i in 0..n {
                assert_eq!(pts[i].into_affine(), g1(lag[i]), "iFFT identity failed at n={n} i={i}");
            }
        }
        println!("A. iFFT identity  domain.ifft([tau^i G]) == [L_i(tau) G]            OK");
    }

    // ---- B. derive_pk == arkworks QAP, element-wise (known tau, alpha, beta; gamma=delta=1) ------
    {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let tau = Fr::rand(&mut rng); let alpha = Fr::rand(&mut rng); let beta = Fr::rand(&mut rng);
        let y = Fr::from(3u64.pow(3) + 3 + 5);
        let circ = Cube { x: Some(Fr::from(3u64)), y };

        // size + reference QAP from arkworks
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circ.clone().generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        let num_instance = cs.num_instance_variables();
        let domain_size = cs.num_constraints() + num_instance;
        let n = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap().size();
        let (a, b, c, zt, _qap_m, m_raw) =
            LibsnarkReduction::instance_map_with_evaluation::<Fr, GeneralEvaluationDomain<Fr>>(cs, &tau).unwrap();

        // build Phase-1 from the known secrets (initial then one contribution = tau,alpha,beta)
        let mut p1 = Phase1::initial(n);
        let mut os = ark_std::rand::rngs::StdRng::seed_from_u64(99);
        p1.contribute(tau, alpha, beta, &mut os);
        let pk = setup_mpc::derive_pk(circ.clone(), &p1);

        // reference key elements (gamma=1, delta=1)
        let ref_a: Vec<G1Affine> = a.iter().map(|s| g1(*s)).collect();
        let ref_b1: Vec<G1Affine> = b.iter().map(|s| g1(*s)).collect();
        let ref_b2: Vec<G2Affine> = b.iter().map(|s| g2(*s)).collect();
        let numer: Vec<Fr> = (0..a.len()).map(|i| beta * a[i] + alpha * b[i] + c[i]).collect();
        let ref_ic: Vec<G1Affine> = numer[..num_instance].iter().map(|s| g1(*s)).collect();
        let ref_l: Vec<G1Affine> = numer[num_instance..].iter().map(|s| g1(*s)).collect();
        let ref_h: Vec<G1Affine> = (0..(m_raw - 1)).map(|i| g1(zt * tau.pow([i as u64]))).collect();

        assert_eq!(pk.a_query, ref_a, "a_query mismatch");
        assert_eq!(pk.b_g1_query, ref_b1, "b_g1 mismatch");
        assert_eq!(pk.b_g2_query, ref_b2, "b_g2 mismatch");
        assert_eq!(pk.vk.gamma_abc_g1, ref_ic, "gamma_abc/IC mismatch");
        assert_eq!(pk.l_query, ref_l, "l_query mismatch");
        assert_eq!(pk.h_query, ref_h, "h_query mismatch");
        assert_eq!(pk.vk.alpha_g1, g1(alpha), "alpha_g1 mismatch");
        assert_eq!(pk.beta_g1, g1(beta), "beta_g1 mismatch");
        assert_eq!(pk.vk.beta_g2, g2(beta), "beta_g2 mismatch");
        assert_eq!(pk.vk.gamma_g2, G2Affine::generator(), "gamma_g2 != G2 (gamma=1)");
        assert_eq!(pk.vk.delta_g2, G2Affine::generator(), "delta_g2 != G2 (delta=1)");
        assert_eq!(pk.delta_g1, G1Affine::generator(), "delta_g1 != G1 (delta=1)");
        println!("B. derive_pk == ark-groth16 QAP, element-wise (n={n})                OK");
    }

    // ---- C. full ceremony -> prove -> verify -----------------------------------------------------
    {
        let y = Fr::from(3u64.pow(3) + 3 + 5);
        let circ = Cube { x: Some(Fr::from(3u64)), y };
        let (pk, transcript) = setup_mpc::run_ceremony(circ.clone(), 3, 3, "selftest-cube");
        let mut os = setup_mpc::os_rng();
        let proof = Groth16::<Bls12_381>::prove(&pk, circ, &mut os).unwrap();
        let ok = Groth16::<Bls12_381>::verify(&pk.vk, &[y], &proof).unwrap();
        assert!(ok, "proof under ceremony key did NOT verify");
        println!("C. run_ceremony -> prove -> arkworks verify                          OK ({ok})");
        eprintln!("transcript: {}", serde_json::to_string(&transcript).unwrap());
    }

    println!("\nALL CEREMONY SELF-TESTS PASSED");
}
