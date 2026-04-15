//! Eaglesong gadget bench: isolate the constraint count of CKB's Eaglesong PoW hash (R1) and time a
//! Groth16 setup+prove+verify of an N-Eaglesong circuit (EAG_N independent 48-byte invocations).
//!   EAG_N=1 cargo run --release --bin eag_bench
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use std::time::Instant;
use ckb_consensus_circuit::eaglesong_gadget;

#[derive(Clone)]
struct EagN { input: Vec<u8>, n: usize }
impl ConstraintSynthesizer<Fr> for EagN {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let inp: Vec<UInt8<Fr>> = self.input.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
        let mut last: Option<Vec<UInt8<Fr>>> = None;
        for _ in 0..self.n {
            let out = eaglesong_gadget::eaglesong(&inp)?;   // 48B -> 32B, exactly R1's invocation
            // keep the output live by chaining an equality so nothing is trivially dropped
            if let Some(prev) = &last { for i in 0..32 { out[i].enforce_equal(&prev[i])?; } }
            last = Some(out);
        }
        Ok(())
    }
}

fn main() {
    let n: usize = std::env::var("EAG_N").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let input = vec![7u8; 48];
    let circ = EagN { input, n };
    let cs = ConstraintSystem::<Fr>::new_ref();
    circ.clone().generate_constraints(cs.clone()).unwrap();
    let nc = cs.num_constraints();
    eprintln!("EAG_N={} CONSTRAINTS={} (per-eaglesong ~{})", n, nc, nc / n.max(1));
    if std::env::var("COUNT_ONLY").is_ok() { return; }
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
    let t0 = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(), &mut rng).unwrap();
    let t_setup = t0.elapsed();
    let t1 = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circ, &mut rng).unwrap();
    let t_prove = t1.elapsed();
    let ok = Groth16::<Bls12_381>::verify(&vk, &[], &proof).unwrap();
    eprintln!("setup={:.3}s  prove={:.3}s  verify_ok={}", t_setup.as_secs_f64(), t_prove.as_secs_f64(), ok);
}
