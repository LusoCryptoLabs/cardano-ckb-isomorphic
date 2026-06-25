//! Groth16 Phase-2 trusted-setup CEREMONY (multi-party). Each contributor re-randomizes delta with a
//! secret s (destroyed after): delta *= s in G1/G2, and h_query,l_query *= s^{-1}. The final toxic
//! delta = delta_0 * prod(s_i) is unknown unless ALL contributors collude - secure if >=1 is honest.
//! Each contribution is publicly VERIFIABLE (no secrets) via pairing checks. Phase-1 (alpha,beta,tau)
//! must come from a universal Powers-of-Tau (e.g. the perpetual PoT) - that's the per-circuit-independent
//! input; this is the circuit-specific phase-2. Demonstrated on a small circuit; the identical transform
//! applies to the leap/advance proving keys (relay_prove can call contribute() on its pk in production).
use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
#[allow(unused_imports)] use ark_ec::AffineRepr as _;
use ark_ff::{PrimeField, BigInteger, Field};
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::{fields::fp::FpVar, fields::FieldVar, alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK; use ark_std::{rand::SeedableRng, UniformRand};

// small but real circuit: y = x^3 + x + 5 (1 public input)
#[derive(Clone)] struct Cube { x: Option<Fr>, y: Fr }
impl ConstraintSynthesizer<Fr> for Cube {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = FpVar::new_witness(cs.clone(), || self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = FpVar::new_input(cs.clone(), || Ok(self.y))?;
        let x3 = &x * &x * &x;
        (x3 + &x + FpVar::constant(Fr::from(5u64))).enforce_equal(&y)
    }
}
// SEC D6: a contribution carries a Schnorr PROOF-OF-KNOWLEDGE of the secret `s` (delta_new = s·delta_old).
// Without it a "rogue" contributor could publish a delta_new whose relationship to delta_old they do NOT
// know honestly (e.g. derived from another party's contribution), and the plain ratio check would still
// pass - breaking the "≥1 honest party ⇒ secure" guarantee. The PoK is a standard Σ-protocol on the
// discrete-log ratio in G1, made non-interactive with a Fiat–Shamir challenge bound to (old,new) deltas.
#[derive(Clone)]
struct Pok { k_g1: ArkG1, z: Fr }
fn fs_challenge(old_g1: &ArkG1, new_g1: &ArkG1, k_g1: &ArkG1) -> Fr {
    // Fiat–Shamir: hash the transcript to a scalar. Binds the PoK to THIS contribution.
    let mut h = blake2b_rs::Blake2bBuilder::new(32).build();
    for p in [old_g1, new_g1, k_g1] { h.update(&g1_bytes(p)); }
    let mut o=[0u8;32]; h.finalize(&mut o); Fr::from_le_bytes_mod_order(&o)
}
fn g1_bytes(p:&ArkG1)->[u8;96]{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;96]; u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y)); u }

// a contributor applies secret s: delta *= s (G1,G2); h_query,l_query *= s^{-1}; returns a PoK of s.
fn contribute<R: ark_std::rand::Rng>(pk: &mut ProvingKey<Bls12_381>, s: Fr, rng: &mut R) -> Pok {
    let old_g1 = pk.delta_g1;
    let si = s.inverse().unwrap();
    pk.vk.delta_g2 = (pk.vk.delta_g2 * s).into_affine();
    pk.delta_g1    = (pk.delta_g1 * s).into_affine();
    for h in pk.h_query.iter_mut() { *h = (*h * si).into_affine(); }
    for l in pk.l_query.iter_mut() { *l = (*l * si).into_affine(); }
    // Σ-protocol PoK of s s.t. delta_new = s·delta_old (in G1): commit k·delta_old, respond z = k + c·s.
    let k = Fr::rand(rng);
    let k_g1 = (old_g1 * k).into_affine();
    let c = fs_challenge(&old_g1, &pk.delta_g1, &k_g1);
    let z = k + c * s;
    Pok { k_g1, z }
}
// public verification of a contribution (no secret): the delta ratio is consistent across G1/G2, h,l are
// scaled by the inverse, AND the Schnorr PoK proves the contributor KNEW the secret s.
fn verify_contribution(old:&ProvingKey<Bls12_381>, new:&ProvingKey<Bls12_381>, pok:&Pok) -> bool {
    // ratios (arkworks uses random generators, so generators cancel): same s scales delta in G1 and G2.
    let same_ratio = Bls12_381::pairing(new.delta_g1, old.vk.delta_g2) == Bls12_381::pairing(old.delta_g1, new.vk.delta_g2);
    let h_ok = old.h_query.iter().zip(&new.h_query).all(|(o,n)| Bls12_381::pairing(*n,new.vk.delta_g2)==Bls12_381::pairing(*o,old.vk.delta_g2));
    let l_ok = old.l_query.iter().zip(&new.l_query).all(|(o,n)| Bls12_381::pairing(*n,new.vk.delta_g2)==Bls12_381::pairing(*o,old.vk.delta_g2));
    // SEC D6: Schnorr PoK - z·delta_old == k_commit + c·delta_new  (knowledge of s with delta_new=s·delta_old).
    let c = fs_challenge(&old.delta_g1, &new.delta_g1, &pok.k_g1);
    let lhs = (old.delta_g1 * pok.z).into_affine();
    let rhs = (pok.k_g1.into_group() + new.delta_g1 * c).into_affine();
    let pok_ok = lhs == rhs;
    same_ratio && h_ok && l_ok && pok_ok
}
fn fq_be(x:&Fq)->[u8;48]{ let mut o=[0u8;48]; let v=x.into_bigint().to_bytes_be(); o[48-v.len()..].copy_from_slice(&v); o }
fn g1c(p:&ArkG1)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;96]; u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y)); hexs(bls12_381::G1Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn g2c(p:&ArkG2)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;192]; u[0..48].copy_from_slice(&fq_be(&x.c1)); u[48..96].copy_from_slice(&fq_be(&x.c0)); u[96..144].copy_from_slice(&fq_be(&y.c1)); u[144..192].copy_from_slice(&fq_be(&y.c0)); hexs(bls12_381::G2Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn hexs(b:impl AsRef<[u8]>)->String{ b.as_ref().iter().map(|x| format!("{:02x}",x)).collect() }
fn fr_dec(x:&Fr)->String{ x.into_bigint().to_string() }

fn main(){
    // SEC D6: contributor secrets are drawn from OS entropy (was a deterministic seed → recoverable toxic
    // waste). In a REAL ceremony each `s` is generated on a separate offline machine and destroyed there;
    // here we draw from the OS CSPRNG and drop it. The setup-RNG below stands in for the phase-1/PoT output.
    let mut setup_rng = ark_std::rand::rngs::StdRng::seed_from_u64(1);
    let mut os = { use std::io::Read; let mut seed=[0u8;32]; std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed).unwrap(); ark_std::rand::rngs::StdRng::from_seed(seed) };
    let y = Fr::from(3u64.pow(3) + 3 + 5);                  // x=3 -> y=35
    // INITIAL params (stand-in for phase-1/PoT output). Its delta_0 is "known" - the ceremony erases it.
    // NOTE: `contribute()` only transforms pk.{delta_g1,delta_g2,h_query,l_query} - it is CIRCUIT-AGNOSTIC,
    // so the IDENTICAL multi-party flow applies to the real leap/advance proving keys (the production
    // ceremony runs these same contributions + PoK on leap_prove's pk). The TRUST (≥1 honest party who
    // destroys their s) is inherently external and cannot be provided in-sandbox.
    let (mut pk, _vk0) = Groth16::<Bls12_381>::circuit_specific_setup(Cube{x:None,y}, &mut setup_rng).unwrap();
    eprintln!("ceremony: initial params generated (phase-1/PoT assumed external). running phase-2 contributions:");
    for i in 0..3 {
        let before = pk.clone();
        let s = Fr::rand(&mut os);                           // contributor i's SECRET (OS entropy; destroyed here)
        let pok = contribute(&mut pk, s, &mut os);
        let ok = verify_contribution(&before, &pk, &pok);
        eprintln!("  contributor {}: applied secret + Schnorr PoK, contribution verifiable = {}", i+1, ok);
        assert!(ok, "contribution {} failed verification", i+1);
        // SEC D6: a ROGUE contribution (valid delta ratio but a FORGED PoK) must be REJECTED.
        let mut forged = pok.clone(); forged.z += Fr::from(1u64);
        assert!(!verify_contribution(&before, &pk, &forged), "a forged-PoK contribution must be rejected");
    }
    eprintln!("ceremony: rogue-contribution (forged PoK) rejected at every step ✓");
    let vk = pk.vk.clone();
    // prove with the ceremonied key; verify
    let proof = Groth16::<Bls12_381>::prove(&pk, Cube{x:Some(Fr::from(3u64)), y}, &mut os).unwrap();
    let ok = Groth16::<Bls12_381>::verify(&vk, &[y], &proof).unwrap();
    eprintln!("ceremony: proof under the multi-party key verifies = {}", ok); assert!(ok);
    let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    let out=serde_json::json!({
      "note":"Groth16 key from a 3-party phase-2 ceremony (delta secret unknown unless all collude)",
      "vk":{"alpha_g1":g1c(&vk.alpha_g1),"beta_g2":g2c(&vk.beta_g2),"gamma_g2":g2c(&vk.gamma_g2),"delta_g2":g2c(&vk.delta_g2),"ic":ic},
      "proof":{"a":g1c(&proof.a),"b":g2c(&proof.b),"c":g1c(&proof.c)},
      "public_inputs_dec":[fr_dec(&y)]
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
