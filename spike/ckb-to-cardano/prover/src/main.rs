// Generate a REAL Groth16 proof over BLS12-381 (arkworks), then RE-ENCODE every curve point into the
// CIP-0381 / Plutus compressed format (the zkcrypto bls12_381 `to_compressed`, which is what the
// Cardano BLS builtins `bls12_381_G1/G2_uncompress` expect). Emits a fixture (vk, proof, public
// inputs) the Aiken Groth16 verifier consumes - so we can MEASURE the on-chain verify budget on a
// genuine proof. The circuit: prove knowledge of w1,w2,w3 with wi*wi == yi for public y1,y2,y3
// (3 public inputs - realistic for a consensus statement: header_root, seal_outpoint, commitment).
use ark_bls12_381::{Bls12_381, Fr, Fq, Fq2, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, BigInteger, Field};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;

#[derive(Clone)]
struct SquaresCircuit { w: Vec<Option<Fr>>, y: Vec<Fr> } // public yi = wi^2

impl ConstraintSynthesizer<Fr> for SquaresCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        for i in 0..self.y.len() {
            let yi = cs.new_input_variable(|| Ok(self.y[i]))?;            // public
            let wi = cs.new_witness_variable(|| self.w[i].ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_constraint(
                ark_relations::lc!() + wi, ark_relations::lc!() + wi, ark_relations::lc!() + yi)?; // wi*wi = yi
        }
        Ok(())
    }
}

// ---- re-encode arkworks points into zkcrypto/CIP-0381 compressed bytes ----
fn fq_be(x: &Fq) -> [u8;48] { let mut o=[0u8;48]; let v=x.into_bigint().to_bytes_be(); o[48-v.len()..].copy_from_slice(&v); o }
fn g1_compressed(p: &ArkG1) -> String {
    let (x,y) = p.xy().unwrap();
    let mut un = [0u8;96]; un[..48].copy_from_slice(&fq_be(&x)); un[48..].copy_from_slice(&fq_be(&y));
    let zp = bls12_381::G1Affine::from_uncompressed_unchecked(&un).unwrap();
    hex::encode(zp.to_compressed())
}
fn g2_compressed(p: &ArkG2) -> String {
    let (x,y) = p.xy().unwrap();
    // zkcrypto uncompressed G2 layout: x.c1 | x.c0 | y.c1 | y.c0  (each 48 BE)
    let mut un=[0u8;192];
    un[0..48].copy_from_slice(&fq_be(&x.c1));   un[48..96].copy_from_slice(&fq_be(&x.c0));
    un[96..144].copy_from_slice(&fq_be(&y.c1)); un[144..192].copy_from_slice(&fq_be(&y.c0));
    let zp = bls12_381::G2Affine::from_uncompressed_unchecked(&un).unwrap();
    hex::encode(zp.to_compressed())
}
fn fr_be(x: &Fr) -> String { hex::encode(x.into_bigint().to_bytes_be()) }

mod hex { pub fn encode(b: impl AsRef<[u8]>) -> String { b.as_ref().iter().map(|x| format!("{:02x}",x)).collect() } }

fn main() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
    let k = 3usize;
    let ws: Vec<Fr> = (0..k).map(|i| Fr::from((i as u64)+7)).collect();
    let ys: Vec<Fr> = ws.iter().map(|w| w.square()).collect();

    let setup_c = SquaresCircuit { w: vec![None;k], y: ys.clone() };
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(setup_c, &mut rng).unwrap();

    let prove_c = SquaresCircuit { w: ws.iter().map(|w| Some(*w)).collect(), y: ys.clone() };
    let proof = Groth16::<Bls12_381>::prove(&pk, prove_c, &mut rng).unwrap();

    // sanity: arkworks itself verifies
    let ok = Groth16::<Bls12_381>::verify(&vk, &ys, &proof).unwrap();
    eprintln!("arkworks self-verify = {ok} (public inputs k={k})");
    assert!(ok);

    // emit the fixture in CIP-0381 compressed hex
    let ic: Vec<String> = vk.gamma_abc_g1.iter().map(g1_compressed).collect();
    let inputs: Vec<String> = ys.iter().map(fr_be).collect();
    println!("{{");
    println!("  \"vk\": {{");
    println!("    \"alpha_g1\": \"{}\",", g1_compressed(&vk.alpha_g1));
    println!("    \"beta_g2\": \"{}\",", g2_compressed(&vk.beta_g2));
    println!("    \"gamma_g2\": \"{}\",", g2_compressed(&vk.gamma_g2));
    println!("    \"delta_g2\": \"{}\",", g2_compressed(&vk.delta_g2));
    println!("    \"ic\": [{}]", ic.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","));
    println!("  }},");
    println!("  \"proof\": {{ \"a\": \"{}\", \"b\": \"{}\", \"c\": \"{}\" }},",
             g1_compressed(&proof.a), g2_compressed(&proof.b), g1_compressed(&proof.c));
    println!("  \"public_inputs\": [{}]", inputs.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","));
    println!("}}");
}
