//// Groth16 verifier over BLS12-381 using the Plutus builtins (CIP-0381). Verification equation:
////   e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta),  vk_x = IC[0] + Σ inputᵢ·IC[i].
//// Implemented as one final_verify over a product of four Miller loops. This is the on-chain
//// SNARK verifier for the CKB->Cardano leg (it would check a proof of a CKB seal-spend).
use aiken/builtin.{
  bls12_381_g1_uncompress as g1, bls12_381_g2_uncompress as g2,
  bls12_381_g1_add as g1_add, bls12_381_g1_scalar_mul as g1_mul,
  bls12_381_miller_loop as ml, bls12_381_mul_miller_loop_result as ml_mul,
  bls12_381_final_verify as final_verify,
}
use aiken/collection/list

pub type VerifyingKey {
  alpha_g1: ByteArray,
  beta_g2: ByteArray,
  gamma_g2: ByteArray,
  delta_g2: ByteArray,
  ic: List<ByteArray>,
}

pub type Proof {
  a: ByteArray,
  b: ByteArray,
  c: ByteArray,
}

// vk_x = IC[0] + Σ inputᵢ · IC[i+1]   (the public-input linear combination, a small G1 MSM)
fn msm(acc, inputs: List<Int>, ics: List<ByteArray>) {
  when inputs is {
    [] -> acc
    [i, ..irest] ->
      when ics is {
        [] -> acc
        [g, ..grest] -> msm(g1_add(acc, g1_mul(i, g1(g))), irest, grest)
      }
  }
}

pub fn verify(vk: VerifyingKey, proof: Proof, inputs: List<Int>) -> Bool {
  expect [ic0, ..ic_rest] = vk.ic
  // SEC B5: pin the public-input count to exactly length(ic)-1, so `msm` can't silently drop or
  // under-count inputs on a length mismatch (which would compute a vk_x different from the circuit's).
  expect list.length(inputs) == list.length(ic_rest)
  let vk_x = msm(g1(ic0), inputs, ic_rest)
  let ml_ab = ml(g1(proof.a), g2(proof.b))
  let ml_x = ml(vk_x, g2(vk.gamma_g2))
  let ml_c = ml(g1(proof.c), g2(vk.delta_g2))
  let ml_alpha = ml(g1(vk.alpha_g1), g2(vk.beta_g2))
  let rhs = ml_mul(ml_x, ml_mul(ml_c, ml_alpha))
  final_verify(ml_ab, rhs)
}
