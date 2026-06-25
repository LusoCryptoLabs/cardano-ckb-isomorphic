//! M2 core (BLS aggregate) - optimized to ONE multi-Miller-loop + ONE final-exponentiation:
//!   e(agg_pk, H(msg)) == e(g1, agg_sig)  <=>  e(agg_pk,H) * e(-g1, agg_sig) == 1
//! halves the final-exp cost vs two pairing() calls, to fit the SP1 prover in 15GB.
#![no_main]
sp1_zkvm::entrypoint!(main);
use bls12_381::{G1Affine, G2Affine, G2Prepared, multi_miller_loop, Gt};
use core::ops::Neg;
pub fn main() {
    let pk_v: Vec<u8> = sp1_zkvm::io::read();
    let sig_v: Vec<u8> = sp1_zkvm::io::read();
    let hm_v: Vec<u8> = sp1_zkvm::io::read();
    let pk_b: [u8;48] = pk_v.try_into().unwrap();
    let sig_b: [u8;96] = sig_v.try_into().unwrap();
    let hm_b: [u8;96] = hm_v.try_into().unwrap();
    let agg_pk = G1Affine::from_compressed(&pk_b).unwrap();
    let agg_sig = G2Affine::from_compressed(&sig_b).unwrap();
    let hm = G2Affine::from_compressed(&hm_b).unwrap();
    let neg_g1 = G1Affine::generator().neg();
    let hm_p = G2Prepared::from(hm);
    let sig_p = G2Prepared::from(agg_sig);
    let ml = multi_miller_loop(&[(&agg_pk, &hm_p), (&neg_g1, &sig_p)]);
    let ok = ml.final_exponentiation() == Gt::identity();
    sp1_zkvm::io::commit(&ok);
}
