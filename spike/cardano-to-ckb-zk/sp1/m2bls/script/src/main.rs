//! M2 host: aggregate a BLS12-381 signature (10 signers) and PROVE the pairing verification in SP1
//! (precompile-accelerated). H(msg) computed here and passed to the guest.
use sp1_sdk::{blocking::{ProveRequest, Prover, ProverClient}, include_elf, Elf, ProvingKey, SP1Stdin};
use bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine, Scalar};
use bls12_381::hash_to_curve::{HashToCurve, ExpandMsgXmd};
const ELF: Elf = include_elf!("m2bls-program");
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_M2_";
fn main() {
    let msg = b"mithril stm aggregate demo".to_vec();
    let hm = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(&msg, DST);
    let hm_aff = G2Affine::from(hm);
    let mut agg_pk = G1Projective::identity();
    let mut agg_sig = G2Projective::identity();
    for i in 1..=10u64 {
        let sk = Scalar::from(i * 1234567 + 89);
        agg_pk += G1Projective::generator() * sk;
        agg_sig += hm * sk;
    }
    let pk_c = G1Affine::from(agg_pk).to_compressed().to_vec();
    let sig_c = G2Affine::from(agg_sig).to_compressed().to_vec();
    let hm_c = hm_aff.to_compressed().to_vec();
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&pk_c); stdin.write(&sig_c); stdin.write(&hm_c);
    let (mut out, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    let ok: bool = out.read();
    println!("EXECUTE cycles={} bls_aggregate_verify={}", report.total_instruction_count(), ok);
    assert!(ok, "BLS aggregate verify must pass");
    let pk = client.setup(ELF).expect("setup");
    let proof = client.prove(&pk, stdin).run().expect("prove");
    client.verify(&proof, pk.verifying_key(), None).expect("verify");
    println!("M2_BLS_PROVED true  (BLS12-381 aggregate signature verified in SP1 zkVM, precompile-accelerated)");
}
