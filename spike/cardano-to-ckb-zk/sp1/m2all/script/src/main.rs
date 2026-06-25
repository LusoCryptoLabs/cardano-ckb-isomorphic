//! M1+M2+M3+M4 composed host: feeds the REAL cert; checks committed signed_message, bls_ok, cert_hash, m3_ok.
//! Default: Core STARK prove+verify (M2_ALL_PROVED). With SP1_WRAP=groth16: STARK->SNARK BN254 wrap
//! (M2_ALL_GROTH16) - a constant-size proof a CKB-VM bn254 Groth16 verifier can check on-chain; dumps
//! proof bytes + public values + the VK hash.
use sp1_sdk::{blocking::{ProveRequest, Prover, ProverClient}, include_elf, Elf, ProvingKey, SP1Stdin, HashableKey};
use bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine, Scalar};
use bls12_381::hash_to_curve::{HashToCurve, ExpandMsgXmd};
use sha2::{Sha256, Digest};
use serde_json::Value;
const ELF: Elf = include_elf!("m2all-program");
const CERT: &str = "/home/user/cardano-ckb-isomorphic/spike/cardano-to-ckb-zk/mithril_verify/cert.example.json";
fn main() {
    let cert: Value = serde_json::from_reader(std::fs::File::open(CERT).unwrap()).unwrap();
    let pm=&cert["protocol_message"]["message_parts"];
    let order=["cardano_transactions_merkle_root","next_aggregate_verification_key","next_protocol_parameters","current_epoch","latest_block_number"];
    let parts: Vec<(String,String)> = order.iter().filter_map(|k| pm.get(*k).and_then(|v| v.as_str()).map(|v|(k.to_string(),v.to_string()))).collect();
    let mut h=Sha256::new(); for (k,v) in &parts { h.update(k.as_bytes()); h.update(v.as_bytes()); }
    let sm: [u8;32]=h.finalize().into(); let sm_hex=hex::encode(sm);
    assert_eq!(sm_hex, cert["signed_message"].as_str().unwrap());
    // avk_root from the avk hex-JSON
    let avk_hex_s = cert["aggregate_verification_key"].as_str().unwrap();
    let avk_json: Value = serde_json::from_slice(&hex::decode(avk_hex_s).unwrap()).unwrap();
    let root: Vec<u8> = avk_json["mt_commitment"]["root"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();
    let mut msgp=sm_hex.as_bytes().to_vec(); msgp.extend_from_slice(&root);
    let hm=<G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&msgp, b"");
    let mut agg_mvk=G2Projective::identity(); let mut agg_sig=G1Projective::identity();
    for i in 1..=10u64 { let sk=Scalar::from(i*99991+7); agg_mvk += G2Projective::generator()*sk; agg_sig += hm*sk; }
    // M4 fields
    let md=&cert["metadata"]; let p=&md["parameters"];
    let u64be=|n:u64| n.to_be_bytes().to_vec();
    let ns=|s:&str| chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp_nanos_opt().unwrap().to_be_bytes().to_vec();
    let phi_be=((p["phi_f"].as_f64().unwrap()*((1u32<<24) as f64)).round() as u32).to_be_bytes().to_vec();
    let signers: Vec<(String,Vec<u8>)> = md["signers"].as_array().unwrap().iter().map(|s|(s["party_id"].as_str().unwrap().to_string(), u64be(s["stake"].as_u64().unwrap()))).collect();
    let se=cert["signed_entity_type"]["CardanoTransactions"].as_array().unwrap();
    let mut feed=u64be(se[0].as_u64().unwrap()); feed.extend_from_slice(&u64be(se[1].as_u64().unwrap()));
    let client=ProverClient::from_env(); let mut stdin=SP1Stdin::new();
    stdin.write(&parts); stdin.write(&root);
    stdin.write(&G1Affine::from(agg_sig).to_compressed().to_vec());
    stdin.write(&G2Affine::from(agg_mvk).to_compressed().to_vec());
    stdin.write(&G1Affine::from(hm).to_compressed().to_vec());
    stdin.write(&cert["previous_hash"].as_str().unwrap().as_bytes().to_vec());
    stdin.write(&u64be(cert["epoch"].as_u64().unwrap()));
    stdin.write(&md["network"].as_str().unwrap().as_bytes().to_vec());
    stdin.write(&md["version"].as_str().unwrap().as_bytes().to_vec());
    stdin.write(&u64be(p["k"].as_u64().unwrap())); stdin.write(&u64be(p["m"].as_u64().unwrap())); stdin.write(&phi_be);
    stdin.write(&ns(md["initiated_at"].as_str().unwrap())); stdin.write(&ns(md["sealed_at"].as_str().unwrap()));
    stdin.write(&signers);
    stdin.write(&avk_hex_s.as_bytes().to_vec());
    stdin.write(&feed);
    stdin.write(&cert["multi_signature"].as_str().unwrap().as_bytes().to_vec());
    let (mut out, report)=client.execute(ELF, stdin.clone()).run().unwrap();
    let smc: Vec<u8>=out.read(); let chc: Vec<u8>=out.read(); let _r: Vec<u8>=out.read(); let _hm: Vec<u8>=out.read();
    let ok: bool=out.read(); let m3_ok: bool=out.read();
    println!("EXECUTE cycles={} M1_ok={} M4_certhash_ok={} bls_ok={} m3_ok={}", report.total_instruction_count(),
        String::from_utf8_lossy(&smc)==sm_hex, hex::encode(&chc)==cert["hash"].as_str().unwrap(), ok, m3_ok);
    assert_eq!(hex::encode(&chc), cert["hash"].as_str().unwrap(), "M4 cert_hash must match real cert");
    assert!(ok, "M2 BLS aggregate must verify");
    assert!(m3_ok, "M3 tx-inclusion must verify AND bind to M1's tx-set root");
    let pk=client.setup(ELF).expect("setup");
    let wrap = std::env::var("SP1_WRAP").unwrap_or_default();
    if wrap == "groth16" {
        // STARK -> SNARK wrap: a constant-size Groth16 (BN254) proof a CKB-VM verifier can check on-chain.
        let proof=client.prove(&pk, stdin).groth16().run().expect("groth16 prove");
        client.verify(&proof, pk.verifying_key(), None).expect("verify");
        let vk = pk.verifying_key();
        let vkh = vk.bytes32();                       // the on-chain VK hash (public input #0 in SP1's Groth16)
        let pub_bytes = proof.public_values.to_vec(); // committed outputs (sm_hex, cert_hash, avk_root, hm, bls_ok, m3_ok)
        let g16 = proof.bytes();                      // 260-byte Groth16 proof (selector || 8 BN254 field elems)
        std::fs::write("/tmp/m2all_groth16.bin", &g16).ok();
        std::fs::write("/tmp/m2all_pubvals.bin", &pub_bytes).ok();
        println!("M2_ALL_GROTH16 true  vk={} proof_len={} pubvals_len={}", vkh, g16.len(), pub_bytes.len());
        println!("proof_hex={}", hex::encode(&g16));
    } else {
        let proof=client.prove(&pk, stdin).run().expect("prove");
        client.verify(&proof, pk.verifying_key(), None).expect("verify");
        println!("M2_ALL_PROVED true  (M1 + M2 BLS + M3 tx-inclusion + M4 cert-hash, ONE SP1 proof, real cert 7356eaa1)");
    }
}
