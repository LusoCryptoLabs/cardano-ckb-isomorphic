//! M2 host: prove (in SP1) that the real Mithril cert's signed_message = Sha256(protocol_message) (M1).
use sp1_sdk::{blocking::{ProveRequest, Prover, ProverClient}, include_elf, Elf, ProvingKey, SP1Stdin};
use serde_json::Value;
const ELF: Elf = include_elf!("m2-program");
const CERT: &str = "/home/user/cardano-ckb-isomorphic/spike/cardano-to-ckb-zk/mithril_verify/cert.example.json";
fn main() {
    let cert: Value = serde_json::from_reader(std::fs::File::open(CERT).unwrap()).unwrap();
    let pm = &cert["protocol_message"]["message_parts"];
    let order = ["cardano_transactions_merkle_root","next_aggregate_verification_key","next_protocol_parameters","current_epoch","latest_block_number"];
    let parts: Vec<(String,String)> = order.iter()
        .filter_map(|k| pm.get(*k).and_then(|v| v.as_str()).map(|v| (k.to_string(), v.to_string()))).collect();
    let expected = cert["signed_message"].as_str().unwrap().to_string();
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&parts);
    let (mut output, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    let digest: [u8;32] = output.read();
    println!("EXECUTE cycles={} digest={} match={}", report.total_instruction_count(), hex::encode(digest), hex::encode(&digest)==expected);
    assert_eq!(hex::encode(&digest), expected, "guest digest must equal real cert signed_message");
    let pk = client.setup(ELF).expect("setup");
    let proof = client.prove(&pk, stdin).run().expect("prove");
    client.verify(&proof, pk.verifying_key(), None).expect("verify");
    println!("M2_M1_PROVED true  (Mithril signed_message proven in SP1 zkVM, verified)");
}
