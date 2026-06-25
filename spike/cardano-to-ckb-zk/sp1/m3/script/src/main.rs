//! M3 host: prove (in SP1) a Mithril MKMapProof - a real Cardano tx is in the certified tx-set root.
use sp1_sdk::{blocking::{ProveRequest, Prover, ProverClient}, include_elf, Elf, ProvingKey, SP1Stdin};
const ELF: Elf = include_elf!("m3-program");
fn main() {
    let client = ProverClient::from_env();
    let stdin = SP1Stdin::new();
    let (mut out, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    let root: Vec<u8> = out.read(); let ok: bool = out.read();
    println!("EXECUTE cycles={} cert_root={} tx_in_root={}", report.total_instruction_count(), hex::encode(&root), ok);
    assert!(ok, "tx must be proven in the certified root");
    let pk = client.setup(ELF).expect("setup");
    let proof = client.prove(&pk, stdin).run().expect("prove");
    client.verify(&proof, pk.verifying_key(), None).expect("verify");
    println!("M3_PROVED true  (real Cardano tx-inclusion in the certified Mithril root, SP1 zkVM)");
}
