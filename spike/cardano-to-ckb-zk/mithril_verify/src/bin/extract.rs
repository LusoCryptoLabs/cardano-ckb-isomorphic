//! extract.rs - decode the REAL CardanoTransactions cert's multi_signature into the constants a CKB-VM
//! TxSetCert verifier needs (per-signer sigma/vk/stake/indexes, avk root, signed_message, params), and
//! RE-VERIFY them on the host so the embedded constants are proven correct before they go on-chain.
use mithril_common::messages::CertificateMessage;
use mithril_common::entities::{Certificate, CertificateSignature};
use mithril_common::crypto_helper::ProtocolParameters as StmParameters;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_json = std::env::args().nth(1).unwrap_or("cert.example.json".into());
    let cm: CertificateMessage = serde_json::from_reader(std::fs::File::open(&cert_json)?)?;
    let cert: Certificate = cm.try_into()?;
    let msig = match &cert.signature {
        CertificateSignature::MultiSignature(_, s) => s,
        _ => panic!("not a standard certificate"),
    };
    let avk = cert.create_aggregate_verification_key();
    let params: StmParameters = cert.metadata.protocol_parameters.clone().into();
    // host re-verify (ground truth)
    msig.verify(cert.signed_message.as_bytes(), &avk, &params)?;
    println!("HOST_VERIFY ok; signed_message={}", cert.signed_message);
    println!("params k={} m={} phi_f={:?}", params.k, params.m, params.phi_f);

    // extract via the concatenation proof (signatures pub(crate); reach them through Serialize)
    let cp = (*msig).to_concatenation_proof().expect("concatenation proof");
    let j = serde_json::to_value(cp).expect("cp serialize");
    match j.as_object() {
        Some(o) => {
            println!("CP_KEYS={:?}", o.keys().cloned().collect::<Vec<_>>());
            if let Some(sigs)=o.get("signatures").and_then(|v| v.as_array()) {
                println!("num_signers={}", sigs.len());
                for (n,sg) in sigs.iter().enumerate() {
                    let a=sg.as_array().unwrap();
                    println!("SIG{}_PART0={}", n, serde_json::to_string(&a[0]).unwrap());
                    println!("SIG{}_PART1={}", n, serde_json::to_string(&a[1]).unwrap());
                }
            }
            if let Some(bp)=o.get("batch_proof") {
                println!("BATCH_PROOF={}", serde_json::to_string(bp).unwrap().chars().take(500).collect::<String>());
            }
        }
        None => println!("CP serialized as non-object: {}", serde_json::to_string(&j).unwrap().chars().take(200).collect::<String>()),
    }
    // dump the full extracted constant set for the CKB TxSetCert verifier
    let avk_hex = cert_avk_hex(&cert_json);
    let avk_json: serde_json::Value = serde_json::from_slice(&hex::decode(&avk_hex).unwrap()).unwrap();
    let out = serde_json::json!({
        "signed_message": cert.signed_message,
        "avk_root": avk_json["mt_commitment"]["root"],
        "total_stake": avk_json["total_stake"],
        "params": {"k": params.k, "m": params.m, "phi_f": format!("{:?}", params.phi_f)},
        "concatenation_proof": j,
    });
    std::fs::write("/tmp/tx_cert_constants.json", serde_json::to_string_pretty(&out).unwrap()).unwrap();
    println!("DUMPED /tmp/tx_cert_constants.json");
    println!("AVK_HEX={}", avk_hex);
    Ok(())
}
fn cert_avk_hex(path:&str)->String{
    let v: serde_json::Value = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
    v["aggregate_verification_key"].as_str().unwrap_or("").to_string()
}
