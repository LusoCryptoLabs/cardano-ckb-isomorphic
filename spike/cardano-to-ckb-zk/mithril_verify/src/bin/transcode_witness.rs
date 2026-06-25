//! transcode_witness.rs - the RELAYER transcoder: decode a real Mithril CardanoTransactions cert into a
//! compact binary WITNESS that the (parameterized) CKB-VM verifier parses and verifies. This is what lets
//! the light client advance to ANY live cert instead of an embedded fixture. Emits /tmp/cert_witness.bin.
//!
//! Layout (all integers little-endian unless noted):
//!   signed_message[32] | avk_root[32] | total_stake u64 | k u64
//!   num_parts u8, { klen u8, key[klen], vlen u16, val[vlen] }*        (M1 protocol-message parts, in order)
//!   num_signers u8, { sigma[48], mvk[96], stake u64 BE, nidx u16, idx[nidx] u32 }*
//!   nr_leaves u16 | num_mindices u8, mindices u16* | num_bvals u8, bval[32]*
//!   tx_root[32]                                                       (cardano_transactions_merkle_root)
use mithril_common::messages::CertificateMessage;
use mithril_common::entities::{Certificate, CertificateSignature};
use mithril_common::crypto_helper::ProtocolParameters as StmParameters;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_json = std::env::args().nth(1).unwrap_or("cert.example.json".into());
    let raw: serde_json::Value = serde_json::from_reader(std::fs::File::open(&cert_json)?)?;
    let cm: CertificateMessage = serde_json::from_value(raw.clone())?;
    let cert: Certificate = cm.try_into()?;
    let msig = match &cert.signature { CertificateSignature::MultiSignature(_, s) => s, _ => panic!("not standard") };
    let avk = cert.create_aggregate_verification_key();
    let params: StmParameters = cert.metadata.protocol_parameters.clone().into();
    msig.verify(cert.signed_message.as_bytes(), &avk, &params)?;  // ground truth

    let cp = (*msig).to_concatenation_proof().expect("concatenation");
    let j = serde_json::to_value(cp)?;
    let avk_hex = raw["aggregate_verification_key"].as_str().unwrap();
    let avk_json: serde_json::Value = serde_json::from_slice(&hex::decode(avk_hex)?)?;
    let avk_root: Vec<u8> = avk_json["mt_commitment"]["root"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();
    let nr_leaves = avk_json["mt_commitment"]["nr_leaves"].as_u64().unwrap() as u16;
    let total = avk_json["total_stake"].as_u64().unwrap();

    let mut w: Vec<u8> = Vec::new();
    w.extend_from_slice(b"MWIT");  // magic: the verifier finds this cell among cellDeps
    let sm = hex::decode(&cert.signed_message)?;             // 32-byte digest
    w.extend_from_slice(&sm);
    w.extend_from_slice(&avk_root);
    w.extend_from_slice(&total.to_le_bytes());
    w.extend_from_slice(&(params.k as u64).to_le_bytes());

    // M1 parts in canonical (JSON) order - works for any cert type (preserve_order feature)
    let pm = &raw["protocol_message"]["message_parts"];
    let parts: Vec<(String,String)> = pm.as_object().unwrap().iter().map(|(k,v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
    w.push(parts.len() as u8);
    for (k,v) in &parts {
        w.push(k.len() as u8); w.extend_from_slice(k.as_bytes());
        w.extend_from_slice(&(v.len() as u16).to_le_bytes()); w.extend_from_slice(v.as_bytes());
    }
    // signers
    let sigs = j["signatures"].as_array().unwrap();
    w.push(sigs.len() as u8);
    for sg in sigs {
        let a = sg.as_array().unwrap();
        let sigma: Vec<u8> = a[0]["sigma"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();
        let mvk: Vec<u8> = a[1][0].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();
        let stake = a[1][1].as_u64().unwrap();
        let idx: Vec<u32> = a[0]["indexes"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect();
        w.extend_from_slice(&sigma); w.extend_from_slice(&mvk);
        w.extend_from_slice(&stake.to_be_bytes());
        w.extend_from_slice(&(idx.len() as u16).to_le_bytes());
        for i in &idx { w.extend_from_slice(&i.to_le_bytes()); }
    }
    // merkle batch
    w.extend_from_slice(&nr_leaves.to_le_bytes());
    let mindices = j["batch_proof"]["indices"].as_array().unwrap();
    w.push(mindices.len() as u8);
    for m in mindices { w.extend_from_slice(&(m.as_u64().unwrap() as u16).to_le_bytes()); }
    let bvals = j["batch_proof"]["values"].as_array().unwrap();
    w.push(bvals.len() as u8);
    for b in bvals { let bb: Vec<u8> = b.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect(); w.extend_from_slice(&bb); }
    // tx_root (cardano_transactions_merkle_root if present, else 32 zero bytes)
    let tx_root = match pm.get("cardano_transactions_merkle_root").and_then(|v| v.as_str()) { Some(h)=>hex::decode(h)?, None=>vec![0u8;32] };
    w.extend_from_slice(&tx_root);

    std::fs::write("/tmp/cert_witness.bin", &w)?;
    println!("WITNESS {} bytes; signers={} parts={} nr_leaves={} signed_message={}", w.len(), sigs.len(), parts.len(), nr_leaves, cert.signed_message);
    Ok(())
}
