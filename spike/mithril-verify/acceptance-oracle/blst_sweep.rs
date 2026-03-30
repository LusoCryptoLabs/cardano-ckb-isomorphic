use blst::min_sig::{PublicKey, Signature, AggregateSignature, AggregatePublicKey};
fn main() {
    let j: serde_json::Value = serde_json::from_reader(std::fs::File::open("points.json").unwrap()).unwrap();
    let sm = j["signed_message"].as_str().unwrap().to_string();
    let gb = |v:&serde_json::Value| -> Vec<u8> { v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect() };
    let s0=Signature::from_bytes(&gb(&j["sigs"][0])).unwrap(); let s1=Signature::from_bytes(&gb(&j["sigs"][1])).unwrap();
    let p0=PublicKey::from_bytes(&gb(&j["mvks"][0])).unwrap(); let p1=PublicKey::from_bytes(&gb(&j["mvks"][1])).unwrap();
    let c0=j["counts"][0].as_u64().unwrap() as usize; let c1=j["counts"][1].as_u64().unwrap() as usize;
    let raw32: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&sm[i*2..i*2+2],16).unwrap()).collect();
    let ascii = sm.clone().into_bytes();
    // multiplicity aggregation: each signer counted once per winning index
    let mut sig_refs: Vec<&Signature> = Vec::new();
    for _ in 0..c0 { sig_refs.push(&s0); } for _ in 0..c1 { sig_refs.push(&s1); }
    let mut pk_refs: Vec<&PublicKey> = Vec::new();
    for _ in 0..c0 { pk_refs.push(&p0); } for _ in 0..c1 { pk_refs.push(&p1); }
    let aggs = AggregateSignature::aggregate(&sig_refs, true).unwrap().to_signature();
    let aggp = AggregatePublicKey::aggregate(&pk_refs, true).unwrap().to_public_key();
    for (mn,msg) in [("raw32",&raw32),("ascii64",&ascii)] {
        for (dn,dst) in [("empty",&b""[..]),("NUL",&b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"[..]),("POP",&b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"[..])] {
            let r = aggs.verify(true, msg, dst, &[], &aggp, true);
            println!("multiplicity-agg msg={mn} dst={dn} -> {:?}", r);
        }
    }
}
