//! Generate a self-contained, internally-consistent FINALIZE dataset and print it as JSON. Mirrors the
//! verifier's hashing exactly: leaf = ascii_hex(blake2b256(tx_body)); MMR merge = Blake2s256;
//! master_leaf = blake2s256(range_key ‖ sub_root). We BUILD the MMRs with the same crate the verifier uses,
//! so the proofs verify by construction, and we set the checkpoint root = our master root.
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{Merge, Result as MMRResult, util::{MemMMR, MemStore}};

#[derive(Clone, PartialEq, Eq, Debug)]
struct N(Vec<u8>);
struct MB;
impl Merge for MB {
    type Item = N;
    fn merge(l: &N, r: &N) -> MMRResult<N> {
        let mut h = Blake2s256::new();
        h.update(&l.0);
        h.update(&r.0);
        Ok(N(h.finalize().to_vec()))
    }
}
fn b2b256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).build();
    for p in parts { h.update(p); }
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o
}
fn b2s(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Blake2s256::new();
    for p in parts { h.update(p); }
    h.finalize().to_vec()
}
fn hexb(b: &[u8]) -> Vec<u8> {
    let hx = b"0123456789abcdef";
    let mut o = Vec::new();
    for &x in b { o.push(hx[(x >> 4) as usize]); o.push(hx[(x & 0xf) as usize]); }
    o
}
fn hx(b: &[u8]) -> String { hexb(b).into_iter().map(|c| c as char).collect() }

// ---- minimal Cardano tx_body CBOR: { 0: [[seal_txid(32), seal_idx]], 1: [[addr(28), coin]] } ----
fn cbor_txbody(seal_txid: &[u8; 32], seal_idx: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(0xA2); // map(2)
    // key 0 (inputs)
    b.push(0x00);
    b.push(0x81); // array(1)
    b.push(0x82); // array(2): [txid, idx]
    b.push(0x58); b.push(0x20); b.extend_from_slice(seal_txid); // bytes(32)
    // idx as uint
    if seal_idx < 24 { b.push(seal_idx as u8); } else { b.push(0x1a); b.extend_from_slice(&seal_idx.to_be_bytes()); }
    // key 1 (outputs) - one legacy-array output NOT at LOCK_ADDR (28 bytes of 0x11), coin 1_000_000
    b.push(0x01);
    b.push(0x81); // array(1)
    b.push(0x82); // array(2): [addr, coin]
    b.push(0x58); b.push(0x1c); b.extend_from_slice(&[0x11u8; 28]); // bytes(28) != LOCK_ADDR
    b.push(0x1a); b.extend_from_slice(&1_000_000u32.to_be_bytes()); // coin uint32
    b
}

// ---- witness encoder (the verifier's R layout) ----
fn lp(x: &[u8], o: &mut Vec<u8>) { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x); }
fn items(xs: &[Vec<u8>], o: &mut Vec<u8>) { o.extend_from_slice(&(xs.len() as u32).to_le_bytes()); for x in xs { lp(x, o); } }
fn u64le(n: u64, o: &mut Vec<u8>) { o.extend_from_slice(&n.to_le_bytes()); }

fn main() {
    let seal_txid = [0xABu8; 32];
    let seal_idx: u32 = 0;
    let state = b"bound-asset:demo:v1".to_vec();
    let range_key = b"4355040-4355055".to_vec();

    let tx_body = cbor_txbody(&seal_txid, seal_idx);
    let th = b2b256(&[&tx_body]);
    let leaf = N(hexb(&th)); // ascii-hex of blake2b256(tx_body), exactly as the verifier builds it

    // sub MMR: a few leaves incl. ours
    let sub_store = MemStore::default(); let mut sub = MemMMR::<N, MB>::new(0, &sub_store);
    let _ = sub.push(N(b2s(&[b"sib0"]))).unwrap();
    let sub_pos = sub.push(leaf.clone()).unwrap();
    let _ = sub.push(N(b2s(&[b"sib2"]))).unwrap();
    let sub_root = sub.get_root().unwrap();
    let sub_proof = sub.gen_proof(vec![sub_pos]).unwrap();
    let sub_size = sub_proof.mmr_size();
    let sub_items: Vec<Vec<u8>> = sub_proof.proof_items().iter().map(|n| n.0.clone()).collect();

    // master MMR over (range_key ‖ sub_root) leaves
    let master_leaf = N(b2s(&[&range_key, &sub_root.0]));
    let master_store = MemStore::default(); let mut master = MemMMR::<N, MB>::new(0, &master_store);
    let _ = master.push(N(b2s(&[b"m0"]))).unwrap();
    let _ = master.push(N(b2s(&[b"m1"]))).unwrap();
    let master_pos = master.push(master_leaf.clone()).unwrap();
    let _ = master.push(N(b2s(&[b"m3"]))).unwrap();
    let cert_root = master.get_root().unwrap();
    let master_proof = master.gen_proof(vec![master_pos]).unwrap();
    let master_size = master_proof.mmr_size();
    let master_items: Vec<Vec<u8>> = master_proof.proof_items().iter().map(|n| n.0.clone()).collect();

    // encode the witness (the same bytes mithril_proof.mjs::encodeFinalizeWitness must produce)
    let mut w = Vec::new();
    lp(&tx_body, &mut w);
    lp(&sub_root.0, &mut w); u64le(sub_pos, &mut w); u64le(sub_size, &mut w); items(&sub_items, &mut w);
    lp(&range_key, &mut w); u64le(master_pos, &mut w); u64le(master_size, &mut w); items(&master_items, &mut w);

    // bound cell data = seal_txid(32) ‖ seal_idx(u32 LE) ‖ state
    let mut bound = Vec::new();
    bound.extend_from_slice(&seal_txid);
    bound.extend_from_slice(&seal_idx.to_le_bytes());
    bound.extend_from_slice(&state);

    let arr = |xs: &[Vec<u8>]| xs.iter().map(|x| format!("\"{}\"", hx(x))).collect::<Vec<_>>().join(",");
    println!("{{");
    println!("  \"tx_body\": \"{}\",", hx(&tx_body));
    println!("  \"bound_data\": \"{}\",", hx(&bound));
    println!("  \"cert_root\": \"{}\",", hx(&cert_root.0));
    println!("  \"witness\": \"{}\",", hx(&w));
    println!("  \"components\": {{");
    println!("    \"sub_root\": \"{}\", \"sub_pos\": {}, \"sub_size\": {}, \"sub_items\": [{}],", hx(&sub_root.0), sub_pos, sub_size, arr(&sub_items));
    println!("    \"range_key\": \"{}\", \"master_pos\": {}, \"master_size\": {}, \"master_items\": [{}]", hx(&range_key), master_pos, master_size, arr(&master_items));
    println!("  }}");
    println!("}}");
}
