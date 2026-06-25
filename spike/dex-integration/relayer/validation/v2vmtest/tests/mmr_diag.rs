//! Diagnostic: run the EXACT bound_asset_v2 MKMapProof verify (sub + master) on the REAL Mithril witness
//! captured from the live seal-mint tx, to isolate whether the on-chain -1 panic is in the MMR verify.
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
use blake2::{Blake2s256, Digest};

#[derive(Clone, PartialEq, Eq, Debug)]
struct N(Vec<u8>);
struct MB;
impl Merge for MB { type Item = N; fn merge(l: &N, r: &N) -> MMRResult<N> { let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(p: &[&[u8]]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).build(); for x in p { h.update(x); } let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn b2s(p: &[&[u8]]) -> Vec<u8> { let mut h = Blake2s256::new(); for x in p { h.update(x); } h.finalize().to_vec() }
fn hexb(b: &[u8]) -> Vec<u8> { let hx = b"0123456789abcdef"; let mut o = Vec::new(); for &x in b { o.push(hx[(x >> 4) as usize]); o.push(hx[(x & 0xf) as usize]); } o }
fn hx(s: &str) -> Vec<u8> { let s = s.trim(); (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

struct R<'a> { b: &'a [u8], i: usize }
impl<'a> R<'a> {
    fn u32(&mut self) -> usize { if self.i + 4 > self.b.len() { self.i = self.b.len(); return 0; } let v = u32::from_le_bytes([self.b[self.i], self.b[self.i + 1], self.b[self.i + 2], self.b[self.i + 3]]) as usize; self.i += 4; v }
    fn u64(&mut self) -> u64 { if self.i + 8 > self.b.len() { self.i = self.b.len(); return 0; } let mut a = [0u8; 8]; a.copy_from_slice(&self.b[self.i..self.i + 8]); self.i += 8; u64::from_le_bytes(a) }
    fn lp(&mut self) -> &'a [u8] { let n = self.u32(); if self.i + n > self.b.len() { self.i = self.b.len(); return &[]; } let s = &self.b[self.i..self.i + n]; self.i += n; s }
    fn items(&mut self) -> Vec<N> { let n = self.u32(); if n > self.b.len() { return Vec::new(); } (0..n).map(|_| N(self.lp().to_vec())).collect() }
}

#[test]
fn mmr_verify_real_proof() {
    let wit = hx(&std::fs::read_to_string("/tmp/wit.hex").unwrap());
    let cert_root = hx(&std::fs::read_to_string("/tmp/root.hex").unwrap());
    let mut r = R { b: &wit, i: 0 };
    let tx_body = r.lp().to_vec();
    let sub_root = r.lp().to_vec(); let sub_pos = r.u64(); let sub_size = r.u64(); let sub_items = r.items();
    let range_key = r.lp().to_vec();
    let master_pos = r.u64(); let master_size = r.u64(); let master_items = r.items();
    let th = b2b256(&[&tx_body]); let leaf = N(hexb(&th));
    eprintln!("sub: pos={} size={} items={} | master: pos={} size={} items={}", sub_pos, sub_size, sub_items.len(), master_pos, master_size, master_items.len());
    let sub_ok = MerkleProof::<N, MB>::new(sub_size, sub_items).verify(N(sub_root.clone()), [(sub_pos, leaf)].to_vec()).unwrap_or(false);
    eprintln!("sub_ok = {}", sub_ok);
    let master_leaf = N(b2s(&[&range_key, &sub_root]));
    let master_ok = MerkleProof::<N, MB>::new(master_size, master_items).verify(N(cert_root), [(master_pos, master_leaf)].to_vec()).unwrap_or(false);
    eprintln!("master_ok = {}", master_ok);
    assert!(sub_ok && master_ok, "MMR proof verify failed (sub={}, master={})", sub_ok, master_ok);
}
