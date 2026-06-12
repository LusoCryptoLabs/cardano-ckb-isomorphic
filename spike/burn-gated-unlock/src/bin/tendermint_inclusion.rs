//! tendermint_inclusion.rs — the full Cosmos -> CKB finality+inclusion verifier in CKB-VM. Proves "this Cosmos
//! tx is in a FINAL block", which is what binds a real Cosmos action to CKB. Three checks, all encodings pinned
//! off-chain on real cosmoshub-4 data (spike/cosmos-ckb):
//!   1. Reconstruct block_hash = Tendermint Merkle root over the 14 header leaves; parse data_hash from leaf[6].
//!      (The relayer must supply the real leaves: any fake leaf changes block_hash and the commit sigs fail.)
//!   2. Verify the commit: > 2/3 of validator voting power ed25519-signed the canonical vote over block_hash.
//!   3. Verify the tx inclusion proof: computeRoot(index,total, leafHash(SHA256(tx)), aunts) == data_hash.
//!
//! Input blob (witness[0].lock), little-endian:
//!   u8 n_leaves, n_leaves * { u16 leaf_len, leaf_bytes },
//!   u8 chain_id_len, chain_id, u64 height, u64 round, u32 part_total, [32] part_hash,
//!   u16 n_vals, n_vals * { [32] pubkey, u64 power },
//!   u16 n_pre,  n_pre  * { u16 val_idx, i64 ts_seconds, u32 ts_nanos, [64] sig },
//!   u16 tx_len, tx_bytes, u32 incl_index, u32 incl_total, u8 n_aunts, n_aunts * [32]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)] extern crate alloc;
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_witness_args, load_script};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

// ---- protobuf writer (canonical vote) ----
fn varint(mut v: u64, out: &mut Vec<u8>) { while v > 0x7f { out.push((v as u8 & 0x7f) | 0x80); v >>= 7; } out.push(v as u8); }
fn tagw(field: u32, wire: u32, out: &mut Vec<u8>) { varint(((field << 3) | wire) as u64, out); }
fn len_delim(field: u32, bytes: &[u8], out: &mut Vec<u8>) { tagw(field, 2, out); varint(bytes.len() as u64, out); out.extend_from_slice(bytes); }
fn part_set_header(total: u32, hash: &[u8]) -> Vec<u8> { let mut o = Vec::new(); tagw(1, 0, &mut o); varint(total as u64, &mut o); len_delim(2, hash, &mut o); o }
fn canonical_block_id(hash: &[u8], total: u32, part_hash: &[u8]) -> Vec<u8> { let mut o = Vec::new(); len_delim(1, hash, &mut o); let psh = part_set_header(total, part_hash); len_delim(2, &psh, &mut o); o }
fn timestamp(seconds: i64, nanos: u32) -> Vec<u8> { let mut o = Vec::new(); tagw(1, 0, &mut o); varint(seconds as u64, &mut o); if nanos != 0 { tagw(2, 0, &mut o); varint(nanos as u64, &mut o); } o }
fn vote_sign_bytes(height: u64, round: u64, block_hash: &[u8], total: u32, part_hash: &[u8], seconds: i64, nanos: u32, chain_id: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    tagw(1, 0, &mut msg); varint(2, &mut msg);
    tagw(2, 1, &mut msg); msg.extend_from_slice(&height.to_le_bytes());
    if round != 0 { tagw(3, 1, &mut msg); msg.extend_from_slice(&round.to_le_bytes()); }
    let bid = canonical_block_id(block_hash, total, part_hash); len_delim(4, &bid, &mut msg);
    let ts = timestamp(seconds, nanos); len_delim(5, &ts, &mut msg);
    len_delim(6, chain_id, &mut msg);
    let mut out = Vec::new(); varint(msg.len() as u64, &mut out); out.extend_from_slice(&msg); out
}

// ---- Tendermint simple Merkle tree (SHA256) ----
fn sha256(parts: &[&[u8]]) -> [u8; 32] { let mut h = Sha256::new(); for p in parts { h.update(p); } let d = h.finalize(); let mut o = [0u8; 32]; o.copy_from_slice(&d); o }
fn leaf_hash(b: &[u8]) -> [u8; 32] { sha256(&[&[0x00], b]) }
fn inner_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] { sha256(&[&[0x01], l, r]) }
fn split_point(n: usize) -> usize { let mut k = 1; while k * 2 < n { k *= 2; } k }
fn merkle_root(items: &[&[u8]]) -> [u8; 32] {
    match items.len() { 0 => sha256(&[]), 1 => leaf_hash(items[0]),
        n => { let k = split_point(n); inner_hash(&merkle_root(&items[..k]), &merkle_root(&items[k..])) } }
}
// inclusion: recompute the root from (index,total,leaf,aunts); aunts consumed from the end.
fn compute_root(index: usize, total: usize, leaf: [u8; 32], aunts: &[[u8; 32]]) -> [u8; 32] {
    if total == 1 { return leaf; }
    let k = split_point(total);
    let last = aunts.len().wrapping_sub(1);
    if index < k { inner_hash(&compute_root(index, k, leaf, &aunts[..last]), &aunts[last]) }
    else { inner_hash(&aunts[last], &compute_root(index - k, total - k, leaf, &aunts[..last])) }
}

// validators_hash = MerkleRoot([ SimpleValidator(v) ]); SimpleValidator = pub_key(PublicKey{ed25519}) ‖ voting_power.
fn simple_validator(pk: &[u8; 32], power: u64) -> Vec<u8> {
    let mut pubkey_msg = Vec::with_capacity(34); pubkey_msg.push(0x0a); pubkey_msg.push(0x20); pubkey_msg.extend_from_slice(pk);
    let mut o = Vec::new();
    o.push(0x0a); varint(pubkey_msg.len() as u64, &mut o); o.extend_from_slice(&pubkey_msg); // field 1 pub_key
    o.push(0x10); varint(power, &mut o);                                                      // field 2 voting_power
    o
}
fn valset_root(pubkeys: &[[u8; 32]], powers: &[u64]) -> [u8; 32] {
    let items: Vec<Vec<u8>> = (0..pubkeys.len()).map(|i| simple_validator(&pubkeys[i], powers[i])).collect();
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    merkle_root(&refs)
}

struct R<'a> { b: &'a [u8], i: usize, ok: bool }
impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self { R { b, i: 0, ok: true } }
    fn take(&mut self, n: usize) -> &'a [u8] { if self.i + n > self.b.len() { self.ok = false; return &[]; } let s = &self.b[self.i..self.i + n]; self.i += n; s }
    fn u8(&mut self) -> u8 { let s = self.take(1); if s.is_empty() { 0 } else { s[0] } }
    fn u16(&mut self) -> u16 { let s = self.take(2); if s.len() < 2 { 0 } else { u16::from_le_bytes([s[0], s[1]]) } }
    fn u32(&mut self) -> u32 { let s = self.take(4); if s.len() < 4 { 0 } else { u32::from_le_bytes([s[0], s[1], s[2], s[3]]) } }
    fn u64(&mut self) -> u64 { let s = self.take(8); if s.len() < 8 { 0 } else { let mut a = [0u8; 8]; a.copy_from_slice(s); u64::from_le_bytes(a) } }
    fn i64(&mut self) -> i64 { self.u64() as i64 }
}

fn program_entry() -> i8 {
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 1 };
    let blob = match w.lock().to_opt() { Some(b) => b.raw_data(), None => return 2 };
    let mut r = R::new(&blob);

    // 0) the PINNED trusted validator-set hash — from the LOCK SCRIPT ARGS, so the cell itself commits to its
    //    trust anchor (advanced as the set rotates). NOT from the witness, which the relayer controls.
    let sargs = match load_script() { Ok(s) => s.args().raw_data(), Err(_) => return 10 };
    if sargs.len() < 32 { return 10; }
    let mut trusted_valset_hash = [0u8; 32]; trusted_valset_hash.copy_from_slice(&sargs[0..32]);

    // 1) header leaves -> block_hash, data_hash
    let n_leaves = r.u8() as usize;
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(n_leaves);
    for _ in 0..n_leaves { let l = r.u16() as usize; leaves.push(r.take(l).to_vec()); }
    if !r.ok || n_leaves != 14 { return 3; }
    let leaf_refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
    let block_hash = merkle_root(&leaf_refs);
    // data_hash is header leaf[6], encoded as cdcBytes = 0x0a 0x20 || 32 bytes
    let dh_leaf = &leaves[6];
    if dh_leaf.len() != 34 || dh_leaf[0] != 0x0a || dh_leaf[1] != 0x20 { return 4; }
    let mut data_hash = [0u8; 32]; data_hash.copy_from_slice(&dh_leaf[2..34]);

    // commit fields
    let cid_len = r.u8() as usize; let chain_id = r.take(cid_len).to_vec();
    let height = r.u64(); let round = r.u64();
    let part_total = r.u32(); let part_hash = r.take(32).to_vec();

    let n_vals = r.u16() as usize;
    let mut pubkeys: Vec<[u8; 32]> = Vec::with_capacity(n_vals);
    let mut powers: Vec<u64> = Vec::with_capacity(n_vals);
    let mut total_power: u128 = 0;
    for _ in 0..n_vals { let pk = r.take(32); let mut a = [0u8; 32]; if pk.len() == 32 { a.copy_from_slice(pk); } pubkeys.push(a); let p = r.u64(); powers.push(p); total_power += p as u128; }
    if !r.ok || total_power == 0 { return 5; }

    // bind the signing set: it must hash to the header's validators_hash (leaf[7], itself bound to block_hash)
    // AND to the pinned trusted anchor. So the set is the chain's real set and the trusted one, not supplied.
    let vh = valset_root(&pubkeys, &powers);
    let vh_leaf = &leaves[7];
    if vh_leaf.len() != 34 || vh_leaf[0] != 0x0a || vh_leaf[1] != 0x20 || vh_leaf[2..34] != vh[..] { return 8; }
    if vh != trusted_valset_hash { return 9; }

    // 2) commit verify over the RECONSTRUCTED block_hash
    let n_pre = r.u16() as usize;
    let mut signed: u128 = 0;
    for _ in 0..n_pre {
        let idx = r.u16() as usize; let seconds = r.i64(); let nanos = r.u32(); let sig = r.take(64);
        if !r.ok || idx >= n_vals || sig.len() != 64 { return 6; }
        let sb = vote_sign_bytes(height, round, &block_hash, part_total, &part_hash, seconds, nanos, &chain_id);
        let vk = match VerifyingKey::from_bytes(&pubkeys[idx]) { Ok(v) => v, Err(_) => continue };
        let mut sa = [0u8; 64]; sa.copy_from_slice(sig);
        if vk.verify(&sb, &Signature::from_bytes(&sa)).is_ok() { signed += powers[idx] as u128; }
    }
    if signed.saturating_mul(3) <= total_power.saturating_mul(2) { return 20; } // not > 2/3

    // 3) tx inclusion against data_hash (leaf = leafHash(SHA256(tx)))
    let tx_len = r.u16() as usize; let tx = r.take(tx_len).to_vec();
    let incl_index = r.u32() as usize; let incl_total = r.u32() as usize;
    let n_aunts = r.u8() as usize;
    let mut aunts: Vec<[u8; 32]> = Vec::with_capacity(n_aunts);
    for _ in 0..n_aunts { let a = r.take(32); let mut x = [0u8; 32]; if a.len() == 32 { x.copy_from_slice(a); } aunts.push(x); }
    if !r.ok || incl_total == 0 || incl_index >= incl_total { return 7; }
    let tx_hash = sha256(&[&tx]);
    let leaf = leaf_hash(&tx_hash);
    let root = compute_root(incl_index, incl_total, leaf, &aunts);
    if root != data_hash { return 21; } // tx not in data_hash

    0 // commit valid AND tx provably in the final block
}

// --- single-hart __sync_* atomic polyfills ---
#[cfg(not(test))]
#[allow(non_snake_case)]
mod sync_polyfill {
    use core::ptr::{read_volatile, write_volatile};
    macro_rules! sync_ops {
        ($ty:ty, $cas:ident, $bcas:ident, $tas:ident, $faa:ident, $fas:ident, $fao:ident, $faand:ident, $fax:ident) => {
            #[no_mangle] pub unsafe extern "C" fn $cas(p:*mut $ty,old:$ty,new:$ty)->$ty{let c=read_volatile(p);if c==old{write_volatile(p,new);}c}
            #[no_mangle] pub unsafe extern "C" fn $bcas(p:*mut $ty,old:$ty,new:$ty)->bool{let c=read_volatile(p);if c==old{write_volatile(p,new);true}else{false}}
            #[no_mangle] pub unsafe extern "C" fn $tas(p:*mut $ty,new:$ty)->$ty{let c=read_volatile(p);write_volatile(p,new);c}
            #[no_mangle] pub unsafe extern "C" fn $faa(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c.wrapping_add(v));c}
            #[no_mangle] pub unsafe extern "C" fn $fas(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c.wrapping_sub(v));c}
            #[no_mangle] pub unsafe extern "C" fn $fao(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c|v);c}
            #[no_mangle] pub unsafe extern "C" fn $faand(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c&v);c}
            #[no_mangle] pub unsafe extern "C" fn $fax(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c^v);c}
        };
    }
    sync_ops!(u8,  __sync_val_compare_and_swap_1,__sync_bool_compare_and_swap_1,__sync_lock_test_and_set_1,__sync_fetch_and_add_1,__sync_fetch_and_sub_1,__sync_fetch_and_or_1,__sync_fetch_and_and_1,__sync_fetch_and_xor_1);
    sync_ops!(u16, __sync_val_compare_and_swap_2,__sync_bool_compare_and_swap_2,__sync_lock_test_and_set_2,__sync_fetch_and_add_2,__sync_fetch_and_sub_2,__sync_fetch_and_or_2,__sync_fetch_and_and_2,__sync_fetch_and_xor_2);
    sync_ops!(u32, __sync_val_compare_and_swap_4,__sync_bool_compare_and_swap_4,__sync_lock_test_and_set_4,__sync_fetch_and_add_4,__sync_fetch_and_sub_4,__sync_fetch_and_or_4,__sync_fetch_and_and_4,__sync_fetch_and_xor_4);
    sync_ops!(u64, __sync_val_compare_and_swap_8,__sync_bool_compare_and_swap_8,__sync_lock_test_and_set_8,__sync_fetch_and_add_8,__sync_fetch_and_sub_8,__sync_fetch_and_or_8,__sync_fetch_and_and_8,__sync_fetch_and_xor_8);
    #[no_mangle] pub extern "C" fn __sync_synchronize() {}
}
