//! tendermint_skip.rs — the SKIPPING light-client variant (non-adjacent verification). tendermint_advance does
//! SEQUENTIAL advancement: the block is signed by the current trusted set, which is the block's OWN set. That
//! processes every rotation. Skipping lets the anchor jump straight to a far-ahead block H2 without the blocks
//! in between, the standard Tendermint optimization (verifyNonAdjacent), by checking the "trust level": enough
//! of the validators we ALREADY trust signed H2.
//!
//! Two distinct sets are supplied: H2's OWN set (the validators of H2) and the TRUSTED set (what the anchor
//! commits to). The checks mirror Tendermint's verifyNonAdjacent:
//!   (a) H2's own set hashes to H2.validators_hash (leaf[7]);
//!   (b) > 2/3 of H2's OWN power signed H2 (the block is valid per its own set)            -> else 20;
//!   (c) the TRUSTED set hashes to the trusted anchor;
//!   (d) validators in the TRUSTED set who signed H2 hold > 1/3 of the TRUSTED set's power
//!       (trustLevel = 1/3: at least one honest trusted validator vouches for H2)          -> else 22;
//!   (e) new_anchor == H2.next_validators_hash (leaf[8])                                    -> else 21.
//! Then the anchor jumps trusted_anchor -> new_anchor, having skipped the intermediate blocks.
//!
//! NOT covered here (documented, a known residual): the trust-PERIOD bound (H2.time must be within the
//! unbonding window of the trusted time). That needs an on-chain clock (a header-dep, the cells L-2 pattern);
//! the cryptographic skip logic, the new code vs advance, is what this proves. Without it, skipping is sound
//! against any set still inside the trust period; the period gate is an operational add-on.
//!
//! Script args = trusted_anchor(32) ‖ new_anchor(32).
//! Input blob (witness[0].lock):
//!   u8 n_leaves, n_leaves * { u16 leaf_len, leaf_bytes },
//!   u8 chain_id_len, chain_id, u64 height, u64 round, u32 part_total, [32] part_hash,
//!   u16 n_new,   n_new   * { [32] pubkey, u64 power },        (H2's own validator set)
//!   u16 n_trust, n_trust * { [32] pubkey, u64 power },        (the trusted set the anchor commits to)
//!   u16 n_pre,   n_pre   * { u16 val_idx, i64 ts_seconds, u32 ts_nanos, [64] sig }   (val_idx into H2's set)
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
fn sha256(parts: &[&[u8]]) -> [u8; 32] { let mut h = Sha256::new(); for p in parts { h.update(p); } let d = h.finalize(); let mut o = [0u8; 32]; o.copy_from_slice(&d); o }
fn leaf_hash(b: &[u8]) -> [u8; 32] { sha256(&[&[0x00], b]) }
fn inner_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] { sha256(&[&[0x01], l, r]) }
fn split_point(n: usize) -> usize { let mut k = 1; while k * 2 < n { k *= 2; } k }
fn merkle_root(items: &[&[u8]]) -> [u8; 32] { match items.len() { 0 => sha256(&[]), 1 => leaf_hash(items[0]), n => { let k = split_point(n); inner_hash(&merkle_root(&items[..k]), &merkle_root(&items[k..])) } } }
fn simple_validator(pk: &[u8; 32], power: u64) -> Vec<u8> {
    let mut pubkey_msg = Vec::with_capacity(34); pubkey_msg.push(0x0a); pubkey_msg.push(0x20); pubkey_msg.extend_from_slice(pk);
    let mut o = Vec::new(); o.push(0x0a); varint(pubkey_msg.len() as u64, &mut o); o.extend_from_slice(&pubkey_msg); o.push(0x10); varint(power, &mut o); o
}
fn valset_root(pubkeys: &[[u8; 32]], powers: &[u64]) -> [u8; 32] {
    let items: Vec<Vec<u8>> = (0..pubkeys.len()).map(|i| simple_validator(&pubkeys[i], powers[i])).collect();
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    merkle_root(&refs)
}
/// the trusted-set power of a validator identified by pubkey (0 if it is not in the trusted set).
fn trusted_power_of(pk: &[u8; 32], t_pks: &[[u8; 32]], t_pows: &[u64]) -> u64 {
    for i in 0..t_pks.len() { if &t_pks[i] == pk { return t_pows[i]; } }
    0
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
    fn valset(&mut self) -> (Vec<[u8; 32]>, Vec<u64>, u128) {
        let n = self.u16() as usize;
        let (mut pks, mut pows, mut total) = (Vec::with_capacity(n), Vec::with_capacity(n), 0u128);
        for _ in 0..n { let pk = self.take(32); let mut a = [0u8; 32]; if pk.len() == 32 { a.copy_from_slice(pk); } pks.push(a); let p = self.u64(); pows.push(p); total += p as u128; }
        (pks, pows, total)
    }
}

fn program_entry() -> i8 {
    let sargs = match load_script() { Ok(s) => s.args().raw_data(), Err(_) => return 10 };
    if sargs.len() < 64 { return 10; }
    let mut trusted_anchor = [0u8; 32]; trusted_anchor.copy_from_slice(&sargs[0..32]);
    let mut new_anchor = [0u8; 32]; new_anchor.copy_from_slice(&sargs[32..64]);

    let w = match load_witness_args(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 1 };
    let blob = match w.lock().to_opt() { Some(b) => b.raw_data(), None => return 2 };
    let mut r = R::new(&blob);

    let n_leaves = r.u8() as usize;
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(n_leaves);
    for _ in 0..n_leaves { let l = r.u16() as usize; leaves.push(r.take(l).to_vec()); }
    if !r.ok || n_leaves != 14 { return 3; }
    let leaf_refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
    let block_hash = merkle_root(&leaf_refs);

    let cid_len = r.u8() as usize; let chain_id = r.take(cid_len).to_vec();
    let height = r.u64(); let round = r.u64();
    let part_total = r.u32(); let part_hash = r.take(32).to_vec();

    // H2's OWN validator set — must hash to the header's validators_hash (leaf[7]).
    let (new_pks, new_pows, total_new) = r.valset();
    if !r.ok || total_new == 0 { return 5; }
    let vh = valset_root(&new_pks, &new_pows);
    let vh_leaf = &leaves[7];
    if vh_leaf.len() != 34 || vh_leaf[0] != 0x0a || vh_leaf[1] != 0x20 || vh_leaf[2..34] != vh[..] { return 8; }

    // the TRUSTED set — must hash to the trusted anchor (what we already committed to).
    let (t_pks, t_pows, total_trust) = r.valset();
    if !r.ok || total_trust == 0 { return 11; }
    if valset_root(&t_pks, &t_pows) != trusted_anchor { return 9; }

    // verify the commit ONCE per signer (over the reconstructed block_hash). Accumulate BOTH H2-own power and,
    // for signers that are also in the trusted set, the TRUSTED power they carry.
    let n_pre = r.u16() as usize;
    let mut signed_new: u128 = 0;
    let mut signed_trust: u128 = 0;
    for _ in 0..n_pre {
        let idx = r.u16() as usize; let seconds = r.i64(); let nanos = r.u32(); let sig = r.take(64);
        if !r.ok || idx >= new_pks.len() || sig.len() != 64 { return 6; }
        let sb = vote_sign_bytes(height, round, &block_hash, part_total, &part_hash, seconds, nanos, &chain_id);
        let vk = match VerifyingKey::from_bytes(&new_pks[idx]) { Ok(v) => v, Err(_) => continue };
        let mut sa = [0u8; 64]; sa.copy_from_slice(sig);
        if vk.verify(&sb, &Signature::from_bytes(&sa)).is_ok() {
            signed_new += new_pows[idx] as u128;
            signed_trust += trusted_power_of(&new_pks[idx], &t_pks, &t_pows) as u128;
        }
    }
    // (b) > 2/3 of H2's OWN set signed.
    if signed_new.saturating_mul(3) <= total_new.saturating_mul(2) { return 20; }
    // (d) trust level: > 1/3 of the TRUSTED set's power is among the signers.
    if signed_trust.saturating_mul(3) <= total_trust { return 22; }

    // (e) the new anchor is H2's next_validators_hash (leaf[8], cdcBytes-encoded).
    let nv_leaf = &leaves[8];
    if nv_leaf.len() != 34 || nv_leaf[0] != 0x0a || nv_leaf[1] != 0x20 || nv_leaf[2..34] != new_anchor[..] { return 21; }

    0 // non-adjacent (skip) transition trusted_anchor -> new_anchor is valid
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
