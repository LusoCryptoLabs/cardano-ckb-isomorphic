//! tendermint_verify.rs — CKB-VM verifies a Tendermint (CometBFT) commit. The keystone of the Cosmos <-> CKB
//! isomorphic binding, the analog of the Mithril cert verifier that makes CKB <-> Cardano work. It checks that
//! more than 2/3 of a validator set's voting power signed a block, by reconstructing each precommit's canonical
//! vote bytes and verifying its ed25519 signature. The canonical-vote encoding was pinned off-chain against
//! real cosmoshub-4 data (spike/cosmos-ckb/verify_offchain.mjs): round=0 is omitted (proto3 zero-omission).
//!
//! Input blob (in witness[0].lock), little-endian:
//!   u8 chain_id_len, chain_id,
//!   u64 height, u64 round, [32] block_hash, u32 part_total, [32] part_hash,
//!   u16 n_vals,  n_vals * { [32] ed25519 pubkey, u64 voting_power },
//!   u16 n_pre,   n_pre  * { u16 val_idx, i64 ts_seconds, u32 ts_nanos, [64] signature }
//! Returns 0 iff 3 * (signed power) > 2 * (total power).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)] extern crate alloc;
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::load_witness_args;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

// ---- minimal protobuf writer (mirrors verify_offchain.mjs) ----
fn varint(mut v: u64, out: &mut Vec<u8>) { while v > 0x7f { out.push((v as u8 & 0x7f) | 0x80); v >>= 7; } out.push(v as u8); }
fn tagw(field: u32, wire: u32, out: &mut Vec<u8>) { varint(((field << 3) | wire) as u64, out); }
fn len_delim(field: u32, bytes: &[u8], out: &mut Vec<u8>) { tagw(field, 2, out); varint(bytes.len() as u64, out); out.extend_from_slice(bytes); }

fn part_set_header(total: u32, hash: &[u8]) -> Vec<u8> { let mut o = Vec::new(); tagw(1, 0, &mut o); varint(total as u64, &mut o); len_delim(2, hash, &mut o); o }
fn canonical_block_id(hash: &[u8], total: u32, part_hash: &[u8]) -> Vec<u8> {
    let mut o = Vec::new(); len_delim(1, hash, &mut o); let psh = part_set_header(total, part_hash); len_delim(2, &psh, &mut o); o
}
fn timestamp(seconds: i64, nanos: u32) -> Vec<u8> {
    let mut o = Vec::new(); tagw(1, 0, &mut o); varint(seconds as u64, &mut o);
    if nanos != 0 { tagw(2, 0, &mut o); varint(nanos as u64, &mut o); } o
}
// VoteSignBytes = MarshalDelimited(CanonicalVote{type=precommit, height, round, block_id, timestamp, chain_id})
fn vote_sign_bytes(height: u64, round: u64, block_hash: &[u8], total: u32, part_hash: &[u8], seconds: i64, nanos: u32, chain_id: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    tagw(1, 0, &mut msg); varint(2, &mut msg);                                  // type = SIGNED_MSG_TYPE_PRECOMMIT
    tagw(2, 1, &mut msg); msg.extend_from_slice(&height.to_le_bytes());          // height sfixed64
    if round != 0 { tagw(3, 1, &mut msg); msg.extend_from_slice(&round.to_le_bytes()); } // round sfixed64 (omit if 0)
    let bid = canonical_block_id(block_hash, total, part_hash); len_delim(4, &bid, &mut msg);
    let ts = timestamp(seconds, nanos); len_delim(5, &ts, &mut msg);
    len_delim(6, chain_id, &mut msg);
    let mut out = Vec::new(); varint(msg.len() as u64, &mut out); out.extend_from_slice(&msg); out
}

// ---- cursor over the input blob ----
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

    let cid_len = r.u8() as usize;
    let chain_id = r.take(cid_len).to_vec();
    let height = r.u64();
    let round = r.u64();
    let block_hash = r.take(32).to_vec();
    let part_total = r.u32();
    let part_hash = r.take(32).to_vec();

    let n_vals = r.u16() as usize;
    let mut pubkeys: Vec<[u8; 32]> = Vec::with_capacity(n_vals);
    let mut powers: Vec<u64> = Vec::with_capacity(n_vals);
    let mut total_power: u128 = 0;
    for _ in 0..n_vals {
        let pk = r.take(32); let mut a = [0u8; 32]; if pk.len() == 32 { a.copy_from_slice(pk); }
        pubkeys.push(a);
        let p = r.u64(); powers.push(p); total_power += p as u128;
    }
    if !r.ok || total_power == 0 { return 3; }

    let n_pre = r.u16() as usize;
    let mut signed_power: u128 = 0;
    for _ in 0..n_pre {
        let idx = r.u16() as usize;
        let seconds = r.i64();
        let nanos = r.u32();
        let sig = r.take(64);
        if !r.ok || idx >= n_vals || sig.len() != 64 { return 4; }
        let sb = vote_sign_bytes(height, round, &block_hash, part_total, &part_hash, seconds, nanos, &chain_id);
        let vk = match VerifyingKey::from_bytes(&pubkeys[idx]) { Ok(v) => v, Err(_) => continue };
        let mut sa = [0u8; 64]; sa.copy_from_slice(sig);
        if vk.verify(&sb, &Signature::from_bytes(&sa)).is_ok() { signed_power += powers[idx] as u128; }
    }

    // > 2/3 of voting power signed the block
    if signed_power.saturating_mul(3) > total_power.saturating_mul(2) { 0 } else { 20 }
}

// --- single-hart __sync_* atomic polyfills (CKB-VM has no A-extension; built with -a,+forced-atomics) ---
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
