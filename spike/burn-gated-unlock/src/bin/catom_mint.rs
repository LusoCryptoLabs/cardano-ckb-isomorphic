//! catom_mint.rs — the χATOM FORWARD-mint type script (Cosmos -> CKB). The Cosmos-leg mirror of xada_mint.rs:
//! χATOM is wrapped ATOM on CKB (an xUDT-style fungible token whose POLICY is this type script's hash), and
//! issuance is gated NOT on an admin key but on a finalized Cosmos escrow. It composes the two pieces already
//! shipped in this crate:
//!   - the Cosmos finality+inclusion verifier (`tendermint_inclusion.rs`): "this Cosmos tx is in a FINAL block"
//!     (>2/3 ed25519 commit over a reconstructed block_hash, validator set anchored to a pinned checkpoint, tx
//!     Merkle inclusion against the header's data_hash). LIVE on Pudge.
//!   - the mint-binding + replay-once shape from `xada_mint.rs` (NET delta dispatch, recipient binding,
//!     conservation, genesis-pinned nullifier).
//!
//! The escrow is a Cosmos bank `MsgSend` that locks ATOM into a fixed escrow account, with the 32-byte CKB
//! recipient lock-hash carried (lowercase hex) in the tx memo. So the binding parses the SAME tx bytes the
//! inclusion proof certified (TxRaw -> TxBody -> MsgSend + memo) and enforces:
//!   to_address == the pinned escrow account, denom == the pinned denom, Coin.amount == χATOM minted (1:1),
//!   memo == hex(the lock-hash all minted χATOM is locked to).
//! The NEW code vs the two parents is the protobuf MsgSend reader; it is unit-tested below.
//!
//! args = valset_anchor(32) ‖ reg_type(32) ‖ u8 denom_len ‖ denom ‖ escrow_to_address(rest)
//! witness.input_type = the Cosmos inclusion blob (identical layout to tendermint_inclusion's witness).
//! The trusted Osmosis validator-set hash is BAKED into the policy args here (immutable, simplest for a single
//! mint). The advanceable variant reads the anchor from a checkpoint cell-dep advanced by tendermint_advance /
//! tendermint_skip; see those scripts and BRIDGE_TEMPLATE.md.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)] extern crate alloc;
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_script, load_witness_args};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }

// ============================ Tendermint finality+inclusion (from tendermint_inclusion.rs) ============================
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
fn merkle_root(items: &[&[u8]]) -> [u8; 32] {
    match items.len() { 0 => sha256(&[]), 1 => leaf_hash(items[0]),
        n => { let k = split_point(n); inner_hash(&merkle_root(&items[..k]), &merkle_root(&items[k..])) } }
}
fn compute_root(index: usize, total: usize, leaf: [u8; 32], aunts: &[[u8; 32]]) -> [u8; 32] {
    if total == 1 { return leaf; }
    let k = split_point(total);
    let last = aunts.len().wrapping_sub(1);
    if index < k { inner_hash(&compute_root(index, k, leaf, &aunts[..last]), &aunts[last]) }
    else { inner_hash(&aunts[last], &compute_root(index - k, total - k, leaf, &aunts[..last])) }
}
fn simple_validator(pk: &[u8; 32], power: u64) -> Vec<u8> {
    let mut pubkey_msg = Vec::with_capacity(34); pubkey_msg.push(0x0a); pubkey_msg.push(0x20); pubkey_msg.extend_from_slice(pk);
    let mut o = Vec::new();
    o.push(0x0a); varint(pubkey_msg.len() as u64, &mut o); o.extend_from_slice(&pubkey_msg);
    o.push(0x10); varint(power, &mut o);
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
/// Verify the Cosmos inclusion blob against a trusted validator-set anchor; return the certified tx bytes.
fn verify_inclusion(blob: &[u8], trusted_valset_hash: &[u8; 32]) -> Result<Vec<u8>, i8> {
    let mut r = R::new(blob);
    let n_leaves = r.u8() as usize;
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(n_leaves);
    for _ in 0..n_leaves { let l = r.u16() as usize; leaves.push(r.take(l).to_vec()); }
    if !r.ok || n_leaves != 14 { return Err(3); }
    let leaf_refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
    let block_hash = merkle_root(&leaf_refs);
    let dh_leaf = &leaves[6];
    if dh_leaf.len() != 34 || dh_leaf[0] != 0x0a || dh_leaf[1] != 0x20 { return Err(4); }
    let mut data_hash = [0u8; 32]; data_hash.copy_from_slice(&dh_leaf[2..34]);
    let cid_len = r.u8() as usize; let chain_id = r.take(cid_len).to_vec();
    let height = r.u64(); let round = r.u64();
    let part_total = r.u32(); let part_hash = r.take(32).to_vec();
    let n_vals = r.u16() as usize;
    let mut pubkeys: Vec<[u8; 32]> = Vec::with_capacity(n_vals);
    let mut powers: Vec<u64> = Vec::with_capacity(n_vals);
    let mut total_power: u128 = 0;
    for _ in 0..n_vals { let pk = r.take(32); let mut a = [0u8; 32]; if pk.len() == 32 { a.copy_from_slice(pk); } pubkeys.push(a); let p = r.u64(); powers.push(p); total_power += p as u128; }
    if !r.ok || total_power == 0 { return Err(5); }
    let vh = valset_root(&pubkeys, &powers);
    let vh_leaf = &leaves[7];
    if vh_leaf.len() != 34 || vh_leaf[0] != 0x0a || vh_leaf[1] != 0x20 || vh_leaf[2..34] != vh[..] { return Err(8); }
    if &vh != trusted_valset_hash { return Err(9); }
    let n_pre = r.u16() as usize;
    let mut signed: u128 = 0;
    for _ in 0..n_pre {
        let idx = r.u16() as usize; let seconds = r.i64(); let nanos = r.u32(); let sig = r.take(64);
        if !r.ok || idx >= n_vals || sig.len() != 64 { return Err(6); }
        let sb = vote_sign_bytes(height, round, &block_hash, part_total, &part_hash, seconds, nanos, &chain_id);
        let vk = match VerifyingKey::from_bytes(&pubkeys[idx]) { Ok(v) => v, Err(_) => continue };
        let mut sa = [0u8; 64]; sa.copy_from_slice(sig);
        if vk.verify(&sb, &Signature::from_bytes(&sa)).is_ok() { signed += powers[idx] as u128; }
    }
    if signed.saturating_mul(3) <= total_power.saturating_mul(2) { return Err(20); }
    let tx_len = r.u16() as usize; let tx = r.take(tx_len).to_vec();
    let incl_index = r.u32() as usize; let incl_total = r.u32() as usize;
    let n_aunts = r.u8() as usize;
    let mut aunts: Vec<[u8; 32]> = Vec::with_capacity(n_aunts);
    for _ in 0..n_aunts { let a = r.take(32); let mut x = [0u8; 32]; if a.len() == 32 { x.copy_from_slice(a); } aunts.push(x); }
    if !r.ok || incl_total == 0 || incl_index >= incl_total { return Err(7); }
    let tx_hash = sha256(&[&tx]);
    let leaf = leaf_hash(&tx_hash);
    let root = compute_root(incl_index, incl_total, leaf, &aunts);
    if root != data_hash { return Err(21); }
    Ok(tx)
}

// ============================ Cosmos protobuf MsgSend reader (the NEW code) ============================
fn pb_varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut shift = 0u32; let mut v = 0u64;
    loop {
        if *i >= b.len() { return None; }
        let byte = b[*i]; *i += 1;
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 { return Some(v); }
        shift += 7; if shift >= 64 { return None; }
    }
}
/// Return the payload of the FIRST length-delimited (wire 2) field with the given number, skipping other fields.
fn pb_first_bytes<'a>(b: &'a [u8], field: u32) -> Option<&'a [u8]> {
    let mut i = 0usize;
    while i < b.len() {
        let key = pb_varint(b, &mut i)?;
        let f = (key >> 3) as u32; let wire = (key & 7) as u32;
        match wire {
            0 => { pb_varint(b, &mut i)?; }
            5 => { i = i.checked_add(4)?; if i > b.len() { return None; } }
            1 => { i = i.checked_add(8)?; if i > b.len() { return None; } }
            2 => { let len = pb_varint(b, &mut i)? as usize; let e = i.checked_add(len)?; if e > b.len() { return None; }
                   if f == field { return Some(&b[i..e]); } i = e; }
            _ => return None,
        }
    }
    None
}
const MSGSEND_TYPE_URL: &[u8] = b"/cosmos.bank.v1beta1.MsgSend";
/// Parse a Cosmos TxRaw and extract (to_address, denom, amount, memo) from its first MsgSend.
/// TxRaw{1:body} -> TxBody{1:Any(first msg), 2:memo} -> Any{1:type_url, 2:value=MsgSend}
/// -> MsgSend{2:to_address, 3:Coin(first)} -> Coin{1:denom, 2:amount(decimal string)}.
fn parse_msgsend(tx: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u128, Vec<u8>)> {
    let body = pb_first_bytes(tx, 1)?;            // TxRaw.body_bytes
    let any = pb_first_bytes(body, 1)?;           // TxBody.messages[0]
    let memo = pb_first_bytes(body, 2).unwrap_or(&[]).to_vec(); // TxBody.memo (string)
    let type_url = pb_first_bytes(any, 1)?;       // Any.type_url
    if type_url != MSGSEND_TYPE_URL { return None; }
    let msg = pb_first_bytes(any, 2)?;            // Any.value = MsgSend
    let to_address = pb_first_bytes(msg, 2)?.to_vec();   // MsgSend.to_address
    let coin = pb_first_bytes(msg, 3)?;           // MsgSend.amount[0] = Coin
    let denom = pb_first_bytes(coin, 1)?.to_vec();       // Coin.denom
    let amount_str = pb_first_bytes(coin, 2)?;    // Coin.amount (decimal string)
    let amount = ascii_to_u128(amount_str)?;
    Some((to_address, denom, amount, memo))
}
/// Parse an ASCII decimal string to u128 (the Cosmos Coin.amount encoding). Rejects empty / non-digit / overflow.
fn ascii_to_u128(s: &[u8]) -> Option<u128> {
    if s.is_empty() { return None; }
    let mut v: u128 = 0;
    for &c in s { if !(b'0'..=b'9').contains(&c) { return None; } v = v.checked_mul(10)?.checked_add((c - b'0') as u128)?; }
    Some(v)
}
/// Decode a 64-char lowercase-hex memo to 32 bytes (the CKB recipient lock-hash carried in the tx memo).
fn hex_decode_32(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != 64 { return None; }
    let nib = |c: u8| -> Option<u8> { match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(c - b'a' + 10), _ => None } };
    let mut o = [0u8; 32];
    for k in 0..32 { o[k] = (nib(s[2 * k])? << 4) | nib(s[2 * k + 1])?; }
    Some(o)
}

// ============================ mint binding (from xada_mint.rs) ============================
fn registry_inserts_key(reg_type: &[u8; 32], key: &[u8; 32]) -> bool {
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, Source::Input) {
            Ok(Some(th)) if &th == reg_type => {
                if let Ok(w) = load_witness_args(i, Source::Input) {
                    if let Some(b) = w.input_type().to_opt() { let d = b.raw_data(); return d.len() >= 32 && &d[0..32] == &key[..]; }
                }
                return false;
            }
            Ok(_) => { i += 1; }
            Err(_) => return false,
        }
    }
}
fn sum_group(source: Source) -> Option<u128> {
    let mut sum: u128 = 0; let mut i = 0usize;
    loop {
        match load_cell_data(i, source) {
            Ok(d) => { if d.len() < 16 { return None; } let mut a = [0u8; 16]; a.copy_from_slice(&d[0..16]); sum = sum.checked_add(u128::from_le_bytes(a))?; i += 1; }
            Err(_) => break,
        }
    }
    Some(sum)
}
fn outputs_all_at(recipient: &[u8]) -> Result<(), i8> {
    let mut i = 0usize;
    loop {
        match load_cell_lock_hash(i, Source::GroupOutput) {
            Ok(h) => { if h == [0u8; 32] { return Err(28); } if &h[..] != recipient { return Err(28); } i += 1; }
            Err(_) => break,
        }
    }
    Ok(())
}

fn program_entry() -> i8 {
    let args = load_script().unwrap().args().raw_data();
    if args.len() < 64 + 1 { return 2; }
    let mut valset_anchor = [0u8; 32]; valset_anchor.copy_from_slice(&args[0..32]);
    let mut reg_type = [0u8; 32]; reg_type.copy_from_slice(&args[32..64]);
    let denom_len = args[64] as usize;
    if args.len() < 65 + denom_len + 1 { return 2; }
    let denom = &args[65..65 + denom_len];
    let escrow_to = &args[65 + denom_len..];

    // NET χATOM delta this tx.
    let in_sum = match sum_group(Source::GroupInput) { Some(v) => v, None => return 16 };
    let out_sum = match sum_group(Source::GroupOutput) { Some(v) => v, None => return 17 };
    if out_sum <= in_sum { return 0; }            // transfer (==) or burn (<) — allowed
    let minted = out_sum - in_sum;
    if in_sum != 0 { return 18; }                 // a mint tx is mint-only

    // the Cosmos inclusion proof: certifies the escrow tx is in a final block (against the baked anchor),
    // returns its bytes.
    let w = match load_witness_args(0, Source::GroupInput) {
        Ok(w) => w, Err(_) => match load_witness_args(0, Source::GroupOutput) { Ok(w) => w, Err(_) => return 3 } };
    let blob = match w.input_type().to_opt() { Some(l) => l.raw_data(), None => return 4 };
    let tx = match verify_inclusion(&blob, &valset_anchor) { Ok(t) => t, Err(e) => return e };

    // B: parse the escrow MsgSend, bind to_address/denom/amount/memo.
    let (to_address, dn, amount, memo) = match parse_msgsend(&tx) { Some(x) => x, None => return 30 };
    if &to_address[..] != escrow_to { return 31; }
    if &dn[..] != denom { return 32; }
    if minted != amount { return 24; }            // conservation: χATOM minted 1:1 with locked ATOM
    let recipient = match hex_decode_32(&memo) { Some(x) => x, None => return 33 };

    // R: all freshly-minted χATOM is locked at the recipient committed in the escrow memo.
    if let Err(e) = outputs_all_at(&recipient) { return e; }

    // N: nullify the certified Cosmos tx exactly once. leg tag 0x04 = cosmos-escrow nullifier (keyspace disjoint
    // from the χADA legs 0x01/0x02/0x03 sharing this registry).
    let tx_hash = sha256(&[&tx]);
    let key = b2b256(&[&[0x04u8], &tx_hash]);
    if !registry_inserts_key(&reg_type, &key) { return 25; }
    0
}

// --- single-hart __sync_* atomic polyfills (CKB-VM has no A-extension; built with -a,+forced-atomics). ---
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

// ---- host unit tests for the NEW pure logic (the Cosmos protobuf MsgSend reader). Independent protobuf
// encoders build the test vector, so encoder and decoder are separate implementations of the wire format. ----
#[cfg(test)]
mod tests {
    use super::*;
    fn enc_varint(mut v: u64, out: &mut Vec<u8>) { while v > 0x7f { out.push((v as u8 & 0x7f) | 0x80); v >>= 7; } out.push(v as u8); }
    fn enc_bytes(field: u32, b: &[u8], out: &mut Vec<u8>) { enc_varint(((field << 3) | 2) as u64, out); enc_varint(b.len() as u64, out); out.extend_from_slice(b); }
    fn coin(denom: &[u8], amount: &[u8]) -> Vec<u8> { let mut o = Vec::new(); enc_bytes(1, denom, &mut o); enc_bytes(2, amount, &mut o); o }
    fn msgsend(from: &[u8], to: &[u8], coin: &[u8]) -> Vec<u8> { let mut o = Vec::new(); enc_bytes(1, from, &mut o); enc_bytes(2, to, &mut o); enc_bytes(3, coin, &mut o); o }
    fn any(type_url: &[u8], value: &[u8]) -> Vec<u8> { let mut o = Vec::new(); enc_bytes(1, type_url, &mut o); enc_bytes(2, value, &mut o); o }
    fn txbody(msg: &[u8], memo: &[u8]) -> Vec<u8> { let mut o = Vec::new(); enc_bytes(1, msg, &mut o); enc_bytes(2, memo, &mut o); o }
    fn txraw(body: &[u8]) -> Vec<u8> { let mut o = Vec::new(); enc_bytes(1, body, &mut o); o }

    fn build_tx(to: &[u8], denom: &[u8], amount: &[u8], memo: &[u8]) -> Vec<u8> {
        let c = coin(denom, amount);
        let m = msgsend(b"cosmos1from", to, &c);
        let a = any(MSGSEND_TYPE_URL, &m);
        let body = txbody(&a, memo);
        txraw(&body)
    }

    #[test]
    fn parses_a_real_shaped_msgsend() {
        let recip = [0xABu8; 32];
        let memo = super::hex_of(&recip); // 64-char lowercase hex
        let tx = build_tx(b"cosmos1escrowacct", b"uatom", b"20000000", memo.as_bytes());
        let (to, denom, amount, got_memo) = parse_msgsend(&tx).expect("parse");
        assert_eq!(to, b"cosmos1escrowacct".to_vec());
        assert_eq!(denom, b"uatom".to_vec());
        assert_eq!(amount, 20_000_000u128);
        assert_eq!(hex_decode_32(&got_memo).unwrap(), recip);
    }

    #[test]
    fn rejects_wrong_type_url() {
        let c = coin(b"uatom", b"1");
        let m = msgsend(b"a", b"b", &c);
        let a = any(b"/ibc.applications.transfer.v1.MsgTransfer", &m);
        let tx = txraw(&txbody(&a, b""));
        assert!(parse_msgsend(&tx).is_none(), "non-MsgSend must not parse");
    }

    #[test]
    fn ascii_and_hex_helpers() {
        assert_eq!(ascii_to_u128(b"0").unwrap(), 0);
        assert_eq!(ascii_to_u128(b"340282366920938463463374607431768211455").unwrap(), u128::MAX);
        assert!(ascii_to_u128(b"").is_none());
        assert!(ascii_to_u128(b"12a").is_none());
        assert!(ascii_to_u128(b"340282366920938463463374607431768211456").is_none()); // u128::MAX + 1 overflows
        assert!(hex_decode_32(b"00").is_none());
        let bytes = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef].iter().cycle().take(32).cloned().collect::<Vec<u8>>();
        let h: Vec<u8> = bytes.iter().flat_map(|b| { let s = b"0123456789abcdef"; [s[(b >> 4) as usize], s[(b & 0xf) as usize]] }).collect();
        assert_eq!(&hex_decode_32(&h).unwrap()[..], &bytes[..]);
    }

    #[test]
    fn varint_field_skipping() {
        // a message with a varint field (3) before our target bytes field (2) must skip correctly
        let mut b = Vec::new();
        enc_varint((3 << 3) | 0, &mut b); enc_varint(123456, &mut b); // field 3, varint
        enc_bytes(2, b"hello", &mut b);                                // field 2, bytes
        assert_eq!(pb_first_bytes(&b, 2).unwrap(), b"hello");
    }
}

#[cfg(test)]
fn hex_of(b: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    let hx = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b { s.push(hx[(x >> 4) as usize] as char); s.push(hx[(x & 0xf) as usize] as char); }
    s
}
