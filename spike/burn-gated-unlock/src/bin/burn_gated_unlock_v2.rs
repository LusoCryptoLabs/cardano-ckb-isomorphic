//! burn_gated_unlock_v2.rs - the GENERALIZED burn-gated CKB lock (gap #2 generalization). Releases the
//! locked CKB ONLY if a Mithril-certified Cardano burn of the bound asset, of the BOUND AMOUNT, is proven
//! in-VM - for ANY burn tx, not a hardcoded one. Versus the original (which embedded the specific full-supply
//! burn tx 6608c4c8), v2 reads the burn tx body + its MKMapProof from the WITNESS, verifies cert-membership
//! generically against the authenticated checkpoint, PARSES the Conway `mint` field, and binds the release
//! to the exact burned amount of (policy, asset_name).
//!
//! args = checkpoint_type_hash(32) ‖ amount(u128 LE, 16) ‖ policy_id(28) ‖ asset_name(rest)
//! witness.input_type (R layout, same as bound_asset_unified) =
//!   lp(tx_body) ‖ lp(sub_root) ‖ u64(sub_pos) ‖ u64(sub_size) ‖ items(sub_items)
//!   ‖ lp(range_key) ‖ u64(master_pos) ‖ u64(master_size) ‖ items(master_items)
#![no_std]
#![no_main]
use alloc::{vec, vec::Vec};
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{Merge, MerkleProof, Result as MMRResult};
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{load_cell_data, load_cell_type_hash, load_script, load_witness_args};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

#[derive(Clone, PartialEq, Eq)]
struct N(Vec<u8>);
struct MB;
impl Merge for MB {
    type Item = N;
    fn merge(l: &N, r: &N) -> MMRResult<N> {
        let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec()))
    }
}
fn b2s(parts: &[&[u8]]) -> Vec<u8> { let mut h = Blake2s256::new(); for p in parts { h.update(p); } h.finalize().to_vec() }
fn b2b256(p: &[u8]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).build(); h.update(p); let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn hexb(b: &[u8]) -> Vec<u8> { let hx = b"0123456789abcdef"; let mut o = Vec::with_capacity(b.len()*2); for &x in b { o.push(hx[(x>>4)as usize]); o.push(hx[(x&0xf)as usize]); } o }

// ---- witness reader (same layout as bound_asset_unified) ----
struct R<'a> { b: &'a [u8], i: usize }
impl<'a> R<'a> {
    // SEC C6: bounds-checked - malformed/over-long lengths fail the proof cleanly, never panic (OOB).
    fn u32(&mut self) -> usize { if self.i+4>self.b.len(){ self.i=self.b.len(); return 0; } let v = u32::from_le_bytes([self.b[self.i], self.b[self.i+1], self.b[self.i+2], self.b[self.i+3]]) as usize; self.i += 4; v }
    fn u64(&mut self) -> u64 { if self.i+8>self.b.len(){ self.i=self.b.len(); return 0; } let mut a = [0u8; 8]; a.copy_from_slice(&self.b[self.i..self.i+8]); self.i += 8; u64::from_le_bytes(a) }
    fn lp(&mut self) -> &'a [u8] { let n = self.u32(); if self.i+n>self.b.len(){ self.i=self.b.len(); return &[]; } let s = &self.b[self.i..self.i+n]; self.i += n; s }
    fn items(&mut self) -> Vec<N> { let n = self.u32(); if n>self.b.len(){ return Vec::new(); } (0..n).map(|_| N(self.lp().to_vec())).collect() }
}

// ---- Conway CBOR mint-field parser (tested by the v2 integration suite: malformed_txbody_rejected) ----
// SEC C1-R3: every access is BOUNDS-CHECKED - a malformed/truncated `tx_body` returns None and is mapped to
// a sentinel that can never equal a valid burn, so the lock fails cleanly (no reliance on a VM OOB trap).
// A recursion-depth cap on `skip` bounds the CKB-VM stack against a deeply-nested (adversarial) body.
const MAX_DEPTH: usize = 64;
fn hdr(b: &[u8], i: usize) -> Option<(u8, u64, usize)> {
    if i >= b.len() { return None; }
    let ib = b[i]; let m = ib >> 5; let lo = ib & 0x1f;
    let r = match lo {
        0..=23 => (m, lo as u64, i + 1),
        24 => { if i + 1 >= b.len() { return None; } (m, b[i+1] as u64, i + 2) }
        25 => { if i + 2 >= b.len() { return None; } (m, u16::from_be_bytes([b[i+1], b[i+2]]) as u64, i + 3) }
        26 => { if i + 4 >= b.len() { return None; } (m, u32::from_be_bytes([b[i+1], b[i+2], b[i+3], b[i+4]]) as u64, i + 5) }
        27 => { if i + 8 >= b.len() { return None; } (m, u64::from_be_bytes([b[i+1], b[i+2], b[i+3], b[i+4], b[i+5], b[i+6], b[i+7], b[i+8]]), i + 9) }
        _ => (m, 0, i + 1),
    };
    Some(r)
}
fn skip(b: &[u8], i: usize) -> Option<usize> { skip_d(b, i, 0) }
fn skip_d(b: &[u8], i: usize, depth: usize) -> Option<usize> {
    if depth > MAX_DEPTH { return None; } // bound the stack on adversarial nesting (fail-closed)
    let (m, a, j) = hdr(b, i)?;
    let r = match m {
        0 | 1 | 7 => j,
        2 | 3 => { let e = j.checked_add(a as usize)?; if e > b.len() { return None; } e }
        4 => { let mut k = j; for _ in 0..a { k = skip_d(b, k, depth + 1)?; } k }
        5 => { let mut k = j; for _ in 0..a { k = skip_d(b, k, depth + 1)?; k = skip_d(b, k, depth + 1)?; } k }
        6 => skip_d(b, j, depth + 1)?,
        _ => j,
    };
    Some(r)
}
fn cbor_int(b: &[u8], i: usize) -> Option<(i128, usize)> {
    let (m, a, j) = hdr(b, i)?;
    match m { 0 => Some((a as i128, j)), 1 => Some((-1i128 - a as i128, j)), _ => Some((0, skip(b, i)?)) }
}
/// signed quantity minted/burned for (policy, name) from a Conway tx body (key 9 = mint). burn ⇒ negative.
/// Returns `i128::MAX` (PARSE_ERR sentinel) on any malformed/OOB input - never equal to a real `-(amount)`.
fn mint_qty(b: &[u8], policy: &[u8], name: &[u8]) -> i128 {
    mint_qty_inner(b, policy, name).unwrap_or(i128::MAX)
}
fn mint_qty_inner(b: &[u8], policy: &[u8], name: &[u8]) -> Option<i128> {
    let (m, n, mut i) = hdr(b, 0)?;
    if m != 5 { return Some(0); }
    for _ in 0..n {
        let (km, key, ki) = hdr(b, i)?; i = ki;
        if km == 0 && key == 9 {
            let (pm, pcount, mut p) = hdr(b, i)?;
            if pm != 5 { return Some(0); }
            // SEC C3: sum ALL matching (policy,name) entries; never early-return on first match.
            let mut acc: i128 = 0;
            for _ in 0..pcount {
                let (_bm, plen, pa) = hdr(b, p)?;
                let pe = pa.checked_add(plen as usize)?; if pe > b.len() { return None; }
                let pol = &b[pa..pe];
                let (am, acount, mut a) = hdr(b, pe)?;
                if am != 5 { return Some(0); }
                for _ in 0..acount {
                    let (_nm, nlen, na) = hdr(b, a)?;
                    let ne = na.checked_add(nlen as usize)?; if ne > b.len() { return None; }
                    let nm = &b[na..ne];
                    let (qty, aq) = cbor_int(b, ne)?;
                    if pol == policy && nm == name { acc = acc.saturating_add(qty); }
                    a = aq;
                }
                p = a;
            }
            return Some(acc);
        } else { i = skip(b, i)?; }
    }
    Some(0)
}

fn cert_root_from_checkpoint(type_hash: &[u8; 32]) -> Option<Vec<u8>> {
    let mut i = 0usize;
    loop {
        match load_cell_data(i, Source::CellDep) {
            Ok(data) => {
                if data.len() >= 36 && &data[0..4] == b"LCKP" {
                    if let Ok(Some(th)) = load_cell_type_hash(i, Source::CellDep) {
                        if &th == type_hash { return Some(data[4..36].to_vec()); }
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return None,
            Err(_) => return None,
        }
    }
}

// SEC C1: the burn must be NULLIFIED in the global registry in THIS tx - find the (singleton) registry
// input by its type-script hash and require its witness inserts EXACTLY this burn's key. Combined with the
// registry's non-membership proof (a key inserts at most once, ever), a given certified burn can authorize
// at most one unlock across all transactions.
fn registry_inserts_key(reg_type_hash: &[u8; 32], key: &[u8; 32]) -> bool {
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, Source::Input) {
            Ok(Some(th)) if &th == reg_type_hash => {
                if let Ok(w) = load_witness_args(i, Source::Input) {
                    if let Some(b) = w.input_type().to_opt() {
                        let d = b.raw_data();
                        return d.len() >= 32 && &d[0..32] == key; // registry's inserted key == this burn
                    }
                }
                return false;
            }
            Ok(_) => { i += 1; }
            Err(SysError::IndexOutOfBound) => return false,
            Err(_) => return false,
        }
    }
}

fn program_entry() -> i8 {
    let args = load_script().unwrap().args().raw_data();
    // args = checkpoint_type_hash(32) ‖ amount(16 LE) ‖ policy(28) ‖ registry_type_hash(32) ‖ asset_name(rest)
    if args.len() < 32 + 16 + 28 + 32 { return 2; }
    let mut type_hash = [0u8; 32]; type_hash.copy_from_slice(&args[0..32]);
    let mut amt = [0u8; 16]; amt.copy_from_slice(&args[32..48]);
    let amount = u128::from_le_bytes(amt);
    let policy = &args[48..76];
    let mut registry_type_hash = [0u8; 32]; registry_type_hash.copy_from_slice(&args[76..108]);
    let name = &args[108..];

    // SEC C1 (within-tx): at most one cell with THIS exact lock per tx, so a single burn+registry-insert
    // cannot release two identically-bound cells in the same transaction (mirrors the A6 single-cell rule).
    if load_cell_data(1, Source::GroupInput).is_ok() { return 14; }

    // 1. certified tx-set root from the AUTHENTICATED checkpoint cellDep (type == args.type_hash)
    let cert_root = match cert_root_from_checkpoint(&type_hash) { Some(r) => r, None => return 10 };

    // 2. read the burn tx body + its MKMapProof from the witness
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 3 };
    let lock = match w.lock().to_opt() { Some(l) => l.raw_data(), None => return 4 };
    let mut r = R { b: &lock, i: 0 };
    let tx_body = r.lp().to_vec();
    let sub_root = r.lp().to_vec(); let sub_pos = r.u64(); let sub_size = r.u64(); let sub_items = r.items();
    let range_key = r.lp().to_vec();
    let master_pos = r.u64(); let master_size = r.u64(); let master_items = r.items();

    // 3. the burn tx is certified: leaf = hex(blake2b256(tx_body)) under sub_root, and
    //    blake2s(range_key‖sub_root) under cert_root.
    let leaf = N(hexb(&b2b256(&tx_body)));
    if !MerkleProof::<N, MB>::new(sub_size, sub_items).verify(N(sub_root.clone()), vec![(sub_pos, leaf)]).unwrap_or(false) { return 5; }
    let master_leaf = N(b2s(&[&range_key, &sub_root]));
    if !MerkleProof::<N, MB>::new(master_size, master_items).verify(N(cert_root), vec![(master_pos, master_leaf)]).unwrap_or(false) { return 6; }

    // 4. bind the release to the ACTUAL burned amount of (policy, asset_name)
    let burned = mint_qty(&tx_body, policy, name);
    if burned != -(amount as i128) { return 7; } // must burn EXACTLY the bound amount (negative = burn)

    // 5. SEC C1: nullify this burn in the global registry - its key (the Cardano burn tx hash) must be the
    //    one inserted, and the registry's own validator proves it was ABSENT before (replay-once).
    // SEC (domain separation): 1-byte leg tag (0x02 = CKB-release burn nullifier); keyspace disjoint from the
    // χADA-mint (0x01) and χCKB-leap (0x03) legs sharing this registry. A future relayer builder must prefix 0x02.
    let key = { let mut p = vec![0x02u8]; p.extend_from_slice(&tx_body); b2b256(&p) };
    if !registry_inserts_key(&registry_type_hash, &key) { return 15; }
    0
}

// --- single-hart __sync_* atomic polyfills (CKB-VM has no A-extension; built with -a,+forced-atomics).
// Identical to bridge_lock_v1's; the `bytes`/molecule Arc refcount lowers to __sync_* on this target. ---
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
