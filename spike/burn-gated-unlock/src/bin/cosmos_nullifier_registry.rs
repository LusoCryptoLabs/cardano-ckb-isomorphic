//! cosmos_nullifier_registry.rs — the replay-once nullifier set for the Cosmos legs, as a SINGLETON CKB cell.
//! It is a type-id type script (so exactly one such cell can exist) whose data is a concatenation of 32-byte
//! keys (the consumed nullifiers). catom_mint requires this cell as an input carrying, in its witness
//! input_type, the key it is inserting; this script enforces that the recreated cell appends exactly that key,
//! that the key was not already present (no double-spend of a Cosmos escrow), and that the prefix is preserved.
//!
//! GENESIS (no group input): exactly one group output, args == type_id(inputs[0] ‖ out_index), empty data.
//! SPEND (1 group input -> 1 group output): new_data == old_data ‖ key, |old| a multiple of 32, key absent from
//! old, and key == this cell's witness input_type (so the registry and catom_mint agree on the inserted key).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{load_cell_capacity, load_cell_data, load_cell_type_hash, load_input, load_script, load_script_hash, load_witness_args};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

fn b2b256(parts: &[&[u8]]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); for p in parts { h.update(p); } let mut o = [0u8; 32]; h.finalize(&mut o); o }

fn count(src: Source) -> usize { let mut i = 0; loop { match load_cell_capacity(i, src) { Ok(_) => i += 1, Err(_) => break } } i }

fn program_entry() -> i8 {
    let my_hash = match load_script_hash() { Ok(h) => h, Err(_) => return 1 };
    let gi = count(Source::GroupInput);
    let go = count(Source::GroupOutput);

    if gi == 0 {
        // GENESIS: pin the type-id so only one registry can ever be created.
        if go != 1 { return 2; }
        let mut out_idx: i64 = -1;
        let mut i = 0usize;
        loop {
            match load_cell_type_hash(i, Source::Output) {
                Ok(Some(t)) if t == my_hash => { out_idx = i as i64; break; }
                Ok(_) => i += 1,
                Err(_) => break,
            }
        }
        if out_idx < 0 { return 3; }
        let input0 = match load_input(0, Source::Input) { Ok(c) => c, Err(_) => return 4 };
        let tid = b2b256(&[input0.as_slice(), &(out_idx as u64).to_le_bytes()]);
        let args = match load_script() { Ok(s) => s.args().raw_data(), Err(_) => return 5 };
        if args.len() != 32 || args[..] != tid[..] { return 6; }
        let d = match load_cell_data(0, Source::GroupOutput) { Ok(d) => d, Err(_) => return 7 };
        if !d.is_empty() { return 8; }   // a fresh registry starts empty
        return 0;
    }

    // SPEND: append exactly one new key.
    if gi != 1 || go != 1 { return 9; }
    let old = match load_cell_data(0, Source::GroupInput) { Ok(d) => d, Err(_) => return 10 };
    let new = match load_cell_data(0, Source::GroupOutput) { Ok(d) => d, Err(_) => return 11 };
    if old.len() % 32 != 0 || new.len() != old.len() + 32 { return 12; }
    if new[..old.len()] != old[..] { return 13; }            // prefix preserved (append-only)
    let key = &new[old.len()..];                              // the inserted 32-byte key
    let mut i = 0usize;
    while i < old.len() { if &old[i..i + 32] == key { return 14; } i += 32; }   // no double-insert
    // the inserted key must equal this cell's witness input_type (catom_mint reads the same slot).
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 15 };
    match w.input_type().to_opt() { Some(b) if b.raw_data().len() == 32 && &b.raw_data()[..] == key => {}, _ => return 16 }
    0
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
