//! bridge_lock_v1.rs - the CKB→Cardano bridge RECEIPT type script (VALUE_BINDING_FIX.md §2, both/configurable).
//!
//! A "lock for bridging to Cardano" creates exactly one RECEIPT cell carrying this type script with a fixed
//! 49-byte data layout. The receipt is what the leap circuit reads (a canonical, constant-offset blob), and
//! this script is the CHEAP on-chain enforcement that the declared amount is actually locked - so a confirmed
//! lock tx is self-certifying and the circuit only has to prove it is confirmed + carries this type.
//!
//!   receipt data = MAGIC(4)="BRG1" ‖ kind(1) ‖ amount(16 LE) ‖ recipient(28)        (49 bytes)
//!     kind = 0 (CKB)  : the receipt cell's own capacity == amount (the locked CKB IS the receipt capacity)
//!     kind = 1 (xUDT) : a sibling OUTPUT with type-hash == this script's args holds `amount` (data[0..16] LE)
//!   recipient(28) = the Cardano payment credential to mint χCKB to (opaque to CKB; the circuit binds it).
//!
//! CREATE path (receipt in GroupOutput): enforce the layout + singleton + value-lock. CONSUME path (receipt
//! in GroupInput, no output): the burn→unlock return trip - allowed here; the cell's release LOCK gates it on
//! a Mithril-proven Cardano burn (separate, the Mithril oracle). A tx may not both create and consume (no mix).
#![no_std]
#![no_main]
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{load_cell_capacity, load_cell_data, load_cell_type_hash, load_script};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

const MAGIC: &[u8; 4] = b"BRG1";
const KIND_CKB: u8 = 0;
const KIND_UDT: u8 = 1;

fn program_entry() -> i8 {
    // CREATE path iff this type group has an output; otherwise CONSUME (release lock gates the burn) -> allow.
    let data = match load_cell_data(0, Source::GroupOutput) { Ok(d) => d, Err(_) => return 0 };
    if data.len() != 49 { return 1 }
    if &data[0..4] != MAGIC { return 2 }
    let kind = data[4];
    let mut amt = [0u8; 16]; amt.copy_from_slice(&data[5..21]);
    let amount = u128::from_le_bytes(amt);
    if amount == 0 { return 6 }
    // SINGLETON: exactly one receipt of this type in outputs, and none in inputs (a create must not also consume).
    if load_cell_data(1, Source::GroupOutput).is_ok() { return 3 }
    if load_cell_data(0, Source::GroupInput).is_ok() { return 7 }
    match kind {
        KIND_CKB => {
            // the receipt cell's own capacity IS the locked value, and it must equal the declared amount.
            let cap = match load_cell_capacity(0, Source::GroupOutput) { Ok(c) => c, Err(_) => return 4 };
            if cap as u128 != amount { return 4 }
            0
        }
        KIND_UDT => {
            // EXACTLY ONE sibling output carries the bridged token: type-hash == args (the pinned xUDT type),
            // and its xUDT amount (data[0..16] LE) == amount.
            let want = load_script().unwrap().args().raw_data();
            if want.len() != 32 { return 8 }
            let mut i = 0usize; let mut found = false;
            loop {
                match load_cell_type_hash(i, Source::Output) {
                    Ok(Some(th)) if th[..] == want[..] => {
                        let d = match load_cell_data(i, Source::Output) { Ok(d) => d, Err(_) => return 9 };
                        if d.len() < 16 { return 9 }
                        let mut a = [0u8; 16]; a.copy_from_slice(&d[0..16]);
                        if u128::from_le_bytes(a) != amount { return 10 }
                        if found { return 11 }            // more than one bridged xUDT output -> ambiguous
                        found = true;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
                i += 1;
            }
            if !found { return 12 }
            0
        }
        _ => 5,
    }
}

// --- single-hart __sync_* atomic polyfills (CKB-VM has no A-extension; built with -a,+forced-atomics). ---
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
