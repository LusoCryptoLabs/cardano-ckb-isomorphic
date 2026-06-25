//! xada_burn_receipt.rs - the χADA RETURN-leg burn receipt (spike/cardano-to-ckb-zk/XADA_LEG.md §3). To
//! return ADA, a holder BURNS χADA on CKB and creates ONE receipt cell binding (amount, cardano_recipient).
//! The return Groth16 circuit reads this receipt and proves the burn is in a CKB block; `ada_escrow` then
//! releases `amount` lovelace to `cardano_recipient` (replay-once via the burn seal).
//!
//! KEY DESIGN: the receipt SELF-ENFORCES that the tx genuinely burns exactly `amount` of the χADA policy
//! (Σ χADA inputs − Σ χADA outputs == amount), so it can never overstate. Therefore the already-deployed
//! `xada_mint` (whose burn path is permissive) is reused UNCHANGED - the forward and return trips share one
//! χADA policy. No redeploy, no policy fork.
//!
//!   receipt data = MAGIC(4)="XAD1" ‖ amount(16 LE) ‖ cardano_recipient(28)        (48 bytes)
//!   args        = xada_mint_policy_hash(32)   (the χADA type-script hash; the burned amount is summed over
//!                 cells carrying this type, exactly as `xada_mint` denominates χADA in data[0..16] u128 LE).
//!
//! CREATE path (receipt in GroupOutput): pin the layout + singleton + the burn binding. CONSUME path (receipt
//! in GroupInput, no output): reclaiming the receipt's capacity once it has served the circuit - allowed.
#![no_std]
#![no_main]
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_cell_data, load_cell_type_hash, load_script};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

const MAGIC: &[u8; 4] = b"XAD1";

// Σ χADA amounts (data[0..16] u128 LE) over cells whose TYPE hash == policy, in `source`.
fn sum_policy(source: Source, policy: &[u8; 32]) -> Option<u128> {
    let mut sum: u128 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, source) {
            Ok(Some(th)) if &th == policy => {
                let d = load_cell_data(i, source).ok()?;
                if d.len() < 16 { return None; }
                let mut a = [0u8; 16]; a.copy_from_slice(&d[0..16]);
                sum = sum.checked_add(u128::from_le_bytes(a))?;
                i += 1;
            }
            Ok(_) => { i += 1; }
            Err(_) => break,
        }
    }
    Some(sum)
}

fn program_entry() -> i8 {
    // CREATE path iff this type group has an output; otherwise CONSUME (reclaim) -> allow.
    let data = match load_cell_data(0, Source::GroupOutput) { Ok(d) => d, Err(_) => return 0 };
    if data.len() != 48 { return 1; }
    if &data[0..4] != MAGIC { return 2; }
    let mut amt = [0u8; 16]; amt.copy_from_slice(&data[4..20]);
    let amount = u128::from_le_bytes(amt);
    if amount == 0 { return 3; }
    // SINGLETON: exactly one receipt out, none in (a create must not also consume).
    if load_cell_data(1, Source::GroupOutput).is_ok() { return 4; }
    if load_cell_data(0, Source::GroupInput).is_ok() { return 5; }
    // the χADA policy this receipt is bound to.
    let args = load_script().unwrap().args().raw_data();
    if args.len() != 32 { return 6; }
    let mut policy = [0u8; 32]; policy.copy_from_slice(&args);
    // SELF-ENFORCE the burn: Σ χADA inputs − Σ χADA outputs == amount (a genuine burn of exactly `amount`).
    let sin = match sum_policy(Source::Input, &policy) { Some(v) => v, None => return 7 };
    let sout = match sum_policy(Source::Output, &policy) { Some(v) => v, None => return 8 };
    if sin < sout { return 9; }                 // net mint, not a burn
    if sin - sout != amount { return 10; }      // burned amount must equal the receipt's bound amount
    0
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
