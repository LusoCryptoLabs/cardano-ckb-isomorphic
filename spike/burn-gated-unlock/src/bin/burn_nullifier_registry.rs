//! burn_nullifier_registry.rs — the global REPLAY-ONCE nullifier set for the reverse leg (closes C1).
//!
//! C1: `burn_gated_unlock` releases locked CKB on a proof that a Cardano burn is certified — but nothing
//! marked the burn CONSUMED, so ONE real burn could release UNLIMITED locked cells (replay). This is a
//! singleton state cell holding the root of a fixed-depth (256-bit) SPARSE MERKLE TREE over the set of
//! already-consumed burn keys. A spend may only INSERT one new key, and the proof forces that key to have
//! been ABSENT under the OLD root (value 0 = NON-MEMBERSHIP) and PRESENT under the NEW root — so a burn key
//! can be inserted at most once, ever. `burn_gated_unlock_v2` requires its burn's key to be inserted here in
//! the same tx; a replay of the same burn then fails because the key is already present and its
//! non-membership proof against the current root cannot verify.
//!
//! Cell data        = 32-byte SMT root.
//! Singleton        = enforced by requiring EXACTLY ONE registry cell in the GroupInput and one in the
//!                    GroupOutput (a one-shot thread token / type-id pins the lineage in deployment).
//! witness(input_type) = key(32) ‖ 256×sibling(32)   (the merkle path siblings, leaf-level first)
//!   The key is revealed in plaintext so the unlock lock can check its burn-key is the one inserted; the
//!   siblings authenticate that the key moves 0 -> PRESENT against (old_root, new_root).
//!
//! The SMT here is deliberately self-contained pure-Rust (blake2b-ref) — the stock `sparse-merkle-tree`
//! crate hard-depends on the C `blake2b-rs`, which cannot cross-compile to this riscv target.
#![no_std]
#![no_main]
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{load_cell_data, load_input, load_script, load_witness_args};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

const ZERO: [u8; 32] = [0u8; 32];
const PRESENT: [u8; 32] = [1u8; 32]; // leaf value for "consumed" (any fixed non-zero 32 bytes)

fn h2(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-smt-null-set").build();
    h.update(l); h.update(r);
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}

// ckbhash for the TYPE-ID derivation (matches CKB's default personalization).
fn ckbhash(d: &[u8]) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(d);
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}

// the root of the empty 256-deep SMT (all leaves absent) = E[256].
fn empty_root() -> [u8; 32] { let mut e = ZERO; let mut d = 0; while d < 256 { e = h2(&e, &e); d += 1; } e }

/// Fold a leaf `value` at `key`'s 256-bit path up through `sib` (leaf-level first) to a root.
/// At depth `d` from the leaf, the path bit is bit (255-d) of the key, MSB-of-byte-0 first.
fn fold(value: &[u8; 32], key: &[u8; 32], sib: &[[u8; 32]; 256]) -> [u8; 32] {
    let mut cur = *value;
    let mut d = 0usize;
    while d < 256 {
        let bi = 255 - d;
        let bit = (key[bi / 8] >> (7 - (bi % 8))) & 1;
        cur = if bit == 1 { h2(&sib[d], &cur) } else { h2(&cur, &sib[d]) };
        d += 1;
    }
    cur
}

fn program_entry() -> i8 {
    // SEC C1-R1: the registry is a TRUE SINGLETON via the CKB type-id pattern — its args are bound to a
    // uniquely-consumed outpoint at genesis, so its type hash cannot be duplicated and a second (parallel,
    // empty) registry with the same type hash is impossible. The unlock lock pins this type hash, so it can
    // only ever be satisfied by the one canonical lineage.
    let type_id = load_script().unwrap().args().raw_data();
    if type_id.len() != 32 { return 20; }

    // GENESIS branch: no registry input. Create exactly one, EMPTY, with args == ckbhash(first input outpoint).
    if load_cell_data(0, Source::GroupInput).is_err() {
        if load_cell_data(1, Source::GroupOutput).is_ok() { return 21; }      // singleton: one output
        let new_root = match load_cell_data(0, Source::GroupOutput) { Ok(d) => d, Err(_) => return 22 };
        if new_root.len() != 32 || new_root[..] != empty_root()[..] { return 23; } // must start EMPTY
        let first_in = match load_input(0, Source::Input) { Ok(i) => i, Err(_) => return 24 };
        let expected = ckbhash(first_in.previous_output().as_slice());
        if type_id[..] != expected[..] { return 25; }                         // bind to the unique outpoint
        return 0;
    }

    // UPDATE branch.
    // 1) singleton continuity: exactly one registry cell in (GroupInput) and one in (GroupOutput). The
    //    continuing output is in this group, so it carries the SAME type script (same type-id) — preserved.
    let old_root = match load_cell_data(0, Source::GroupInput) { Ok(d) => d, Err(_) => return 2 };
    if load_cell_data(1, Source::GroupInput).is_ok() { return 3; }
    let new_root = match load_cell_data(0, Source::GroupOutput) { Ok(d) => d, Err(_) => return 4 };
    if load_cell_data(1, Source::GroupOutput).is_ok() { return 5; }
    if old_root.len() != 32 || new_root.len() != 32 { return 6; }
    let mut or = [0u8; 32]; or.copy_from_slice(&old_root);
    let mut nr = [0u8; 32]; nr.copy_from_slice(&new_root);

    // 2) read key + 256 siblings from the witness (fixed-size, bounds-checked).
    let wit = match load_witness_args(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 7 };
    let raw = match wit.input_type().to_opt() { Some(b) => b.raw_data(), None => return 8 };
    if raw.len() != 32 + 256 * 32 { return 9; }
    let mut key = [0u8; 32]; key.copy_from_slice(&raw[0..32]);
    let mut sib = [[0u8; 32]; 256];
    let mut i = 0usize;
    while i < 256 { sib[i].copy_from_slice(&raw[32 + i * 32..32 + i * 32 + 32]); i += 1; }

    // 3) NON-MEMBERSHIP: the key was ABSENT (value 0) under the OLD root — so it can't be re-inserted.
    if fold(&ZERO, &key, &sib) != or { return 12; }
    // 4) INSERTION: the SAME siblings take value PRESENT to the NEW root (only this one leaf changed).
    if fold(&PRESENT, &key, &sib) != nr { return 13; }
    0
}
