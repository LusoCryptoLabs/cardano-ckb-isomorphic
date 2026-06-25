//! In-VM (real CKB-VM) validation of the GENERAL sparse-Merkle nullifier registry for REPEATABLE leaps:
//! the real `burn_nullifier_registry` binary must accept a 2nd insert into a NON-EMPTY tree (not just the
//! genesis-empty case the first toggle used) and reject a replay. Siblings are computed by a general SMT
//! (present-key-set based) that is ANCHORED to the live on-chain root: inserting the first live nullifier
//! key (f30ff09b…) into the empty tree must reproduce the live registry root f5a10236… that Pudge actually
//! holds - so the client SMT provably matches on-chain semantics, then the 2-key insert is trusted.
//!
//! This mirrors `relayer/onchain/reg_nullifier_witness.py` (the shipping witness builder); both reduce to
//! the empty-tree case and both reproduce the live anchor, so they agree with each other via on-chain.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 200_000_000;
const REGISTRY: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/burn_nullifier_registry";

const ZERO: [u8; 32] = [0u8; 32];
const PRESENT: [u8; 32] = [1u8; 32];

fn h2(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-smt-null-set").build();
    h.update(l); h.update(r);
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}
// e[h] = empty subtree of height h (e[0] = ZERO leaf), len 257.
fn e_levels() -> Vec<[u8; 32]> { let mut e = vec![ZERO]; for _ in 0..256 { let p = *e.last().unwrap(); e.push(h2(&p, &p)); } e }
fn bit(k: &[u8; 32], bi: usize) -> u8 { (k[bi / 8] >> (7 - (bi % 8))) & 1 }

// hash of the height-h subtree containing exactly `keys`.
fn subtree(h: usize, keys: &[[u8; 32]], e: &[[u8; 32]]) -> [u8; 32] {
    if keys.is_empty() { return e[h]; }
    if h == 0 { return PRESENT; }
    let bi = 256 - h;
    let left: Vec<[u8; 32]> = keys.iter().copied().filter(|k| bit(k, bi) == 0).collect();
    let right: Vec<[u8; 32]> = keys.iter().copied().filter(|k| bit(k, bi) == 1).collect();
    h2(&subtree(h - 1, &left, e), &subtree(h - 1, &right, e))
}
// 256 siblings (fold order) on K's path through the tree over `present` (K absent).
fn siblings(present: &[[u8; 32]], k: &[u8; 32], e: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut sib = vec![ZERO; 256];
    let mut cur: Vec<[u8; 32]> = present.to_vec();
    for h in (1..=256usize).rev() {
        let bi = 256 - h;
        let (same, other): (Vec<_>, Vec<_>) = cur.iter().copied().partition(|x| bit(x, bi) == bit(k, bi));
        sib[h - 1] = subtree(h - 1, &other, e);
        cur = same;
    }
    sib
}
fn fold(value: &[u8; 32], k: &[u8; 32], sib: &[[u8; 32]]) -> [u8; 32] {
    let mut cur = *value;
    for d in 0..256 { cur = if bit(k, 255 - d) == 1 { h2(&sib[d], &cur) } else { h2(&cur, &sib[d]) }; }
    cur
}
fn witness_for(present: &[[u8; 32]], k: &[u8; 32], e: &[[u8; 32]]) -> Vec<u8> {
    let sib = siblings(present, k, e);
    let mut w = k.to_vec(); for s in &sib { w.extend_from_slice(s); } w
}

// run the real registry binary on a minimal one-in/one-out singleton tx; return the verify Result.
fn run_insert(old_root: &[u8; 32], witness: &[u8], new_root: &[u8; 32]) -> Result<u64, String> {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let reg_op = ctx.deploy_cell(Bytes::from(std::fs::read(REGISTRY).unwrap()));
    let reg_type = ctx.build_script(&reg_op, Bytes::from(vec![0x77u8; 32])).unwrap();   // 32-byte type-id args
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let reg_in = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(reg_type.clone()).pack()).build(), Bytes::from(old_root.to_vec()));
    let w = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness.to_vec())).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(reg_in).build())
        .output(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock).type_(Some(reg_type).pack()).build())
        .output_data(Bytes::from(new_root.to_vec()).pack())
        .cell_dep(CellDep::new_builder().out_point(reg_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w.as_bytes().pack())
        .build());
    ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{:?}", e))
}

fn hexk(s: &str) -> [u8; 32] { let v: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect(); v.try_into().unwrap() }

#[test]
fn general_smt_matches_live_anchor() {
    // GROUND TRUTH: inserting the first live nullifier key into the empty tree must reproduce the live
    // on-chain registry root the toggle actually produced on Pudge (S5 tx 0xb45812da, registry out).
    let e = e_levels();
    let live_key = hexk("f30ff09b78286b647ffe53967f106698fe080b224b67ab5692d7b1e165a9b894");
    let empty_root = subtree(256, &[], &e);
    assert_eq!(hex(&empty_root), "5b7ed70cdcbaae36e29a122fb0b7d2414f4ca62a2103d76850e3f8ad1eed663c", "empty root anchor");
    let live_root = subtree(256, &[live_key], &e);
    assert_eq!(hex(&live_root), "f5a102362fde3a1acc37a92924a62658af0b83b269c51ea6c89bc6d483759d6b", "live registry root anchor");
    // and the empty-tree witness for that key folds correctly both ways
    let sib = siblings(&[], &live_key, &e);
    assert_eq!(fold(&ZERO, &live_key, &sib), empty_root);
    assert_eq!(fold(&PRESENT, &live_key, &sib), live_root);
}

#[test]
fn registry_accepts_two_sequential_inserts() {
    let e = e_levels();
    let k1 = hexk("f30ff09b78286b647ffe53967f106698fe080b224b67ab5692d7b1e165a9b894");   // 1st (live) key
    let k2 = hexk("6b3067f9bb3cc3225e586063eba36850c217de3eb2f20365046e36834b77f155");   // 2nd (new) key
    let r0 = subtree(256, &[], &e);          // empty
    let r1 = subtree(256, &[k1], &e);        // after k1 (== live root)
    let r2 = subtree(256, &[k1, k2], &e);    // after k2 (NON-EMPTY tree insert)

    // insert 1: empty -> r1 (the genesis case)
    run_insert(&r0, &witness_for(&[], &k1, &e), &r1).expect("insert into EMPTY tree must pass");
    // insert 2: r1 -> r2, siblings reflect k1's presence (THE NEW non-empty path)
    run_insert(&r1, &witness_for(&[k1], &k2, &e), &r2).expect("insert into NON-EMPTY tree must pass");
}

#[test]
fn registry_rejects_replay_of_present_key() {
    // replaying k1 against the post-insert root r1 with the empty-tree witness fails non-membership (err 12):
    // fold(ZERO, k1, empty_sib) == empty_root != r1.
    let e = e_levels();
    let k1 = hexk("f30ff09b78286b647ffe53967f106698fe080b224b67ab5692d7b1e165a9b894");
    let r1 = subtree(256, &[k1], &e);
    let r2bad = subtree(256, &[k1], &e);   // pretend no-op
    let err = run_insert(&r1, &witness_for(&[], &k1, &e), &r2bad).expect_err("replay must be rejected");
    assert!(err.contains("12"), "expected non-membership error 12, got: {}", err);
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
