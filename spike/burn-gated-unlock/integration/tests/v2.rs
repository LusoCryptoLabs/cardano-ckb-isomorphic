//! Real CKB-VM test for the GENERALIZED burn-gated lock (`burn_gated_unlock_v2`) + the replay-once
//! nullifier registry (`burn_nullifier_registry`). Builds a synthetic Conway burn tx + a consistent
//! two-level Blake2s256 MKMapProof (we control the checkpoint root), wires it into the lock's witness, AND
//! sets up the global SMT nullifier registry so the burn's key is inserted. Proves:
//!   - a certified burn of the BOUND amount, WITH a valid registry insertion, unlocks;
//!   - a wrong amount / tampered proof / missing checkpoint / missing registry is rejected;
//!   - REPLAY (SEC C1): re-using the same burn against a registry that already contains its key fails,
//!     because the registry's non-membership proof cannot verify.
use ckb_merkle_mountain_range::{util::{MemMMR, MemStore}, Merge, Result as MMRResult};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 400_000_000;
const LOCK_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/burn_gated_unlock_v2";
const REG_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/burn_nullifier_registry";

#[derive(Clone, PartialEq, Eq)]
struct N(Vec<u8>);
struct MB;
impl Merge for MB {
    type Item = N;
    fn merge(l: &N, r: &N) -> MMRResult<N> {
        use blake2::{Blake2s256, Digest};
        let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec()))
    }
}
fn b2s(parts: &[&[u8]]) -> Vec<u8> { use blake2::{Blake2s256, Digest}; let mut h = Blake2s256::new(); for p in parts { h.update(p); } h.finalize().to_vec() }
fn b2b256(p: &[u8]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).build(); h.update(p); let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn ckbhash(p: &[u8]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(p); let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn hexb(b: &[u8]) -> Vec<u8> { let hx = b"0123456789abcdef"; let mut o = Vec::new(); for &x in b { o.push(hx[(x>>4)as usize]); o.push(hx[(x&0xf)as usize]); } o }

// ---- the nullifier SMT (mirror of burn_nullifier_registry.rs: same personalization, same fold) ----
const ZERO: [u8; 32] = [0u8; 32];
const PRESENT: [u8; 32] = [1u8; 32];
fn h2(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-smt-null-set").build();
    h.update(l); h.update(r); let mut o = [0u8; 32]; h.finalize(&mut o); o
}
/// empty-subtree roots: E[0]=ZERO, E[d]=h2(E[d-1],E[d-1]); E[256] = root of the empty tree.
fn empties() -> Vec<[u8; 32]> { let mut e = vec![ZERO]; for d in 1..=256 { let p = e[d - 1]; e.push(h2(&p, &p)); } e }
fn fold(value: &[u8; 32], key: &[u8; 32], sib: &[[u8; 32]; 256]) -> [u8; 32] {
    let mut cur = *value;
    for d in 0..256 {
        let bi = 255 - d;
        let bit = (key[bi / 8] >> (7 - (bi % 8))) & 1;
        cur = if bit == 1 { h2(&sib[d], &cur) } else { h2(&cur, &sib[d]) };
    }
    cur
}
/// For inserting `key` into the EMPTY tree: old_root, sib (= empty-subtree roots), new_root, and the
/// registry witness bytes (key ‖ 256 siblings).
fn empty_insert(key: &[u8; 32]) -> ([u8; 32], [[u8; 32]; 256], [u8; 32], Vec<u8>) {
    let e = empties();
    let old_root = e[256];
    let mut sib = [[0u8; 32]; 256];
    for d in 0..256 { sib[d] = e[d]; }
    let new_root = fold(&PRESENT, key, &sib);
    let mut w = Vec::with_capacity(32 + 256 * 32);
    w.extend_from_slice(key);
    for d in 0..256 { w.extend_from_slice(&sib[d]); }
    (old_root, sib, new_root, w)
}

/// CBOR negative int = -(q): major 1, arg = q-1.
fn cbor_neg(q: u128) -> Vec<u8> {
    let arg = q - 1;
    let mut v = Vec::new();
    if arg < 24 { v.push(0x20 + arg as u8); }
    else if arg < 256 { v.push(0x38); v.push(arg as u8); }
    else if arg < 65536 { v.push(0x39); v.extend_from_slice(&(arg as u16).to_be_bytes()); }
    else if arg < (1u128 << 32) { v.push(0x3a); v.extend_from_slice(&(arg as u32).to_be_bytes()); }
    else { v.push(0x3b); v.extend_from_slice(&(arg as u64).to_be_bytes()); }
    v
}
fn build_txbody(policy: &[u8], name: &[u8], burn: u128) -> Vec<u8> {
    let mut b = vec![0xA2u8, 0x00, 0x80, 0x09, 0xA1];
    b.push(0x58); b.push(policy.len() as u8); b.extend_from_slice(policy);
    b.push(0xA1);
    b.push(0x40 + name.len() as u8); b.extend_from_slice(name);
    b.extend_from_slice(&cbor_neg(burn));
    b
}

fn make_proof(tx_body: &[u8], tamper: bool) -> (Vec<u8>, Vec<u8>) {
    let leaf = N(hexb(&b2b256(tx_body)));
    let sub_store = MemStore::default();
    let mut sub = MemMMR::<N, MB>::new(0, &sub_store);
    let _ = sub.push(N(b2s(&[b"s0"]))).unwrap();
    let sub_pos = sub.push(leaf).unwrap();
    let _ = sub.push(N(b2s(&[b"s2"]))).unwrap();
    let sub_root = sub.get_root().unwrap();
    let sp = sub.gen_proof(vec![sub_pos]).unwrap();
    let (sub_size, sub_items) = (sp.mmr_size(), sp.proof_items().iter().map(|n| n.0.clone()).collect::<Vec<_>>());

    let range_key = b"4357140-4357155".to_vec();
    let master_leaf = N(b2s(&[&range_key, &sub_root.0]));
    let master_store = MemStore::default();
    let mut master = MemMMR::<N, MB>::new(0, &master_store);
    let _ = master.push(N(b2s(&[b"m0"]))).unwrap();
    let master_pos = master.push(master_leaf).unwrap();
    let cert_root = master.get_root().unwrap();
    let mp = master.gen_proof(vec![master_pos]).unwrap();
    let (master_size, master_items) = (mp.mmr_size(), mp.proof_items().iter().map(|n| n.0.clone()).collect::<Vec<_>>());

    let lp = |x: &[u8], o: &mut Vec<u8>| { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x); };
    let items = |xs: &[Vec<u8>], o: &mut Vec<u8>| { o.extend_from_slice(&(xs.len() as u32).to_le_bytes()); for x in xs { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x); } };
    let mut w = Vec::new();
    lp(tx_body, &mut w);
    lp(&sub_root.0, &mut w); w.extend_from_slice(&sub_pos.to_le_bytes()); w.extend_from_slice(&sub_size.to_le_bytes()); items(&sub_items, &mut w);
    lp(&range_key, &mut w); w.extend_from_slice(&master_pos.to_le_bytes()); w.extend_from_slice(&master_size.to_le_bytes()); items(&master_items, &mut w);
    if tamper { let n = w.len(); w[n - 1] ^= 0xff; }
    (w, cert_root.0)
}

const POLICY: [u8; 28] = [0xab; 28];
const NAME: &[u8] = b"ckCKB";

struct Cfg {
    state_amount: u128,
    witness_burn: u128,
    tamper: bool,
    include_checkpoint: bool,
    include_registry: bool,
    // registry old root: None => empty tree (valid insert); Some(r) => preset root (replay scenario)
    registry_old_root: Option<[u8; 32]>,
    // override the tx_body with raw (possibly malformed) bytes - exercises the bounds-checked CBOR parser.
    bad_body: Option<Vec<u8>>,
}
impl Cfg {
    fn ok() -> Self { Cfg { state_amount: 100_000, witness_burn: 100_000, tamper: false, include_checkpoint: true, include_registry: true, registry_old_root: None, bad_body: None } }
}

fn build(cfg: Cfg) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let mut ctx = Context::default();
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build burn_gated_unlock_v2 first").into();
    let reg_bin: Bytes = std::fs::read(REG_BIN).expect("build burn_nullifier_registry first").into();
    let lock_op = ctx.deploy_cell(lock_bin);
    let reg_op = ctx.deploy_cell(reg_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let ckpt_type = ctx.build_script(&as_op, Bytes::from(b"txsetcert".to_vec())).unwrap();
    let ckpt_type_hash: [u8; 32] = ckpt_type.calc_script_hash().unpack();
    // a 32-byte type-id arg (the UPDATE branch doesn't re-derive it; genesis is exercised separately).
    let reg_type = ctx.build_script(&reg_op, Bytes::from([0x11u8; 32].to_vec())).unwrap();
    let reg_type_hash: [u8; 32] = reg_type.calc_script_hash().unpack();

    let tx_body = cfg.bad_body.clone().unwrap_or_else(|| build_txbody(&POLICY, NAME, cfg.witness_burn));
    let (lock_witness, cert_root) = make_proof(&tx_body, cfg.tamper);
    let key = { let mut p = vec![0x02u8]; p.extend_from_slice(&tx_body); b2b256(&p) }; // 0x02 = CKB-release leg tag
    let (empty_root, _sib, new_root, reg_witness) = empty_insert(&key);
    let old_root = cfg.registry_old_root.unwrap_or(empty_root);

    // lock args = checkpoint_type_hash(32) ‖ amount(16) ‖ policy(28) ‖ registry_type_hash(32) ‖ name
    let mut args = Vec::new();
    args.extend_from_slice(&ckpt_type_hash);
    args.extend_from_slice(&cfg.state_amount.to_le_bytes());
    args.extend_from_slice(&POLICY);
    args.extend_from_slice(&reg_type_hash);
    args.extend_from_slice(NAME);
    let lock_script = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    let dummy = ctx.build_script(&as_op, Bytes::from(b"d".to_vec())).unwrap();
    let locked = ctx.create_cell(CellOutput::new_builder().capacity(1000u64.pack()).lock(lock_script).build(), Bytes::new());

    let mut b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(locked).build())
        .output(CellOutput::new_builder().capacity(900u64.pack()).lock(dummy.clone()).build())
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(reg_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build());

    // witness[0] = lock's MKMapProof (.lock)
    let mut witnesses: Vec<Bytes> = vec![
        WitnessArgs::new_builder().lock(Some(Bytes::from(lock_witness)).pack()).build().as_bytes(),
    ];

    if cfg.include_registry {
        // registry input (data = old_root) + output (data = new_root), carrying the registry type script.
        let reg_in = ctx.create_cell(
            CellOutput::new_builder().capacity(2000u64.pack()).lock(dummy.clone()).type_(Some(reg_type.clone()).pack()).build(),
            Bytes::from(old_root.to_vec()),
        );
        b = b.input(CellInput::new_builder().previous_output(reg_in).build())
             .output(CellOutput::new_builder().capacity(2000u64.pack()).lock(dummy.clone()).type_(Some(reg_type.clone()).pack()).build())
             .output_data(Bytes::from(new_root.to_vec()).pack());
        // witness[1] = registry's insert (.input_type) - registry input is at input index 1
        witnesses.push(WitnessArgs::new_builder().input_type(Some(Bytes::from(reg_witness)).pack()).build().as_bytes());
    }

    if cfg.include_checkpoint {
        let mut ckpt_data = b"LCKP".to_vec();
        ckpt_data.extend_from_slice(&cert_root);
        let ckpt_cell = ctx.create_cell(
            CellOutput::new_builder().capacity(3000u64.pack()).lock(dummy.clone()).type_(Some(ckpt_type).pack()).build(),
            Bytes::from(ckpt_data),
        );
        b = b.cell_dep(CellDep::new_builder().out_point(ckpt_cell).build());
    }
    for w in witnesses { b = b.witness(w.pack()); }
    let tx = b.build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn certified_burn_of_bound_amount_unlocks() {
    let (ctx, tx) = build(Cfg::ok());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a certified burn of the bound amount, nullified once, must unlock");
}

#[test]
fn wrong_amount_rejected() {
    let (ctx, tx) = build(Cfg { state_amount: 100_000, witness_burn: 99_999, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a burn of the wrong amount must be rejected");
}

#[test]
fn tampered_proof_rejected() {
    let (ctx, tx) = build(Cfg { tamper: true, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a tampered MKMapProof must be rejected");
}

#[test]
fn missing_checkpoint_rejected() {
    let (ctx, tx) = build(Cfg { include_checkpoint: false, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no authenticated checkpoint -> reject");
}

#[test]
fn missing_registry_rejected() {
    // SEC C1: without the nullifier registry insertion, the unlock must fail (code 15).
    let (ctx, tx) = build(Cfg { include_registry: false, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no nullifier insertion -> reject (replay protection)");
}

// ---- registry GENESIS, driven THROUGH the type-id validator (SEC C1-R1) ----
/// Build a genesis tx for the registry: a seed input is consumed, and the registry output's type-id args
/// must equal ckbhash(seed_outpoint) with an EMPTY-tree root. `bad_id`/`bad_root` perturb it.
fn build_genesis(bad_id: bool, bad_root: bool) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let mut ctx = Context::default();
    let reg_bin: Bytes = std::fs::read(REG_BIN).expect("build burn_nullifier_registry first").into();
    let reg_op = ctx.deploy_cell(reg_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let dummy = ctx.build_script(&as_op, Bytes::from(b"d".to_vec())).unwrap();

    let seed = ctx.create_cell(CellOutput::new_builder().capacity(5000u64.pack()).lock(dummy.clone()).build(), Bytes::new());
    // type-id = ckbhash(first_input.previous_output molecule bytes)
    let mut type_id = ckbhash(seed.as_slice());
    if bad_id { type_id[0] ^= 0xff; }
    let reg_type = ctx.build_script(&reg_op, Bytes::from(type_id.to_vec())).unwrap();

    let root = if bad_root { [7u8; 32] } else { empties()[256] };
    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(seed).build())
        .output(CellOutput::new_builder().capacity(2000u64.pack()).lock(dummy.clone()).type_(Some(reg_type).pack()).build())
        .output_data(Bytes::from(root.to_vec()).pack())
        .cell_dep(CellDep::new_builder().out_point(reg_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn registry_genesis_ok() {
    let (ctx, tx) = build_genesis(false, false);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("genesis with type-id==ckbhash(outpoint) and empty root must pass");
}

#[test]
fn registry_genesis_wrong_typeid_rejected() {
    // SEC C1-R1: a registry whose args are NOT bound to the consumed outpoint cannot be created - this is
    // what makes a parallel/duplicate registry (and thus replay into a fresh empty set) impossible.
    let (ctx, tx) = build_genesis(true, false);
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "genesis with a forged type-id must be rejected (code 25)");
}

#[test]
fn registry_genesis_nonempty_rejected() {
    let (ctx, tx) = build_genesis(false, true);
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "genesis must start from the EMPTY root (code 23)");
}

#[test]
fn malformed_txbody_rejected() {
    // SEC C1-R3: a truncated Conway body (header announces a mint map but the bytes end early) is CERTIFIED
    // (we control the root, so the MMR check passes), yet the bounds-checked parser returns the PARSE_ERR
    // sentinel and the amount binding rejects it - a clean fail, no OOB trap, and no unlock from garbage.
    let mut body = build_txbody(&POLICY, NAME, 100_000);
    body.truncate(body.len() - 3); // chop the burn quantity / asset bytes
    let (ctx, tx) = build(Cfg { bad_body: Some(body), ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a certified-but-malformed tx body must not unlock");
}

#[test]
fn replay_same_burn_rejected() {
    // SEC C1 (the core property): the burn's key is ALREADY present in the registry (old_root = the
    // post-insert root). The registry's non-membership proof against that root cannot verify, so the
    // second use of the same certified burn is rejected - one burn can release at most one cell.
    let tx_body = build_txbody(&POLICY, NAME, 100_000);
    let key = { let mut p = vec![0x02u8]; p.extend_from_slice(&tx_body); b2b256(&p) }; // 0x02 = CKB-release leg tag
    let (_empty, _sib, new_root, _w) = empty_insert(&key);
    let (ctx, tx) = build(Cfg { registry_old_root: Some(new_root), ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "replaying the same certified burn must be rejected");
}

// ===================================================================================================
// FULL χCKB BRIDGE-CELL ROUND-TRIP (Phase 4): the return leg with the SAME cell carrying BOTH the
// bridge_lock_v1 RECEIPT type AND the burn_gated_unlock_v2 release lock, bound to the REAL χCKB asset.
// v2.rs above tests the release lock in isolation (dummy lock cell, generic asset); these prove the two
// scripts COMPOSE on one cell and that release is bound to the χCKB asset IDENTITY (policy AND name).
// ===================================================================================================
const BRIDGE_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/bridge_lock_v1";
const CKCKB_POLICY: [u8; 28] = [0x9c; 28];                 // representative leap_mint_guard χCKB policy id
const CKCKB_NAME: &[u8] = &[0xcf, 0x87, 0x43, 0x4b, 0x42]; // "χCKB" (cf87434b42), the real d6_deploy FT_NAME

struct RT { amount: u128, burn_amount: u128, burn_name: Vec<u8>, burn_policy: [u8; 28] }
impl RT {
    // 200 CKB (20e9 shannons), like the live forward receipt 0xcfaaf177.
    fn ok() -> Self { RT { amount: 20_000_000_000, burn_amount: 20_000_000_000, burn_name: CKCKB_NAME.to_vec(), burn_policy: CKCKB_POLICY } }
}

fn build_roundtrip(rt: RT) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let mut ctx = Context::default();
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build burn_gated_unlock_v2 first").into();
    let reg_bin: Bytes = std::fs::read(REG_BIN).expect("build burn_nullifier_registry first").into();
    let bridge_bin: Bytes = std::fs::read(BRIDGE_BIN).expect("build bridge_lock_v1 first").into();
    let lock_op = ctx.deploy_cell(lock_bin);
    let reg_op = ctx.deploy_cell(reg_bin);
    let bridge_op = ctx.deploy_cell(bridge_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let ckpt_type = ctx.build_script(&as_op, Bytes::from(b"txsetcert".to_vec())).unwrap();
    let ckpt_type_hash: [u8; 32] = ckpt_type.calc_script_hash().unpack();
    let reg_type = ctx.build_script(&reg_op, Bytes::from([0x11u8; 32].to_vec())).unwrap();
    let reg_type_hash: [u8; 32] = reg_type.calc_script_hash().unpack();
    let bridge_type = ctx.build_script(&bridge_op, Bytes::new()).unwrap(); // kind=0 ignores args

    // the certified Cardano χCKB burn (real asset name) of `burn_amount`.
    let tx_body = build_txbody(&rt.burn_policy, &rt.burn_name, rt.burn_amount);
    let (lock_witness, cert_root) = make_proof(&tx_body, false);
    let key = { let mut p = vec![0x02u8]; p.extend_from_slice(&tx_body); b2b256(&p) }; // 0x02 = CKB-release leg tag
    let (empty_root, _sib, new_root, reg_witness) = empty_insert(&key);

    // the release lock is bound to the χCKB asset identity (CKCKB_POLICY ‖ CKCKB_NAME) + the bound amount.
    let mut args = Vec::new();
    args.extend_from_slice(&ckpt_type_hash);
    args.extend_from_slice(&rt.amount.to_le_bytes());
    args.extend_from_slice(&CKCKB_POLICY);
    args.extend_from_slice(&reg_type_hash);
    args.extend_from_slice(CKCKB_NAME);
    let lock_script = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    // the forward-locked bridge cell: capacity == amount (kind=0 CKB), LOCK = release lock, TYPE = receipt.
    // 49-byte receipt = MAGIC("BRG1") ‖ kind(0) ‖ amount(16 LE) ‖ recipient(28).
    let mut receipt = b"BRG1".to_vec();
    receipt.push(0u8);
    receipt.extend_from_slice(&rt.amount.to_le_bytes());
    receipt.extend_from_slice(&[0x2du8; 28]);
    let locked = ctx.create_cell(
        CellOutput::new_builder().capacity((rt.amount as u64).pack()).lock(lock_script).type_(Some(bridge_type).pack()).build(),
        Bytes::from(receipt),
    );

    let dummy = ctx.build_script(&as_op, Bytes::from(b"d".to_vec())).unwrap();
    let reg_in = ctx.create_cell(
        CellOutput::new_builder().capacity(2000u64.pack()).lock(dummy.clone()).type_(Some(reg_type.clone()).pack()).build(),
        Bytes::from(empty_root.to_vec()),
    );
    let mut ckpt_data = b"LCKP".to_vec();
    ckpt_data.extend_from_slice(&cert_root);
    let ckpt_cell = ctx.create_cell(
        CellOutput::new_builder().capacity(3000u64.pack()).lock(dummy.clone()).type_(Some(ckpt_type).pack()).build(),
        Bytes::from(ckpt_data),
    );

    // full unlock: the released CKB goes to a plain output (NO bridge receipt output -> bridge_lock_v1 CONSUME).
    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(locked).build())
        .output(CellOutput::new_builder().capacity((rt.amount as u64 - 1000).pack()).lock(dummy.clone()).build())
        .output_data(Bytes::new().pack())
        .input(CellInput::new_builder().previous_output(reg_in).build())
        .output(CellOutput::new_builder().capacity(2000u64.pack()).lock(dummy.clone()).type_(Some(reg_type.clone()).pack()).build())
        .output_data(Bytes::from(new_root.to_vec()).pack())
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(reg_op).build())
        .cell_dep(CellDep::new_builder().out_point(bridge_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_cell).build())
        .witness(WitnessArgs::new_builder().lock(Some(Bytes::from(lock_witness)).pack()).build().as_bytes().pack())
        .witness(WitnessArgs::new_builder().input_type(Some(Bytes::from(reg_witness)).pack()).build().as_bytes().pack())
        .build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn chckb_bridge_cell_roundtrip_unlocks() {
    // The same cell carrying bridge_lock_v1 (receipt) + burn_gated_unlock_v2 (release lock) is released by a
    // certified χCKB burn of the bound amount: bridge_lock_v1 CONSUME allows + the lock gates on the cert.
    let (ctx, tx) = build_roundtrip(RT::ok());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a certified χCKB burn of the bound amount must release the bridge cell");
}

#[test]
fn chckb_wrong_asset_name_rejected() {
    // ASSET-IDENTITY binding (new vs v2.rs, which only varied the amount): a burn of a DIFFERENT asset name
    // (same policy, same amount) does not satisfy the lock's (policy, χCKB-name) lookup -> burned == 0 -> reject.
    let (ctx, tx) = build_roundtrip(RT { burn_name: b"NOTCKB".to_vec(), ..RT::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a burn of a different asset NAME must not release the χCKB cell");
}

#[test]
fn chckb_wrong_policy_rejected() {
    // ASSET-IDENTITY binding: a burn under a DIFFERENT policy id (same name, same amount) -> burned == 0 -> reject.
    let (ctx, tx) = build_roundtrip(RT { burn_policy: [0xee; 28], ..RT::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a burn under a different POLICY must not release the χCKB cell");
}

// FORWARD CREATE (the other half of the loop): the bridge cell the return trip releases is a VALID
// bridge_lock_v1 CREATE output - value-locked (kind=0: capacity == amount) under the burn_gated_unlock_v2
// release lock bound to the χCKB asset. So the exact cell spec the return tests release is one a real forward
// lock produces. (The lock doesn't run on create; bridge_lock_v1 enforces the value-lock + receipt layout.)
fn build_forward_lock(amount: u128, bad_capacity: bool) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let mut ctx = Context::default();
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build burn_gated_unlock_v2 first").into();
    let reg_bin: Bytes = std::fs::read(REG_BIN).expect("build burn_nullifier_registry first").into();
    let bridge_bin: Bytes = std::fs::read(BRIDGE_BIN).expect("build bridge_lock_v1 first").into();
    let lock_op = ctx.deploy_cell(lock_bin);
    let reg_op = ctx.deploy_cell(reg_bin);
    let bridge_op = ctx.deploy_cell(bridge_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let dummy = ctx.build_script(&as_op, Bytes::from(b"d".to_vec())).unwrap();
    let reg_type = ctx.build_script(&reg_op, Bytes::from([0x11u8; 32].to_vec())).unwrap();
    let reg_type_hash: [u8; 32] = reg_type.calc_script_hash().unpack();
    let ckpt_type = ctx.build_script(&as_op, Bytes::from(b"txsetcert".to_vec())).unwrap();
    let ckpt_type_hash: [u8; 32] = ckpt_type.calc_script_hash().unpack();
    // the release lock the forward lock parks the funds under (bound to χCKB identity + amount).
    let mut args = Vec::new();
    args.extend_from_slice(&ckpt_type_hash);
    args.extend_from_slice(&amount.to_le_bytes());
    args.extend_from_slice(&CKCKB_POLICY);
    args.extend_from_slice(&reg_type_hash);
    args.extend_from_slice(CKCKB_NAME);
    let release_lock = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();
    let bridge_type = ctx.build_script(&bridge_op, Bytes::new()).unwrap();
    // 49-byte receipt: MAGIC ‖ kind=0 ‖ amount(16 LE) ‖ recipient(28).
    let mut receipt = b"BRG1".to_vec();
    receipt.push(0u8);
    receipt.extend_from_slice(&amount.to_le_bytes());
    receipt.extend_from_slice(&[0x2du8; 28]);
    let funding = ctx.create_cell(CellOutput::new_builder().capacity((amount as u64 + 100_000).pack()).lock(dummy.clone()).build(), Bytes::new());
    // kind=0 requires the receipt cell's capacity == amount; bad_capacity perturbs it to prove enforcement.
    let out_cap = if bad_capacity { amount as u64 - 1 } else { amount as u64 };
    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(funding).build())
        .output(CellOutput::new_builder().capacity(out_cap.pack()).lock(release_lock).type_(Some(bridge_type).pack()).build())
        .output_data(Bytes::from(receipt).pack())
        .cell_dep(CellDep::new_builder().out_point(bridge_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn chckb_forward_lock_create_valid() {
    // 200 CKB locked under burn_gated_unlock_v2(χCKB) with a value-locked bridge_lock_v1 receipt -> CREATE ok.
    let (ctx, tx) = build_forward_lock(20_000_000_000, false);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a value-locked χCKB bridge receipt under the release lock must create");
}

#[test]
fn chckb_forward_lock_undercapitalized_rejected() {
    // the receipt declares 200 CKB but the cell holds 1 shannon less -> bridge_lock_v1 kind=0 rejects (code 4).
    let (ctx, tx) = build_forward_lock(20_000_000_000, true);
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "capacity < declared amount must not create the receipt");
}
