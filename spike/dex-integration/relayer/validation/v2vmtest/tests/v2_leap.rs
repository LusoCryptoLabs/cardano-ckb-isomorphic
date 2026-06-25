//! In-VM (real CKB-VM) tests for the v2 ownership-toggle leap branches of bound_asset_v2:
//!  - S5 leap_to_ckb POSITIVE (the headline: B1 recipient binding + B3 lock pin + RC + B4 nullifier),
//!  - S5 negatives (bad RC -> 27, wrong output lock -> 29, missing nullifier -> 50),
//!  - S4 leap_to_cardano POSITIVE (input-lock auth + state-unchanged + seal_prime mint + state-only commitment).
//! Each test builds a self-consistent leap-shaped certified Cardano tx in-test (re-parked/minted seal + inline
//! datum + multiasset), MMR-certifies it exactly as the verifier hashes, and rebuilds the verifier with
//! CHIRAL_LCKP_TH/CHIRAL_REG_TH matching the test checkpoint + registry cells.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use std::process::Command;
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{Merge, Result as MMRResult, util::{MemMMR, MemStore}};

const MAX_CYCLES: u64 = 200_000_000;
const BGU_MANIFEST: &str = "../../../../burn-gated-unlock/Cargo.toml";
const VERIFIER: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2";

#[derive(Clone, PartialEq, Eq, Debug)]
struct N(Vec<u8>);
struct MB;
impl Merge for MB { type Item = N; fn merge(l: &N, r: &N) -> MMRResult<N> { let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(parts: &[&[u8]]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).build(); for p in parts { h.update(p); } let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn b2s(parts: &[&[u8]]) -> Vec<u8> { let mut h = Blake2s256::new(); for p in parts { h.update(p); } h.finalize().to_vec() }
fn hexb(b: &[u8]) -> Vec<u8> { let hx = b"0123456789abcdef"; let mut o = Vec::new(); for &x in b { o.push(hx[(x >> 4) as usize]); o.push(hx[(x & 0xf) as usize]); } o }
fn hexstr(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

fn bstr(b: &mut Vec<u8>, x: &[u8]) {
    let n = x.len();
    if n < 24 { b.push(0x40 + n as u8); } else if n < 256 { b.push(0x58); b.push(n as u8); } else { b.push(0x59); b.extend_from_slice(&(n as u16).to_be_bytes()); }
    b.extend_from_slice(x);
}
fn datum3(owner: &[u8], commitment: &[u8], recipient: &[u8]) -> Vec<u8> { let mut d = vec![0xD8, 0x79, 0x83]; bstr(&mut d, owner); bstr(&mut d, commitment); bstr(&mut d, recipient); d }
fn datum2(owner: &[u8], commitment: &[u8]) -> Vec<u8> { let mut d = vec![0xD8, 0x79, 0x82]; bstr(&mut d, owner); bstr(&mut d, commitment); d }
// tx_body = { 0: [[src_txid, src_idx]], 1: [ Babbage{0:lock_addr, 1:[coin,{seal_policy:{name:1}}], 2:inline datum} ] }
fn leap_tx_body(src_txid: &[u8; 32], src_idx: u32, lock_addr: &[u8], seal_policy: &[u8], seal_name: &[u8], datum: &[u8]) -> Vec<u8> {
    let mut b = vec![0xA2];
    b.push(0x00); b.push(0x81); b.push(0x82); b.push(0x58); b.push(0x20); b.extend_from_slice(src_txid);
    if src_idx < 24 { b.push(src_idx as u8); } else { b.push(0x1a); b.extend_from_slice(&src_idx.to_be_bytes()); }
    b.push(0x01); b.push(0x81);
    b.push(0xA3);
    b.push(0x00); bstr(&mut b, lock_addr);
    b.push(0x01); b.push(0x82); b.push(0x1a); b.extend_from_slice(&1_000_000u32.to_be_bytes());
    b.push(0xA1); bstr(&mut b, seal_policy); b.push(0xA1); bstr(&mut b, seal_name); b.push(0x01);
    b.push(0x02); b.push(0x82); b.push(0x01); b.push(0xD8); b.push(0x18); bstr(&mut b, datum);
    b
}

fn lp(x: &[u8], o: &mut Vec<u8>) { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x); }
fn items(xs: &[Vec<u8>], o: &mut Vec<u8>) { o.extend_from_slice(&(xs.len() as u32).to_le_bytes()); for x in xs { lp(x, o); } }
fn certify(tx_body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let range_key = b"4355040-4355055".to_vec();
    let leaf = N(hexb(&b2b256(&[tx_body])));
    let ss = MemStore::default(); let mut sub = MemMMR::<N, MB>::new(0, &ss);
    let _ = sub.push(N(b2s(&[b"sib0"]))).unwrap();
    let sub_pos = sub.push(leaf).unwrap();
    let _ = sub.push(N(b2s(&[b"sib2"]))).unwrap();
    let sub_root = sub.get_root().unwrap();
    let sp = sub.gen_proof(vec![sub_pos]).unwrap();
    let (sub_size, sub_items): (u64, Vec<Vec<u8>>) = (sp.mmr_size(), sp.proof_items().iter().map(|n| n.0.clone()).collect());
    let master_leaf = N(b2s(&[&range_key, &sub_root.0]));
    let ms = MemStore::default(); let mut master = MemMMR::<N, MB>::new(0, &ms);
    let _ = master.push(N(b2s(&[b"m0"]))).unwrap();
    let _ = master.push(N(b2s(&[b"m1"]))).unwrap();
    let master_pos = master.push(master_leaf).unwrap();
    let _ = master.push(N(b2s(&[b"m3"]))).unwrap();
    let cert_root = master.get_root().unwrap();
    let mp = master.gen_proof(vec![master_pos]).unwrap();
    let (master_size, master_items): (u64, Vec<Vec<u8>>) = (mp.mmr_size(), mp.proof_items().iter().map(|n| n.0.clone()).collect());
    let mut w = Vec::new();
    lp(tx_body, &mut w);
    lp(&sub_root.0, &mut w); w.extend_from_slice(&sub_pos.to_le_bytes()); w.extend_from_slice(&sub_size.to_le_bytes()); items(&sub_items, &mut w);
    lp(&range_key, &mut w); w.extend_from_slice(&master_pos.to_le_bytes()); w.extend_from_slice(&master_size.to_le_bytes()); items(&master_items, &mut w);
    (cert_root.0, w)
}
fn build_verifier(lckp_hex: &str, reg_hex: &str) {
    let st = Command::new("cargo")
        .args(["build", "--release", "--bin", "bound_asset_v2", "--target", "riscv64imac-unknown-none-elf", "--manifest-path", BGU_MANIFEST])
        .env("CHIRAL_LCKP_TH", lckp_hex).env("CHIRAL_REG_TH", reg_hex)
        .status().expect("spawn cargo build");
    assert!(st.success(), "verifier build failed");
}

const REGISTRY: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/burn_nullifier_registry";
// the registry's SMT (mirrors burn_nullifier_registry.rs: h2 personalized "ckb-smt-null-set").
fn h2(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-smt-null-set").build(); h.update(l); h.update(r); let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn empty_levels() -> [[u8; 32]; 256] { let mut e = [[0u8; 32]; 256]; let mut cur = [0u8; 32]; let mut d = 0; while d < 256 { e[d] = cur; cur = h2(&cur, &cur); d += 1; } e }   // e[d] = empty subtree of height d
fn empty_root() -> [u8; 32] { let mut e = [0u8; 32]; let mut d = 0; while d < 256 { e = h2(&e, &e); d += 1; } e }
fn root_after_insert(key: &[u8; 32], e: &[[u8; 32]; 256]) -> [u8; 32] {           // fold(PRESENT, key, siblings=e)
    let mut cur = [1u8; 32]; let mut d = 0;
    while d < 256 { let bi = 255 - d; let bit = (key[bi / 8] >> (7 - (bi % 8))) & 1; cur = if bit == 1 { h2(&e[d], &cur) } else { h2(&cur, &e[d]) }; d += 1; }
    cur
}

// fixed deployment constants shared by the leap fixtures
const SRC_TXID: [u8; 32] = [0xABu8; 32];
const OWNER: [u8; 28] = [0x0bu8; 28];
const LOCK_ADDR: [u8; 29] = [0x07u8; 29];
const SEAL_POLICY: [u8; 28] = [0xA0u8; 28];

// ---- S5 (LEAP_TO_CKB) builder with negative-test knobs ----
fn build_s5(bad_rc: bool, wrong_lock: bool, omit_registry: bool) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let recipient_lock = ctx.build_script(&as_op, Bytes::from(b"recip".to_vec())).unwrap();
    let recipient = recipient_lock.calc_script_hash().as_slice().to_vec();
    let reg_type = ctx.build_script(&as_op, Bytes::from(b"registry".to_vec())).unwrap();
    let reg_h = reg_type.calc_script_hash().as_slice().to_vec();
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();

    let seal_name = b"SEAL".to_vec();
    let out_state = b"leap-demo-state".to_vec();
    let mut src_seal36 = SRC_TXID.to_vec(); src_seal36.extend_from_slice(&0u32.to_le_bytes());
    let rc = b2b256(&[&out_state, &src_seal36, &recipient]);
    let commitment = if bad_rc { [0xFFu8; 32].to_vec() } else { rc.to_vec() };   // corrupt -> RC mismatch (27)
    let datum = datum3(&OWNER, &commitment, &recipient);
    let tx_body = leap_tx_body(&SRC_TXID, 0, &LOCK_ADDR, &SEAL_POLICY, &seal_name, &datum);
    let th = b2b256(&[&tx_body]);
    let (cert_root, witness) = certify(&tx_body);
    let null_key = b2b256(&[&src_seal36]);

    build_verifier(&hexstr(&lckp_h), &hexstr(&reg_h));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let mut args = SEAL_POLICY.to_vec(); args.extend_from_slice(&LOCK_ADDR);
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();

    let mut bin = vec![0x02u8, 0x01u8]; bin.extend_from_slice(&SRC_TXID); bin.extend_from_slice(&0u32.to_le_bytes());
    bin.extend_from_slice(&[0u8; 32]); bin.extend_from_slice(&out_state);
    let bound_in = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype.clone()).pack()).build(), Bytes::from(bin));
    let mut bout = vec![0x02u8, 0x02u8]; bout.extend_from_slice(&th); bout.extend_from_slice(&0u32.to_le_bytes());
    bout.extend_from_slice(&recipient); bout.extend_from_slice(&out_state);
    let out_lock = if wrong_lock { lock.clone() } else { recipient_lock };          // wrong actual lock -> 29
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_357_154u64.to_le_bytes());   // M2: LCKP‖root‖height(8 LE)
    let ckpt_op = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(), Bytes::from(ckpt_data));

    let w_cert = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let mut tb = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(out_lock).type_(Some(vtype).pack()).build())
        .output_data(Bytes::from(bout).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w_cert.as_bytes().pack());
    if !omit_registry {                                                              // omit -> nullifier missing (50)
        let reg_in = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(reg_type).pack()).build(), Bytes::new());
        let w_reg = WitnessArgs::new_builder().input_type(Some(Bytes::from(null_key.to_vec())).pack()).build();
        tb = tb.input(CellInput::new_builder().previous_output(reg_in).build()).witness(w_reg.as_bytes().pack());
    }
    let tx = ctx.complete_tx(tb.build());
    (ctx, tx)
}

#[test]
fn s5_leap_to_ckb_accepts() {
    let (ctx, tx) = build_s5(false, false, false);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("v2 LEAP_TO_CKB on a real leap-shaped certified tx must pass");
}
#[test]
fn s5_bad_rc_rejected_27() {
    let (ctx, tx) = build_s5(true, false, false);
    let e = ctx.verify_tx(&tx, MAX_CYCLES).expect_err("RC mismatch must be rejected");
    assert!(format!("{:?}", e).contains("27"), "expected 27, got: {:?}", e);
}
#[test]
fn s5_wrong_output_lock_rejected_29() {
    let (ctx, tx) = build_s5(false, true, false);
    let e = ctx.verify_tx(&tx, MAX_CYCLES).expect_err("relayer-substituted output lock must be rejected");
    assert!(format!("{:?}", e).contains("29"), "expected 29, got: {:?}", e);
}
#[test]
fn s5_missing_nullifier_rejected_50() {
    let (ctx, tx) = build_s5(false, false, true);
    let e = ctx.verify_tx(&tx, MAX_CYCLES).expect_err("missing nullifier insert must be rejected");
    assert!(format!("{:?}", e).contains("50"), "expected 50, got: {:?}", e);
}

// ---- S4 (LEAP_TO_CARDANO) positive: CkbOwned -> CardanoBound; no nullifier (native single-use) ----
#[test]
fn s4_leap_to_cardano_accepts() {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let owner_lock = ctx.build_script(&as_op, Bytes::from(b"owner".to_vec())).unwrap();   // the CkbOwned input's owner
    let owner_h = owner_lock.calc_script_hash().as_slice().to_vec();
    let reg_type = ctx.build_script(&as_op, Bytes::from(b"registry".to_vec())).unwrap();
    let reg_h = reg_type.calc_script_hash().as_slice().to_vec();
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();

    let out_state = b"leap-out-state".to_vec();
    // certified tx MINTS seal_prime at lock; output 0 carries a 2-field SealDatum with commitment = b2b256(state)
    let commitment = b2b256(&[&out_state]);
    let datum = datum2(&OWNER, &commitment);
    let tx_body = leap_tx_body(&SRC_TXID, 0, &LOCK_ADDR, &SEAL_POLICY, &b"SEAL".to_vec(), &datum);
    let th = b2b256(&[&tx_body]);
    let (cert_root, witness) = certify(&tx_body);

    build_verifier(&hexstr(&lckp_h), &hexstr(&reg_h));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let mut args = SEAL_POLICY.to_vec(); args.extend_from_slice(&LOCK_ADDR);
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();
    let sink = ctx.build_script(&as_op, Bytes::new()).unwrap();   // precompute to avoid nested ctx borrows

    // CkbOwned input: lock slot == its ACTUAL lock (owner_lock); state carried unchanged
    let mut bin = vec![0x02u8, 0x02u8]; bin.extend_from_slice(&[0x55u8; 32]); bin.extend_from_slice(&0u32.to_le_bytes());
    bin.extend_from_slice(&owner_h); bin.extend_from_slice(&out_state);
    let bound_in = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(owner_lock).type_(Some(vtype.clone()).pack()).build(), Bytes::from(bin));
    // CardanoBound output: dest seal == th, lock slot ZEROED, state unchanged
    let mut bout = vec![0x02u8, 0x01u8]; bout.extend_from_slice(&th); bout.extend_from_slice(&0u32.to_le_bytes());
    bout.extend_from_slice(&[0u8; 32]); bout.extend_from_slice(&out_state);
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_357_154u64.to_le_bytes());   // M2: LCKP‖root‖height(8 LE)
    let ckpt_op = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(sink.clone()).type_(Some(ckpt_type).pack()).build(), Bytes::from(ckpt_data));

    let w_cert = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(sink.clone()).type_(Some(vtype).pack()).build())
        .output_data(Bytes::from(bout).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w_cert.as_bytes().pack())
        .build());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("v2 LEAP_TO_CARDANO must pass in CKB-VM");
}

// S1 GENESIS (∅ -> CkbOwned): a fresh bound cell minted by a certified Cardano seal. There is NO bound INPUT,
// so the cert witness is read from GroupOutput[0] (program_entry's fallback). Exercises the genesis branch end
// to end in CKB-VM - seal == th, STATE-ONLY commitment, seal-positively-at-lock, and ls_pin on the new cell -
// closing the last open positive branch in the v2 matrix.
#[test]
fn s1_genesis_accepts() {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let out_lock = ctx.build_script(&as_op, Bytes::from(b"genowner".to_vec())).unwrap();   // the new cell's owner
    let out_lock_h = out_lock.calc_script_hash().as_slice().to_vec();
    let reg_type = ctx.build_script(&as_op, Bytes::from(b"registry".to_vec())).unwrap();
    let reg_h = reg_type.calc_script_hash().as_slice().to_vec();
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();

    let out_state = b"genesis-state".to_vec();
    let commitment = b2b256(&[&out_state]);                              // STATE-ONLY (live parity)
    let datum = datum2(&OWNER, &commitment);
    let tx_body = leap_tx_body(&SRC_TXID, 0, &LOCK_ADDR, &SEAL_POLICY, &b"SEAL".to_vec(), &datum);
    let th = b2b256(&[&tx_body]);
    let (cert_root, witness) = certify(&tx_body);

    build_verifier(&hexstr(&lckp_h), &hexstr(&reg_h));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();          // funding-cell lock (always_success)
    let mut args = SEAL_POLICY.to_vec(); args.extend_from_slice(&LOCK_ADDR);
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();

    // NO bound input - only a funding cell. Output 0 is the genesis CkbOwned cell (so GroupOutput[0] == witness[0]).
    let funding = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).build(), Bytes::new());
    let mut bout = vec![0x02u8, 0x02u8]; bout.extend_from_slice(&th); bout.extend_from_slice(&0u32.to_le_bytes());
    bout.extend_from_slice(&out_lock_h); bout.extend_from_slice(&out_state);
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_357_154u64.to_le_bytes());
    let ckpt_op = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(), Bytes::from(ckpt_data));

    let w_cert = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(funding).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(out_lock).type_(Some(vtype).pack()).build())
        .output_data(Bytes::from(bout).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w_cert.as_bytes().pack())
        .build());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("v2 GENESIS must pass in CKB-VM");
}

// S2 TRANSITION (CkbOwned -> CkbOwned): a CKB-native state transition; exercises ls_pin (invariant LS, B3 for
// the produced CkbOwned cell) which no leap test hits. State MAY change; the new commitment binds out_state.
#[test]
fn s2_transition_accepts() {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let out_lock = ctx.build_script(&as_op, Bytes::from(b"outlock".to_vec())).unwrap();   // the output owner's lock
    let out_lock_h = out_lock.calc_script_hash().as_slice().to_vec();
    let reg_type = ctx.build_script(&as_op, Bytes::from(b"registry".to_vec())).unwrap();
    let reg_h = reg_type.calc_script_hash().as_slice().to_vec();
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();

    let new_state = b"new-state".to_vec();
    let commitment = b2b256(&[&new_state]);
    let datum = datum2(&OWNER, &commitment);
    let tx_body = leap_tx_body(&SRC_TXID, 0, &LOCK_ADDR, &SEAL_POLICY, &b"SEAL".to_vec(), &datum);
    let th = b2b256(&[&tx_body]);
    let (cert_root, witness) = certify(&tx_body);

    build_verifier(&hexstr(&lckp_h), &hexstr(&reg_h));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let mut args = SEAL_POLICY.to_vec(); args.extend_from_slice(&LOCK_ADDR);
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();

    // input CkbOwned (old seal consumed by the cert); state may differ from out_state
    let mut bin = vec![0x02u8, 0x02u8]; bin.extend_from_slice(&SRC_TXID); bin.extend_from_slice(&0u32.to_le_bytes());
    bin.extend_from_slice(&[0u8; 32]); bin.extend_from_slice(b"old-state");
    let bound_in = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype.clone()).pack()).build(), Bytes::from(bin));
    // output CkbOwned: dest seal = th, lock slot == its ACTUAL lock (ls_pin), state = new_state
    let mut bout = vec![0x02u8, 0x02u8]; bout.extend_from_slice(&th); bout.extend_from_slice(&0u32.to_le_bytes());
    bout.extend_from_slice(&out_lock_h); bout.extend_from_slice(&new_state);
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_357_154u64.to_le_bytes());   // M2: LCKP‖root‖height(8 LE)
    let ckpt_op = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(), Bytes::from(ckpt_data));

    let w_cert = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(out_lock).type_(Some(vtype).pack()).build())
        .output_data(Bytes::from(bout).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w_cert.as_bytes().pack())
        .build());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("v2 TRANSITION must pass in CKB-VM");
}

// S5 driven by the REAL burn_nullifier_registry: its SMT non-membership->insert actually enforces single-use
// (vs the always_success mock used by the other tests). Proves the consumer + real registry integrate.
#[test]
fn s5_leap_with_real_nullifier_registry() {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let recipient_lock = ctx.build_script(&as_op, Bytes::from(b"recip".to_vec())).unwrap();
    let recipient = recipient_lock.calc_script_hash().as_slice().to_vec();
    let reg_op = ctx.deploy_cell(Bytes::from(std::fs::read(REGISTRY).unwrap()));
    let reg_type = ctx.build_script(&reg_op, Bytes::from(vec![0x77u8; 32])).unwrap();   // 32-byte type-id args
    let reg_h = reg_type.calc_script_hash().as_slice().to_vec();
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();

    let out_state = b"leap-demo-state".to_vec();
    let mut src_seal36 = SRC_TXID.to_vec(); src_seal36.extend_from_slice(&0u32.to_le_bytes());
    let rc = b2b256(&[&out_state, &src_seal36, &recipient]);
    let datum = datum3(&OWNER, &rc, &recipient);
    let tx_body = leap_tx_body(&SRC_TXID, 0, &LOCK_ADDR, &SEAL_POLICY, &b"SEAL".to_vec(), &datum);
    let th = b2b256(&[&tx_body]);
    let (cert_root, witness) = certify(&tx_body);
    let null_key = b2b256(&[&src_seal36]);
    let e = empty_levels();
    let new_root = root_after_insert(&null_key, &e);
    let mut reg_wit = null_key.to_vec(); for d in 0..256 { reg_wit.extend_from_slice(&e[d]); }

    build_verifier(&hexstr(&lckp_h), &hexstr(&reg_h));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let mut args = SEAL_POLICY.to_vec(); args.extend_from_slice(&LOCK_ADDR);
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();

    let mut bin = vec![0x02u8, 0x01u8]; bin.extend_from_slice(&SRC_TXID); bin.extend_from_slice(&0u32.to_le_bytes());
    bin.extend_from_slice(&[0u8; 32]); bin.extend_from_slice(&out_state);
    let bound_in = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype.clone()).pack()).build(), Bytes::from(bin));
    let mut bout = vec![0x02u8, 0x02u8]; bout.extend_from_slice(&th); bout.extend_from_slice(&0u32.to_le_bytes());
    bout.extend_from_slice(&recipient); bout.extend_from_slice(&out_state);
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_357_154u64.to_le_bytes());   // M2: LCKP‖root‖height(8 LE)
    let ckpt_op = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(), Bytes::from(ckpt_data));
    let reg_in = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(reg_type.clone()).pack()).build(), Bytes::from(empty_root().to_vec()));

    let w_cert = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let w_reg = WitnessArgs::new_builder().input_type(Some(Bytes::from(reg_wit)).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())
        .input(CellInput::new_builder().previous_output(reg_in).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(recipient_lock).type_(Some(vtype).pack()).build())
        .output_data(Bytes::from(bout).pack())
        .output(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock).type_(Some(reg_type).pack()).build())   // continuing registry
        .output_data(Bytes::from(new_root.to_vec()).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(reg_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w_cert.as_bytes().pack())
        .witness(w_reg.as_bytes().pack())
        .build());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("v2 LEAP_TO_CKB with the REAL nullifier registry must pass in CKB-VM");
}
