//! THE headline in-VM test: drive bound_asset_v2 through the S5 LEAP_TO_CKB branch in a real CKB-VM, on a
//! self-consistent leap-shaped certified tx. Proves B1 (recipient bound to the owner-signed datum) + B3
//! (actual output lock pinned via load_cell_lock_hash) + the RC recompute + the cross-leg nullifier — all in
//! real CKB-VM, not just unit-tested bytes.
//!
//! We build a leap Cardano tx_body in-test: it CONSUMES the source seal AND re-parks it at the binding lock in
//! output 0, whose inline datum is a 3-field LeapSealDatum carrying RC = blake2b256(state ‖ source_seal ‖
//! recipient). We MMR-certify it exactly as the verifier hashes, mock the canonical nullifier registry, and
//! rebuild the verifier with CHIRAL_LCKP_TH / CHIRAL_REG_TH matching our checkpoint + registry cells.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use std::process::Command;
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{Merge, Result as MMRResult, util::{MemMMR, MemStore}};

const MAX_CYCLES: u64 = 200_000_000;
const BGU_MANIFEST: &str = "../../../../burn-gated-unlock/Cargo.toml";
const VERIFIER: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2";

// ---- the verifier's exact hashing (mirrors gen/main.rs and bound_asset_v2.rs) ----
#[derive(Clone, PartialEq, Eq, Debug)]
struct N(Vec<u8>);
struct MB;
impl Merge for MB {
    type Item = N;
    fn merge(l: &N, r: &N) -> MMRResult<N> { let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) }
}
fn b2b256(parts: &[&[u8]]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).build(); for p in parts { h.update(p); } let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn b2s(parts: &[&[u8]]) -> Vec<u8> { let mut h = Blake2s256::new(); for p in parts { h.update(p); } h.finalize().to_vec() }
fn hexb(b: &[u8]) -> Vec<u8> { let hx = b"0123456789abcdef"; let mut o = Vec::new(); for &x in b { o.push(hx[(x >> 4) as usize]); o.push(hx[(x & 0xf) as usize]); } o }
fn hexstr(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

// ---- CBOR builders ----
fn bstr(b: &mut Vec<u8>, x: &[u8]) {
    let n = x.len();
    if n < 24 { b.push(0x40 + n as u8); } else if n < 256 { b.push(0x58); b.push(n as u8); } else { b.push(0x59); b.extend_from_slice(&(n as u16).to_be_bytes()); }
    b.extend_from_slice(x);
}
// Constr 121 [owner, commitment(=RC), recipient]
fn leap_seal_datum(owner: &[u8], commitment: &[u8; 32], recipient: &[u8]) -> Vec<u8> {
    let mut d = vec![0xD8, 0x79, 0x83]; bstr(&mut d, owner); bstr(&mut d, commitment); bstr(&mut d, recipient); d
}
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

// ---- MMR certify (mirrors gen/main.rs exactly so proofs verify by construction) ----
fn lp(x: &[u8], o: &mut Vec<u8>) { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x); }
fn items(xs: &[Vec<u8>], o: &mut Vec<u8>) { o.extend_from_slice(&(xs.len() as u32).to_le_bytes()); for x in xs { lp(x, o); } }
fn certify(tx_body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let range_key = b"4355040-4355055".to_vec();
    let th = b2b256(&[tx_body]);
    let leaf = N(hexb(&th));
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

#[test]
fn v2_leap_to_ckb_accepts() {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    // recipient lock (the owner-intended CKB owner of the surviving cell); recipient = its script hash
    let recipient_lock = ctx.build_script(&as_op, Bytes::from(b"recip".to_vec())).unwrap();
    let recipient = recipient_lock.calc_script_hash().as_slice().to_vec();
    // canonical nullifier registry script + the trusted checkpoint script
    let reg_type = ctx.build_script(&as_op, Bytes::from(b"registry".to_vec())).unwrap();
    let reg_h = reg_type.calc_script_hash().as_slice().to_vec();
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();

    // deployment constants of the leap fixture
    let src_txid = [0xABu8; 32];
    let src_idx: u32 = 0;
    let owner = [0x0bu8; 28];
    let lock_addr = [0x07u8; 29];           // Cardano binding lock address (full bytes)
    let seal_policy = [0xA0u8; 28];
    let seal_name = b"SEAL".to_vec();
    let out_state = b"leap-demo-state".to_vec();

    let mut src_seal36 = src_txid.to_vec(); src_seal36.extend_from_slice(&src_idx.to_le_bytes());
    let rc = b2b256(&[&out_state, &src_seal36, &recipient]);   // RC = blake2b256(state ‖ SOURCE seal ‖ recipient)
    let datum = leap_seal_datum(&owner, &rc, &recipient);
    let tx_body = leap_tx_body(&src_txid, src_idx, &lock_addr, &seal_policy, &seal_name, &datum);
    let th = b2b256(&[&tx_body]);
    let (cert_root, witness) = certify(&tx_body);
    let null_key = b2b256(&[&src_seal36]);                     // == b2b256(src_txid ‖ src_idx_le), the nullifier key

    build_verifier(&hexstr(&lckp_h), &hexstr(&reg_h));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let mut args = seal_policy.to_vec(); args.extend_from_slice(&lock_addr);   // seal_policy(28) ‖ lock_addr(29) = 57
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();

    // CardanoBound input: tag 0x01, source seal, zero lock slot, state == out_state (state-unchanged)
    let mut bin = vec![0x02u8, 0x01u8];
    bin.extend_from_slice(&src_txid); bin.extend_from_slice(&src_idx.to_le_bytes());
    bin.extend_from_slice(&[0u8; 32]); bin.extend_from_slice(&out_state);
    let bound_in = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype.clone()).pack()).build(),
        Bytes::from(bin));
    // CkbOwned output: tag 0x02, dest seal = th, lock slot = recipient, state == out_state; ACTUAL lock = recipient_lock
    let mut bout = vec![0x02u8, 0x02u8];
    bout.extend_from_slice(&th); bout.extend_from_slice(&0u32.to_le_bytes());
    bout.extend_from_slice(&recipient); bout.extend_from_slice(&out_state);
    // checkpoint + registry input cells
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root);
    let ckpt_op = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(),
        Bytes::from(ckpt_data));
    let reg_in = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(reg_type).pack()).build(),
        Bytes::new());

    let w_cert = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let w_reg = WitnessArgs::new_builder().input_type(Some(Bytes::from(null_key.to_vec())).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())     // input 0: the bound cell
        .input(CellInput::new_builder().previous_output(reg_in).build())       // input 1: the nullifier registry
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(recipient_lock).type_(Some(vtype).pack()).build())
        .output_data(Bytes::from(bout).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w_cert.as_bytes().pack())
        .witness(w_reg.as_bytes().pack())
        .build());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("v2 LEAP_TO_CKB on a real leap-shaped certified tx must pass in CKB-VM");
}
