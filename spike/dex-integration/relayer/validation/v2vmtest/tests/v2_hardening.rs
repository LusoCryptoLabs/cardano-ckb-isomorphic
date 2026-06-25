//! In-VM (real CKB-VM) hardening tests for bound_asset_v2:
//!  - RQ-4: two TRUSTED checkpoint cell-deps that DISAGREE must fail closed (checkpoint_root -> 53). The
//!          canonical checkpoint is a type-id singleton, so production never sees two; this proves the
//!          defense-in-depth path rejects a smuggled-in stale checkpoint instead of silently using it.
//!  - RQ-8: more than one bound_asset_v2 cell of the same CODE among the tx inputs (the cross-type-group
//!          same-seal batch) must be rejected (51), enforcing one-leap-per-tx across ALL instances.
//! Both guards run BEFORE the cert/MMR verification, so neither test needs a valid Mithril certificate.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use std::process::Command;

const MAX_CYCLES: u64 = 200_000_000;
const BGU_MANIFEST: &str = "../../../../burn-gated-unlock/Cargo.toml";
const VERIFIER: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2";

fn hexstr(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
fn build_verifier(lckp_hex: &str, reg_hex: &str) {
    let st = Command::new("cargo")
        .args(["build", "--release", "--bin", "bound_asset_v2", "--target", "riscv64imac-unknown-none-elf", "--manifest-path", BGU_MANIFEST])
        .env("CHIRAL_LCKP_TH", lckp_hex).env("CHIRAL_REG_TH", reg_hex)
        .status().expect("spawn cargo build");
    assert!(st.success(), "verifier build failed");
}
/// minimal well-formed v2 cell: version(0x02) ‖ tag ‖ seal(36) ‖ lock(32) = 70 bytes (the guards run before
/// any field is interpreted, so zeroed seal/lock is fine here).
fn v2_cell(tag: u8) -> Bytes { let mut d = vec![0x02u8, tag]; d.extend_from_slice(&[0u8; 68]); Bytes::from(d) }
/// a valid 57-byte verifier arg block (seal_policy(28) ‖ lock_addr(29)); `salt` distinguishes instances.
fn vargs(salt: u8) -> Bytes { let mut a = vec![0xA0u8; 28]; a.extend_from_slice(&[salt; 29]); Bytes::from(a) }

#[test]
fn rq8_two_bound_inputs_rejected_51() {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    build_verifier(&hexstr(&[0u8; 32]), &hexstr(&[0u8; 32]));   // guard fires pre-cert -> LCKP/REG irrelevant
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    // two DIFFERENT instances of the SAME verifier code (different args -> different type hash, same code hash)
    let vtype_a = ctx.build_script(&v_op, vargs(0x01)).unwrap();
    let vtype_b = ctx.build_script(&v_op, vargs(0x02)).unwrap();

    let in_a = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype_a.clone()).pack()).build(), v2_cell(0x02));
    let in_b = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype_b.clone()).pack()).build(), v2_cell(0x02));

    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(in_a).build())
        .input(CellInput::new_builder().previous_output(in_b).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(lock.clone()).type_(Some(vtype_a).pack()).build())
        .output_data(v2_cell(0x02).pack())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(lock).type_(Some(vtype_b).pack()).build())
        .output_data(v2_cell(0x02).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .build());
    let e = ctx.verify_tx(&tx, MAX_CYCLES).expect_err("two bound cells of the same code in one tx must be rejected");
    assert!(format!("{:?}", e).contains("51"), "expected 51 (RQ-8 batch guard), got: {:?}", e);
}

#[test]
fn rq4_conflicting_checkpoints_rejected_53() {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();
    build_verifier(&hexstr(&lckp_h), &hexstr(&[0u8; 32]));      // trust the test checkpoint type
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let vtype = ctx.build_script(&v_op, vargs(0x07)).unwrap();

    // one bound input so A6 + RQ-8 pass and we reach checkpoint_root()
    let bin = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype).pack()).build(), v2_cell(0x02));
    // TWO trusted checkpoints (same type hash) that DISAGREE on root+height -> checkpoint_root -> Err(53)
    let mk = |root: u8, h: u64| -> Bytes { let mut d = b"LCKP".to_vec(); d.extend_from_slice(&[root; 32]); d.extend_from_slice(&h.to_le_bytes()); Bytes::from(d) };
    let ckpt1 = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type.clone()).pack()).build(), mk(0x11, 100));
    let ckpt2 = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(), mk(0x22, 200));

    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bin).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(lock).build())
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt1).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt2).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .build());
    let e = ctx.verify_tx(&tx, MAX_CYCLES).expect_err("conflicting trusted checkpoints must fail closed");
    assert!(format!("{:?}", e).contains("53"), "expected 53 (RQ-4 checkpoint conflict), got: {:?}", e);
}
