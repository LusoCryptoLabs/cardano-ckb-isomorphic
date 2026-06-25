//! In-VM (real CKB-VM) tests for bridge_lock_v1 - the CKB→Cardano bridge RECEIPT type script that pins the
//! canonical 49-byte receipt layout the leap circuit reads and enforces the value-lock per kind.
//! Accepts a well-formed CKB-kind receipt (capacity == amount) and a well-formed xUDT-kind receipt (a sibling
//! output of the pinned type holds `amount`); rejects bad magic / wrong length / capacity≠amount / two
//! receipts / amount 0 / xUDT amount mismatch.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 50_000_000;
const BRIDGE: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bridge_lock_v1";
const KIND_CKB: u8 = 0;
const KIND_UDT: u8 = 1;

fn receipt(kind: u8, amount: u128, recipient: &[u8; 28]) -> Vec<u8> {
    let mut d = b"BRG1".to_vec(); d.push(kind);
    d.extend_from_slice(&amount.to_le_bytes()); d.extend_from_slice(recipient); d   // 4+1+16+28 = 49
}
fn err_code(e: &ckb_testtool::ckb_error::Error) -> String { format!("{:?}", e) }

// ---- CKB kind: a receipt whose OWN capacity must equal the declared amount ----
fn run_ckb(cap: u64, data: Vec<u8>, extra_receipt: bool) -> Result<u64, ckb_testtool::ckb_error::Error> {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let br_op = ctx.deploy_cell(Bytes::from(std::fs::read(BRIDGE).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let btype = ctx.build_script(&br_op, Bytes::from(vec![0u8; 32])).unwrap();   // CKB bridge instance id
    let funding = ctx.create_cell(CellOutput::new_builder().capacity(1_000_000u64.saturating_mul(100_000_000).pack()).lock(lock.clone()).build(), Bytes::new());
    let mut tb = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(funding).build())
        .output(CellOutput::new_builder().capacity(cap.pack()).lock(lock.clone()).type_(Some(btype.clone()).pack()).build())
        .output_data(Bytes::from(data).pack())
        .cell_dep(CellDep::new_builder().out_point(br_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build());
    if extra_receipt {
        let r2 = receipt(KIND_CKB, cap as u128, &[0x44u8; 28]);
        tb = tb.output(CellOutput::new_builder().capacity(cap.pack()).lock(lock.clone()).type_(Some(btype).pack()).build()).output_data(Bytes::from(r2).pack());
    }
    let tx = ctx.complete_tx(tb.build());
    ctx.verify_tx(&tx, MAX_CYCLES)
}

#[test]
fn ckb_receipt_capacity_eq_amount_ok() {
    let amt = 1000u128 * 100_000_000;
    run_ckb(amt as u64, receipt(KIND_CKB, amt, &[0x33; 28]), false).expect("well-formed CKB receipt must pass");
}
#[test]
fn ckb_receipt_capacity_mismatch_rejected() {
    let amt = 1000u128 * 100_000_000;
    let e = run_ckb(amt as u64, receipt(KIND_CKB, amt - 100_000_000, &[0x33; 28]), false).expect_err("capacity != amount must fail");
    assert!(err_code(&e).contains("4"), "expected 4, got {}", err_code(&e));
}
#[test]
fn ckb_bad_magic_rejected() {
    let amt = 1000u128 * 100_000_000;
    let mut d = receipt(KIND_CKB, amt, &[0x33; 28]); d[0] = b'X';
    let e = run_ckb(amt as u64, d, false).expect_err("bad magic must fail");
    assert!(err_code(&e).contains("2"), "expected 2, got {}", err_code(&e));
}
#[test]
fn ckb_wrong_length_rejected() {
    let amt = 1000u128 * 100_000_000;
    let mut d = receipt(KIND_CKB, amt, &[0x33; 28]); d.push(0);   // 50 bytes
    let e = run_ckb(amt as u64, d, false).expect_err("len != 49 must fail");
    assert!(err_code(&e).contains("1"), "expected 1, got {}", err_code(&e));
}
#[test]
fn ckb_zero_amount_rejected() {
    let e = run_ckb(1000u64 * 100_000_000, receipt(KIND_CKB, 0, &[0x33; 28]), false).expect_err("amount 0 must fail");
    assert!(err_code(&e).contains("6"), "expected 6, got {}", err_code(&e));
}
#[test]
fn ckb_two_receipts_rejected() {
    let amt = 1000u128 * 100_000_000;
    let e = run_ckb(amt as u64, receipt(KIND_CKB, amt, &[0x33; 28]), true).expect_err("two receipts must fail (singleton)");
    assert!(err_code(&e).contains("3"), "expected 3, got {}", err_code(&e));
}

// ---- xUDT kind: a sibling output of the pinned type must hold `amount` ----
fn run_udt(receipt_amount: u128, udt_amount: u128) -> Result<u64, ckb_testtool::ckb_error::Error> {
    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let br_op = ctx.deploy_cell(Bytes::from(std::fs::read(BRIDGE).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let xudt = ctx.build_script(&as_op, Bytes::from(b"xudt-policy".to_vec())).unwrap();
    let xudt_hash = xudt.calc_script_hash().as_slice().to_vec();
    let btype = ctx.build_script(&br_op, Bytes::from(xudt_hash)).unwrap();        // args = pinned xUDT type hash
    let min = 500u64 * 100_000_000;
    let funding = ctx.create_cell(CellOutput::new_builder().capacity((10_000u64 * 100_000_000).pack()).lock(lock.clone()).build(), Bytes::new());
    let tb = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(funding).build())
        // receipt (capacity is just a normal cell, NOT tied to amount for the xUDT kind)
        .output(CellOutput::new_builder().capacity(min.pack()).lock(lock.clone()).type_(Some(btype).pack()).build())
        .output_data(Bytes::from(receipt(KIND_UDT, receipt_amount, &[0x33; 28])).pack())
        // sibling xUDT output holding `udt_amount` (data[0..16] LE)
        .output(CellOutput::new_builder().capacity(min.pack()).lock(lock.clone()).type_(Some(xudt).pack()).build())
        .output_data(Bytes::from(udt_amount.to_le_bytes().to_vec()).pack())
        .cell_dep(CellDep::new_builder().out_point(br_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build());
    let tx = ctx.complete_tx(tb.build());
    ctx.verify_tx(&tx, MAX_CYCLES)
}

#[test]
fn udt_receipt_matching_amount_ok() {
    let amt = 5_000_000u128;
    run_udt(amt, amt).expect("xUDT receipt with a matching sibling amount must pass");
}
#[test]
fn udt_receipt_amount_mismatch_rejected() {
    let e = run_udt(5_000_000, 1).expect_err("xUDT sibling amount != declared must fail");
    assert!(err_code(&e).contains("10"), "expected 10, got {}", err_code(&e));
}
