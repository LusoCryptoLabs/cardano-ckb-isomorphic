//! In-VM (ckb-testtool, real CKB-VM) tests for bound_asset_v2's PRE-CERT guard paths - these fire before the
//! checkpoint/MMR verification, so they need no certified-tx fixture. They prove the v2 binary actually loads
//! and executes in CKB-VM (atomics polyfill, load_script/load_cell_data host calls, the entry guards), a real
//! step beyond "it compiles + pure-fn unit tests". The cert-passing FINALIZE/leap tests live separately (they
//! need the LCKP type-hash bootstrap).
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 200_000_000;
const VERIFIER: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2";

// a minimal v2 CkbOwned cell: version(0x02) tag(0x02) seal_txid(32) seal_idx(4) lock(32) state
fn v2_ckb_owned() -> Bytes {
    let mut d = vec![0x02u8, 0x02u8];
    d.extend_from_slice(&[0xABu8; 32]);
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&[0u8; 32]);
    d.extend_from_slice(b"st");
    Bytes::from(d)
}

/// Build a tx with `n_inputs` bound cells (type = verifier with `args`), one sink output, optionally a
/// well-typed LCKP checkpoint cell-dep. Returns the verify result.
fn run(args: Vec<u8>, n_inputs: usize) -> Result<ckb_testtool::ckb_types::core::Cycle, ckb_testtool::ckb_error::Error> {
    let mut ctx = Context::default();
    let vbin: Bytes = std::fs::read(VERIFIER).expect("build bound_asset_v2 (cargo build --release --bin bound_asset_v2) first").into();
    let v_op = ctx.deploy_cell(vbin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();

    let mut tb = TransactionBuilder::default()
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(lock.clone()).build())
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(v_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build())
        .witness(WitnessArgs::new_builder().input_type(Some(Bytes::from(vec![0u8; 4])).pack()).build().as_bytes().pack());

    for _ in 0..n_inputs {
        let cell = ctx.create_cell(
            CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype.clone()).pack()).build(),
            v2_ckb_owned(),
        );
        tb = tb.input(CellInput::new_builder().previous_output(cell).build());
    }
    let tx = ctx.complete_tx(tb.build());
    ctx.verify_tx(&tx, MAX_CYCLES)
}

#[test]
fn short_args_returns_30() {
    // args < 57 -> return 30, before anything else
    let r = run(vec![0u8; 10], 1);
    let e = r.expect_err("short args must be rejected");
    assert!(format!("{:?}", e).contains("30"), "expected exit code 30, got: {:?}", e);
}

#[test]
fn a6_two_group_inputs_returns_38() {
    // two bound cells in the same type group -> A6 reject (38), before checkpoint
    let r = run(vec![0u8; 57], 2);
    let e = r.expect_err("two bound inputs must be rejected (A6)");
    assert!(format!("{:?}", e).contains("38"), "expected exit code 38, got: {:?}", e);
}

#[test]
fn no_checkpoint_returns_1() {
    // valid args, single cell, NO "LCKP" checkpoint cell-dep -> checkpoint_root() None -> return 1
    let r = run(vec![0u8; 57], 1);
    let e = r.expect_err("missing checkpoint must be rejected");
    assert!(format!("{:?}", e).contains(" 1") || format!("{:?}", e).contains("(1)") || format!("{:?}", e).contains("code: 1"),
        "expected exit code 1, got: {:?}", e);
}
