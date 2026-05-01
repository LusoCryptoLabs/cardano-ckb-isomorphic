//! Cert-PASSING in-VM test: run a real certified-tx FINALIZE (the generator's self-consistent dataset)
//! through bound_asset_v2 in CKB-VM. This exercises the full path the guard tests don't reach: checkpoint
//! read (SEC-A1), the double-MMR cert verify, the v2 tag dispatcher, and the FINALIZE branch on the v2 layout.
//!
//! SEC-A1 obstacle solved cleanly: the verifier only trusts a checkpoint cell whose type-hash ==
//! LCKP_TYPE_HASH. We compute the test checkpoint script hash at runtime and rebuild bound_asset_v2 with
//! CHIRAL_LCKP_TH set to it (option_env override; production default unchanged), so the test's checkpoint is
//! the trusted one.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use std::process::Command;

const MAX_CYCLES: u64 = 200_000_000;
const BGU_MANIFEST: &str = "../../../../burn-gated-unlock/Cargo.toml";
const VERIFIER: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2";
const DATASET: &str = "../dataset.json";

fn hexbytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hexstr(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

/// Build bound_asset_v2 with CHIRAL_LCKP_TH = the test checkpoint script hash (so SEC-A1 trusts our checkpoint).
fn build_verifier_with_lckp(lckp_hex: &str) {
    // --target explicit: .cargo/config resolves from the INVOCATION cwd (this test crate), not the manifest
    // dir, so without it the nested build would use the host target and fail (no_std, no panic handler).
    let st = Command::new("cargo")
        .args(["build", "--release", "--bin", "bound_asset_v2", "--target", "riscv64imac-unknown-none-elf", "--manifest-path", BGU_MANIFEST])
        .env("CHIRAL_LCKP_TH", lckp_hex)
        .status().expect("spawn cargo build");
    assert!(st.success(), "verifier build (CHIRAL_LCKP_TH) failed");
}

#[test]
fn v2_finalize_accepts_real_cert() {
    let ds: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(DATASET).expect("dataset.json")).unwrap();
    let bound_v1 = hexbytes(ds["bound_data"].as_str().unwrap());   // v1 layout: seal(32) ‖ idx(4) ‖ state
    let witness = hexbytes(ds["witness"].as_str().unwrap());
    let cert_root = hexbytes(ds["cert_root"].as_str().unwrap());

    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    // the checkpoint TYPE script (always_success, empty args); its hash is what the verifier must trust.
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let lckp_hex = hexstr(ckpt_type.calc_script_hash().as_slice());

    build_verifier_with_lckp(&lckp_hex);
    let vbin: Bytes = std::fs::read(VERIFIER).expect("verifier artifact").into();
    let v_op = ctx.deploy_cell(vbin);

    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    // args = seal_policy(28) ‖ lock_addr(29); values irrelevant here (the FINALIZE output is a plain coin
    // address, so seal_at_lock == Some(false) for any policy/addr). Just needs len >= 57.
    let vtype = ctx.build_script(&v_op, Bytes::from(vec![0u8; 57])).unwrap();

    // v2 CkbOwned input carrying the dataset's consumed seal (so finalize's "seal consumed" check passes).
    let mut cell = vec![0x02u8, 0x02u8];
    cell.extend_from_slice(&bound_v1[0..32]);   // seal txid -> [2..34]
    cell.extend_from_slice(&bound_v1[32..36]);  // seal idx  -> [34..38]
    cell.extend_from_slice(&[0u8; 32]);         // lock slot -> [38..70] (finalize ignores it)
    cell.extend_from_slice(&bound_v1[36..]);    // state     -> [70..]
    let bound_in = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype).pack()).build(),
        Bytes::from(cell));

    // the "LCKP"||cert_root checkpoint cell-dep, TYPED so its type-hash == the verifier's LCKP_TYPE_HASH.
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_357_154u64.to_le_bytes());   // M2: LCKP‖root‖height(8 LE)
    let ckpt_op = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(),
        Bytes::from(ckpt_data));

    let wa = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(lock).build())   // FINALIZE: no verifier-typed output
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(wa.as_bytes().pack())
        .build();
    let tx = ctx.complete_tx(tx);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("v2 FINALIZE on a real certified tx must pass in CKB-VM");
}

// Build a single-input, no-verifier-output tx past the (real) cert, with the bound cell's [version,tag] set
// by the caller. Returns the verify result so dispatcher arms can be asserted in-VM.
fn run_dispatch(version: u8, tag: u8) -> Result<ckb_testtool::ckb_types::core::Cycle, ckb_testtool::ckb_error::Error> {
    let ds: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(DATASET).unwrap()).unwrap();
    let bound_v1 = hexbytes(ds["bound_data"].as_str().unwrap());
    let witness = hexbytes(ds["witness"].as_str().unwrap());
    let cert_root = hexbytes(ds["cert_root"].as_str().unwrap());

    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let ckpt_type = ctx.build_script(&as_op, Bytes::new()).unwrap();
    build_verifier_with_lckp(&hexstr(ckpt_type.calc_script_hash().as_slice()));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let vtype = ctx.build_script(&v_op, Bytes::from(vec![0u8; 57])).unwrap();

    let mut cell = vec![version, tag];
    cell.extend_from_slice(&bound_v1[0..32]);
    cell.extend_from_slice(&bound_v1[32..36]);
    cell.extend_from_slice(&[0u8; 32]);
    cell.extend_from_slice(&bound_v1[36..]);
    let bound_in = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(vtype).pack()).build(),
        Bytes::from(cell));
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_357_154u64.to_le_bytes());   // M2: LCKP‖root‖height(8 LE)
    let ckpt_op = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(),
        Bytes::from(ckpt_data));
    let wa = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(lock).build())
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(wa.as_bytes().pack())
        .build());
    ctx.verify_tx(&tx, MAX_CYCLES)
}

#[test]
fn cardano_bound_input_no_output_is_illegal_41() {
    // (CARDANO_BOUND, None) past the cert -> a CardanoBound anchor cannot just vanish -> 41
    let e = run_dispatch(0x02, 0x01).expect_err("CardanoBound->nothing must be rejected");
    assert!(format!("{:?}", e).contains("41"), "expected 41, got: {:?}", e);
}

#[test]
fn bad_version_byte_rejected_43() {
    // version != 0x02 -> tag_of rejects (43); keeps v1 cells out of the v2 dispatcher
    let e = run_dispatch(0x01, 0x02).expect_err("bad version must be rejected");
    assert!(format!("{:?}", e).contains("43"), "expected 43, got: {:?}", e);
}
