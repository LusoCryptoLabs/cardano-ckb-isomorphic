//! Prove leap-out works: run the FINALIZE-capable verifier (built from the current
//! spike/phase1/bound_asset_unified.rs - the redeploy candidate) on the relayer's leap-out witness, in
//! ckb-testtool's real CKB-VM. FINALIZE = the bound cell is an INPUT with NO continuing output; its
//! witness.input_type = the (relayer-encoded) Mithril proof; a cell-dep carries "LCKP"||cert_root.
//! Success here is the on-chain leap-out the deployed (pre-FINALIZE) verifier can't yet do - once this
//! binary is redeployed, the CKB->Cardano exit leg runs.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 200_000_000;
const VERIFIER_BIN: &str = "../verifier/target/riscv64imac-unknown-none-elf/release/bound_asset_unified";
const DATASET: &str = "../dataset.json";

fn hexbytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Build the FINALIZE tx from the dataset. `cert_root_override` lets the negative test corrupt the
/// checkpoint root (so the master MMR proof must fail).
fn build(cert_root_override: Option<Vec<u8>>) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let ds: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(DATASET).expect("dataset.json")).unwrap();
    let bound_data = hexbytes(ds["bound_data"].as_str().unwrap());
    let witness = hexbytes(ds["witness"].as_str().unwrap());
    let cert_root = cert_root_override.unwrap_or_else(|| hexbytes(ds["cert_root"].as_str().unwrap()));

    let mut ctx = Context::default();
    let verifier_bin: Bytes = std::fs::read(VERIFIER_BIN).expect("build the verifier first").into();
    let verifier_op = ctx.deploy_cell(verifier_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let always = ctx.build_script(&as_op, Bytes::from(b"l".to_vec())).unwrap();
    let verifier = ctx.build_script(&verifier_op, Bytes::new()).unwrap(); // bound cell TYPE = the verifier

    // the bound cell (FINALIZE input): type = verifier, data = seal||idx||state
    let bound_in = ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(always.clone())
            .type_(Some(verifier).pack()).build(),
        Bytes::from(bound_data),
    );
    // the "LCKP"||cert_root checkpoint cell, referenced (cell-dep) - the verifier reads the root from it
    let mut ckpt = b"LCKP".to_vec();
    ckpt.extend_from_slice(&cert_root);
    let ckpt_op = ctx.deploy_cell(Bytes::from(ckpt));

    let wa = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack()).build();

    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(bound_in).build())
        // FINALIZE: NO output carrying the verifier type. A plain sink output only.
        .output(CellOutput::new_builder().capacity(19000u64.pack()).lock(always).build())
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(verifier_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(wa.as_bytes().pack())
        .build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn leap_out_finalize_accepts() {
    let (ctx, tx) = build(None);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("FINALIZE leap-out must pass on the relayer-encoded witness");
}

#[test]
fn leap_out_bad_root_rejects() {
    // corrupt the checkpoint root -> the master MMR proof must fail -> the verifier rejects.
    let mut bad = hexbytes(
        &serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(DATASET).unwrap()).unwrap()["cert_root"]
            .as_str().unwrap(),
    );
    bad[0] ^= 0xff;
    let (ctx, tx) = build(Some(bad));
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a corrupted checkpoint root must be rejected");
}
