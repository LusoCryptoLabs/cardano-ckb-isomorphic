//! Real CKB-VM integration tests for the leap-mint guard, running the ACTUAL deployed xUDT type script
//! (the binary fetched from Pudge testnet, `fixtures/xudt_testnet.bin`) - no ALWAYS_SUCCESS stand-in for
//! the token. Each tx wires the real owner-mode xUDT (args = owner lock hash = the guard's own script
//! hash) together with the guard lock on a bridge "owner cell", a REAL-layout bound cell
//! (seal32 ‖ idx4 ‖ amount16 ‖ recipient32), and (optionally) the real admin policy cell. The xUDT type
//! script and the guard both execute in ckb-testtool's VM, so the full supply gate is exercised for real:
//! the xUDT permits the mint/burn (owner present) and the guard constrains it (conservation + caps/pause).
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_hash::new_blake2b;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 200_000_000;
const GUARD_BIN: &str = "../ckb_script/target/riscv64imac-unknown-none-elf/release/leap_mint_guard";
const XUDT_BIN: &str = "fixtures/xudt_testnet.bin"; // the real xUDT, fetched from Pudge
const UNIQUE_BIN: &str = "fixtures/unique_testnet.bin"; // the real Unique (token-info) type script, from Pudge

fn u128_le(v: u128) -> Vec<u8> { v.to_le_bytes().to_vec() }
fn policy_data(flags: u8, min: u128, max: u128) -> Vec<u8> {
    let mut d = vec![flags];
    d.extend_from_slice(&u128_le(min));
    d.extend_from_slice(&u128_le(max));
    d
}

/// Shared scaffolding: deploy the real xUDT + guard + ALWAYS_SUCCESS, and resolve the (non-circular)
/// script identities - guard args = xUDT CODE hash ‖ bound hash ‖ [policy hash]; xUDT args = owner =
/// guard lock hash. Returns the context plus the scripts the tx builders need.
struct Rig {
    ctx: Context,
    guard_op: OutPoint,
    xudt_op: OutPoint,
    unique_op: OutPoint,
    as_op: OutPoint,
    guard_lock: Script,   // the xUDT owner lock (runs the guard)
    xudt: Script,         // real owner-mode xUDT, owner = guard_lock hash
    bound: Script,
    recipient: Script,
    other: Script,
    dummy: Script,
    policy_script: Script,
    recipient_hash: [u8; 32],
}

fn rig(with_policy: bool) -> Rig {
    let mut ctx = Context::default();
    let guard_op = ctx.deploy_cell(std::fs::read(GUARD_BIN).expect("build guard first").into());
    let xudt_op = ctx.deploy_cell(std::fs::read(XUDT_BIN).expect("fetch xudt fixture").into());
    let unique_op = ctx.deploy_cell(std::fs::read(UNIQUE_BIN).expect("fetch unique fixture").into());
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let bound = ctx.build_script(&as_op, Bytes::from(b"bound".to_vec())).unwrap();
    let recipient = ctx.build_script(&as_op, Bytes::from(b"recipient".to_vec())).unwrap();
    let other = ctx.build_script(&as_op, Bytes::from(b"other".to_vec())).unwrap();
    let dummy = ctx.build_script(&as_op, Bytes::from(b"dummy".to_vec())).unwrap();
    let policy_script = ctx.build_script(&as_op, Bytes::from(b"policy".to_vec())).unwrap();

    // xUDT CODE hash (data hash of the deployed binary) - fixed, does NOT depend on the guard.
    let xudt_code: [u8; 32] = ctx.build_script(&xudt_op, Bytes::new()).unwrap().code_hash().unpack();
    let bound_hash: [u8; 32] = bound.calc_script_hash().unpack();
    let policy_hash: [u8; 32] = policy_script.calc_script_hash().unpack();

    // guard args = xUDT code hash ‖ bound type hash ‖ [policy type hash]
    let mut guard_args = Vec::with_capacity(96);
    guard_args.extend_from_slice(&xudt_code);
    guard_args.extend_from_slice(&bound_hash);
    if with_policy { guard_args.extend_from_slice(&policy_hash); }
    let guard_lock = ctx.build_script(&guard_op, Bytes::from(guard_args)).unwrap();

    // xUDT owner = the guard's OWN script hash (standard owner-mode xUDT) - no circularity.
    let owner: [u8; 32] = guard_lock.calc_script_hash().unpack();
    let xudt = ctx.build_script(&xudt_op, Bytes::from(owner.to_vec())).unwrap();

    let recipient_hash: [u8; 32] = recipient.calc_script_hash().unpack();
    Rig { ctx, guard_op, xudt_op, unique_op, as_op, guard_lock, xudt, bound, recipient, other, dummy, policy_script, recipient_hash }
}

/// token-info bytes read by ckb-explorer / JoyID: [decimals u8][nameLen u8][name][symLen u8][symbol].
fn token_info(decimals: u8, name: &str, symbol: &str) -> Vec<u8> {
    let (n, s) = (name.as_bytes(), symbol.as_bytes());
    let mut d = vec![decimals, n.len() as u8];
    d.extend_from_slice(n);
    d.push(s.len() as u8);
    d.extend_from_slice(s);
    d
}

/// the Unique type-id args = blake2b(first_input ‖ output_index_u64_le)[0..20] - exactly what the real
/// Unique type script checks on creation (and what CCC's hashTypeId computes off-chain).
fn unique_args(first_input: &CellInput, output_index: u64) -> Vec<u8> {
    let mut hasher = new_blake2b();
    hasher.update(first_input.as_slice());
    hasher.update(&output_index.to_le_bytes());
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out[0..20].to_vec()
}

fn bound_data(amount: u128, recipient_hash: &[u8; 32]) -> Vec<u8> {
    let mut d = vec![0u8; 32]; // seal
    d.extend_from_slice(&0u32.to_le_bytes()); // idx
    d.extend_from_slice(&u128_le(amount)); // amount(16 LE)
    d.extend_from_slice(recipient_hash); // recipient(32)
    d
}

fn verify(rig: &Rig, tx: ckb_testtool::ckb_types::core::TransactionView) -> Result<u64, String> {
    rig.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{e}"))
}

// ---- leap-in MINT (real xUDT type script runs on the minted output) ----

fn build_mint(rig: &mut Rig, state_amount: u128, mint_amount: u128, diverted: u128, with_policy: Option<Vec<u8>>)
    -> ckb_testtool::ckb_types::core::TransactionView {
    // the bridge OWNER cell, locked by the guard. Spending it: (a) runs the guard, (b) makes the xUDT see
    // its owner lock present in inputs -> owner mode -> mint permitted.
    let owner_in = rig.ctx.create_cell(
        CellOutput::new_builder().capacity(1000u64.pack()).lock(rig.guard_lock.clone()).build(),
        Bytes::new(),
    );

    let mut outputs = vec![
        CellOutput::new_builder().capacity(2000u64.pack()).lock(rig.dummy.clone())
            .type_(Some(rig.bound.clone()).pack()).build(),
        CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone())
            .type_(Some(rig.xudt.clone()).pack()).build(),
    ];
    let mut outputs_data = vec![Bytes::from(bound_data(state_amount, &rig.recipient_hash)), Bytes::from(u128_le(mint_amount - diverted))];
    if diverted > 0 {
        outputs.push(CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.other.clone())
            .type_(Some(rig.xudt.clone()).pack()).build());
        outputs_data.push(Bytes::from(u128_le(diverted)));
    }

    let mut b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(owner_in).build())
        .outputs(outputs)
        .outputs_data(outputs_data.into_iter().map(|d| d.pack()).collect::<Vec<_>>())
        .cell_dep(CellDep::new_builder().out_point(rig.guard_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.xudt_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.as_op.clone()).build());
    if let Some(pd) = with_policy {
        let policy_op = rig.ctx.create_cell(
            CellOutput::new_builder().capacity(3000u64.pack()).lock(rig.dummy.clone())
                .type_(Some(rig.policy_script.clone()).pack()).build(),
            Bytes::from(pd),
        );
        b = b.cell_dep(CellDep::new_builder().out_point(policy_op).build());
    }
    rig.ctx.complete_tx(b.build())
}

#[test]
fn mint_exact_accepts() {
    let mut rig = rig(false);
    let tx = build_mint(&mut rig, 52_000_000, 52_000_000, 0, None);
    verify(&rig, tx).expect("valid leap-in mint must pass (real xUDT + guard)");
}

#[test]
fn mint_inflation_rejects() {
    let mut rig = rig(false);
    let tx = build_mint(&mut rig, 52_000_000, 52_000_001, 0, None);
    assert!(verify(&rig, tx).is_err(), "inflation must be rejected");
}

#[test]
fn mint_undermint_rejects() {
    let mut rig = rig(false);
    let tx = build_mint(&mut rig, 52_000_000, 51_000_000, 0, None);
    assert!(verify(&rig, tx).is_err(), "under-mint must be rejected");
}

#[test]
fn mint_leakage_rejects() {
    let mut rig = rig(false);
    let tx = build_mint(&mut rig, 52_000_000, 52_000_000, 2_000_000, None);
    assert!(verify(&rig, tx).is_err(), "diverted mint must be rejected");
}

// ---- GENESIS: mint + co-mint the real token-info (Unique) cell in ONE owner-mode tx ----
// This is the only arrangement JoyID/explorers bind metadata from. Runs the real xUDT AND the real Unique
// type script alongside the guard, so "renders in JoyID" is proven in-VM, not just constructed off-chain.

#[test]
fn genesis_with_real_tokeninfo_accepts() {
    let mut rig = rig(false);
    let owner_in = rig.ctx.create_cell(
        CellOutput::new_builder().capacity(1000u64.pack()).lock(rig.guard_lock.clone()).build(),
        Bytes::new(),
    );
    let first_input = CellInput::new_builder().previous_output(owner_in).build();
    // the Unique token-info cell is output index 2; derive its args from (first_input, 2)
    let uniq = rig.ctx
        .build_script(&rig.unique_op, Bytes::from(unique_args(&first_input, 2)))
        .unwrap();

    let outputs = vec![
        // [0] the verified bound cell (genesis/transition)
        CellOutput::new_builder().capacity(2000u64.pack()).lock(rig.dummy.clone())
            .type_(Some(rig.bound.clone()).pack()).build(),
        // [1] the xUDT minted to the user's lock (owner mode)
        CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone())
            .type_(Some(rig.xudt.clone()).pack()).build(),
        // [2] the co-minted Unique token-info cell (immutable display metadata)
        CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone())
            .type_(Some(uniq).pack()).build(),
    ];
    let outputs_data = vec![
        Bytes::from(bound_data(52_000_000, &rig.recipient_hash)),
        Bytes::from(u128_le(52_000_000)),
        Bytes::from(token_info(6, "Wrapped ADA", "wADA")),
    ];
    let tx = TransactionBuilder::default()
        .input(first_input)
        .outputs(outputs)
        .outputs_data(outputs_data.into_iter().map(|d| d.pack()).collect::<Vec<_>>())
        .cell_dep(CellDep::new_builder().out_point(rig.guard_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.xudt_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.unique_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.as_op.clone()).build())
        .build();
    let tx = rig.ctx.complete_tx(tx);
    verify(&rig, tx).expect("genesis with co-minted token-info must pass (real xUDT + Unique + guard)");
}

#[test]
fn genesis_wrong_tokeninfo_args_rejects() {
    // derive the Unique args from the WRONG output index (1, not 2) -> the real Unique type script must
    // reject, proving the type-id binding is enforced (the token-info can't be forged/duplicated).
    let mut rig = rig(false);
    let owner_in = rig.ctx.create_cell(
        CellOutput::new_builder().capacity(1000u64.pack()).lock(rig.guard_lock.clone()).build(),
        Bytes::new(),
    );
    let first_input = CellInput::new_builder().previous_output(owner_in).build();
    let uniq = rig.ctx
        .build_script(&rig.unique_op, Bytes::from(unique_args(&first_input, 1))) // WRONG index
        .unwrap();
    let outputs = vec![
        CellOutput::new_builder().capacity(2000u64.pack()).lock(rig.dummy.clone())
            .type_(Some(rig.bound.clone()).pack()).build(),
        CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone())
            .type_(Some(rig.xudt.clone()).pack()).build(),
        CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone())
            .type_(Some(uniq).pack()).build(),
    ];
    let outputs_data = vec![
        Bytes::from(bound_data(52_000_000, &rig.recipient_hash)),
        Bytes::from(u128_le(52_000_000)),
        Bytes::from(token_info(6, "Wrapped ADA", "wADA")),
    ];
    let tx = TransactionBuilder::default()
        .input(first_input)
        .outputs(outputs)
        .outputs_data(outputs_data.into_iter().map(|d| d.pack()).collect::<Vec<_>>())
        .cell_dep(CellDep::new_builder().out_point(rig.guard_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.xudt_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.unique_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.as_op.clone()).build())
        .build();
    let tx = rig.ctx.complete_tx(tx);
    assert!(verify(&rig, tx).is_err(), "real Unique type script must reject a wrong type-id");
}

// ---- the REAL xUDT itself enforces (no guard, no owner): proves it isn't a no-op ----

fn build_transfer(rig: &mut Rig, in_amt: u128, out_amt: u128) -> ckb_testtool::ckb_types::core::TransactionView {
    // a plain transfer with NO owner cell present -> xUDT is NOT in owner mode -> it must enforce
    // sum(inputs) == sum(outputs). No guard runs here (lock is ALWAYS_SUCCESS).
    let xudt_in = rig.ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone()).type_(Some(rig.xudt.clone()).pack()).build(),
        Bytes::from(u128_le(in_amt)),
    );
    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(xudt_in).build())
        .output(CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone()).type_(Some(rig.xudt.clone()).pack()).build())
        .output_data(Bytes::from(u128_le(out_amt)).pack())
        .cell_dep(CellDep::new_builder().out_point(rig.xudt_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.as_op.clone()).build())
        .build();
    rig.ctx.complete_tx(tx)
}

#[test]
fn xudt_balanced_transfer_accepts() {
    let mut rig = rig(false);
    let tx = build_transfer(&mut rig, 100, 100);
    verify(&rig, tx).expect("balanced xUDT transfer must pass the real xUDT");
}

#[test]
fn xudt_non_owner_inflation_rejects() {
    // 100 in, 101 out, no owner -> the REAL xUDT (not the guard) must reject. Proves it's enforcing.
    let mut rig = rig(false);
    let tx = build_transfer(&mut rig, 100, 101);
    assert!(verify(&rig, tx).is_err(), "real xUDT must reject a non-owner supply increase");
}

// ---- leap-out BURN (real xUDT runs on the burned input) ----

fn build_burn(rig: &mut Rig, state_amount: u128, held: u128) -> ckb_testtool::ckb_types::core::TransactionView {
    let owner_in = rig.ctx.create_cell(
        CellOutput::new_builder().capacity(1000u64.pack()).lock(rig.guard_lock.clone()).build(),
        Bytes::new(),
    );
    let bound_in = rig.ctx.create_cell(
        CellOutput::new_builder().capacity(2000u64.pack()).lock(rig.dummy.clone()).type_(Some(rig.bound.clone()).pack()).build(),
        Bytes::from(bound_data(state_amount, &rig.recipient_hash)),
    );
    // the user's xUDT (owner-mode token), all burned (no xUDT output)
    let xudt_in = rig.ctx.create_cell(
        CellOutput::new_builder().capacity(20000u64.pack()).lock(rig.recipient.clone()).type_(Some(rig.xudt.clone()).pack()).build(),
        Bytes::from(u128_le(held)),
    );
    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder().previous_output(owner_in).build(),
            CellInput::new_builder().previous_output(bound_in).build(),
            CellInput::new_builder().previous_output(xudt_in).build(),
        ])
        .output(CellOutput::new_builder().capacity(3000u64.pack()).lock(rig.dummy.clone()).build())
        .output_data(Bytes::new().pack())
        .cell_dep(CellDep::new_builder().out_point(rig.guard_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.xudt_op.clone()).build())
        .cell_dep(CellDep::new_builder().out_point(rig.as_op.clone()).build())
        .build();
    rig.ctx.complete_tx(tx)
}

#[test]
fn burn_exact_accepts() {
    let mut rig = rig(false);
    let tx = build_burn(&mut rig, 52_000_000, 52_000_000);
    verify(&rig, tx).expect("exact leap-out burn must pass (real xUDT + guard)");
}

#[test]
fn burn_underburn_rejects() {
    let mut rig = rig(false);
    let tx = build_burn(&mut rig, 52_000_000, 51_000_000);
    assert!(verify(&rig, tx).is_err(), "under-burn must be rejected");
}

// ---- caps / pause (real policy cell-dep, enforced alongside the real xUDT) ----

#[test]
fn policy_within_cap_accepts() {
    let mut rig = rig(true);
    let tx = build_mint(&mut rig, 52_000_000, 52_000_000, 0, Some(policy_data(0, 1_000, 100_000_000)));
    verify(&rig, tx).expect("within-cap mint must pass");
}

#[test]
fn policy_over_cap_rejects() {
    let mut rig = rig(true);
    let tx = build_mint(&mut rig, 150_000_000, 150_000_000, 0, Some(policy_data(0, 0, 100_000_000)));
    assert!(verify(&rig, tx).is_err(), "over-cap leap must be rejected");
}

#[test]
fn policy_under_min_rejects() {
    let mut rig = rig(true);
    let tx = build_mint(&mut rig, 500, 500, 0, Some(policy_data(0, 1_000, 0)));
    assert!(verify(&rig, tx).is_err(), "below-min leap must be rejected");
}

#[test]
fn policy_global_pause_rejects() {
    let mut rig = rig(true);
    let tx = build_mint(&mut rig, 52_000_000, 52_000_000, 0, Some(policy_data(1, 0, 0)));
    assert!(verify(&rig, tx).is_err(), "global pause must halt mints");
}

#[test]
fn policy_pause_in_rejects() {
    let mut rig = rig(true);
    let tx = build_mint(&mut rig, 52_000_000, 52_000_000, 0, Some(policy_data(2, 0, 0)));
    assert!(verify(&rig, tx).is_err(), "pause-in must halt mints");
}

#[test]
fn policy_pause_out_allows_in() {
    let mut rig = rig(true);
    let tx = build_mint(&mut rig, 52_000_000, 52_000_000, 0, Some(policy_data(4, 0, 0)));
    verify(&rig, tx).expect("pause-out must not affect leap-in");
}
