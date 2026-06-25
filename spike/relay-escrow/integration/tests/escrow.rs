//! Real CKB-VM test for relay_escrow (SEC C7 + C8). Proves: a relayer can claim the escrow ONLY by both
//! referencing an authenticated checkpoint AND delivering THIS escrow's specific event payout (C7 - a live
//! checkpoint alone can no longer sweep every escrow); and the timeout refund must actually pay the
//! depositor (C8).
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 100_000_000;
const BIN: &str = "../target/riscv64imac-unknown-none-elf/release/relay_escrow";

const ESCROW_CAP: u64 = 20_000_000_000; // 200 CKB (so the 1-CKB fee allowance is small relative to it)
const EVENT_AMOUNT: u64 = 6_000_000_000; // 60 CKB

struct Opts {
    include_checkpoint: bool,
    deliver_payout: bool,
    payout_cap: u64,
    deadline: u64,
    depositor_out_cap: Option<u64>, // Some => add a depositor output of this capacity (refund path)
}
impl Opts {
    fn relay() -> Self { Opts { include_checkpoint: true, deliver_payout: true, payout_cap: EVENT_AMOUNT, deadline: 0xffff_ffff, depositor_out_cap: None } }
}

fn build(o: Opts) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let mut ctx = Context::default();
    let bin: Bytes = std::fs::read(BIN).expect("build relay_escrow first").into();
    let lock_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    // the authenticated checkpoint type script; its hash goes into the escrow lock args.
    let ckpt_type = ctx.build_script(&as_op, Bytes::from(b"txsetcert".to_vec())).unwrap();
    let ckpt_type_hash: [u8; 32] = ckpt_type.calc_script_hash().unpack();

    // the event payout lock (the bridged recipient) and the depositor lock.
    let event_lock = ctx.build_script(&as_op, Bytes::from(b"recipient".to_vec())).unwrap();
    let event_lock_hash: [u8; 32] = event_lock.calc_script_hash().unpack();
    let depositor = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();
    let depositor_hash: [u8; 32] = depositor.calc_script_hash().unpack();

    // escrow lock: args = auth_ckpt_type_hash(32); data = depositor(32)‖deadline(8)‖event_lock(32)‖event_amount(8)
    let escrow_lock = ctx.build_script(&lock_op, Bytes::from(ckpt_type_hash.to_vec())).unwrap();
    let mut data = Vec::new();
    data.extend_from_slice(&depositor_hash);
    data.extend_from_slice(&o.deadline.to_le_bytes());
    data.extend_from_slice(&event_lock_hash);
    data.extend_from_slice(&EVENT_AMOUNT.to_le_bytes());
    let escrow_cell = ctx.create_cell(CellOutput::new_builder().capacity(ESCROW_CAP.pack()).lock(escrow_lock).build(), Bytes::from(data));

    let dummy = ctx.build_script(&as_op, Bytes::from(b"d".to_vec())).unwrap();
    let mut b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(escrow_cell).build())
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build());

    if o.deliver_payout {
        b = b.output(CellOutput::new_builder().capacity(o.payout_cap.pack()).lock(event_lock.clone()).build()).output_data(Bytes::new().pack());
    }
    if let Some(cap) = o.depositor_out_cap {
        b = b.output(CellOutput::new_builder().capacity(cap.pack()).lock(depositor.clone()).build()).output_data(Bytes::new().pack());
    }
    // a generic change output so the tx is well-formed even when no payout/refund output is added.
    b = b.output(CellOutput::new_builder().capacity(100u64.pack()).lock(dummy.clone()).build()).output_data(Bytes::new().pack());

    if o.include_checkpoint {
        let ckpt = ctx.create_cell(
            CellOutput::new_builder().capacity(3000u64.pack()).lock(dummy.clone()).type_(Some(ckpt_type).pack()).build(),
            Bytes::from(b"LCKP".to_vec()),
        );
        b = b.cell_dep(CellDep::new_builder().out_point(ckpt).build());
    }
    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn relay_with_payout_and_checkpoint_unlocks() {
    let (ctx, tx) = build(Opts::relay());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("relay with checkpoint + delivered payout must unlock");
}

#[test]
fn relay_without_payout_rejected() {
    // SEC C7: an authenticated checkpoint alone (no event payout delivered) must NOT sweep the escrow.
    let (ctx, tx) = build(Opts { deliver_payout: false, ..Opts::relay() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "checkpoint without the event payout must be rejected");
}

#[test]
fn relay_underpaid_payout_rejected() {
    // payout below the bound event_amount must not count.
    let (ctx, tx) = build(Opts { payout_cap: EVENT_AMOUNT - 1, ..Opts::relay() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "an underpaid event payout must be rejected");
}

#[test]
fn relay_without_checkpoint_rejected() {
    let (ctx, tx) = build(Opts { include_checkpoint: false, ..Opts::relay() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no authenticated checkpoint must be rejected");
}

#[test]
fn refund_after_deadline_pays_depositor() {
    // deadline 0 => time gate open; depositor receives >= escrow - 1 CKB (C8).
    let (ctx, tx) = build(Opts { include_checkpoint: false, deliver_payout: false, deadline: 0, depositor_out_cap: Some(ESCROW_CAP - 50), ..Opts::relay() });
    ctx.verify_tx(&tx, MAX_CYCLES).expect("refund after deadline paying the depositor must unlock");
}

#[test]
fn refund_dust_to_depositor_rejected() {
    // SEC C8: a dust refund to the depositor (remainder pocketed) must be rejected.
    let (ctx, tx) = build(Opts { include_checkpoint: false, deliver_payout: false, deadline: 0, depositor_out_cap: Some(1_000_000_000), ..Opts::relay() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a dust refund must be rejected");
}
