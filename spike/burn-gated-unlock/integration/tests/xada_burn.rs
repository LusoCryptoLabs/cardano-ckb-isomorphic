//! Real CKB-VM test for the χADA return-leg burn receipt (`xada_burn_receipt`). A receipt cell binding
//! (amount, cardano_recipient) is valid ONLY if the tx genuinely burns exactly `amount` of the χADA policy
//! (Σ χADA inputs − Σ χADA outputs). Proves: a real burn of the bound amount passes; a partial burn (with a
//! χADA change output) passes; wrong amount / no burn / a net mint / bad magic / bad length all fail closed.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionView, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 100_000_000;
const RCPT_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/xada_burn_receipt";

fn receipt_data(magic: &[u8], amount: u128, recipient_len: usize) -> Bytes {
    let mut d = Vec::new();
    d.extend_from_slice(magic);                     // 4 (or wrong)
    d.extend_from_slice(&amount.to_le_bytes());     // 16
    d.extend_from_slice(&vec![0x33u8; recipient_len]); // 28 (or wrong)
    Bytes::from(d)
}

struct Cfg { in_amt: u128, out_amt: u128, receipt_amt: u128, magic: Vec<u8>, recipient_len: usize }
impl Cfg { fn ok() -> Self { Cfg { in_amt: 5_000_000, out_amt: 0, receipt_amt: 5_000_000, magic: b"XAD1".to_vec(), recipient_len: 28 } } }

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let mut ctx = Context::default();
    let rcpt_bin: Bytes = std::fs::read(RCPT_BIN).expect("build xada_burn_receipt first").into();
    let rcpt_op = ctx.deploy_cell(rcpt_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let dummy = ctx.build_script(&as_op, Bytes::from(b"d".to_vec())).unwrap();
    let xada_policy = ctx.build_script(&as_op, Bytes::from(b"xada-policy".to_vec())).unwrap();
    let policy_hash: [u8; 32] = xada_policy.calc_script_hash().unpack();
    let rcpt_script = ctx.build_script(&rcpt_op, Bytes::from(policy_hash.to_vec())).unwrap();

    let rdata = receipt_data(&cfg.magic, cfg.receipt_amt, cfg.recipient_len);

    let mut b = ckb_testtool::ckb_types::core::TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(rcpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build());

    if cfg.in_amt > 0 {
        let xin = ctx.create_cell(
            CellOutput::new_builder().capacity(1000u64.pack()).lock(dummy.clone()).type_(Some(xada_policy.clone()).pack()).build(),
            Bytes::from(cfg.in_amt.to_le_bytes().to_vec()),
        );
        b = b.input(CellInput::new_builder().previous_output(xin).build());
    }
    let fund = ctx.create_cell(CellOutput::new_builder().capacity(100_000u64.pack()).lock(dummy.clone()).build(), Bytes::new());
    b = b.input(CellInput::new_builder().previous_output(fund).build());

    // output 0 = the receipt (GroupOutput[0] for xada_burn_receipt)
    b = b.output(CellOutput::new_builder().capacity(6000u64.pack()).lock(dummy.clone()).type_(Some(rcpt_script).pack()).build())
         .output_data(rdata.pack());
    if cfg.out_amt > 0 {
        b = b.output(CellOutput::new_builder().capacity(1000u64.pack()).lock(dummy.clone()).type_(Some(xada_policy.clone()).pack()).build())
             .output_data(Bytes::from(cfg.out_amt.to_le_bytes().to_vec()).pack());
    }
    b = b.output(CellOutput::new_builder().capacity(50_000u64.pack()).lock(dummy.clone()).build())
         .output_data(Bytes::new().pack());

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

fn run(cfg: Cfg) -> bool {
    let (ctx, tx) = build(cfg);
    ctx.verify_tx(&tx, MAX_CYCLES).is_ok()
}

#[test]
fn full_burn_receipt_ok() {
    assert!(run(Cfg::ok()), "burning exactly the bound amount must validate the receipt");
}
#[test]
fn partial_burn_with_change_ok() {
    assert!(run(Cfg { in_amt: 10_000_000, out_amt: 4_000_000, receipt_amt: 6_000_000, ..Cfg::ok() }),
            "burn = in - out = 6,000,000 must match the receipt");
}
#[test]
fn wrong_amount_rejected() {
    assert!(!run(Cfg { receipt_amt: 4_000_000, ..Cfg::ok() }), "receipt amount != burned must fail (code 10)");
}
#[test]
fn no_burn_rejected() {
    assert!(!run(Cfg { in_amt: 5_000_000, out_amt: 5_000_000, receipt_amt: 5_000_000, ..Cfg::ok() }),
            "no net burn (in == out) must fail (code 10)");
}
#[test]
fn net_mint_rejected() {
    assert!(!run(Cfg { in_amt: 0, out_amt: 5_000_000, receipt_amt: 5_000_000, ..Cfg::ok() }),
            "a net mint (in < out) must fail (code 9)");
}
#[test]
fn bad_magic_rejected() {
    assert!(!run(Cfg { magic: b"XXXX".to_vec(), ..Cfg::ok() }), "wrong MAGIC must fail (code 2)");
}
#[test]
fn bad_length_rejected() {
    assert!(!run(Cfg { recipient_len: 27, ..Cfg::ok() }), "receipt data != 48 bytes must fail (code 1)");
}
