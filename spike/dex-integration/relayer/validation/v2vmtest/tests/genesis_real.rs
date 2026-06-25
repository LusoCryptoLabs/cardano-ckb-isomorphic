//! Reproduce the LIVE v2 genesis in CKB-VM with the REAL Mithril witness + cell data, to pinpoint the on-chain
//! -1 panic. Builds bound_asset_v2 with CHIRAL_LCKP_TH = the test checkpoint hash so the real cert_root cell is
//! trusted; the witness (captured from the live seal-mint) proves the tx against that root.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::{TransactionBuilder, ScriptHashType}, packed::*, prelude::*};
use ckb_testtool::context::Context;
use std::process::Command;

const MAX_CYCLES: u64 = 2_000_000_000;
const BGU_MANIFEST: &str = "../../../../burn-gated-unlock/Cargo.toml";
const VERIFIER: &str = "../../../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2";

fn hx(s: &str) -> Vec<u8> { let s = s.trim().strip_prefix("0x").unwrap_or(s.trim()); (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn hexstr(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

fn build_verifier(lckp_hex: &str) {
    let st = Command::new("cargo")
        .args(["build", "--release", "--bin", "bound_asset_v2", "--target", "riscv64imac-unknown-none-elf", "--manifest-path", BGU_MANIFEST])
        .env("CHIRAL_LCKP_TH", lckp_hex).env("CHIRAL_REG_TH", &hexstr(&[0u8; 32]))
        .env("RUSTFLAGS", "-C target-feature=-a,+forced-atomics")   // match the DEPLOYED binary exactly
        .status().expect("spawn cargo build");
    assert!(st.success(), "verifier build failed");
    // strip in place to match the deployed binary EXACTLY
    let st2 = Command::new("riscv64-unknown-elf-strip").arg(VERIFIER).status().expect("spawn strip");
    assert!(st2.success(), "strip failed");
}

#[test]
fn genesis_real_seal_mint() {
    let witness = hx(&std::fs::read_to_string("/tmp/wit.hex").unwrap());
    let cert_root = hx(&std::fs::read_to_string("/tmp/root.hex").unwrap());
    let th = hx("08000078bce80ed84d5409e12aa28c24e06591c87c23cdfff8606f947ba006cb"); // = b2b256(tx_body)
    let seal_policy = hx("ec8d2c7485d2f2aa31003d94b97fbf44fabf10f231534dd931970b10");        // 28 bytes
    let lock_addr = hx("7047c5d94c9338243bf0624b4d3b25840c0f913f2c9b92387f66970263");          // 29 bytes (0x70 ‖ hash)
    let state = b"bound-asset:demo:v1".to_vec();                                                // S0

    let mut ctx = Context::default();
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let out_lock = ctx.build_script(&as_op, Bytes::from(b"genowner".to_vec())).unwrap();
    let out_lock_h = out_lock.calc_script_hash().as_slice().to_vec();
    // construct the checkpoint TYPE exactly as the live one: Script{code=ckbhash(cv_deploy_v2.bin), data1, args:""}
    // so its hash == the live 0xa055798e the deployed verifier bakes. EXACT reproduction of Pudge.
    let cvd_data_hash = hx("75b288f3774bfe553fc72895f940578214e2111208f5a85fb5c5dbf5e9017bf9");
    let ckpt_type = Script::new_builder()
        .code_hash(Byte32::from_slice(&cvd_data_hash).unwrap())
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::new().pack())
        .build();
    let lckp_h = ckpt_type.calc_script_hash().as_slice().to_vec();
    eprintln!("test checkpoint type hash = {} (must == a055798e911a4f7ed074d5e1ee6273683e9a446c70d3e22adab680d70eea5b74)", hexstr(&lckp_h));

    build_verifier(&hexstr(&lckp_h));
    let v_op = ctx.deploy_cell(Bytes::from(std::fs::read(VERIFIER).unwrap()));
    let lock = ctx.build_script(&as_op, Bytes::new()).unwrap();
    let mut args = seal_policy.clone(); args.extend_from_slice(&lock_addr);
    let vtype = ctx.build_script(&v_op, Bytes::from(args)).unwrap();

    // v2 CkbOwned cell: 02 02 ‖ th(32) ‖ idx(0) ‖ lock_slot(32) ‖ state
    let mut bout = vec![0x02u8, 0x02u8]; bout.extend_from_slice(&th); bout.extend_from_slice(&0u32.to_le_bytes());
    bout.extend_from_slice(&out_lock_h); bout.extend_from_slice(&state);
    let funding = ctx.create_cell(CellOutput::new_builder().capacity(100000u64.pack()).lock(lock.clone()).build(), Bytes::new());
    // checkpoint: "LCKP" ‖ cert_root(32) ‖ height(8 LE)
    let mut ckpt_data = b"LCKP".to_vec(); ckpt_data.extend_from_slice(&cert_root); ckpt_data.extend_from_slice(&4_368_089u64.to_le_bytes());
    let ckpt_op = ctx.create_cell(CellOutput::new_builder().capacity(20000u64.pack()).lock(lock.clone()).type_(Some(ckpt_type).pack()).build(), Bytes::from(ckpt_data));

    // mimic the live witness: a secp256k1 lock sig (65 bytes) ALONGSIDE the cert in input_type
    let w = WitnessArgs::new_builder().lock(Some(Bytes::from(vec![0u8; 65])).pack()).input_type(Some(Bytes::from(witness)).pack()).build();
    let tx = ctx.complete_tx(TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(funding).build())
        .output(CellOutput::new_builder().capacity(30000u64.pack()).lock(out_lock).type_(Some(vtype).pack()).build())
        .output_data(Bytes::from(bout).pack())
        .cell_dep(CellDep::new_builder().out_point(v_op).build())
        .cell_dep(CellDep::new_builder().out_point(ckpt_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w.as_bytes().pack())
        .build());
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    eprintln!("genesis_real verify result: {:?}", res);
    res.expect("v2 GENESIS on the REAL certified seal mint must pass in CKB-VM");
}
