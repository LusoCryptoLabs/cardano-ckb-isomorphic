//! Real CKB-VM test for the χADA FORWARD-mint type script (`xada_mint`) - the second leg's keystone
//! (spike/cardano-to-ckb-zk/XADA_LEG.md). Builds a synthetic Conway ESCROW tx (ADA locked at the escrow
//! address, with an inline `EscrowDatum` binding a CKB recipient + amount) + a consistent two-level
//! Blake2s256 MKMapProof (we control the checkpoint root) + the genesis-pinned replay-once registry, and
//! drives `xada_mint` in-VM. Proves:
//!   - a CERTIFIED ADA-lock of `coin` lovelace mints EXACTLY `coin` χADA to the committed recipient;
//!   - wrong mint amount / wrong datum amount / wrong recipient / tampered proof / missing checkpoint /
//!     missing or mis-keyed registry insertion / a stray χADA input are all rejected (fail-closed).
use ckb_merkle_mountain_range::{util::{MemMMR, MemStore}, Merge, Result as MMRResult};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 400_000_000;
const MINT_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/xada_mint";
const REG_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/burn_nullifier_registry";

// ---- MMR / hashing (mirror of xada_mint.rs + v2.rs: same merge, same personalizations) ----
#[derive(Clone, PartialEq, Eq)] struct N(Vec<u8>);
struct MB;
impl Merge for MB {
    type Item = N;
    fn merge(l: &N, r: &N) -> MMRResult<N> { use blake2::{Blake2s256, Digest}; let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) }
}
fn b2s(parts: &[&[u8]]) -> Vec<u8> { use blake2::{Blake2s256, Digest}; let mut h = Blake2s256::new(); for p in parts { h.update(p); } h.finalize().to_vec() }
fn b2b256(p: &[u8]) -> [u8; 32] { let mut h = blake2b_ref::Blake2bBuilder::new(32).build(); h.update(p); let mut o = [0u8; 32]; h.finalize(&mut o); o }
fn hexb(b: &[u8]) -> Vec<u8> { let hx = b"0123456789abcdef"; let mut o = Vec::new(); for &x in b { o.push(hx[(x>>4)as usize]); o.push(hx[(x&0xf)as usize]); } o }

// ---- replay-once SMT (mirror of burn_nullifier_registry.rs) ----
const ZERO: [u8; 32] = [0u8; 32];
const PRESENT: [u8; 32] = [1u8; 32];
fn h2(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-smt-null-set").build();
    h.update(l); h.update(r); let mut o = [0u8; 32]; h.finalize(&mut o); o
}
fn empties() -> Vec<[u8; 32]> { let mut e = vec![ZERO]; for d in 1..=256 { let p = e[d - 1]; e.push(h2(&p, &p)); } e }
fn fold(value: &[u8; 32], key: &[u8; 32], sib: &[[u8; 32]; 256]) -> [u8; 32] {
    let mut cur = *value;
    for d in 0..256 { let bi = 255 - d; let bit = (key[bi / 8] >> (7 - (bi % 8))) & 1; cur = if bit == 1 { h2(&sib[d], &cur) } else { h2(&cur, &sib[d]) }; }
    cur
}
fn empty_insert(key: &[u8; 32]) -> ([u8; 32], [u8; 32], Vec<u8>) {
    let e = empties();
    let old_root = e[256];
    let mut sib = [[0u8; 32]; 256];
    for d in 0..256 { sib[d] = e[d]; }
    let new_root = fold(&PRESENT, key, &sib);
    let mut w = Vec::with_capacity(32 + 256 * 32);
    w.extend_from_slice(key);
    for d in 0..256 { w.extend_from_slice(&sib[d]); }
    (old_root, new_root, w)
}

// ---- minimal CBOR encoders to build the synthetic Conway escrow tx ----
fn bstr(b: &[u8]) -> Vec<u8> { let mut o = Vec::new(); let n = b.len();
    if n < 24 { o.push(0x40 + n as u8); } else if n < 256 { o.push(0x58); o.push(n as u8); } else { o.push(0x59); o.extend_from_slice(&(n as u16).to_be_bytes()); }
    o.extend_from_slice(b); o }
fn uint(n: u64) -> Vec<u8> { let mut o = Vec::new();
    if n < 24 { o.push(n as u8); } else if n < 256 { o.push(0x18); o.push(n as u8); }
    else if n < 65536 { o.push(0x19); o.extend_from_slice(&(n as u16).to_be_bytes()); }
    else if n < (1u64 << 32) { o.push(0x1a); o.extend_from_slice(&(n as u32).to_be_bytes()); }
    else { o.push(0x1b); o.extend_from_slice(&n.to_be_bytes()); } o }
// EscrowDatum = Constr 121 [ recipient:bytes32, amount:int, nonce:int ] - INDEFINITE inner array (the standard
// Plutus / pycardano encoding the live escrow datum actually uses: 0x9f … 0xff).
fn escrow_datum(recipient: &[u8], amount: u64, nonce: u64) -> Vec<u8> {
    let mut o = vec![0xd8u8, 0x79, 0x9f]; o.extend(bstr(recipient)); o.extend(uint(amount)); o.extend(uint(nonce)); o.push(0xff); o }
fn inline(datum: &[u8]) -> Vec<u8> { let mut o = vec![0x82u8, 0x01, 0xd8, 0x18]; o.extend(bstr(datum)); o }   // [1, 24(bstr)]
fn map_output(addr: &[u8], coin: u64, datum: &[u8]) -> Vec<u8> {
    let mut o = vec![0xa3u8];
    o.push(0x00); o.extend(bstr(addr));
    o.push(0x01); o.extend(uint(coin));
    o.push(0x02); o.extend(inline(datum));
    o }
fn build_escrow_body(addr: &[u8], coin: u64, recipient: &[u8], datum_amount: u64, nonce: u64) -> Vec<u8> {
    let out = map_output(addr, coin, &escrow_datum(recipient, datum_amount, nonce));
    let mut o = vec![0xa2u8];                       // tx body map(2)
    o.push(0x00); o.push(0x80);                     // 0 -> [] inputs
    o.push(0x01); o.push(0x81); o.extend_from_slice(&out);   // 1 -> array(1) outputs
    o }

// two-level MKMap proof (verbatim from v2.rs): leaf = hex(blake2b256(tx_body)) under sub_root under cert_root.
fn make_proof(tx_body: &[u8], tamper: bool) -> (Vec<u8>, Vec<u8>) {
    let leaf = N(hexb(&b2b256(tx_body)));
    let sub_store = MemStore::default();
    let mut sub = MemMMR::<N, MB>::new(0, &sub_store);
    let _ = sub.push(N(b2s(&[b"s0"]))).unwrap();
    let sub_pos = sub.push(leaf).unwrap();
    let _ = sub.push(N(b2s(&[b"s2"]))).unwrap();
    let sub_root = sub.get_root().unwrap();
    let sp = sub.gen_proof(vec![sub_pos]).unwrap();
    let (sub_size, sub_items) = (sp.mmr_size(), sp.proof_items().iter().map(|n| n.0.clone()).collect::<Vec<_>>());

    let range_key = b"4357140-4357155".to_vec();
    let master_leaf = N(b2s(&[&range_key, &sub_root.0]));
    let master_store = MemStore::default();
    let mut master = MemMMR::<N, MB>::new(0, &master_store);
    let _ = master.push(N(b2s(&[b"m0"]))).unwrap();
    let master_pos = master.push(master_leaf).unwrap();
    let cert_root = master.get_root().unwrap();
    let mp = master.gen_proof(vec![master_pos]).unwrap();
    let (master_size, master_items) = (mp.mmr_size(), mp.proof_items().iter().map(|n| n.0.clone()).collect::<Vec<_>>());

    let lp = |x: &[u8], o: &mut Vec<u8>| { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x); };
    let items = |xs: &[Vec<u8>], o: &mut Vec<u8>| { o.extend_from_slice(&(xs.len() as u32).to_le_bytes()); for x in xs { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x); } };
    let mut w = Vec::new();
    lp(tx_body, &mut w);
    lp(&sub_root.0, &mut w); w.extend_from_slice(&sub_pos.to_le_bytes()); w.extend_from_slice(&sub_size.to_le_bytes()); items(&sub_items, &mut w);
    lp(&range_key, &mut w); w.extend_from_slice(&master_pos.to_le_bytes()); w.extend_from_slice(&master_size.to_le_bytes()); items(&master_items, &mut w);
    if tamper { let n = w.len(); w[n - 1] ^= 0xff; }
    (w, cert_root.0)
}

const ESCROW_ADDR: [u8; 29] = [0x70, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB];
const COIN: u64 = 20_000_000;   // 20 ADA locked (lovelace)

struct Cfg {
    coin: u64,
    datum_amount: u64,
    mint_amount: u128,
    recipient_match: bool,
    tamper: bool,
    include_checkpoint: bool,
    include_registry: bool,
    registry_key_override: Option<[u8; 32]>,
    stray_xada_input: bool,
    height: u64,
}
impl Cfg { fn ok() -> Self { Cfg { coin: COIN, datum_amount: COIN, mint_amount: COIN as u128, recipient_match: true, tamper: false, include_checkpoint: true, include_registry: true, registry_key_override: None, stray_xada_input: false, height: 4_371_186 } } }

fn build(cfg: Cfg) -> (Context, ckb_testtool::ckb_types::core::TransactionView) {
    let mut ctx = Context::default();
    let mint_bin: Bytes = std::fs::read(MINT_BIN).expect("build xada_mint first").into();
    let reg_bin: Bytes = std::fs::read(REG_BIN).expect("build burn_nullifier_registry first").into();
    let mint_op = ctx.deploy_cell(mint_bin);
    let reg_op = ctx.deploy_cell(reg_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let dummy = ctx.build_script(&as_op, Bytes::from(b"d".to_vec())).unwrap();
    let recipient_lock = ctx.build_script(&as_op, Bytes::from(b"xada-recipient".to_vec())).unwrap();
    let recipient_hash: [u8; 32] = recipient_lock.calc_script_hash().unpack();

    let lckp_type = ctx.build_script(&as_op, Bytes::from(b"lckp".to_vec())).unwrap();
    let lckp_type_hash: [u8; 32] = lckp_type.calc_script_hash().unpack();
    let reg_type = ctx.build_script(&reg_op, Bytes::from([0x11u8; 32].to_vec())).unwrap();
    let reg_type_hash: [u8; 32] = reg_type.calc_script_hash().unpack();

    let body = build_escrow_body(&ESCROW_ADDR, cfg.coin, &recipient_hash, cfg.datum_amount, 1);
    let (mint_witness, cert_root) = make_proof(&body, cfg.tamper);
    let key = cfg.registry_key_override.unwrap_or_else(|| { let mut p = vec![0x01u8]; p.extend_from_slice(&body); b2b256(&p) }); // 0x01 = χADA-mint leg tag
    let (old_root, new_root, reg_witness) = empty_insert(&key);

    // args = LCKP_type_hash(32) ‖ registry_type_hash(32) ‖ escrow_addr
    let mut args = Vec::new();
    args.extend_from_slice(&lckp_type_hash);
    args.extend_from_slice(&reg_type_hash);
    args.extend_from_slice(&ESCROW_ADDR);
    let mint_script = ctx.build_script(&mint_op, Bytes::from(args)).unwrap();

    // funding input (provides capacity; always_success lock)
    let funding = ctx.create_cell(CellOutput::new_builder().capacity(100_000u64.pack()).lock(dummy.clone()).build(), Bytes::new());

    // χADA mint output: type = xada_mint, data = amount(u128 LE 16B), locked at the recipient (or a wrong lock).
    let out_lock = if cfg.recipient_match { recipient_lock.clone() } else { dummy.clone() };
    let xada_out = CellOutput::new_builder().capacity(9_000u64.pack()).lock(out_lock).type_(Some(mint_script.clone()).pack()).build();

    let mut b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(funding).build())
        .output(xada_out)
        .output_data(Bytes::from(cfg.mint_amount.to_le_bytes().to_vec()).pack())
        .cell_dep(CellDep::new_builder().out_point(mint_op).build())
        .cell_dep(CellDep::new_builder().out_point(reg_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build());

    // witness[0] holds the MKMapProof in .input_type (read via GroupOutput witness 0 on the mint path).
    let mut witnesses: Vec<Bytes> = vec![
        WitnessArgs::new_builder().input_type(Some(Bytes::from(mint_witness)).pack()).build().as_bytes(),
    ];

    if cfg.include_registry {
        let reg_in = ctx.create_cell(
            CellOutput::new_builder().capacity(2000u64.pack()).lock(dummy.clone()).type_(Some(reg_type.clone()).pack()).build(),
            Bytes::from(old_root.to_vec()),
        );
        b = b.input(CellInput::new_builder().previous_output(reg_in).build())
             .output(CellOutput::new_builder().capacity(2000u64.pack()).lock(dummy.clone()).type_(Some(reg_type.clone()).pack()).build())
             .output_data(Bytes::from(new_root.to_vec()).pack());
        witnesses.push(WitnessArgs::new_builder().input_type(Some(Bytes::from(reg_witness)).pack()).build().as_bytes());
    }

    if cfg.stray_xada_input {
        // a χADA input makes in_sum != 0, so the mint-only discipline rejects (code 18).
        let stray = ctx.create_cell(
            CellOutput::new_builder().capacity(9000u64.pack()).lock(dummy.clone()).type_(Some(mint_script.clone()).pack()).build(),
            Bytes::from(0u128.to_le_bytes().to_vec()),
        );
        b = b.input(CellInput::new_builder().previous_output(stray).build());
        witnesses.push(WitnessArgs::new_builder().build().as_bytes());
    }

    if cfg.include_checkpoint {
        let mut ckpt_data = b"LCKP".to_vec();
        ckpt_data.extend_from_slice(&cert_root);
        ckpt_data.extend_from_slice(&cfg.height.to_le_bytes());   // LCKP ‖ root(32) ‖ height(8 LE) = 44B
        let ckpt_cell = ctx.create_cell(
            CellOutput::new_builder().capacity(3000u64.pack()).lock(dummy.clone()).type_(Some(lckp_type).pack()).build(),
            Bytes::from(ckpt_data),
        );
        b = b.cell_dep(CellDep::new_builder().out_point(ckpt_cell).build());
    }
    for w in witnesses { b = b.witness(w.pack()); }
    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn forward_mint_ok() {
    let (ctx, tx) = build(Cfg::ok());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a certified ADA-lock of COIN must mint exactly COIN χADA to the recipient");
}

#[test]
fn wrong_mint_amount_rejected() {
    let (ctx, tx) = build(Cfg { mint_amount: (COIN as u128) - 1, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "minting != locked lovelace must be rejected (code 24)");
}

#[test]
fn datum_amount_mismatch_rejected() {
    let (ctx, tx) = build(Cfg { datum_amount: COIN - 1, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "datum.amount != on-chain coin must be rejected (code 23)");
}

#[test]
fn wrong_recipient_rejected() {
    let (ctx, tx) = build(Cfg { recipient_match: false, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "χADA minted to a lock != the committed recipient must be rejected (code 28)");
}

#[test]
fn tampered_proof_rejected() {
    let (ctx, tx) = build(Cfg { tamper: true, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a tampered MKMapProof must be rejected");
}

#[test]
fn missing_checkpoint_rejected() {
    let (ctx, tx) = build(Cfg { include_checkpoint: false, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no authenticated checkpoint -> reject (code 10)");
}

#[test]
fn missing_registry_rejected() {
    let (ctx, tx) = build(Cfg { include_registry: false, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no replay-once registry insertion -> reject (code 25)");
}

#[test]
fn wrong_registry_key_rejected() {
    // the registry inserts SOME key, but not blake2b256(escrow tx body) -> the mint's binding fails (code 25).
    let (ctx, tx) = build(Cfg { registry_key_override: Some([0x99u8; 32]), ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "registry must insert THIS escrow's key, else reject (code 25)");
}

#[test]
fn stray_xada_input_rejected() {
    let (ctx, tx) = build(Cfg { stray_xada_input: true, ..Cfg::ok() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a mint tx must be mint-only (no χADA inputs) -> reject (code 18)");
}
