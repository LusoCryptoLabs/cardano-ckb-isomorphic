//! value_bind_test - PROTOTYPE for the CKB→Cardano value-binding fix (VALUE_BINDING_FIX.md §9 step 1).
//! De-risks the one technically-risky part: in-circuit, hash the FULL canonical bridge-lock tx body to its
//! CKB tx hash (proving the real outputs are in-circuit), then read the locked CAPACITY at its molecule
//! offset and bind it. This is the constraint that kills the "lock 1, mint a billion" attack.
//!
//! Differential test: build a real canonical RawTransaction (1 cell_dep, 1 input, 1 output - the rigid
//! template the bridge_lock_v1 type script will enforce), hash it natively, and check the circuit (a)
//! recomputes the same tx hash from the body and (b) binds body[CAP_OFF..]==amount. Then assert the negative
//! (wrong amount => unsatisfiable). Run: cargo run --release --bin value_bind_test
use ark_bls12_381::Fr;
use ark_r1cs_std::{uint8::UInt8, alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use blake2b_rs::Blake2bBuilder;
use ckb_consensus_circuit::blake2b_gadget::blake2b256;

fn ckbhash(d: &[u8]) -> [u8; 32] { let mut h = Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o = [0u8; 32]; h.finalize(&mut o); o }

// ---- minimal molecule builders (mirror relayer/ckb_lock.py) ----
fn u32(n: u32) -> Vec<u8> { n.to_le_bytes().to_vec() }
fn u64(n: u64) -> Vec<u8> { n.to_le_bytes().to_vec() }
fn fixvec(items: &[Vec<u8>]) -> Vec<u8> { let mut o = u32(items.len() as u32); for it in items { o.extend_from_slice(it); } o }
fn dynvec(items: &[Vec<u8>]) -> Vec<u8> {
    let n = items.len();
    let total: usize = 4 + 4 * n + items.iter().map(|i| i.len()).sum::<usize>();
    let mut o = u32(total as u32);
    let mut p = 4 + 4 * n;
    for it in items { o.extend_from_slice(&u32(p as u32)); p += it.len(); }
    for it in items { o.extend_from_slice(it); }
    o
}
fn table(fields: &[Vec<u8>]) -> Vec<u8> { dynvec(fields) }
fn molbytes(b: &[u8]) -> Vec<u8> { let mut o = u32(b.len() as u32); o.extend_from_slice(b); o }
fn outpoint(txh: &[u8; 32], idx: u32) -> Vec<u8> { let mut o = txh.to_vec(); o.extend_from_slice(&u32(idx)); o }

// bridge_lock_v1 type code hash the circuit pins (placeholder; the real deploy hash is baked at build).
const BRIDGE_CODE_HASH: [u8; 32] = [0xB1u8; 32];

/// Build the canonical bridge-RECEIPT RawTransaction (the rigid template bridge_lock_v1 enforces): 1 cell_dep,
/// 1 input, receipt at output[0] with lock(20-byte arg) + type=bridge_lock_v1(32-byte arg), and outputs_data[0]
/// = the 49-byte receipt MAGIC‖kind‖amount‖recipient.
fn build_canonical_tx(amount: u128, recipient: &[u8; 28], bridge_code: &[u8; 32]) -> Vec<u8> {
    let dep_tx = [0xDEu8; 32]; let in_tx = [0xABu8; 32];
    let lock_code = [0x9Bu8; 32]; let lock_arg = [0x11u8; 20]; let bridge_arg = [0x22u8; 32];
    let version = u32(0);
    let mut dep = outpoint(&dep_tx, 0); dep.push(1u8);
    let cell_deps = fixvec(&[dep]);
    let header_deps = fixvec(&[]);
    let cell_input = { let mut c = u64(0); c.extend_from_slice(&outpoint(&in_tx, 0)); c };
    let inputs = fixvec(&[cell_input]);
    let lock = table(&[lock_code.to_vec(), vec![1u8], molbytes(&lock_arg)]);       // Script (20-byte args)
    let typ = table(&[bridge_code.to_vec(), vec![1u8], molbytes(&bridge_arg)]);    // bridge_lock_v1 (32-byte args)
    let cell_output = table(&[u64(amount as u64), lock, typ]);
    let outputs = dynvec(&[cell_output]);
    let mut data = b"BRG1".to_vec(); data.push(0u8); data.extend_from_slice(&amount.to_le_bytes()); data.extend_from_slice(recipient); // 49 B
    let outputs_data = dynvec(&[molbytes(&data)]);
    table(&[version, cell_deps, header_deps, inputs, outputs, outputs_data])
}

/// Read RawTransaction field offset i from the molecule header (total(4) ‖ offsets[..]).
fn field_off(body: &[u8], i: usize) -> usize { u32::from_le_bytes(body[4 + 4 * i..8 + 4 * i].try_into().unwrap()) as usize }
fn cellout_off(body: &[u8]) -> usize { field_off(body, 4) + 8 }            // outputs[0] (CellOutput) absolute offset
fn type_off(body: &[u8]) -> usize { let co = cellout_off(body); co + field_off(&body[co..], 2) } // CellOutput.type
fn type_code_off(body: &[u8]) -> usize { let t = type_off(body); t + field_off(&body[t..], 0) } // type Script.code_hash
fn data_off(body: &[u8]) -> usize { field_off(body, 5) + 8 + 4 }           // outputs_data[0] content (after dynvec hdr + molbytes len)

// the FULL receipt reader: body authenticity + type==BRIDGE + amount/recipient bound from the receipt data.
struct ReceiptBind { body: Vec<u8>, tx_hash: [u8; 32], amount: u128, recipient: [u8; 28],
                     type_code_off: usize, amount_off: usize, recip_off: usize }
impl ConstraintSynthesizer<Fr> for ReceiptBind {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let body: Vec<UInt8<Fr>> = self.body.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_, _>>()?;
        // (1) body authenticity: ckbhash(full body) == the proven-confirmed tx hash
        let h = blake2b256(&body, b"ckb-default-hash")?;
        for i in 0..32 { h[i].enforce_equal(&UInt8::constant(self.tx_hash[i]))?; }
        // (2) the receipt output carries bridge_lock_v1 (its type Script code_hash == the pinned constant)
        for i in 0..32 { body[self.type_code_off + i].enforce_equal(&UInt8::constant(BRIDGE_CODE_HASH[i]))?; }
        // (3) VALUE BINDING: new_state.amount/recipient == the receipt's declared amount(16 LE)/recipient(28)
        let amt = self.amount.to_le_bytes();
        for i in 0..16 { body[self.amount_off + i].enforce_equal(&UInt8::constant(amt[i]))?; }
        for i in 0..28 { body[self.recip_off + i].enforce_equal(&UInt8::constant(self.recipient[i]))?; }
        Ok(())
    }
}
fn run(body: Vec<u8>, tx_hash: [u8; 32], amount: u128, recipient: [u8; 28], toff: usize, aoff: usize, roff: usize) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    ReceiptBind { body, tx_hash, amount, recipient, type_code_off: toff, amount_off: aoff, recip_off: roff }.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

fn main() {
    let recipient = [0x33u8; 28];
    let amount: u128 = 100_000 * 100_000_000;
    let body = build_canonical_tx(amount, &recipient, &BRIDGE_CODE_HASH);
    let tx_hash = ckbhash(&body);
    let (toff, aoff, roff) = (type_code_off(&body), data_off(&body) + 5, data_off(&body) + 21);  // amount after MAGIC(4)+kind(1); recipient after +16
    println!("body {} bytes | tx_hash {} | type_code_off {} amount_off {} recip_off {}", body.len(), hex(&tx_hash), toff, aoff, roff);
    // native cross-checks
    assert_eq!(&body[toff..toff + 32], &BRIDGE_CODE_HASH[..], "type code_hash offset wrong");
    assert_eq!(u128::from_le_bytes(body[aoff..aoff + 16].try_into().unwrap()), amount, "amount offset wrong");
    assert_eq!(&body[roff..roff + 28], &recipient[..], "recipient offset wrong");

    // (A) real receipt: type==bridge + amount/recipient match -> SATISFIED
    let ok = run(body.clone(), tx_hash, amount, recipient, toff, aoff, roff);
    println!("[A] real receipt, correct amount+recipient -> satisfied = {}  (expect true)", ok);
    assert!(ok, "circuit rejected a valid canonical receipt tx");

    // (B) the inflate attack: claim a huge amount the receipt doesn't carry -> UNSATISFIED (the fix)
    let bad = run(body.clone(), tx_hash, 1_000_000_000u128 * 100_000_000, recipient, toff, aoff, roff);
    println!("[B] INFLATED amount                        -> satisfied = {}  (expect false)", bad);
    assert!(!bad, "VALUE-BINDING BROKEN: accepted an inflated amount");

    // (C) the redirect attack: claim a different recipient -> UNSATISFIED (recipient binding, B1-equivalent)
    let badr = run(body.clone(), tx_hash, amount, [0x44u8; 28], toff, aoff, roff);
    println!("[C] REDIRECTED recipient                   -> satisfied = {}  (expect false)", badr);
    assert!(!badr, "RECIPIENT-BINDING BROKEN: accepted a substituted recipient");

    // (D) wrong type: a receipt whose type isn't bridge_lock_v1 -> UNSATISFIED (didn't run the bridge script)
    let body2 = build_canonical_tx(amount, &recipient, &[0xCCu8; 32]);    // non-bridge type code hash
    let tx_hash2 = ckbhash(&body2);
    let badt = run(body2, tx_hash2, amount, recipient, toff, aoff, roff);
    println!("[D] non-bridge type code hash              -> satisfied = {}  (expect false)", badt);
    assert!(!badt, "TYPE-BINDING BROKEN: accepted a non-bridge receipt");

    // (E) tampered body but real tx_hash -> body authenticity rejects
    let mut tb = body.clone(); tb[aoff] ^= 0xFF;
    let bade = run(tb, tx_hash, amount, recipient, toff, aoff, roff);
    println!("[E] tampered body, real hash               -> satisfied = {}  (expect false)", bade);
    assert!(!bade, "body authenticity BROKEN");

    println!("\nVALUE-BINDING GADGET (full receipt): all checks passed - real ACCEPT; inflate/redirect/wrong-type/tamper all REJECT.");
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
