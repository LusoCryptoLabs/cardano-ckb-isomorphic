//! value_bind_test — PROTOTYPE for the CKB→Cardano value-binding fix (VALUE_BINDING_FIX.md §9 step 1).
//! De-risks the one technically-risky part: in-circuit, hash the FULL canonical bridge-lock tx body to its
//! CKB tx hash (proving the real outputs are in-circuit), then read the locked CAPACITY at its molecule
//! offset and bind it. This is the constraint that kills the "lock 1, mint a billion" attack.
//!
//! Differential test: build a real canonical RawTransaction (1 cell_dep, 1 input, 1 output — the rigid
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

/// Build the canonical bridge-lock RawTransaction. amount = locked capacity; recipient(28) in cell data.
fn build_canonical_tx(amount: u64, recipient: &[u8; 28]) -> Vec<u8> {
    let dep_tx = [0xDEu8; 32];
    let in_tx = [0xABu8; 32];
    let code = [0x9Bu8; 32];            // bridge release-lock code hash (placeholder)
    let arg = [0x11u8; 20];             // lock arg
    let bridge_code = [0xB1u8; 32];     // bridge_lock_v1 type code hash (placeholder)
    let bridge_arg = [0x22u8; 32];      // bridge instance id

    let version = u32(0);
    let mut dep = outpoint(&dep_tx, 0); dep.push(1u8);             // CellDep = OutPoint(36)+dep_type(1)
    let cell_deps = fixvec(&[dep]);
    let header_deps = fixvec(&[]);
    let cell_input = { let mut c = u64(0); c.extend_from_slice(&outpoint(&in_tx, 0)); c };
    let inputs = fixvec(&[cell_input]);
    let lock = table(&[code.to_vec(), vec![1u8], molbytes(&arg)]);          // Script{code, hash_type, args}
    let typ = table(&[bridge_code.to_vec(), vec![1u8], molbytes(&bridge_arg)]); // bridge_lock_v1 type
    let cell_output = table(&[u64(amount), lock, typ]);                     // CellOutput{capacity, lock, type}
    let outputs = dynvec(&[cell_output]);
    // canonical cell data = MAGIC(4) ‖ amount(16 LE) ‖ recipient(28)  = 48 bytes
    let mut data = b"BRG1".to_vec(); let mut amt16 = u64(amount); amt16.extend_from_slice(&[0u8; 8]); data.extend_from_slice(&amt16); data.extend_from_slice(recipient);
    let outputs_data = dynvec(&[molbytes(&data)]);
    table(&[version, cell_deps, header_deps, inputs, outputs, outputs_data])
}

/// Read RawTransaction field offset i from the molecule header (total(4) ‖ offsets[..]).
fn field_off(body: &[u8], i: usize) -> usize { u32::from_le_bytes(body[4 + 4 * i..8 + 4 * i].try_into().unwrap()) as usize }
/// Absolute offset of outputs[0].capacity (CellOutput is dynvec item 0 at +8; capacity is table field 0 at +16).
fn capacity_off(body: &[u8]) -> usize { field_off(body, 4) + 8 + 16 }

struct ValueBind { body: Vec<u8>, tx_hash: [u8; 32], amount: u64, cap_off: usize }
impl ConstraintSynthesizer<Fr> for ValueBind {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let body: Vec<UInt8<Fr>> = self.body.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_, _>>()?;
        // (1) body authenticity: ckbhash(full body) == the proven-confirmed tx hash (here: enforced vs constant)
        let h = blake2b256(&body, b"ckb-default-hash")?;
        for i in 0..32 { h[i].enforce_equal(&UInt8::constant(self.tx_hash[i]))?; }
        // (2) VALUE BINDING: capacity@offset (8 LE) == the committed amount (the fix). amount is the witnessed
        //     `new_state.amount`; here we enforce body[cap..cap+8] == amount bytes.
        let amt = self.amount.to_le_bytes();
        for i in 0..8 { body[self.cap_off + i].enforce_equal(&UInt8::constant(amt[i]))?; }
        Ok(())
    }
}

fn run(body: Vec<u8>, tx_hash: [u8; 32], amount: u64, cap_off: usize) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    ValueBind { body, tx_hash, amount, cap_off }.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

fn main() {
    let recipient = [0x33u8; 28];
    let amount: u64 = 100_000 * 100_000_000;          // 100,000 CKB (shannons)
    let body = build_canonical_tx(amount, &recipient);
    let tx_hash = ckbhash(&body);
    let cap_off = capacity_off(&body);

    // native cross-check: the capacity bytes really sit at cap_off
    let native_cap = u64::from_le_bytes(body[cap_off..cap_off + 8].try_into().unwrap());
    println!("body {} bytes | tx_hash {} | capacity_off {} | native capacity {}", body.len(), hex(&tx_hash), cap_off, native_cap);
    assert_eq!(native_cap, amount, "molecule capacity offset wrong");

    // (A) real body + correct amount -> circuit MUST be satisfied (proves in-circuit hash + capacity read)
    let ok = run(body.clone(), tx_hash, amount, cap_off);
    println!("[A] real body, correct amount  -> satisfied = {}  (expect true)", ok);
    assert!(ok, "circuit rejected a valid canonical tx");

    // (B) attack: same minimal lock, claim a huge amount -> circuit MUST be UNSATISFIED (the fix)
    let bad = run(body.clone(), tx_hash, 1_000_000_000u64 * 100_000_000, cap_off);
    println!("[B] real body, INFLATED amount -> satisfied = {}  (expect false)", bad);
    assert!(!bad, "VALUE-BINDING BROKEN: circuit accepted an inflated amount");

    // (C) tampered body (flip a capacity byte) but real tx_hash -> hash mismatch -> UNSATISFIED
    let mut tb = body.clone(); tb[cap_off] ^= 0xFF;
    let badc = run(tb, tx_hash, amount, cap_off);
    println!("[C] tampered body, real hash   -> satisfied = {}  (expect false)", badc);
    assert!(!badc, "body authenticity BROKEN: circuit accepted a body that doesn't hash to tx_hash");

    println!("\nVALUE-BINDING PROTOTYPE: all checks passed (real ACCEPT, inflate REJECT, tamper REJECT).");
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
