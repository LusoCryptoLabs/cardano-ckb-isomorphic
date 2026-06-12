//! burn_math_check — ties the RETURN-leg circuit's commitment math (leap_burn_windowed.rs) to the Cosmos-side
//! contract (derive_burn_inputs / derive_inputs.mjs) NUMERICALLY, with no proving and no PoW. It recomputes the
//! burn commitment with blake2b_rs (the exact crate the circuit's b2b() uses) and ark_bls12_381 Fr (the exact
//! field reduction the public input uses) on the shared test vector, and asserts the canonical little-endian
//! scalar equals the value the contract's `binds_burn_event_to_public_inputs` test and derive_inputs.mjs emit.
//!
//!   amount=7654321, recipient=0xbb*20, seal=0x01..0x20  =>  commitment scalar (LE) ==
//!     4cff559d7f8462c9df3b7e9a43c9908e190aff5531de52d9aaee88db0729385c
//!
//!   cargo run --release --bin burn_math_check
use ark_bls12_381::Fr;
use ark_ff::{PrimeField, BigInteger};
use blake2b_rs::Blake2bBuilder;

fn b2b(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }

fn main(){
    // the shared burn vector (derive_inputs.mjs `bev` + contract test binds_burn_event_to_public_inputs).
    let amount: u128 = 7654321;
    let recip: [u8;20] = [0xbb;20];
    let seal: [u8;32] = core::array::from_fn(|i| (i as u8).wrapping_add(1));   // 01 02 .. 20

    // circuit preimage: amount(16 LE) ‖ recipient(20) ‖ seal(32)   (== derive_burn_inputs)
    let mut pre = Vec::with_capacity(16+20+32);
    pre.extend_from_slice(&amount.to_le_bytes());
    pre.extend_from_slice(&recip);
    pre.extend_from_slice(&seal);
    let comm = b2b(&pre);

    // public input #2 = LEmod(comm): read little-endian, reduce mod r, canonical 32-byte LE encoding.
    let scalar = Fr::from_le_bytes_mod_order(&comm);
    let le = scalar.into_bigint().to_bytes_le();
    let got = le.iter().map(|x| format!("{:02x}", x)).collect::<String>();

    let want = "4cff559d7f8462c9df3b7e9a43c9908e190aff5531de52d9aaee88db0729385c";
    println!("circuit blake2b256(amount16||recip20||seal32) = {}", comm.iter().map(|x|format!("{:02x}",x)).collect::<String>());
    println!("circuit public_input[2] (LEmod) = {got}");
    println!("contract/JS reference          = {want}");
    assert_eq!(got, want, "RETURN-leg circuit commitment != contract derive_burn_inputs (preimage/hash mismatch)");
    println!("MATCH: the burn circuit's commitment is byte-for-byte the contract's derive_burn_inputs.");
}
