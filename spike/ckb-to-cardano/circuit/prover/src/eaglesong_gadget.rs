//! Eaglesong R1CS gadget (ark-r1cs-std, BLS12-381 Fr) - a faithful in-circuit port of CKB's
//! Eaglesong sponge (the PoW hash, relation R1). State = 16×UInt32; per round: GF(2) bit-matrix
//! (XOR) + rotation layer + constant injection + 8× (add, rotl8, rotl24, add) ARX nonlinearity;
//! 43 rounds. Sponge: rate 256 bits, delimiter 0x06, big-endian absorb / little-endian squeeze.
//! Differential-tested against the native `eaglesong` crate (see main.rs).
use ark_ff::PrimeField;
use ark_r1cs_std::{uint32::UInt32, uint8::UInt8, ToBitsGadget};
use ark_relations::r1cs::SynthesisError;
use crate::eag_const::*;

fn rotl<F: PrimeField>(x: &UInt32<F>, n: usize) -> UInt32<F> {
    if n % 32 == 0 { x.clone() } else { x.rotr(32 - (n % 32)) }
}

fn permutation<F: PrimeField>(state: &mut [UInt32<F>; 16]) -> Result<(), SynthesisError> {
    for i in 0..NUM_ROUNDS {
        // 1) bit matrix: new[j] = XOR of state[k] for k in BIT_MATRIX_ADJ[j]
        let mut new: Vec<UInt32<F>> = Vec::with_capacity(16);
        for j in 0..16 {
            let adj = BIT_MATRIX_ADJ[j];
            let mut acc = state[adj[0]].clone();
            for &k in &adj[1..] { acc = acc.xor(&state[k])?; }
            new.push(acc);
        }
        for j in 0..16 { state[j] = new[j].clone(); }
        // 2) rotation layer: state[j] ^= rotl(state[j], C[3j+1]) ^ rotl(state[j], C[3j+2])
        for j in 0..16 {
            let r1 = rotl(&state[j], COEFFICIENTS[3*j+1] as usize);
            let r2 = rotl(&state[j], COEFFICIENTS[3*j+2] as usize);
            state[j] = state[j].xor(&r1)?.xor(&r2)?;
        }
        // 3) constant injection
        for j in 0..16 {
            state[j] = state[j].xor(&UInt32::constant(INJECTION_CONSTANTS[i*16+j]))?;
        }
        // 4) add / rotl8 / rotl24 / add  (the ARX nonlinearity)
        let mut j = 0;
        while j < 16 {
            state[j]   = UInt32::addmany(&[state[j].clone(), state[j+1].clone()])?;
            state[j]   = rotl(&state[j], 8);
            state[j+1] = rotl(&state[j+1], 24);
            state[j+1] = UInt32::addmany(&[state[j].clone(), state[j+1].clone()])?;
            j += 2;
        }
    }
    Ok(())
}

// big-endian pack of `bytes` (1..=4) into one UInt32 (mirrors the native (integer<<8)^byte loop).
fn pack_be<F: PrimeField>(bytes: &[UInt8<F>]) -> Result<UInt32<F>, SynthesisError> {
    let m = bytes.len();
    let mut bits = Vec::with_capacity(32);
    // little-endian bit order: lowest byte (last in big-endian) first
    for t in (0..m).rev() { bits.extend_from_slice(&bytes[t].to_bits_le()?); }
    while bits.len() < 32 { bits.push(ark_r1cs_std::boolean::Boolean::FALSE); }
    Ok(UInt32::from_bits_le(&bits))
}

/// Eaglesong sponge over a length-`L` input (L known at build time). Returns 32 output UInt8.
pub fn eaglesong<F: PrimeField>(input: &[UInt8<F>]) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let l = input.len();
    let rate_bytes = 32usize; // RATE/8
    let blocks = ((l + 1) * 8 + 256 - 1) / 256;
    let mut state: [UInt32<F>; 16] = core::array::from_fn(|_| UInt32::constant(0));
    let delim = UInt8::constant(DELIMITER);
    for i in 0..blocks {
        for j in 0..8 {
            // collect the bytes that the native loop would pack for this lane (k = 0..4)
            let mut packed: Vec<UInt8<F>> = Vec::new();
            for k in 0..4 {
                let p = i * rate_bytes + j * 4 + k;
                if p < l { packed.push(input[p].clone()); }
                else if p == l { packed.push(delim.clone()); }
                // p > l: nothing (no shift) - matches native
            }
            if !packed.is_empty() {
                let lane = pack_be(&packed)?;
                state[j] = state[j].xor(&lane)?;
            }
        }
        permutation(&mut state)?;
    }
    // squeeze 32 bytes: lanes 0..8, each little-endian
    let mut out = Vec::with_capacity(32);
    for j in 0..8 {
        let bits = state[j].to_bits_le();
        for k in 0..4 { out.push(UInt8::from_bits_le(&bits[k*8..k*8+8])); }
    }
    Ok(out)
}
