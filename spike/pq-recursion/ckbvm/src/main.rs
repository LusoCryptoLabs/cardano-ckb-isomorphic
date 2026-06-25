//! poseidon2_goldilocks - measures, in CKB-VM, the cost of a **recursion-friendly** hash: Poseidon2 over
//! Goldilocks (width 8, S-box x^7, 8 full + 22 partial rounds, à la Plonky3). This is the primitive that
//! makes STARK recursion possible: verifying a STARK inside another STARK means re-hashing in-circuit, and a
//! permutation built from field operations (Poseidon2) is arithmetizable as AIR constraints, whereas blake2b
//! (bit/ARX) is not. So our on-chain verifier's blake2b is ideal as a *native* op but hostile to recursion;
//! Poseidon2-Goldilocks is the converse. This measures what that recursion-friendly hash costs natively, to
//! ground the recursion cost model in RECURSION.md. (Round constants are placeholders - irrelevant to cycle
//! count, which is fixed by rounds/width/S-box/matrices.)
#![no_std]
#![no_main]
use fri_core::{add, sub, mul};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

const WIDTH: usize = 8;
const RF: usize = 8;   // full rounds (4 begin + 4 end)
const RP: usize = 22;  // partial rounds

#[inline(always)]
fn sbox(x: u64) -> u64 { // x^7 (Goldilocks Poseidon2 S-box; gcd(7, p-1)=1)
    let x2 = mul(x, x);
    let x3 = mul(x2, x);
    let x4 = mul(x2, x2);
    mul(x4, x3)
}

// external MDS-light 4x4 (the [2 3 1 1; …] matrix) via adds/doubles - multiplication-free
#[inline(always)]
fn mat4(x: &mut [u64; 4]) {
    let t01 = add(x[0], x[1]);
    let t23 = add(x[2], x[3]);
    let t0123 = add(t01, t23);
    let t01123 = add(t0123, x[1]);
    let t01233 = add(t0123, x[3]);
    x[3] = add(t01233, add(x[0], x[0]));
    x[1] = add(t01123, add(x[2], x[2]));
    x[0] = add(t01123, t01);
    x[2] = add(t01233, t23);
}
// external linear layer (width 8 = two 4-blocks + circulant sums)
fn external(s: &mut [u64; WIDTH]) {
    let mut i = 0;
    while i < WIDTH {
        let mut b = [s[i], s[i + 1], s[i + 2], s[i + 3]];
        mat4(&mut b);
        s[i] = b[0]; s[i + 1] = b[1]; s[i + 2] = b[2]; s[i + 3] = b[3];
        i += 4;
    }
    let mut sums = [0u64; 4];
    for k in 0..4 { sums[k] = add(s[k], s[k + 4]); }
    for i in 0..WIDTH { s[i] = add(s[i], sums[i % 4]); }
}
// internal diffusion (width 8): state[i] = state[i]*diag[i] + sum - real field muls (Goldilocks, not
// Monty-shift-optimized), so 8 muls/round. diag are placeholder constants (cost-identical).
const DIAG: [u64; WIDTH] = [2, 3, 5, 7, 11, 13, 17, 19];
fn internal(s: &mut [u64; WIDTH]) {
    let mut sum = 0u64;
    for i in 0..WIDTH { sum = add(sum, s[i]); }
    for i in 0..WIDTH { s[i] = add(mul(s[i], DIAG[i]), sum); }
}

fn permute(s: &mut [u64; WIDTH], rc_f: &[[u64; WIDTH]; RF], rc_p: &[u64; RP]) {
    external(s);
    for r in 0..RF / 2 {
        for i in 0..WIDTH { s[i] = sbox(add(s[i], rc_f[r][i])); }
        external(s);
    }
    for r in 0..RP {
        s[0] = sbox(add(s[0], rc_p[r]));
        internal(s);
    }
    for r in RF / 2..RF {
        for i in 0..WIDTH { s[i] = sbox(add(s[i], rc_f[r][i])); }
        external(s);
    }
}

#[cfg(feature = "perms")]
const K: usize = 1000;
#[cfg(not(feature = "perms"))]
const K: usize = 0;

fn program_entry() -> i8 {
    let mut rc_f = [[0u64; WIDTH]; RF];
    for r in 0..RF { for i in 0..WIDTH { rc_f[r][i] = (r * WIDTH + i + 1) as u64; } }
    let mut rc_p = [0u64; RP];
    for r in 0..RP { rc_p[r] = (r + 3) as u64; }
    let mut s = [0u64; WIDTH];
    for i in 0..WIDTH { s[i] = (i as u64) + 7; }
    for _ in 0..K { permute(&mut s, &rc_f, &rc_p); }
    let acc = s.iter().fold(0u64, |a, &x| a ^ x);
    (acc & 0x3f) as i8
}
