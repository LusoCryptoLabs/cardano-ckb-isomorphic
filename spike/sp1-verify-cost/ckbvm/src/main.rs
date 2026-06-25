//! sp1_hash_cost - measures the CKB-VM cost of SP1's hash primitive, **Poseidon2 over KoalaBear**, by running
//! it inside CKB-VM. This is the dominant primitive of an SP1 compressed-STARK verify, so its
//! per-permutation cost is the keystone for "can an SP1 proof be verified on-chain in CKB-VM, post-quantum,
//! in budget?" - exactly as blake2b cost was the keystone for our own Goldilocks STARK verifier.
//!
//! This is a faithful port of SP1 v6's actual permutation (the p3 'succinct' crates couldn't be compiled to
//! CKB-VM directly because they pull `rand`→`getrandom`, which won't build no_std). It reproduces:
//!   * KoalaBear field, p = 2^31 - 2^24 + 1 = 0x7f000001, in **Montgomery form** with SP1's MONTY_MU and
//!     `monty_reduce` - the real field-mul instruction mix;
//!   * the external linear layer (circ(2·M4, M4, …) via the [2 3 1 1; …] MDS-light matrix, multiplication-free);
//!   * the internal diffusion layer for width 16 (diagonal via the real monty shift table, also mul-free);
//!   * 8 full rounds (4 begin + 4 end) + 20 partial rounds, S-box x^3.
//! Only the round-constant *values* are placeholders - they have no effect on cycle count, which is fixed by
//! the rounds / width / S-box / matrices reproduced above.
#![no_std]
#![no_main]
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

// ---------------- KoalaBear field (Montgomery, exactly as p3-koala-bear) ----------------
const P: u32 = 0x7f00_0001;
const MU: u32 = 0x8100_0001; // = P^{-1} mod 2^32 (SP1's convention; avoids a carry in monty_reduce)

#[inline(always)]
fn add(a: u32, b: u32) -> u32 { let s = a + b; if s >= P { s - P } else { s } }
#[inline(always)]
fn sub(a: u32, b: u32) -> u32 { if a >= b { a - b } else { a + P - b } }
#[inline(always)]
fn neg(a: u32) -> u32 { if a == 0 { 0 } else { P - a } }
#[inline(always)]
fn dbl(a: u32) -> u32 { add(a, a) }
#[inline(always)]
fn monty_reduce(x: u64) -> u32 {
    let t = x.wrapping_mul(MU as u64) & 0xFFFF_FFFF;
    let u = t * (P as u64);
    let (x_sub_u, over) = x.overflowing_sub(u);
    let hi = (x_sub_u >> 32) as u32;
    if over { hi.wrapping_add(P) } else { hi }
}
#[inline(always)]
fn mul(a: u32, b: u32) -> u32 { monty_reduce((a as u64) * (b as u64)) }
#[inline(always)]
fn cube(a: u32) -> u32 { mul(mul(a, a), a) } // S-box, degree 3
#[inline(always)]
fn to_monty(x: u32) -> u32 { (((x as u64) << 32) % P as u64) as u32 }

const SHIFTS: [u8; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15];

// external MDS-light 4x4 ([2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]) via adds/doubles (mul-free)
#[inline(always)]
fn mat4(x: &mut [u32; 4]) {
    let t01 = add(x[0], x[1]);
    let t23 = add(x[2], x[3]);
    let t0123 = add(t01, t23);
    let t01123 = add(t0123, x[1]);
    let t01233 = add(t0123, x[3]);
    x[3] = add(t01233, dbl(x[0]));
    x[1] = add(t01123, dbl(x[2]));
    x[0] = add(t01123, t01);
    x[2] = add(t01233, t23);
}

// external linear layer for width 16: M4 on each 4-block, then the outer circulant sums
fn external_layer(s: &mut [u32; 16]) {
    let mut i = 0;
    while i < 16 {
        let mut blk = [s[i], s[i + 1], s[i + 2], s[i + 3]];
        mat4(&mut blk);
        s[i] = blk[0]; s[i + 1] = blk[1]; s[i + 2] = blk[2]; s[i + 3] = blk[3];
        i += 4;
    }
    let mut sums = [0u32; 4];
    for k in 0..4 { sums[k] = add(add(s[k], s[k + 4]), add(s[k + 8], s[k + 12])); }
    for i in 0..16 { s[i] = add(s[i], sums[i % 4]); }
}

// internal diffusion layer for width 16 (diagonal via monty shifts), exactly as p3-koala-bear
fn internal_layer(s: &mut [u32; 16]) {
    let part_sum: u64 = (1..16).map(|i| s[i] as u64).sum();
    let full_sum = part_sum + s[0] as u64;
    let s0 = part_sum + neg(s[0]) as u64;
    s[0] = monty_reduce(s0);
    for i in 1..16 {
        let si = full_sum + ((s[i] as u64) << SHIFTS[i - 1]);
        s[i] = monty_reduce(si);
    }
}

fn full_round(s: &mut [u32; 16], rc: &[u32; 16]) {
    for i in 0..16 { s[i] = add(s[i], rc[i]); }
    for i in 0..16 { s[i] = cube(s[i]); }
    external_layer(s);
}
fn partial_round(s: &mut [u32; 16], rc: u32) {
    s[0] = add(s[0], rc);
    s[0] = cube(s[0]);
    internal_layer(s);
}

/// SP1's Poseidon2-KoalaBear permutation: initial external layer, 4 full, 20 partial, 4 full.
fn permute(s: &mut [u32; 16], ext_rc: &[[u32; 16]; 8], int_rc: &[u32; 20]) {
    external_layer(s);
    for r in 0..4 { full_round(s, &ext_rc[r]); }
    for r in 0..20 { partial_round(s, int_rc[r]); }
    for r in 4..8 { full_round(s, &ext_rc[r]); }
}

#[cfg(any(feature = "perms", feature = "blake"))]
const K: usize = 1000;
#[cfg(not(any(feature = "perms", feature = "blake")))]
const K: usize = 0;

// blake2b 2-to-1 compression (64-byte input -> 32-byte digest): the Merkle compress our Goldilocks STARK
// verifier uses, measured here in the same harness for an apples-to-apples ratio against Poseidon2.
#[cfg(feature = "blake")]
fn blake_compress(input: &[u8; 64]) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).build();
    h.update(input);
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o
}

fn program_entry() -> i8 {
    // placeholder round constants (values do not affect cycle count)
    let mut ext_rc = [[0u32; 16]; 8];
    for r in 0..8 { for i in 0..16 { ext_rc[r][i] = to_monty(((r * 16 + i + 1) as u32) % P); } }
    let mut int_rc = [0u32; 20];
    for r in 0..20 { int_rc[r] = to_monty(((r + 3) as u32) % P); }

    let mut state = [0u32; 16];
    for i in 0..16 { state[i] = to_monty((i as u32) + 7); }

    #[cfg(not(feature = "blake"))]
    for _ in 0..K { permute(&mut state, &ext_rc, &int_rc); }

    #[cfg(feature = "blake")]
    {
        let mut buf = [0u8; 64];
        for _ in 0..K {
            let d = blake_compress(&buf);
            buf[0..32].copy_from_slice(&d);
            buf[32..64].copy_from_slice(&d);
            state[0] ^= d[0] as u32; // keep it live
        }
    }

    // fold the state into the exit code so the loop cannot be optimized away
    let acc = state.iter().fold(0u32, |a, &x| a ^ x);
    (acc & 0x3f) as i8
}
