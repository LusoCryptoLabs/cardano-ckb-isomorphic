//! pq-fri-ckbvm/bench - measure, in CKB-VM, the per-op cost of the two primitives a FRI verifier is made of:
//!   * a Merkle-node hash  (blake2b, 64B -> 32B) - the dominant FRI cost (authentication paths)
//!   * a field multiply     (Goldilocks p = 2^64 - 2^32 + 1) - the FRI folding arithmetic
//! Built one-workload-per-feature so ckb-debugger's total-cycle count attributes cleanly to one primitive.
//! `baseline` is the empty loop (subtract it for loop overhead). From these two numbers + standard FRI
//! parameters we derive the on-chain-in-CKB-VM cost of a full FRI verify (see RESULTS.md). This is the PQ
//! analogue of the "Groth16 fits Plutus at 22.7%" keystone: it shows a hash-only (post-quantum) verifier
//! fits CKB-VM's budget, where Plutus cannot host one.
#![no_std]
#![no_main]
use core::hint::black_box;
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

#[cfg(feature = "baseline")]
const N: u64 = 100_000;
#[cfg(feature = "hash")]
const N: u64 = 100_000;
#[cfg(feature = "fmul")]
const N: u64 = 1_000_000;
#[cfg(not(any(feature = "baseline", feature = "hash", feature = "fmul")))]
const N: u64 = 0;

const GP: u128 = 0xFFFF_FFFF_0000_0001; // Goldilocks prime

#[inline(always)]
fn gmul(a: u64, b: u64) -> u64 {
    // full 128-bit product reduced mod p (correctness-first; cost is what we measure)
    let prod = (a as u128) * (b as u128);
    (prod % GP) as u64
}

#[allow(unused_variables)]
fn program_entry() -> i8 {
    let mut acc: u8 = 0;

    #[cfg(feature = "baseline")]
    {
        // empty loop with a data dependency so it isn't elided
        let mut x: u64 = 0xdead_beef;
        for i in 0..N {
            x = black_box(x).wrapping_add(black_box(i));
        }
        acc = black_box(x) as u8;
    }

    #[cfg(feature = "hash")]
    {
        // chain each 32B digest into the next 64B input so the loop can't be hoisted
        let mut buf = [0u8; 64];
        let mut out = [0u8; 32];
        for i in 0..N {
            buf[0] = i as u8;
            let mut h = blake2b_ref::Blake2bBuilder::new(32).build();
            h.update(black_box(&buf));
            h.finalize(&mut out);
            buf[..32].copy_from_slice(&out);
        }
        acc = black_box(out)[0];
    }

    #[cfg(feature = "fmul")]
    {
        let mut a: u64 = 0x1234_5678_9abc_def0;
        let mut b: u64 = 0x0fed_cba9_8765_4321;
        for _ in 0..N {
            a = gmul(black_box(a), black_box(b));
            b = b.wrapping_add(1);
        }
        acc = black_box(a) as u8;
    }

    (acc & 0x7f) as i8
}
