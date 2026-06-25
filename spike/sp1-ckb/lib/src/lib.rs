//! The CKB-consensus kernel the trustless light-client proves: verify a chain of block headers - parent
//! linkage, **real Eaglesong proof-of-work** meeting the **compact-target difficulty**, and **U256 cumulative
//! work** - and output the tip hash and total difficulty (the `chain_root` / `total_difficulty` the checkpoint
//! pins). Upgraded from the earlier stand-ins to real CKB primitives:
//!   * PoW hash = **Eaglesong** (CKB's actual PoW permutation, via the upstream `eaglesong` crate).
//!   * difficulty = CKB's **compact_to_target** (Bitcoin-style nBits) with U256 targets and U256 work.
//!   * block hash = blake2b-256 with CKB's `ckb-default-hash` personalization (parent linkage).
//! (The MMR `chain_root` light-client accumulator is the remaining fidelity item; here the tip is the chain's
//! final block hash, and linkage is enforced block-to-block.)
use serde::{Deserialize, Serialize};
use blake2b_ref::Blake2bBuilder;
use eaglesong::eaglesong;
use primitive_types::U256;

/// The consensus-relevant fields of a CKB block header.
#[derive(Clone, Serialize, Deserialize)]
pub struct Header {
    pub parent_hash: [u8; 32],
    pub number: u64,
    pub compact_target: u32, // CKB compact difficulty (nBits-style)
    pub nonce: u128,
}

fn ckbhash(parts: &[&[u8]]) -> [u8; 32] {
    let mut b = Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    for p in parts { b.update(p); }
    let mut o = [0u8; 32];
    b.finalize(&mut o);
    o
}

/// The CKB block hash: blake2b-256 (ckb-default-hash) over the full header. Used for parent linkage.
pub fn block_hash(h: &Header) -> [u8; 32] {
    ckbhash(&[&h.parent_hash, &h.number.to_le_bytes(), &h.compact_target.to_le_bytes(), &h.nonce.to_le_bytes()])
}

/// The Eaglesong PoW value of a header: eaglesong(pow_hash ‖ nonce) as a big-endian U256 (must be ≤ target).
/// `pow_hash` is the blake2b of the header *without* the nonce - CKB's structure (PoW over header-hash+nonce).
pub fn pow_value(h: &Header) -> U256 {
    let pow_hash = ckbhash(&[&h.parent_hash, &h.number.to_le_bytes(), &h.compact_target.to_le_bytes()]);
    let mut input = [0u8; 48];
    input[0..32].copy_from_slice(&pow_hash);
    input[32..48].copy_from_slice(&h.nonce.to_le_bytes());
    let mut out = [0u8; 32];
    eaglesong(&input, &mut out); // CKB's real Eaglesong permutation
    U256::from_big_endian(&out)
}

/// CKB's compact_to_target (nBits-style): exponent in the top byte, mantissa in the low 24 bits.
pub fn compact_to_target(compact: u32) -> U256 {
    let exponent = compact >> 24;
    let mantissa = U256::from(compact & 0x00ff_ffff);
    if exponent <= 3 {
        mantissa >> (8 * (3 - exponent))
    } else {
        mantissa << (8 * (exponent - 3))
    }
}

/// Work contributed by one block at `target` ≈ 2^256/(target+1) - the heaviest-chain weight (U256).
pub fn work_of(target: U256) -> U256 {
    (U256::MAX / (target.saturating_add(U256::one()))).saturating_add(U256::one())
}

/// A Merkle Mountain Range over block hashes - CKB's light-client chain accumulator. `chain_root` is the
/// commitment a light client / the checkpoint pins (lets later proofs show a block is in the chain).
/// Standard MMR: append merges equal-height peaks; the root bags the peaks right-to-left.
#[derive(Default)]
pub struct Mmr {
    peaks: alloc_vec::Vec<(u32, [u8; 32])>, // (height, hash), increasing height left→right
}
mod alloc_vec { pub use std::vec::Vec; }
impl Mmr {
    pub fn append(&mut self, leaf: [u8; 32]) {
        let mut node = (0u32, leaf);
        while let Some(&(h, _)) = self.peaks.last() {
            if h != node.0 { break; }
            let (_, left) = self.peaks.pop().unwrap();
            node = (node.0 + 1, ckbhash(&[&left, &node.1])); // merge equal-height peaks
        }
        self.peaks.push(node);
    }
    /// Bag the peaks right-to-left into the chain root.
    pub fn root(&self) -> [u8; 32] {
        match self.peaks.split_last() {
            None => [0u8; 32],
            Some((&(_, last), rest)) => {
                let mut acc = last;
                for &(_, p) in rest.iter().rev() { acc = ckbhash(&[&p, &acc]); }
                acc
            }
        }
    }
}

/// The verified summary of a header chain (work + MMR root as 32 big-endian bytes - the checkpoint's fields).
#[derive(Serialize, Deserialize)]
pub struct ChainSummary {
    pub chain_root: [u8; 32], // MMR root over all block hashes (the light-client commitment)
    pub tip_hash: [u8; 32],   // the final block hash (parent-linkage anchor)
    pub total_work: [u8; 32],
    pub count: u32,
}

/// Verify a header chain: parent linkage, sequential height, **Eaglesong PoW ≤ compact target**, and U256
/// cumulative work. Returns the tip + total work, or `None` on any violation - the canonical-chain predicate.
pub fn verify_chain(genesis_parent: [u8; 32], compact_target: u32, headers: &[Header]) -> Option<ChainSummary> {
    let target = compact_to_target(compact_target);
    let w = work_of(target);
    let mut prev = genesis_parent;
    let mut total = U256::zero();
    let mut mmr = Mmr::default();
    for (i, h) in headers.iter().enumerate() {
        if h.parent_hash != prev { return None; }          // parent linkage
        if h.number != i as u64 { return None; }            // sequential height
        if h.compact_target != compact_target { return None; } // agreed difficulty
        if pow_value(h) > target { return None; }           // Eaglesong PoW meets target
        total = total.checked_add(w)?;                      // accumulate work
        let bh = block_hash(h);
        mmr.append(bh);                                     // extend the chain accumulator
        prev = bh;
    }
    let mut tw = [0u8; 32];
    total.to_big_endian(&mut tw);
    Some(ChainSummary { chain_root: mmr.root(), tip_hash: prev, total_work: tw, count: headers.len() as u32 })
}
