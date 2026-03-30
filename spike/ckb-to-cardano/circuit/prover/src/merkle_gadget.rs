//! Merkle membership + target-compare R1CS gadgets.
//!  - `merkle_root`: the shared mechanism for CKB's tx-CBMT (R3) and header-MMR (R2) membership — a
//!    sequence of `ckbhash(left ‖ right)` merges from a leaf up to the root, ordered by direction
//!    bits. (CBMT and MMR differ only in how the path/index is laid out; both reduce to this.)
//!  - `enforce_leq_be`: the PoW target check (R1) — enforce a 32-byte big-endian value ≤ target.
use ark_ff::PrimeField;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, ToBitsGadget, eq::EqGadget, select::CondSelectGadget};
use ark_relations::r1cs::SynthesisError;
use crate::blake2b_gadget::blake2b256;

const CKB_PERSONAL: &[u8; 16] = b"ckb-default-hash";

/// Recompute a Merkle root from `leaf` and its `path` of (sibling, leaf_is_left) steps, using
/// merge = ckbhash(left ‖ right). Returns the 32-byte root.
pub fn merkle_root<F: PrimeField>(
    leaf: &[UInt8<F>],
    path: &[(Vec<UInt8<F>>, Boolean<F>)],
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let mut cur = leaf.to_vec();
    for (sib, leaf_is_left) in path {
        // ordered concat: if leaf_is_left -> cur‖sib else sib‖cur  (byte-wise conditional select)
        let mut left = Vec::with_capacity(32);
        let mut right = Vec::with_capacity(32);
        for i in 0..32 {
            left.push(UInt8::conditionally_select(leaf_is_left, &cur[i], &sib[i])?);
            right.push(UInt8::conditionally_select(leaf_is_left, &sib[i], &cur[i])?);
        }
        let mut concat = left; concat.extend(right);
        cur = blake2b256(&concat, CKB_PERSONAL)?;
    }
    Ok(cur)
}

/// Enforce `a <= b` for two 32-byte BIG-ENDIAN values (the PoW ≤ target check). Builds `gt` over the
/// bits MSB→LSB and enforces it is false.
pub fn enforce_leq_be<F: PrimeField>(a: &[UInt8<F>], b: &[UInt8<F>]) -> Result<(), SynthesisError> {
    let mut lt = Boolean::FALSE;
    let mut gt = Boolean::FALSE;
    for i in 0..32 {
        // bits within a byte, MSB first
        let ab = a[i].to_bits_le()?; // little-endian
        let bb = b[i].to_bits_le()?;
        for k in (0..8).rev() {
            let ai = &ab[k];
            let bi = &bb[k];
            let eq_so_far = lt.or(&gt)?.not();
            let a_lt = ai.not().and(bi)?;          // 0 vs 1
            let a_gt = ai.and(&bi.not())?;         // 1 vs 0
            lt = lt.or(&eq_so_far.and(&a_lt)?)?;
            gt = gt.or(&eq_so_far.and(&a_gt)?)?;
        }
    }
    gt.enforce_equal(&Boolean::FALSE)
}

/// R3: bind a tx to a header's `transactions_root`. raw_root = merkle_root(leaf, path) (the CBMT path);
/// transactions_root = ckbhash(raw_root ‖ witnesses_root). Returns the 32-byte transactions_root.
pub fn tx_root_from_proof<F: PrimeField>(
    leaf: &[UInt8<F>],
    path: &[(Vec<UInt8<F>>, Boolean<F>)],
    witnesses_root: &[UInt8<F>],
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let raw_root = merkle_root(leaf, path)?;
    let mut concat = raw_root; concat.extend_from_slice(witnesses_root);
    blake2b256(&concat, CKB_PERSONAL)
}

/// R1 helper: decode CKB's Bitcoin-style compact target (4 bytes, little-endian as in the header)
/// into a 32-byte big-endian target. compact_le = [m0, m1, m2_raw, exp]; mantissa = m2&0x7f, m1, m0
/// placed at big-endian positions [32-exp .. 32-exp+2]. Handles a data-dependent exponent.
pub fn compact_to_target<F: PrimeField>(compact_le: &[UInt8<F>]) -> Result<Vec<UInt8<F>>, SynthesisError> {
    use ark_r1cs_std::eq::EqGadget;
    let exp = &compact_le[3];
    let m0 = compact_le[0].clone();
    let m1 = compact_le[1].clone();
    let mut b2 = compact_le[2].to_bits_le()?; b2[7] = Boolean::FALSE; // clear the sign/overflow flag
    let m2 = UInt8::from_bits_le(&b2);
    let zero = UInt8::constant(0u8);
    // SEC D7: reject HIGH-SIDE OVERFLOW (a non-canonical compact whose mantissa would exceed 2^256). The
    // mantissa bytes land at big-endian positions (32-exp, 33-exp, 34-exp) for (m2, m1, m0); a byte at a
    // NEGATIVE position has been shifted past the most-significant end. CKB flags that as overflow and
    // rejects the header. So enforce: m2==0 when exp>32, m1==0 when exp>33, m0==0 when exp>34. (Low-side
    // truncation for small exp is legitimate — that mirrors CKB's right-shift, not an overflow.)
    for (k, mb) in [(32u8, &m2), (33u8, &m1), (34u8, &m0)] {
        let over = u8_gt_const(exp, k)?;
        mb.conditional_enforce_equal(&zero, &over)?;
    }
    let mut target = vec![zero.clone(); 32];
    for pos in 0..32i32 {
        let mut cur = zero.clone();
        for (e, mb) in [(34 - pos, &m0), (33 - pos, &m1), (32 - pos, &m2)] {
            if (0..=255).contains(&e) {
                let is_e = exp.is_eq(&UInt8::constant(e as u8))?;
                cur = UInt8::conditionally_select(&is_e, mb, &cur)?;
            }
        }
        target[pos as usize] = cur;
    }
    Ok(target)
}

/// Boolean = (`exp` > `k`) for a constant `k`, via an MSB→LSB compare of `exp` against `k+1`.
fn u8_gt_const<F: PrimeField>(exp: &UInt8<F>, k: u8) -> Result<Boolean<F>, SynthesisError> {
    if k == 255 { return Ok(Boolean::FALSE); }      // exp (u8) can never exceed 255
    let kp = k + 1;                                  // exp > k  <=>  exp >= kp
    let bits = exp.to_bits_le()?;                    // LSB-first, 8 bits
    let mut gt = Boolean::FALSE;
    let mut lt = Boolean::FALSE;
    for i in (0..8).rev() {                          // MSB-first
        let ei = &bits[i];
        let eq_so_far = gt.or(&lt)?.not();
        if (kp >> i) & 1 == 1 {
            lt = lt.or(&eq_so_far.and(&ei.not())?)?; // ei vs 1: less-than if ei==0
        } else {
            gt = gt.or(&eq_so_far.and(ei)?)?;        // ei vs 0: greater-than if ei==1
        }
    }
    Ok(lt.not())                                     // exp >= kp  iff  not(exp < kp)
}
