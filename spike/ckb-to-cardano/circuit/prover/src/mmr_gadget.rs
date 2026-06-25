//! R2: CKB ChainRootMMR membership gadget. Given a leaf HeaderDigest (120 bytes) and a proof path
//! of (sibling digest, direction, parent digest) up to the bagged root, recompute the children_hash
//! spine - parent.children_hash == ckbhash(mmr_hash(cur) || mmr_hash(sibling)) - and enforce
//! mmr_hash(root) == the checkpointed chain root. (The digests' non-children_hash fields are carried
//! witnesses; their aggregation consistency is enforced by AdvanceCKBCert, not per-leap membership.)
use ark_ff::PrimeField;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, eq::EqGadget, select::CondSelectGadget};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};
use crate::blake2b_gadget::blake2b256;

const CKB: &[u8;16] = b"ckb-default-hash";
fn mmr_hash<F: PrimeField>(d: &[UInt8<F>]) -> Result<Vec<UInt8<F>>, SynthesisError> { blake2b256(d, CKB) }

/// Recompute the chain root from `leaf` + path; enforce it equals `chain_root`. Each path step:
/// (sibling 120B digest, `cur_is_left`, parent 120B digest).
/// SEC D4: bind the FULL 120-byte parent digest - not just `children_hash[0..32]`. The parent is DERIVED
/// from (left,right) via `merge_digest` (children_hash = ckbhash(mmr_hash(l)||mmr_hash(r)),
/// total_difficulty = add256(l,r), ranges = l.start/r.end) and the witnessed parent must equal it byte-for
/// byte. So the digests' difficulty/number/epoch/timestamp/compact fields can no longer be free witnesses -
/// the whole MMR shape that hashes to `chain_root` is reconstructed in-circuit.
pub fn enforce_membership<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    leaf: &[UInt8<F>],
    path: &[(Vec<UInt8<F>>, Boolean<F>, Vec<UInt8<F>>)],
    chain_root: &[UInt8<F>],
) -> Result<(), SynthesisError> {
    let mut cur = leaf.to_vec();
    for (sib, cur_is_left, parent) in path {
        // ordered children: if cur_is_left -> (cur, sib) else (sib, cur)
        let left = sel120(cur_is_left, &cur, sib)?;
        let right = sel120(cur_is_left, sib, &cur)?;
        let derived = merge_digest(cs, &left, &right)?;          // full 120-byte parent, fully derived
        for i in 0..120 { parent[i].enforce_equal(&derived[i])?; } // bind EVERY byte (was only [0..32])
        cur = parent.clone();
    }
    let root_hash = mmr_hash(&cur)?;
    for i in 0..32 { root_hash[i].enforce_equal(&chain_root[i])?; }
    Ok(())
}
/// Public mmr_hash = ckbhash(serialize(120-byte digest)).
pub fn root_hash<F: PrimeField>(d: &[UInt8<F>]) -> Result<Vec<UInt8<F>>, SynthesisError> { mmr_hash(d) }

/// MMR-append building block: fully DERIVE the parent HeaderDigest from children l,r (no witness):
/// children_hash = ckbhash(mmr_hash(l)||mmr_hash(r)); total_difficulty = add256(l,r) (LE, proven);
/// ranges = l.start / r.end. So appending leaves yields a PROVEN new root with proven cumulative work.
pub fn merge_digest<F: PrimeField>(
    cs: &ConstraintSystemRef<F>, l: &[UInt8<F>], r: &[UInt8<F>],
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let lh = mmr_hash(l)?; let rh = mmr_hash(r)?;
    let mut cat = lh; cat.extend(rh);
    let ch = blake2b256(&cat, CKB)?;                                   // children_hash [0..32]
    let (sum, _carry) = crate::difficulty_gadget::add256(cs, &l[32..64], &r[32..64])?; // total_difficulty [32..64] LE
    let mut p = Vec::with_capacity(120);
    p.extend(ch); p.extend(sum);
    p.extend_from_slice(&l[64..72]);  p.extend_from_slice(&r[72..80]);   // start_number(l) end_number(r)
    p.extend_from_slice(&l[80..88]);  p.extend_from_slice(&r[88..96]);   // epoch
    p.extend_from_slice(&l[96..104]); p.extend_from_slice(&r[104..112]); // timestamp
    p.extend_from_slice(&l[112..116]);p.extend_from_slice(&r[116..120]); // compact_target
    Ok(p)
}

fn sel120<F: PrimeField>(c:&Boolean<F>, a:&[UInt8<F>], b:&[UInt8<F>])->Result<Vec<UInt8<F>>,SynthesisError>{
    (0..120).map(|i| UInt8::conditionally_select(c,&a[i],&b[i])).collect()
}
/// Variable-carry MMR append over a fixed array of H height slots. `pres[h]` = bit h of leaf_count,
/// `peak[h]` = the peak digest at height h (meaningful iff pres[h]). Returns (new_pres, new_peak) for
/// leaf_count+1 - the carry propagates exactly through the trailing set bits, in-circuit. General to
/// ANY chain position (vs the earlier fixed full-carry case).
pub fn append_var<F: PrimeField>(
    cs:&ConstraintSystemRef<F>, pres:&[Boolean<F>], peak:&[Vec<UInt8<F>>], leaf:&[UInt8<F>],
) -> Result<(Vec<Boolean<F>>, Vec<Vec<UInt8<F>>>), SynthesisError> {
    let h_max = pres.len();
    let mut carry = leaf.to_vec();
    let mut active = Boolean::TRUE;
    let mut new_pres = Vec::with_capacity(h_max);
    let mut new_peak = Vec::with_capacity(h_max);
    for h in 0..h_max {
        let do_merge = active.and(&pres[h])?;
        let stop_here = active.and(&pres[h].not())?;
        let merged = merge_digest(cs, &peak[h], &carry)?;          // always computed (fixed structure)
        let np = sel120(&stop_here, &carry, &peak[h])?;            // place carry where the carry stops
        let npres = pres[h].and(&do_merge.not())?.or(&stop_here)?; // consumed->false; stop->true; else keep
        carry = sel120(&do_merge, &merged, &carry)?;              // advance carry if merged
        active = do_merge;                                         // continue only while merging
        new_peak.push(np); new_pres.push(npres);
    }
    Ok((new_pres, new_peak))
}
/// Bag a height-indexed peak set into the root digest (low->high, merge(higher,acc)).
pub fn bag_var<F: PrimeField>(
    cs:&ConstraintSystemRef<F>, pres:&[Boolean<F>], peak:&[Vec<UInt8<F>>],
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let mut acc = peak[0].clone();
    let mut acc_active = Boolean::FALSE;
    for h in 0..pres.len() {
        let merged = merge_digest(cs, &peak[h], &acc)?;
        let if_present = sel120(&acc_active, &merged, &peak[h])?;  // merge onto acc, or start acc
        acc = sel120(&pres[h], &if_present, &acc)?;                // only if this slot present
        acc_active = acc_active.or(&pres[h])?;
    }
    Ok(acc)
}
