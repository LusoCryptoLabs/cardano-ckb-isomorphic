//! g16-ckbvm - verify the SP1 Groth16 (BN254) wrap of the composed Mithril STARK *inside CKB-VM*.
//!
//! This is the on-chain half of the optional "succinct reverse leg" (Cardano->CKB): instead of
//! verifying a full Mithril certificate directly in CKB-VM (~146M cycles), a relayer presents one
//! constant-size BN254 Groth16 proof (356 bytes) attesting the composed M1..M4 Mithril statement,
//! and CKB-VM checks it here. The verify logic is vendored from SP1's `sp1-verifier` crate
//! (Groth16 path only), so it accepts proofs produced by the SP1 SDK's `.groth16()` prover.
//!
//! Inputs are baked in via include_bytes! from the real wrap run (cert 7356eaa1):
//!   proof.bin (356B), pubvals.bin (210B), groth16_vk.bin (492B, SP1 v6 Groth16 vkey).
//! Exit 0 = proof verified; nonzero = a specific failure stage.
#![no_std]
#![no_main]

use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};
use sha2::{Digest, Sha256};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

mod atomics;

// ---- embedded real artifacts (from the SP1_WRAP=groth16 run on the real preview cert) ----
static PROOF: &[u8] = include_bytes!("../proof.bin"); // 356 = 4 vkprefix + 32 exit + 32 vkroot + 32 nonce + 256 gnark
static PUBVALS: &[u8] = include_bytes!("../pubvals.bin"); // 210 SP1 public values
static GROTH16_VK: &[u8] = include_bytes!("../groth16_vk.bin"); // 492 SP1 v6 Groth16 verifying key
// SP1 program vkey hash: 0x008a8215ff859b6c741815c584dc8247b4a8c3fd3aa856fa75876fbea02763e8
static VKEY_HASH: [u8; 32] = [
    0x00, 0x8a, 0x82, 0x15, 0xff, 0x85, 0x9b, 0x6c, 0x74, 0x18, 0x15, 0xc5, 0x84, 0xdc, 0x82, 0x47,
    0xb4, 0xa8, 0xc3, 0xfd, 0x3a, 0xa8, 0x56, 0xfa, 0x75, 0x87, 0x6f, 0xbe, 0xa0, 0x27, 0x63, 0xe8,
];

const MASK: u8 = 0b11 << 6;
const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(PartialEq)]
enum Flag {
    Positive,
    Negative,
    Infinity,
}

fn deserialize_with_flags(buf: &[u8]) -> Option<(Fq, Flag)> {
    if buf.len() != 32 {
        return None;
    }
    let m = buf[0] & MASK;
    if m == 0 {
        return None;
    }
    if m == COMPRESSED_INFINITY {
        if buf[0] & !MASK == 0 && buf[1..].iter().all(|&b| b == 0) {
            return Some((Fq::zero(), Flag::Infinity));
        }
        return None;
    }
    let mut xb = [0u8; 32];
    xb.copy_from_slice(buf);
    xb[0] &= !MASK;
    let x = Fq::from_be_bytes_mod_order(&xb).ok()?;
    let flag = if m == COMPRESSED_POSITIVE { Flag::Positive } else { Flag::Negative };
    Some((x, flag))
}

fn comp_x_to_g1(buf: &[u8]) -> Option<AffineG1> {
    let (x, m) = deserialize_with_flags(buf)?;
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x)?;
    let mut fy = y;
    if y.cmp(&neg_y) == core::cmp::Ordering::Greater {
        if m == Flag::Positive {
            fy = -y;
        }
    } else if m == Flag::Negative {
        fy = -y;
    }
    Some(AffineG1::new_unchecked(x, fy))
}

fn uncomp_g1(buf: &[u8]) -> Option<AffineG1> {
    if buf.len() != 64 {
        return None;
    }
    let x = Fq::from_slice(&buf[..32]).ok()?;
    let y = Fq::from_slice(&buf[32..]).ok()?;
    AffineG1::new(x, y).ok()
}

fn comp_x_to_g2(buf: &[u8]) -> Option<AffineG2> {
    if buf.len() != 64 {
        return None;
    }
    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]).ok()?;
    let x = Fq2::new(x0, x1);
    if flag == Flag::Infinity {
        return Some(AffineG2::zero());
    }
    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x)?;
    match flag {
        Flag::Positive => Some(AffineG2::new_unchecked(x, y)),
        Flag::Negative => Some(AffineG2::new_unchecked(x, neg_y)),
        _ => None,
    }
}

fn uncomp_g2(buf: &[u8]) -> Option<AffineG2> {
    if buf.len() != 128 {
        return None;
    }
    let x1 = Fq::from_slice(&buf[0..32]).ok()?;
    let x0 = Fq::from_slice(&buf[32..64]).ok()?;
    let y1 = Fq::from_slice(&buf[64..96]).ok()?;
    let y0 = Fq::from_slice(&buf[96..128]).ok()?;
    AffineG2::new(Fq2::new(x0, x1), Fq2::new(y0, y1)).ok()
}

struct Vk {
    alpha: AffineG1,
    k: Vec<AffineG1>,
    beta: AffineG2, // stored negated, exactly as sp1-verifier
    gamma: AffineG2,
    delta: AffineG2,
}

fn load_vk(buf: &[u8]) -> Option<Vk> {
    if buf.len() < 292 {
        return None;
    }
    let alpha = comp_x_to_g1(&buf[..32])?;
    let beta = comp_x_to_g2(&buf[64..128])?;
    let gamma = comp_x_to_g2(&buf[128..192])?;
    let delta = comp_x_to_g2(&buf[224..288])?;
    let num_k = u32::from_be_bytes([buf[288], buf[289], buf[290], buf[291]]);
    let mut k = Vec::new();
    let mut off = 292usize;
    if (buf.len() as u64) < (num_k as u64) * 32 + off as u64 {
        return None;
    }
    for _ in 0..num_k {
        k.push(comp_x_to_g1(&buf[off..off + 32])?);
        off += 32;
    }
    Some(Vk { alpha, k, beta: -beta, gamma, delta })
}

struct Pf {
    ar: AffineG1,
    krs: AffineG1,
    bs: AffineG2,
}

fn load_proof(buf: &[u8]) -> Option<Pf> {
    if buf.len() != 256 {
        return None;
    }
    let ar = uncomp_g1(&buf[..64])?;
    let bs = uncomp_g2(&buf[64..192])?;
    let krs = uncomp_g1(&buf[192..256])?;
    Some(Pf { ar, krs, bs })
}

fn prepare_inputs(vk: &Vk, public_inputs: &[Fr]) -> Option<G1> {
    if (public_inputs.len() + 1) != vk.k.len() {
        return None;
    }
    Some(
        public_inputs
            .iter()
            .zip(vk.k.iter().skip(1))
            .fold(vk.k[0], |acc, (i, b)| if *i != Fr::zero() { acc + (*b * *i) } else { acc })
            .into(),
    )
}

fn verify_alg(vk: &Vk, p: &Pf, public_inputs: &[Fr]) -> bool {
    let prepared = match prepare_inputs(vk, public_inputs) {
        Some(x) => x,
        None => return false,
    };
    pairing_batch(&[
        (-Into::<G1>::into(p.ar), p.bs.into()),
        (prepared, vk.gamma.into()),
        (p.krs.into(), vk.delta.into()),
        (vk.alpha.into(), -Into::<G2>::into(vk.beta)),
    ]) == Gt::one()
}

fn slice32(s: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(s);
    a
}

fn program_entry() -> i8 {
    // SP1 prepends the raw proof with the first 4 bytes of sha256(groth16_vk).
    let vkh = Sha256::digest(GROTH16_VK);
    if vkh[..4] != PROOF[..4] {
        return 10;
    }
    let exit_code = slice32(&PROOF[4..36]);
    let vk_root = slice32(&PROOF[36..68]);
    let proof_nonce = slice32(&PROOF[68..100]);
    let gnark = &PROOF[100..356];

    // hash_public_inputs: sha256(pubvals) with top 3 bits zeroed (fit BN254 Fr)
    let mut pd: [u8; 32] = Sha256::digest(PUBVALS).into();
    pd[0] &= 0x1F;

    // 5 Groth16 public inputs, in sp1-verifier order
    let inputs_bytes: [[u8; 32]; 5] = [VKEY_HASH, pd, exit_code, vk_root, proof_nonce];
    let mut frs: Vec<Fr> = Vec::new();
    for ib in inputs_bytes.iter() {
        match Fr::from_slice(ib) {
            Ok(f) => frs.push(f),
            Err(_) => return 11,
        }
    }

    let vk = match load_vk(GROTH16_VK) {
        Some(v) => v,
        None => return 12,
    };
    let pf = match load_proof(gnark) {
        Some(p) => p,
        None => return 13,
    };

    if verify_alg(&vk, &pf, &frs) {
        0
    } else {
        1
    }
}
