//! verifier.rs - a HOST copy of the in-script Mithril certificate verifier (the exact logic of
//! spike/light-client-cell/light_client_advance.rs), but parameterized over cert inputs so the
//! differential/tamper tests can feed real fixtures AND mutated ones. Same crypto, same constructions:
//!  - compute_hash  = SHA-256 over the protocol message parts -> ascii-hex == cert.signed_message
//!  - aggregate BLS = e(Σσ, g2) == e(H(msgp, dst=""), Σmvk),  msgp = msg || avk_root
//!  - lottery       = the Phase-2 per-party SNARK target (fixed-point exp), ev<T per index
//!  - merkle        = reconstruct the avk batch-commitment root from the signer leaves
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, pairing, hash_to_curve::{HashToCurve, ExpandMsgXmd}};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use sha2::{Sha256, Digest as _};

pub fn b2b256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).build();
    for p in parts { h.update(p); } let mut o=[0u8;32]; h.finalize(&mut o); o.to_vec()
}
pub fn ev_le(msgp: &[u8], index: u64, sigma: &[u8]) -> [u8;64] {
    let mut h = blake2b_ref::Blake2bBuilder::new(64).build();
    h.update(b"map"); h.update(msgp); h.update(&index.to_le_bytes()); h.update(sigma);
    let mut o=[0u8;64]; h.finalize(&mut o); o
}

/// compute_hash: SHA-256 over the (key,value) parts; the signed_message is its ascii-hex.
pub fn compute_signed_message(parts: &[(&[u8],&[u8])]) -> Vec<u8> {
    let mut h = Sha256::new();
    for (k,v) in parts { sha2::Digest::update(&mut h, k); sha2::Digest::update(&mut h, v); }
    let digest = h.finalize();
    let hex=b"0123456789abcdef"; let mut sm=Vec::with_capacity(64);
    for i in 0..32 { sm.push(hex[(digest[i]>>4) as usize]); sm.push(hex[(digest[i]&0xf) as usize]); }
    sm
}

/// aggregate BLS verify (min-sig: sigma G1 48B, mvk G2 96B), empty DST, msgp = msg || avk_root.
pub fn aggregate_bls(sigmas: &[&[u8]], mvks: &[&[u8]], msgp: &[u8]) -> bool {
    let mut agg_sig = G1Projective::identity();
    let mut agg_mvk = G2Projective::identity();
    for s in sigmas {
        let a: [u8;48] = match (*s).try_into() { Ok(a)=>a, Err(_)=>return false };
        let p=G1Affine::from_compressed(&a); if bool::from(p.is_none()) { return false; }
        agg_sig += G1Projective::from(p.unwrap());
    }
    for v in mvks {
        let a: [u8;96] = match (*v).try_into() { Ok(a)=>a, Err(_)=>return false };
        let p=G2Affine::from_compressed(&a); if bool::from(p.is_none()) { return false; }
        agg_mvk += G2Projective::from(p.unwrap());
    }
    let h:G1Affine = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msgp, b"").into();
    pairing(&G1Affine::from(agg_sig), &G2Affine::generator()) == pairing(&h, &G2Affine::from(agg_mvk))
}

/// Phase-2 per-party SNARK-lottery target: T = 2^512 - floor(2^512 * (1-phi_f)^w).
pub fn compute_target(stake: u64, total: u64, c_num: i64, c_den: i64) -> BigInt {
    const SHIFT: u32 = 768;
    let s = BigInt::one() << SHIFT;
    let xa = BigInt::from(stake) * BigInt::from(c_num);
    let xb = BigInt::from(total) * BigInt::from(c_den);
    let mut t = s.clone(); let mut acc = s.clone(); let mut n: u64 = 0;
    loop { n+=1; t = &t*&xa; t = &t/&xb; t = &t/&BigInt::from(n);
        if t.is_zero() { break; } acc += &t; if n>400 { break; } }
    let e512 = &acc >> (SHIFT-512);
    (BigInt::one() << 512) - e512
}
/// every declared index of every party must win (ev<T), and the unique count >= k.
pub fn lottery_quorum(parties: &[(&[u64], &[u8;48], u64)], msgp: &[u8], total: u64,
                      c_num: i64, c_den: i64, k: usize) -> bool {
    let mut count=0usize;
    for (idxs, sigma, stake) in parties {
        let t = compute_target(*stake, total, c_num, c_den);
        for &i in idxs.iter() {
            let evi = BigInt::from_bytes_le(Sign::Plus, &ev_le(msgp, i, *sigma));
            if !(evi < t) { return false; }
            count += 1;
        }
    }
    count >= k
}

/// Reconstruct the avk batch-commitment root from the signer leaves + the proof vals (the in-script
/// merkle check). Returns the recomputed root.
pub fn merkle_root(leaves_in: &[&[u8]], vals_in: &[&[u8]], indices: &[usize], nr_leaves: usize) -> Vec<u8> {
    fn parent(i:usize)->usize{(i-1)/2} fn sibling(i:usize)->usize{if i%2==1{i+1}else{i-1}}
    fn npow2(n:usize)->usize{let mut p=1usize; while p<n{p<<=1;} p}
    let npo=npow2(nr_leaves); let nr_nodes=nr_leaves+npo-1;
    let mut oi: Vec<usize>=indices.iter().map(|i| i+npo-1).collect();
    let mut leaves: Vec<Vec<u8>>=leaves_in.iter().map(|l| b2b256(&[l])).collect();
    let mut vals: Vec<Vec<u8>>=vals_in.iter().map(|v| v.to_vec()).collect();
    let zero=b2b256(&[&[0u8]]); let mut idx=oi[0];
    while idx>0 {
        let mut nh:Vec<Vec<u8>>=Vec::new(); let mut ni:Vec<usize>=Vec::new(); let mut i=0; idx=parent(idx);
        while i<oi.len() {
            ni.push(parent(oi[i]));
            if oi[i]&1==0 { let h=b2b256(&[&vals[0],&leaves[i]]); nh.push(h); vals.remove(0); }
            else { let sib=sibling(oi[i]);
                if i<oi.len()-1 && oi[i+1]==sib { nh.push(b2b256(&[&leaves[i],&leaves[i+1]])); i+=1; }
                else if sib<nr_nodes { let h=b2b256(&[&leaves[i],&vals[0]]); nh.push(h); vals.remove(0); }
                else { nh.push(b2b256(&[&leaves[i],&zero])); } }
            i+=1;
        }
        leaves=nh; oi=ni;
    }
    leaves[0].clone()
}
