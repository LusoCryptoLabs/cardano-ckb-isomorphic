//! Blake2b-256 R1CS gadget (ark-r1cs-std, BLS12-381 Fr) - the most-reused CKB primitive: `ckbhash`
//! (Blake2b-256 personalized "ckb-default-hash") and the Merkle merges in the header-MMR (R2) and
//! tx-CBMT (R3). State = UInt64; the G mixing function = 64-bit add (addmany) + xor + rotr; 12 rounds.
//! Supports a custom 16-byte personalization (for ckbhash). Differential-tested vs the native
//! `blake2b-rs` with the same personalization (see main.rs).
use ark_ff::PrimeField;
use ark_r1cs_std::{uint64::UInt64, uint8::UInt8, ToBitsGadget};
use ark_relations::r1cs::SynthesisError;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];
const SIGMA: [[usize; 16]; 12] = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
    [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
    [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
    [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
    [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
];

fn add3<F: PrimeField>(a:&UInt64<F>,b:&UInt64<F>,c:&UInt64<F>)->Result<UInt64<F>,SynthesisError>{ UInt64::addmany(&[a.clone(),b.clone(),c.clone()]) }

#[allow(clippy::too_many_arguments)]
fn g<F: PrimeField>(v:&mut [UInt64<F>;16], a:usize,b:usize,c:usize,d:usize, x:&UInt64<F>, y:&UInt64<F>) -> Result<(),SynthesisError> {
    v[a] = add3(&v[a],&v[b],x)?;
    v[d] = v[d].xor(&v[a])?.rotr(32);
    v[c] = UInt64::addmany(&[v[c].clone(), v[d].clone()])?;
    v[b] = v[b].xor(&v[c])?.rotr(24);
    v[a] = add3(&v[a],&v[b],y)?;
    v[d] = v[d].xor(&v[a])?.rotr(16);
    v[c] = UInt64::addmany(&[v[c].clone(), v[d].clone()])?;
    v[b] = v[b].xor(&v[c])?.rotr(63);
    Ok(())
}

fn compress<F: PrimeField>(h:&mut [UInt64<F>;8], m:&[UInt64<F>;16], t:u128, last:bool) -> Result<(),SynthesisError> {
    let mut v: [UInt64<F>;16] = core::array::from_fn(|i| if i<8 { h[i].clone() } else { UInt64::constant(IV[i-8]) });
    v[12] = v[12].xor(&UInt64::constant(t as u64))?;
    v[13] = v[13].xor(&UInt64::constant((t>>64) as u64))?;
    if last { v[14] = v[14].xor(&UInt64::constant(u64::MAX))?; }
    for r in 0..12 {
        let s = &SIGMA[r];
        g(&mut v,0,4,8,12,&m[s[0]],&m[s[1]])?;
        g(&mut v,1,5,9,13,&m[s[2]],&m[s[3]])?;
        g(&mut v,2,6,10,14,&m[s[4]],&m[s[5]])?;
        g(&mut v,3,7,11,15,&m[s[6]],&m[s[7]])?;
        g(&mut v,0,5,10,15,&m[s[8]],&m[s[9]])?;
        g(&mut v,1,6,11,12,&m[s[10]],&m[s[11]])?;
        g(&mut v,2,7,8,13,&m[s[12]],&m[s[13]])?;
        g(&mut v,3,4,9,14,&m[s[14]],&m[s[15]])?;
    }
    for i in 0..8 { h[i] = h[i].xor(&v[i])?.xor(&v[i+8])?; }
    Ok(())
}

/// Blake2b-256 with a 16-byte personalization (ckbhash uses "ckb-default-hash"). Output 32 UInt8.
pub fn blake2b256<F: PrimeField>(input: &[UInt8<F>], personal: &[u8; 16]) -> Result<Vec<UInt8<F>>, SynthesisError> {
    // parameter block: digest_len=32, key=0 -> h[0] ^= 0x0101_0020; personalization -> h[6],h[7]
    let mut h: [UInt64<F>;8] = core::array::from_fn(|i| UInt64::constant(IV[i]));
    h[0] = h[0].xor(&UInt64::constant(0x0101_0020))?;
    h[6] = h[6].xor(&UInt64::constant(u64::from_le_bytes(personal[0..8].try_into().unwrap())))?;
    h[7] = h[7].xor(&UInt64::constant(u64::from_le_bytes(personal[8..16].try_into().unwrap())))?;

    let l = input.len();
    let nblocks = if l == 0 { 1 } else { (l + 127) / 128 };
    for bi in 0..nblocks {
        // assemble 16 LE u64 words from 128 input bytes (zero-padded)
        let mut m: [UInt64<F>;16] = core::array::from_fn(|_| UInt64::constant(0));
        for w in 0..16 {
            let mut bits = Vec::with_capacity(64);
            for byte in 0..8 {
                let p = bi*128 + w*8 + byte;
                if p < l { bits.extend_from_slice(&input[p].to_bits_le()?); }
                else { for _ in 0..8 { bits.push(ark_r1cs_std::boolean::Boolean::FALSE); } }
            }
            m[w] = UInt64::from_bits_le(&bits);
        }
        let last = bi == nblocks - 1;
        let t: u128 = if last { l as u128 } else { ((bi+1)*128) as u128 };
        compress(&mut h, &m, t, last)?;
    }
    // output first 32 bytes = h[0..4] little-endian
    let mut out = Vec::with_capacity(32);
    for i in 0..4 {
        let bits = h[i].to_bits_le();
        for k in 0..8 { out.push(UInt8::from_bits_le(&bits[k*8..k*8+8])); }
    }
    Ok(out)
}
