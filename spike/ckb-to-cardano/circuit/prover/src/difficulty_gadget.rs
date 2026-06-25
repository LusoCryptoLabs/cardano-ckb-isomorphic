//! Difficulty gadgets for AdvanceCKBCert (trustless cumulative work):
//!  - add256: enforced 256-bit add (LE), returns (sum, carry).
//!  - mul256: enforced 256x256 -> 512 multiply (LE), witness-and-verify (schoolbook columns + carry).
//!  - difficulty_verify: enforce diff == floor((2^256-1)/target), i.e. diff*target <= MAX < (diff+1)*target.
//! These let the advance circuit bind each header's work to its target and sum it honestly, so the
//! on-chain heaviest-chain check (advance_ckbcert.ak) is meaningful.
use ark_ff::PrimeField;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, fields::fp::FpVar, fields::FieldVar, alloc::AllocVar, eq::EqGadget, R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};

fn byte_fp<F: PrimeField>(u:&UInt8<F>)->Result<FpVar<F>,SynthesisError>{
    let mut acc=FpVar::<F>::zero(); let mut c=F::one();
    for bit in u.to_bits_le()? { acc += FpVar::from(bit)*c; c.double_in_place(); }
    Ok(acc)
}
fn val<F:PrimeField>(u:&UInt8<F>)->u8{ u.value().unwrap_or_default() }

/// enforced LE add of two 32-byte numbers -> (sum[32], carry_out bit)
pub fn add256<F:PrimeField>(cs:&ConstraintSystemRef<F>, a:&[UInt8<F>], b:&[UInt8<F>])->Result<(Vec<UInt8<F>>,Boolean<F>),SynthesisError>{
    let mut sum=Vec::with_capacity(32); let mut carry=FpVar::<F>::zero();
    let mut carry_val=0u16;
    let two56=F::from(256u64);
    for i in 0..32 {
        let t = byte_fp(&a[i])? + byte_fp(&b[i])? + &carry;
        let tv = a[i].value().unwrap_or_default() as u16 + b[i].value().unwrap_or_default() as u16 + carry_val;
        let s = UInt8::new_witness(cs.clone(), || Ok((tv & 0xff) as u8))?;
        let nc = (tv >> 8) as u8; // 0 or 1
        let ncb = Boolean::new_witness(cs.clone(), || Ok(nc==1))?;
        // enforce t == s + 256*carry_next
        (byte_fp(&s)? + FpVar::from(ncb.clone())*two56.clone()).enforce_equal(&t)?;
        sum.push(s); carry = FpVar::from(ncb.clone()); carry_val = nc as u16;
    }
    let carry_bit = Boolean::new_witness(cs.clone(), || Ok(carry_val==1))?;
    carry.enforce_equal(&FpVar::from(carry_bit.clone()))?;
    Ok((sum, carry_bit))
}

/// enforced LE 256x256 -> 512 multiply (witness the 64-byte product, verify columns with carry).
pub fn mul256<F:PrimeField>(cs:&ConstraintSystemRef<F>, a:&[UInt8<F>], b:&[UInt8<F>])->Result<Vec<UInt8<F>>,SynthesisError>{
    // compute product bytes natively for the witness
    let av:Vec<u16>=a.iter().map(|u| val(u) as u16).collect();
    let bv:Vec<u16>=b.iter().map(|u| val(u) as u16).collect();
    let mut prod=[0u32;64];
    for i in 0..32 { for j in 0..32 { prod[i+j]+= (av[i]*bv[j]) as u32; } }
    // carry-propagate natively to get the witnessed bytes
    let mut out=[0u8;64]; let mut carry=0u32;
    for k in 0..64 { let t=prod[k]+carry; out[k]=(t&0xff) as u8; carry=t>>8; }
    let outv:Vec<UInt8<F>>=(0..64).map(|k| UInt8::new_witness(cs.clone(),||Ok(out[k]))).collect::<Result<_,_>>()?;
    // verify columns: for each k, Σ_{i+j=k} a_i*b_j + carry_in == out_k + 256*carry_out
    let mut carry=FpVar::<F>::zero(); let mut carry_native=0u32;
    let two56=F::from(256u64);
    for k in 0..64 {
        let mut s=carry.clone();
        for i in 0..32 { let j=k as i32 - i as i32; if j>=0 && j<32 { s += byte_fp(&a[i])? * byte_fp(&b[j as usize])?; } }
        let tnat = prod[k]+carry_native; let cnat=tnat>>8;
        let co = FpVar::new_witness(cs.clone(), || Ok(F::from(cnat as u64)))?;
        (byte_fp(&outv[k])? + &co*two56.clone()).enforce_equal(&s)?;
        // range-check carry_out < 2^20 (a column sum is < 32·255² + carry ≈ 2^21, so carry < 2^13; 2^20 is a
        // safe over-bound that keeps the (out_k, co) decomposition unique - no field wraparound).
        let co_bits = co.to_bits_le()?; for bit in co_bits.iter().skip(20) { bit.enforce_equal(&Boolean::FALSE)?; }
        carry=co; carry_native=cnat;
    }
    // SEC D8: the product of two 256-bit values is < 2^512 = 64 bytes, so the carry OUT of the last column
    // MUST be zero. Enforcing it makes mul256 a complete, non-truncating 512-bit product on its own (callers
    // no longer have to assume the high limb didn't silently overflow).
    carry.enforce_equal(&FpVar::<F>::zero())?;
    Ok(outv)
}

/// enforce diff == floor((2^256-1)/target), with target,diff given big-endian (32B each).
pub fn difficulty_verify<F:PrimeField>(cs:&ConstraintSystemRef<F>, target_be:&[UInt8<F>], diff_be:&[UInt8<F>])->Result<(),SynthesisError>{
    let rev=|v:&[UInt8<F>]| { let mut r=v.to_vec(); r.reverse(); r };
    let t=rev(target_be); let d=rev(diff_be);
    let p = mul256(cs,&d,&t)?;                        // P = diff*target (LE, 64B)
    // P <= MAX = 2^256-1  <=>  high 256 bits are zero
    for k in 32..64 { p[k].enforce_equal(&UInt8::constant(0))?; }
    // P + target >= 2^256  <=>  carry out of (P_low + target)
    let (_s, carry) = add256(cs, &p[0..32], &t)?;
    carry.enforce_equal(&Boolean::TRUE)?;
    Ok(())
}
