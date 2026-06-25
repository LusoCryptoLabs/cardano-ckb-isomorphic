//! mithril_verify_bench.rs - REAL Mithril aggregate-signature verify INSIDE CKB-VM over a
//! genuine Cardano preview certificate. min-sig BLS (sigma in G1 48B, mvk in G2 96B), EMPTY
//! DST (mithril-stm calls blst `verify(false, msg, &[], &[], ..)` - confirmed in source:
//! signature_scheme/bls_multi_signature/signature.rs). Aggregate = same-message sum of the
//! distinct signers (PoP-registered keys). Constants MSG/SIG*/MVK*/N_ELIG are emitted by
//! transcode.py from a real cert. Build into a CKB script workspace with:
//!   bls12_381 = { version="0.8", default-features=false, features=["groups","pairings","alloc","experimental"] }
//!   sha2      = { version="0.9", default-features=false }   # 0.9 to match bls12_381 0.8's digest 0.9
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)] extern crate alloc;
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, pairing,
    hash_to_curve::{HashToCurve, ExpandMsgXmd}};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();
// const MSG/SIG0/SIG1/MVK0/MVK1/N_ELIG injected by transcode.py
fn program_entry() -> i8 {
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w)=>w, Err(_)=>return 1 };
    let lock = match w.lock().to_opt() { Some(l)=>l.raw_data(), None=>return 2 };
    let mode = if lock.is_empty() {0u8} else {lock[0]};
    let s0=G1Affine::from_compressed(&SIG0); let s1=G1Affine::from_compressed(&SIG1);
    let v0=G2Affine::from_compressed(&MVK0); let v1=G2Affine::from_compressed(&MVK1);
    if bool::from(s0.is_none()|s1.is_none()|v0.is_none()|v1.is_none()) { return 5; }
    let agg_sig=G1Affine::from(G1Projective::from(s0.unwrap())+G1Projective::from(s1.unwrap()));
    let agg_mvk=G2Affine::from(G2Projective::from(v0.unwrap())+G2Projective::from(v1.unwrap()));
    let h:G1Affine=<G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(&MSG,b"").into();
    let verified = pairing(&agg_sig,&G2Affine::generator()) == pairing(&h,&agg_mvk);
    let mut acc=0u8; let mut i=0u32;
    while i<N_ELIG { let mut hr=blake2b_ref::Blake2bBuilder::new(32).build();
        hr.update(&MSG); hr.update(&i.to_le_bytes()); hr.update(&SIG0);
        let mut o=[0u8;32]; hr.finalize(&mut o); acc^=o[0]; i+=1; }
    core::hint::black_box(acc);
    if mode==1 { if verified {0} else {7} } else { core::hint::black_box(verified); 0 }
}
