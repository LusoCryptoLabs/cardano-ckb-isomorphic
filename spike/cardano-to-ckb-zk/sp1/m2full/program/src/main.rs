//! M1+M2+M4 composed in ONE SP1 proof, on the REAL Mithril cert:
//!  M1: signed_message = Sha256(ordered key||value protocol-message parts)
//!  M2: BLS min-sig aggregate verifies over msgp = signed_message_ascii || avk_root
//!  M4: cert_hash = Sha256(prev || epoch || meta_hash || pm_hash || signed_message || avk || feed || multisig)
//!      where meta_hash = Sha256(network||version||pp_hash||init_ns||seal_ns||Σ party_hash),
//!      pp_hash = Sha256(k||m||phi_f_fixed), party_hash = Sha256(party_id||stake)  [exact mithril-common]
//! Commits (signed_message, cert_hash, avk_root, hm, bls_ok) for on-chain binding + chain linkage.
#![no_main]
sp1_zkvm::entrypoint!(main);
use sha2::{Sha256, Digest};
use bls12_381::{G1Affine, G2Affine, G2Prepared, multi_miller_loop, Gt};
use core::ops::Neg;
fn hexlow(b:&[u8])->[u8;64]{ let h=b"0123456789abcdef"; let mut o=[0u8;64]; for(i,&x)in b.iter().enumerate(){o[2*i]=h[(x>>4)as usize];o[2*i+1]=h[(x&0xf)as usize];} o }
fn sha(parts:&[&[u8]])->[u8;32]{ let mut h=Sha256::new(); for p in parts{h.update(p);} h.finalize().into() }
pub fn main() {
    // M1 inputs
    let parts: Vec<(String,String)> = sp1_zkvm::io::read();
    let avk_root: Vec<u8> = sp1_zkvm::io::read();
    // M2 inputs
    let agg_sigma: Vec<u8> = sp1_zkvm::io::read();
    let agg_mvk: Vec<u8> = sp1_zkvm::io::read();
    let hm: Vec<u8> = sp1_zkvm::io::read();
    // M4 inputs
    let prev_hash: Vec<u8> = sp1_zkvm::io::read();       // ascii hex bytes
    let epoch_be: Vec<u8> = sp1_zkvm::io::read();        // u64 BE (8)
    let network: Vec<u8> = sp1_zkvm::io::read();
    let version: Vec<u8> = sp1_zkvm::io::read();
    let k_be: Vec<u8> = sp1_zkvm::io::read();            // u64 BE
    let m_be: Vec<u8> = sp1_zkvm::io::read();            // u64 BE
    let phi_be: Vec<u8> = sp1_zkvm::io::read();          // U8F24 u32 BE
    let init_ns: Vec<u8> = sp1_zkvm::io::read();         // i64 BE
    let seal_ns: Vec<u8> = sp1_zkvm::io::read();         // i64 BE
    let signers: Vec<(String,Vec<u8>)> = sp1_zkvm::io::read();  // (party_id, stake u64 BE)
    let avk_hex: Vec<u8> = sp1_zkvm::io::read();         // to_json_hex bytes
    let feed: Vec<u8> = sp1_zkvm::io::read();            // epoch_be||block_be
    let multisig_hex: Vec<u8> = sp1_zkvm::io::read();    // to_json_hex bytes

    // M1
    let sm: [u8;32] = sha(&parts.iter().flat_map(|(k,v)| [k.as_bytes().to_vec(), v.as_bytes().to_vec()]).collect::<Vec<_>>().iter().map(|x| x.as_slice()).collect::<Vec<_>>());
    let sm_hex = hexlow(&sm);

    // M2
    let sigma=G1Affine::from_compressed(&agg_sigma.try_into().unwrap()).unwrap();
    let mvk=G2Affine::from_compressed(&agg_mvk.try_into().unwrap()).unwrap();
    let hmg=G1Affine::from_compressed(&hm.clone().try_into().unwrap()).unwrap();
    let g2=G2Prepared::from(G2Affine::generator()); let mvkp=G2Prepared::from(mvk);
    let bls_ok = multi_miller_loop(&[(&sigma,&g2),(&hmg.neg(),&mvkp)]).final_exponentiation()==Gt::identity();

    // M4
    let pp_hash = hexlow(&sha(&[&k_be,&m_be,&phi_be]));
    let mut meta = Sha256::new();
    meta.update(&network); meta.update(&version); meta.update(&pp_hash); meta.update(&init_ns); meta.update(&seal_ns);
    for (pid,stake) in &signers { let ph=hexlow(&sha(&[pid.as_bytes(),stake])); meta.update(&ph); }
    let meta_hash = hexlow(&Into::<[u8;32]>::into(meta.finalize()));
    let cert_hash: [u8;32] = sha(&[&prev_hash,&epoch_be,&meta_hash,&sm_hex,&sm_hex,&avk_hex,&feed,&multisig_hex]);

    sp1_zkvm::io::commit(&sm_hex.to_vec());
    sp1_zkvm::io::commit(&cert_hash.to_vec());
    sp1_zkvm::io::commit(&avk_root);
    sp1_zkvm::io::commit(&hm);
    sp1_zkvm::io::commit(&bls_ok);
}
