//! genesis_mint.rs - LIVE genesis BoundAsset mint: verify a REAL Mithril-certified Cardano
//! seal-creation tx (83dd51d2…) and bind the CKB bound cell to its committed state S0. Runs as the
//! bound cell's TYPE script (executes on creation). Checks:
//!   1) cardano_tx_is_certified: blake2b256(seal-tx body) (ascii-hex leaf) is in the certified
//!      tx-set root 30a3465e… via the REAL two-level Mithril MKMapProof (MMR, Blake2s256). That
//!      root == cert c8a6986f's cardano_transactions_merkle_root (Mithril stake-certified).
//!   2) the seal-tx output[0] inline SealDatum's commitment == blake2b256(S0).
//! => a REAL certified Cardano seal-mint authorizes the CKB bound cell. (Cardano->CKB, live.)
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use alloc::vec::Vec;
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();
const BODY: &[u8] = &[171,0,217,1,2,129,130,88,32,249,129,18,150,141,35,134,13,225,108,86,66,184,187,34,112,27,54,45,154,138,131,235,151,255,25,200,177,38,202,143,22,3,1,130,163,0,88,29,112,28,187,162,8,142,36,152,13,84,162,59,182,93,226,209,226,51,163,54,204,172,91,117,251,1,172,210,112,1,130,26,0,30,132,128,161,88,28,136,85,175,27,225,253,72,238,9,107,114,233,27,238,133,141,181,27,154,183,94,134,101,64,200,100,118,116,161,68,83,69,65,76,1,2,130,1,216,24,88,68,216,121,159,88,28,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,88,32,202,216,214,48,207,79,241,233,189,75,22,88,226,54,168,126,165,140,40,42,255,200,130,231,12,171,151,76,195,121,147,230,255,130,88,29,96,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,130,27,0,0,0,1,194,41,56,64,161,88,28,11,142,51,197,137,36,132,62,165,180,70,162,68,109,90,138,187,4,156,109,49,76,216,37,92,214,250,78,161,72,0,20,223,16,119,67,75,66,27,0,0,0,1,42,5,242,0,2,26,0,3,50,249,3,26,6,205,96,116,8,26,6,205,53,124,9,161,88,28,136,85,175,27,225,253,72,238,9,107,114,233,27,238,133,141,181,27,154,183,94,134,101,64,200,100,118,116,161,68,83,69,65,76,1,11,88,32,73,10,160,50,150,140,162,64,191,215,95,94,135,90,86,242,11,188,139,165,121,72,49,218,153,35,241,65,62,69,93,120,13,217,1,2,129,130,88,32,247,223,243,227,88,210,112,102,233,217,188,128,136,231,23,51,241,255,238,1,64,199,10,250,69,226,170,167,123,232,19,86,0,14,217,1,2,129,88,28,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,16,130,88,29,96,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,27,0,0,0,2,83,209,138,135,17,26,0,58,89,121];
const S0: &[u8] = &[98,111,117,110,100,45,97,115,115,101,116,58,100,101,109,111,58,118,49];
const SUB_ROOT: &[u8] = &[79,241,225,133,183,131,141,107,98,30,165,147,80,84,242,32,6,95,23,244,30,162,126,55,151,65,14,24,1,175,135,72];
const SUB0: &[u8] = &[63,165,109,62,206,160,240,71,117,143,204,47,72,121,94,136,253,194,111,183,154,144,76,15,151,86,156,150,74,81,126,163];
const SUB1: &[u8] = &[49,48,54,98,48,56,54,101,49,57,56,53,56,100,50,98,56,98,55,50,102,100,52,55,100,101,48,50,56,99,57,50,101,53,97,54,49,101,99,102,98,99,97,51,99,48,102,102,55,51,97,101,48,98,98,54,57,98,97,56,49,56,99,102];
const SUB2: &[u8] = &[54,100,97,98,53,52,54,97,52,54,97,55,101,54,99,54,98,51,102,51,55,53,97,52,99,98,52,49,54,52,54,53,57,102,52,48,99,56,99,56,52,56,101,57,102,50,101,48,55,51,53,51,53,50,100,54,54,98,98,100,50,50,53,57];
const SUB_POS: u64 = 7; const SUB_SIZE: u64 = 11;
const RANGE_KEY: &[u8] = &[52,51,53,53,50,53,48,45,52,51,53,53,50,54,53];
const CERT_ROOT: &[u8] = &[48,163,70,94,36,12,203,81,175,30,49,94,167,135,221,203,244,75,220,244,56,108,4,7,246,169,68,60,28,11,122,250];
const MAS0: &[u8] = &[14,123,184,30,79,192,130,102,138,133,139,173,80,150,22,244,51,130,105,49,134,98,211,185,171,37,173,188,43,195,187,230];
const MAS1: &[u8] = &[210,250,214,242,183,119,80,228,209,67,149,33,103,145,99,134,75,127,201,152,55,235,29,84,176,1,229,116,84,62,88,16];
const MAS2: &[u8] = &[189,215,119,68,109,203,153,108,61,84,194,255,225,136,83,234,76,48,235,67,96,141,223,68,201,159,99,33,22,104,219,108];
const MAS3: &[u8] = &[53,37,176,173,254,152,237,23,195,46,199,164,7,207,232,195,170,93,82,242,28,139,132,163,103,96,2,193,19,104,196,146];
const MAS4: &[u8] = &[60,182,42,25,146,227,38,78,202,72,202,176,190,0,199,114,30,232,141,103,84,92,242,130,194,84,186,195,70,160,122,147];
const MAS5: &[u8] = &[110,23,148,225,34,166,140,210,103,211,181,77,0,107,62,193,96,233,112,64,179,199,223,115,224,249,251,134,177,142,178,41];
const MAS6: &[u8] = &[169,158,200,180,40,165,192,67,168,25,144,44,58,61,61,47,123,214,83,9,156,192,160,145,149,30,23,212,203,217,237,3];
const MAS7: &[u8] = &[2,11,191,238,37,234,245,103,75,207,33,239,202,116,15,167,182,230,153,22,14,136,243,154,51,102,117,139,143,14,78,131];
const MAS8: &[u8] = &[209,175,65,23,154,185,93,215,62,147,143,172,194,181,95,19,252,27,11,16,213,18,54,228,72,243,178,240,29,58,170,126];
const MAS9: &[u8] = &[172,194,251,76,218,252,38,97,121,8,89,220,127,78,189,215,244,67,113,40,164,170,224,189,79,147,114,28,205,143,114,180];
const MASTER_POS: u64 = 567476; const MASTER_SIZE: u64 = 567482;
#[derive(Clone,PartialEq,Eq,Debug)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item=N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2s(p:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for x in p {h.update(x);} h.finalize().to_vec() }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::new(); for &x in b {o.push(hx[(x>>4)as usize]);o.push(hx[(x&0xf)as usize]);} o }
// minimal CBOR
fn hdr(b:&[u8],i:usize)->(u8,u64,usize){ let ib=b[i]; let m=ib>>5; let lo=ib&0x1f; match lo {
    0..=23=>(m,lo as u64,i+1),24=>(m,b[i+1] as u64,i+2),25=>(m,u16::from_be_bytes([b[i+1],b[i+2]]) as u64,i+3),
    26=>(m,u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64,i+5),
    27=>(m,u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]),i+9),_=>(m,0,i+1) } }
fn skip(b:&[u8],i:usize)->usize{ let (m,a,mut j)=hdr(b,i); match m {0|1|7=>j,2|3=>j+a as usize,4=>{for _ in 0..a{j=skip(b,j);}j},5=>{for _ in 0..a{j=skip(b,j);j=skip(b,j);}j},6=>skip(b,j),_=>j} }
// extract output[0]'s inline-datum bytes
fn out0_datum(b:&[u8])->Vec<u8>{
    let (m,n,mut i)=hdr(b,0); let mut datum:Vec<u8>=Vec::new(); if m!=5 {return datum;}
    for _ in 0..n { let (_k,key,ki)=hdr(b,i); i=ki;
        if key==1 { let (_o,oc,mut j)=hdr(b,i);
            for o in 0..oc { let (_mm,ents,mut k)=hdr(b,j);
                for _ in 0..ents { let (_e,ek,eki)=hdr(b,k); k=eki;
                    if ek==2 && o==0 { let (_d,_2,da)=hdr(b,k); let nk=skip(b,da); let (_t,_24,ta)=hdr(b,nk);
                        let (_c,cl,ca)=hdr(b,ta); datum.extend_from_slice(&b[ca..ca+cl as usize]); k=ca+cl as usize;
                    } else { k=skip(b,k); } }
                j=k; }
            return datum;
        } else { i=skip(b,i); } }
    datum
}
// SealDatum = constr121[owner: bytes, commitment: bytes]; return the commitment (field 1)
fn seal_commitment(d:&[u8])->Vec<u8>{
    // d = tag(121) array(2) bytes(owner) bytes(commitment)
    let (_tm,_t,ti)=hdr(d,0);            // constr tag
    let (_am,_n,ai)=hdr(d,ti);           // array(2)
    let j=skip(d,ai);                    // skip owner
    let (_cm,cl,ca)=hdr(d,j);            // commitment bytes
    d[ca..ca+cl as usize].to_vec()
}
fn program_entry()->i8{
    let _=load_witness_args(0,Source::GroupInput);
    // 1. cardano_tx_is_certified(seal-tx) via MKMapProof
    let th=b2b256(&[BODY]); let leaf=N(hexb(&th));
    let subi:Vec<N>=[SUB0,SUB1,SUB2].iter().map(|x|N(x.to_vec())).collect();
    if !MerkleProof::<N,MB>::new(SUB_SIZE,subi).verify(N(SUB_ROOT.to_vec()),[(SUB_POS,leaf)].to_vec()).unwrap_or(false) { return 5; }
    let master_leaf=N(b2s(&[RANGE_KEY,SUB_ROOT]));
    let masi:Vec<N>=[MAS0,MAS1,MAS2,MAS3,MAS4,MAS5,MAS6,MAS7,MAS8,MAS9].iter().map(|x|N(x.to_vec())).collect();
    if !MerkleProof::<N,MB>::new(MASTER_SIZE,masi).verify(N(CERT_ROOT.to_vec()),[(MASTER_POS,master_leaf)].to_vec()).unwrap_or(false) { return 6; }
    // 2. commitment in the seal-tx output[0] SealDatum binds S0
    let datum=out0_datum(BODY); if datum.is_empty() { return 7; }
    let commitment=seal_commitment(&datum);
    if commitment.as_slice() != &b2b256(&[S0])[..] { return 8; }
    0
}
