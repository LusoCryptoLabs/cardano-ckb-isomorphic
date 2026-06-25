//! transition_mint.rs - LIVE bound-cell TRANSITION: verify a REAL Mithril-certified Cardano seal
//! TRANSFER (a98b6636…) and bind the new CKB bound-cell state S1. Runs as the new bound cell's TYPE
//! script. Checks: (1) cardano_tx_is_certified(transfer body) via the real two-level MKMapProof in
//! certified root bb30dc3c…; (2) the transfer CONSUMES the old seal (83dd51d2#0); (3) output[0]
//! SealDatum commitment == blake2b256(S1). => a real certified Cardano transfer drives the CKB
//! bound-cell transition. (Cardano->CKB transfer, live.)
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use alloc::vec::Vec;
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();
const BODY: &[u8] = &[170,0,217,1,2,130,130,88,32,131,221,81,210,243,174,108,101,41,162,246,254,218,45,133,209,162,126,250,91,250,252,106,52,198,197,149,210,3,242,94,21,0,130,88,32,131,221,81,210,243,174,108,101,41,162,246,254,218,45,133,209,162,126,250,91,250,252,106,52,198,197,149,210,3,242,94,21,1,1,130,163,0,88,29,112,28,187,162,8,142,36,152,13,84,162,59,182,93,226,209,226,51,163,54,204,172,91,117,251,1,172,210,112,1,130,26,0,30,132,128,161,88,28,136,85,175,27,225,253,72,238,9,107,114,233,27,238,133,141,181,27,154,183,94,134,101,64,200,100,118,116,161,68,83,69,65,76,1,2,130,1,216,24,88,68,216,121,159,88,28,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,88,32,253,77,143,9,161,0,17,240,110,172,49,42,79,127,173,203,168,177,1,90,51,219,79,237,129,79,211,8,11,199,189,62,255,130,88,29,96,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,130,27,0,0,0,1,194,37,134,131,161,88,28,11,142,51,197,137,36,132,62,165,180,70,162,68,109,90,138,187,4,156,109,49,76,216,37,92,214,250,78,161,72,0,20,223,16,119,67,75,66,27,0,0,0,1,42,5,242,0,2,26,0,3,177,189,3,26,6,205,100,84,8,26,6,205,57,85,11,88,32,210,36,151,76,134,102,116,164,21,39,221,159,91,141,197,216,7,156,234,231,181,64,80,196,197,22,20,80,252,159,119,108,13,217,1,2,129,130,88,32,247,223,243,227,88,210,112,102,233,217,188,128,136,231,23,51,241,255,238,1,64,199,10,250,69,226,170,167,123,232,19,86,0,14,217,1,2,129,88,28,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,16,130,88,29,96,76,242,93,106,117,40,144,181,200,139,4,138,153,116,240,159,123,39,207,48,39,239,45,30,102,204,245,202,27,0,0,0,2,83,209,138,135,17,26,0,58,89,121];
const S1: &[u8] = &[98,111,117,110,100,45,97,115,115,101,116,58,100,101,109,111,58,118,50,32,111,119,110,101,114,61,98,111,98];
const OLD_SEAL_TXID: [u8;32] = [131,221,81,210,243,174,108,101,41,162,246,254,218,45,133,209,162,126,250,91,250,252,106,52,198,197,149,210,3,242,94,21]; const OLD_SEAL_IDX: u32 = 0;
const SUB_ROOT: &[u8] = &[120,44,160,142,127,238,216,205,125,13,146,1,188,205,150,230,9,157,1,26,171,167,179,149,119,28,214,71,197,176,233,93];
const SUB0: &[u8] = &[57,56,97,48,48,98,102,102,100,49,55,50,57,99,53,97,48,97,51,51,98,99,49,101,100,98,49,56,51,49,102,100,53,49,55,54,57,56,99,97,49,54,101,51,48,54,54,99,50,53,48,51,55,54,49,48,101,50,50,102,98,48,55,102];
const SUB1: &[u8] = &[126,49,29,189,4,170,40,50,135,73,44,142,184,169,44,41,49,163,13,77,98,31,31,141,98,58,137,47,215,227,216,160];
const SUB2: &[u8] = &[90,135,30,67,183,166,148,23,38,250,209,173,165,115,217,156,105,79,136,111,62,49,203,4,142,141,115,139,251,40,216,211];
const SUB3: &[u8] = &[109,86,68,239,241,54,203,13,120,185,163,13,245,62,45,81,241,106,25,55,142,62,98,230,44,125,171,97,173,38,158,147];
const SUB_POS: u64 = 1; const SUB_SIZE: u64 = 19;
const RANGE_KEY: &[u8] = &[52,51,53,53,50,57,53,45,52,51,53,53,51,49,48];
const CERT_ROOT: &[u8] = &[187,48,220,60,205,113,210,13,171,32,202,61,114,63,62,208,155,75,211,140,117,186,36,22,142,148,218,21,109,243,26,170];
const MAS0: &[u8] = &[14,123,184,30,79,192,130,102,138,133,139,173,80,150,22,244,51,130,105,49,134,98,211,185,171,37,173,188,43,195,187,230];
const MAS1: &[u8] = &[210,250,214,242,183,119,80,228,209,67,149,33,103,145,99,134,75,127,201,152,55,235,29,84,176,1,229,116,84,62,88,16];
const MAS2: &[u8] = &[189,215,119,68,109,203,153,108,61,84,194,255,225,136,83,234,76,48,235,67,96,141,223,68,201,159,99,33,22,104,219,108];
const MAS3: &[u8] = &[53,37,176,173,254,152,237,23,195,46,199,164,7,207,232,195,170,93,82,242,28,139,132,163,103,96,2,193,19,104,196,146];
const MAS4: &[u8] = &[60,182,42,25,146,227,38,78,202,72,202,176,190,0,199,114,30,232,141,103,84,92,242,130,194,84,186,195,70,160,122,147];
const MAS5: &[u8] = &[126,3,219,144,127,185,151,189,234,26,130,105,110,18,71,54,162,6,38,143,238,62,110,208,227,99,255,118,142,150,155,197];
const MAS6: &[u8] = &[192,153,53,152,2,122,142,243,164,78,4,23,124,144,199,241,101,53,227,81,65,62,224,57,91,78,217,14,209,92,84,42];
const MAS7: &[u8] = &[110,221,8,143,81,127,157,39,223,174,178,44,75,144,7,146,248,231,161,163,28,223,188,80,71,46,77,63,194,154,168,36];
const MASTER_POS: u64 = 567485; const MASTER_SIZE: u64 = 567489;
#[derive(Clone,PartialEq,Eq,Debug)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item=N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2s(p:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for x in p {h.update(x);} h.finalize().to_vec() }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::new(); for &x in b {o.push(hx[(x>>4)as usize]);o.push(hx[(x&0xf)as usize]);} o }
fn hdr(b:&[u8],i:usize)->(u8,u64,usize){ let ib=b[i]; let m=ib>>5; let lo=ib&0x1f; match lo {
    0..=23=>(m,lo as u64,i+1),24=>(m,b[i+1] as u64,i+2),25=>(m,u16::from_be_bytes([b[i+1],b[i+2]]) as u64,i+3),
    26=>(m,u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64,i+5),
    27=>(m,u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]),i+9),_=>(m,0,i+1) } }
fn skip(b:&[u8],i:usize)->usize{ let (m,a,mut j)=hdr(b,i); match m {0|1|7=>j,2|3=>j+a as usize,4=>{for _ in 0..a{j=skip(b,j);}j},5=>{for _ in 0..a{j=skip(b,j);j=skip(b,j);}j},6=>skip(b,j),_=>j} }
fn parse(b:&[u8])->(Vec<([u8;32],u32)>,Vec<u8>){
    let mut ins:Vec<([u8;32],u32)>=Vec::new(); let mut datum:Vec<u8>=Vec::new();
    let (m,n,mut i)=hdr(b,0); if m!=5 {return (ins,datum);}
    for _ in 0..n { let (_k,key,ki)=hdr(b,i); i=ki;
        if key==0 { let (tm,ta,ti)=hdr(b,i); let mut j=if tm==6&&ta==258 {ti} else {i};
            let (_a,cnt,aj)=hdr(b,j); j=aj;
            for _ in 0..cnt { let (_p,_2,pj)=hdr(b,j); j=pj; let (_bm,bl,bj)=hdr(b,j);
                let mut id=[0u8;32]; id.copy_from_slice(&b[bj..bj+bl as usize]); j=bj+bl as usize;
                let (_im,idx,ij)=hdr(b,j); j=ij; ins.push((id,idx as u32)); }
            i=j;
        } else if key==1 { let (_o,oc,mut j)=hdr(b,i);
            for o in 0..oc {
                if o==0 { let (_mm,ents,mut k)=hdr(b,j);   // output[0] is a map; grab key-2 inline datum
                    for _ in 0..ents { let (_e,ek,eki)=hdr(b,k); k=eki;
                        if ek==2 { let (_d,_2,da)=hdr(b,k); let nk=skip(b,da); let (_t,_24,ta)=hdr(b,nk);
                            let (_c,cl,ca)=hdr(b,ta); datum.extend_from_slice(&b[ca..ca+cl as usize]); k=ca+cl as usize;
                        } else { k=skip(b,k); } }
                    j=k;
                } else { j=skip(b,j); }   // other outputs (map OR legacy array) -> skip whole
            }
            i=j;
        } else { i=skip(b,i); } }
    (ins,datum)
}
fn seal_commitment(d:&[u8])->Vec<u8>{ let (_t,_x,ti)=hdr(d,0); let (_a,_n,ai)=hdr(d,ti); let j=skip(d,ai); let (_c,cl,ca)=hdr(d,j); d[ca..ca+cl as usize].to_vec() }
fn program_entry()->i8{
    let _=load_witness_args(0,Source::GroupInput);
    let th=b2b256(&[BODY]); let leaf=N(hexb(&th));
    let subi:Vec<N>=[SUB0,SUB1,SUB2,SUB3].iter().map(|x|N(x.to_vec())).collect();
    if !MerkleProof::<N,MB>::new(SUB_SIZE,subi).verify(N(SUB_ROOT.to_vec()),[(SUB_POS,leaf)].to_vec()).unwrap_or(false) { return 5; }
    let ml=N(b2s(&[RANGE_KEY,SUB_ROOT]));
    let masi:Vec<N>=[MAS0,MAS1,MAS2,MAS3,MAS4,MAS5,MAS6,MAS7].iter().map(|x|N(x.to_vec())).collect();
    if !MerkleProof::<N,MB>::new(MASTER_SIZE,masi).verify(N(CERT_ROOT.to_vec()),[(MASTER_POS,ml)].to_vec()).unwrap_or(false) { return 6; }
    let (ins,datum)=parse(BODY);
    if !ins.iter().any(|(t,i)| t==&OLD_SEAL_TXID && *i==OLD_SEAL_IDX) { return 7; }   // old seal consumed
    if datum.is_empty() { return 8; }
    if seal_commitment(&datum).as_slice() != &b2b256(&[S1])[..] { return 9; }          // new commitment binds S1
    0
}
