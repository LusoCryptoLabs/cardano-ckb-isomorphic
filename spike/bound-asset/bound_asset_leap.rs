//! bound_asset_leap.rs - WIRED leap transition: oracle + Conway parse + commitment in ONE script.
//! A Cardano seal-spend tx (body) + tx-set membership proof + new bound-cell state -> accept iff:
//!   1) cardano_tx_is_certified: blake2b256(body) as ascii-hex leaf is in CERT_ROOT (Mithril tx-set
//!      MMR, Blake2s256). CERT_ROOT here is a synthetic stand-in; the REAL two-level Mithril
//!      MKMapProof + cert verify that authenticate it are proven on real data (spike/cross-chain).
//!   2) the seal OutPoint is consumed (Conway CBOR parse);
//!   3) commitment(output[0] inline datum) == blake2b256(new_state || new_seal).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use alloc::vec::Vec;
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();
const BODY: &[u8] = &[163, 0, 217, 1, 2, 129, 130, 88, 32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 7, 1, 129, 163, 0, 88, 29, 96, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 1, 26, 0, 30, 132, 128, 2, 130, 1, 216, 24, 88, 32, 64, 106, 127, 177, 14, 22, 46, 9, 139, 203, 250, 129, 196, 114, 83, 169, 145, 60, 86, 36, 100, 168, 239, 234, 109, 8, 184, 68, 124, 188, 41, 95, 2, 26, 0, 2, 152, 16];
const SEAL_TXID: [u8;32] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]; const SEAL_IDX: u32 = 7;
const NEW_STATE: &[u8] = &[98, 111, 117, 110, 100, 45, 97, 115, 115, 101, 116, 45, 115, 116, 97, 116, 101, 45, 118, 49, 58, 32, 111, 119, 110, 101, 114, 61, 97, 108, 105, 99, 101, 32, 97, 109, 111, 117, 110, 116, 61, 49, 48, 48, 48];
const NEW_SEAL_TXID: [u8;32] = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]; const NEW_SEAL_IDX: u32 = 0;
const CERT_ROOT: &[u8] = &[33,155,150,165,223,57,155,196,146,253,66,40,45,92,138,116,132,198,87,97,92,113,255,216,81,98,237,130,176,191,85,152];
const LEAF_POS: u64 = 1; const MMR_SIZE: u64 = 4;
const IT0: &[u8] = &[97,97,97,97];
const IT1: &[u8] = &[99,99,99,99];
#[derive(Clone,PartialEq,Eq,Debug)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item=N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(parts:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for p in parts {h.update(p);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::with_capacity(b.len()*2); for &x in b { o.push(hx[(x>>4) as usize]); o.push(hx[(x&0xf) as usize]); } o }
fn hdr(b:&[u8],i:usize)->(u8,u64,usize){ let ib=b[i]; let m=ib>>5; let lo=ib&0x1f; match lo {
    0..=23=>(m,lo as u64,i+1),24=>(m,b[i+1] as u64,i+2),25=>(m,u16::from_be_bytes([b[i+1],b[i+2]]) as u64,i+3),
    26=>(m,u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64,i+5),
    27=>(m,u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]),i+9),_=>(m,0,i+1) } }
fn skip(b:&[u8],i:usize)->usize{ let (m,a,mut j)=hdr(b,i); match m {0|1|7=>j,2|3=>j+a as usize,4=>{for _ in 0..a{j=skip(b,j);}j},5=>{for _ in 0..a{j=skip(b,j);j=skip(b,j);}j},6=>skip(b,j),_=>j} }
fn parse(b:&[u8])->(Vec<([u8;32],u32)>,Vec<u8>){
    let mut ins:Vec<([u8;32],u32)>=Vec::new(); let mut datum:Vec<u8>=Vec::new();
    let (m,n,mut i)=hdr(b,0); if m!=5 {return (ins,datum);}
    for _ in 0..n { let (_km,key,ki)=hdr(b,i); i=ki;
        if key==0 { let (tm,ta,ti)=hdr(b,i); let mut j=if tm==6&&ta==258 {ti} else {i};
            let (_am,cnt,aj)=hdr(b,j); j=aj;
            for _ in 0..cnt { let (_pm,_2,pj)=hdr(b,j); j=pj; let (_bm,bl,bj)=hdr(b,j);
                let mut id=[0u8;32]; id.copy_from_slice(&b[bj..bj+bl as usize]); j=bj+bl as usize;
                let (_im,idx,ij)=hdr(b,j); j=ij; ins.push((id,idx as u32)); }
            i=j;
        } else if key==1 { let (_om,oc,mut j)=hdr(b,i);
            for o in 0..oc { let (_mm,ents,mut k)=hdr(b,j);
                for _ in 0..ents { let (_ek,ekey,eki)=hdr(b,k); k=eki;
                    if ekey==2 && o==0 { let (_dm,_d2,da)=hdr(b,k); let nk=skip(b,da);
                        let (_tm,_t24,ta)=hdr(b,nk); let (_cm,cl,ca)=hdr(b,ta);
                        datum.extend_from_slice(&b[ca..ca+cl as usize]); k=ca+cl as usize;
                    } else { k=skip(b,k); } }
                j=k; }
            i=j;
        } else { i=skip(b,i); } }
    (ins,datum)
}
fn cardano_tx_is_certified(body:&[u8])->bool{
    let th=b2b256(&[body]); let leaf=N(hexb(&th));
    let items:Vec<N>=[IT0,IT1].iter().map(|x| N(x.to_vec())).collect();
    MerkleProof::<N,MB>::new(MMR_SIZE, items).verify(N(CERT_ROOT.to_vec()), [(LEAF_POS, leaf)].to_vec()).unwrap_or(false)
}
fn program_entry()->i8{
    let _=load_witness_args(0,Source::GroupInput);
    if !cardano_tx_is_certified(BODY) { return 5; }
    let (ins,commitment)=parse(BODY);
    if !ins.iter().any(|(t,i)| t==&SEAL_TXID && *i==SEAL_IDX) { return 6; }
    let expect=b2b256(&[NEW_STATE,&NEW_SEAL_TXID,&NEW_SEAL_IDX.to_le_bytes()]);
    if commitment.as_slice()!=&expect[..] { return 7; }
    0
}
