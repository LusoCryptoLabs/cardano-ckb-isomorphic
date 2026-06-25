//! p3_finalize_bench.rs - PHASE 3: the LEAP-OUT finalize (the symmetric leg). Verifies, in-script
//! on REAL Mithril-certified data, that the bound cell may be DESTROYED: the certified Cardano
//! Unbind tx (6c729ea6) consumed the old seal AND did NOT recreate it at the binding_lock (the seal
//! NFT was released to a plain address). Same MKMapProof oracle as the transition; the new logic is
//! the "seal not recreated at lock" output parse. Embeds the real unbind tx body + its MKMapProof.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

#[path = "p3_data.rs"]
#[allow(dead_code)]
mod p3_data;
use p3_data::*;

#[derive(Clone, PartialEq, Eq, Debug)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item = N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2s(p:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for x in p {h.update(x);} h.finalize().to_vec() }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::new(); for &x in b {o.push(hx[(x>>4)as usize]);o.push(hx[(x&0xf)as usize]);} o }

fn hdr(b:&[u8],i:usize)->(u8,u64,usize){ let ib=b[i]; let m=ib>>5; let lo=ib&0x1f; match lo {
    0..=23=>(m,lo as u64,i+1),24=>(m,b[i+1] as u64,i+2),25=>(m,u16::from_be_bytes([b[i+1],b[i+2]]) as u64,i+3),
    26=>(m,u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64,i+5),
    27=>(m,u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]),i+9),_=>(m,0,i+1) } }
fn skip(b:&[u8],i:usize)->usize{ let (m,a,mut j)=hdr(b,i); match m {0|1|7=>j,2|3=>j+a as usize,4=>{for _ in 0..a{j=skip(b,j);}j},5=>{for _ in 0..a{j=skip(b,j);j=skip(b,j);}j},6=>skip(b,j),_=>j} }

/// inputs (txid,idx) of a Conway tx body.
fn parse_inputs(b:&[u8])->Vec<([u8;32],u32)>{
    let mut ins:Vec<([u8;32],u32)>=Vec::new();
    let (m,n,mut i)=hdr(b,0); if m!=5 {return ins;}
    for _ in 0..n { let (_k,key,ki)=hdr(b,i); i=ki;
        if key==0 { let (tm,ta,ti)=hdr(b,i); let mut j=if tm==6&&ta==258 {ti} else {i};
            let (_a,cnt,aj)=hdr(b,j); j=aj;
            for _ in 0..cnt { let (_p,_2,pj)=hdr(b,j); j=pj; let (_bm,bl,bj)=hdr(b,j);
                let mut id=[0u8;32]; id.copy_from_slice(&b[bj..bj+bl as usize]); j=bj+bl as usize;
                let (_im,idx,ij)=hdr(b,j); j=ij; ins.push((id,idx as u32)); }
            i=j;
        } else { i=skip(b,i); } }
    ins
}
/// true iff some OUTPUT carries the seal NFT (SEAL_POLICY) at the binding_lock address (LOCK_ADDR).
/// value = uint(coin) | [coin, multiasset{ policy: {asset: amt} }]. Handles Babbage-map + legacy-array outputs.
fn seal_recreated_at_lock(b:&[u8])->bool{
    let (m,n,mut i)=hdr(b,0); if m!=5 {return false;}
    for _ in 0..n { let (_k,key,ki)=hdr(b,i); i=ki;
        if key==1 { let (_o,oc,mut j)=hdr(b,i);
            for _ in 0..oc {
                let (om,oarg,ok)=hdr(b,j);
                // locate this output's address bytes + value start
                let (addr_lo, addr_hi, val_at, next);
                if om==5 { // Babbage map output {0:addr,1:value,...}
                    let mut k=ok; let mut a0=0usize; let mut a1=0usize; let mut v=0usize;
                    for _ in 0..oarg { let (_e,ek,eki)=hdr(b,k);
                        if ek==0 { let (_am,al,aa)=hdr(b,eki); a0=aa; a1=aa+al as usize; k=a1; }
                        else if ek==1 { v=eki; k=skip(b,eki); }
                        else { k=skip(b,eki); } }
                    addr_lo=a0; addr_hi=a1; val_at=v; next=k;
                } else { // legacy array [addr, value, ...]
                    let (_am,al,aa)=hdr(b,ok); let a0=aa; let a1=aa+al as usize;
                    addr_lo=a0; addr_hi=a1; val_at=a1; next=skip(b,j);
                }
                if addr_hi>addr_lo && &b[addr_lo..addr_hi]==LOCK_ADDR && val_at!=0 {
                    // value: if it's an array [coin, multiasset], scan the multiasset map for SEAL_POLICY
                    let (vm,vlen,va)=hdr(b,val_at);
                    if vm==4 && vlen>=2 { let ca=skip(b,va);            // skip coin -> multiasset map
                        let (mm,mc,mut p)=hdr(b,ca);
                        if mm==5 { for _ in 0..mc { let (_pm,pl,pa)=hdr(b,p);
                            if pl as usize==SEAL_POLICY.len() && &b[pa..pa+pl as usize]==SEAL_POLICY { return true; }
                            let after=pa+pl as usize; p=skip(b,after); } }   // skip the per-policy asset map
                    }
                }
                j=next;
            }
            i=j;
        } else { i=skip(b,i); } }
    false
}

fn mkmap_certified()->bool{
    let th=b2b256(&[F_TXBODY]); let leaf=N(hexb(&th));
    let sub_items:Vec<N>=F_SUB_ITEMS.iter().map(|x| N(x.to_vec())).collect();
    if !MerkleProof::<N,MB>::new(F_SUB_SIZE,sub_items).verify(N(F_SUB_ROOT.to_vec()),[(F_SUB_POS,leaf)].to_vec()).unwrap_or(false) { return false; }
    let master_leaf=N(b2s(&[F_RANGE_KEY,F_SUB_ROOT]));
    let master_items:Vec<N>=F_MASTER_ITEMS.iter().map(|x| N(x.to_vec())).collect();
    MerkleProof::<N,MB>::new(F_MASTER_SIZE,master_items).verify(N(F_CERT_ROOT.to_vec()),[(F_MASTER_POS,master_leaf)].to_vec()).unwrap_or(false)
}

/// FINALIZE: the certified Unbind tx is in the cert root, consumed the old seal, and did NOT recreate
/// it at the binding_lock => the bound cell may be destroyed (no output bound cell).
fn finalize_ok(body:&[u8], old_txid:&[u8], old_idx:u32)->bool{
    if !mkmap_certified() { return false; }
    let ins=parse_inputs(body);
    let mut id=[0u8;32]; id.copy_from_slice(old_txid);
    if !ins.iter().any(|(t,i)| t==&id && *i==old_idx) { return false; }  // old seal consumed
    if seal_recreated_at_lock(body) { return false; }                    // must NOT be recreated at lock
    true
}

fn program_entry()->i8{
    if finalize_ok(F_TXBODY, OLD_SEAL_TXID, OLD_SEAL_IDX) { 0 } else { 30 }
}
#[allow(dead_code)] fn main() {}
