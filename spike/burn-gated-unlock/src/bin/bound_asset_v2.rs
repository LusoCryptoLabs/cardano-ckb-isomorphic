//! bound_asset_v2.rs - v2 ownership-toggle BoundAsset type script (docs/LEAP_BRIEF_V2.md +
//! docs/RECIPIENT_COMMITMENT.md). DISJOINT DEPLOYMENT: a NEW code_hash deployed ALONGSIDE the immutable v1
//! `bound_asset_unified_ours` (0x42f74fbc). v1 cells never run this script (version byte + new code_hash).
//!
//! v2 cell data = version(1)=0x02 ‖ tag(1) ‖ seal_txid(32) ‖ seal_idx(u32 LE) ‖ lock_slot(32) ‖ state.
//! tag ∈ { CARDANO_BOUND=0x01, CKB_OWNED=0x02 } is the PRIMARY dispatch key (closes B2). Five legal shapes:
//!   S1 GENESIS  (∅ -> CkbOwned)        S2 TRANSITION (CkbOwned -> CkbOwned)   S3 FINALIZE (CkbOwned -> ∅)
//!   S4 LEAP_TO_CARDANO (CkbOwned -> CardanoBound)   S5 LEAP_TO_CKB (CardanoBound -> CkbOwned)
//! S5 is the dangerous direction: a permissionless relayer builds the CKB tx, so the surviving cell's ACTUAL
//! lock is pinned (load_cell_lock_hash, B3) to the owner-signed, Mithril-certified recipient committed via
//! RC = blake2b256(state ‖ SOURCE seal ‖ recipient_lock_hash) (closes B1).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)] extern crate alloc;   // host test build: default_alloc!() (which links alloc) is cfg(not(test))-gated
use alloc::vec::Vec;
use ckb_std::{ckb_constants::Source, high_level::{load_witness_args, load_cell_data, load_cell_type, load_cell_type_hash, load_cell_lock_hash, load_script}};
use ckb_std::ckb_types::prelude::*;   // RQ-8: Byte32/Byte::as_slice on Script.code_hash()/hash_type()
// SEC A1: the ONLY trusted checkpoint is one carrying the TxSetCert verifier's type script (cert-verified
// in-VM). Same authenticated checkpoint as v1 (cv_deploy type-hash 0x855231b3).
// Deploy/test-time parameterization of the two "set at deploy" type hashes (default = production value).
const fn hexv(c:u8)->u8{ match c { b'0'..=b'9'=>c-b'0', b'a'..=b'f'=>c-b'a'+10, b'A'..=b'F'=>c-b'A'+10, _=>0 } }
const fn hex32(s:&str)->[u8;32]{ let b=s.as_bytes(); let off=if b.len()>=2 && b[0]==b'0' && (b[1]==b'x'||b[1]==b'X') {2} else {0}; let mut o=[0u8;32]; let mut i=0; while i<32 { o[i]=(hexv(b[off+2*i])<<4)|hexv(b[off+2*i+1]); i+=1; } o }
const LCKP_TYPE_HASH: [u8;32] = match option_env!("CHIRAL_LCKP_TH") {
    Some(h) => hex32(h),
    None => [133,82,49,179,57,175,212,62,166,215,227,196,181,212,68,27,38,60,90,54,42,71,159,85,234,239,130,153,203,135,121,185],
};
// B4/F2: the ONE canonical leap seal-outpoint nullifier registry. Its type hash is the genesis type-id of the
// singleton registry deployed alongside v2 (burn_nullifier_registry pattern). HARDCODED - never a script arg -
// so no bound cell can point the nullifier check at a parallel/empty registry. **SET AT DEPLOY** from the
// canonical registry genesis type-id (mirrors LCKP_TYPE_HASH).
const LEAP_REGISTRY_TYPE_HASH: [u8;32] = match option_env!("CHIRAL_REG_TH") {
    Some(h) => hex32(h),
    None => [0u8;32],   // PLACEHOLDER - bake the canonical registry genesis type-id here (or pass CHIRAL_REG_TH)
};
const CARDANO_BOUND: u8 = 0x01;
const CKB_OWNED: u8 = 0x02;
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

#[derive(Clone,PartialEq,Eq,Debug)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item=N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2s(p:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for x in p {h.update(x);} h.finalize().to_vec() }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::new(); for &x in b {o.push(hx[(x>>4)as usize]);o.push(hx[(x&0xf)as usize]);} o }
struct R<'a>{ b:&'a[u8], i:usize }
impl<'a> R<'a>{
    fn u32(&mut self)->usize{ if self.i+4>self.b.len(){ self.i=self.b.len(); return 0; } let v=u32::from_le_bytes([self.b[self.i],self.b[self.i+1],self.b[self.i+2],self.b[self.i+3]]) as usize; self.i+=4; v }
    fn u64(&mut self)->u64{ if self.i+8>self.b.len(){ self.i=self.b.len(); return 0; } let mut a=[0u8;8]; a.copy_from_slice(&self.b[self.i..self.i+8]); self.i+=8; u64::from_le_bytes(a) }
    fn lp(&mut self)->&'a[u8]{ let n=self.u32(); if self.i+n>self.b.len(){ self.i=self.b.len(); return &[]; } let s=&self.b[self.i..self.i+n]; self.i+=n; s }
    fn items(&mut self)->Vec<N>{ let n=self.u32(); if n>self.b.len(){ return Vec::new(); } (0..n).map(|_| N(self.lp().to_vec())).collect() }
}
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
            for o in 0..oc { let (om,oarg,ok)=hdr(b,j);
                if om==5 { let ents=oarg; let mut k=ok;
                    for _ in 0..ents { let (_e,ek,eki)=hdr(b,k); k=eki;
                        if ek==2 && o==0 { let (_d,_2,da)=hdr(b,k); let nk=skip(b,da); let (_t,_24,ta)=hdr(b,nk);
                            let (_c,cl,ca)=hdr(b,ta); datum.extend_from_slice(&b[ca..ca+cl as usize]); k=ca+cl as usize;
                        } else { k=skip(b,k); } }
                    j=k;
                } else { j=skip(b,j); } }
            i=j;
        } else { i=skip(b,i); } }
    (ins,datum)
}
// field 1 of the Constr SealDatum/LeapSealDatum = commitment (works for 2- or 3-field datums).
fn seal_commitment(d:&[u8])->Vec<u8>{ let (_t,_x,ti)=hdr(d,0); let (_a,_n,ai)=hdr(d,ti); let j=skip(d,ai); let (_c,cl,ca)=hdr(d,j); d[ca..ca+cl as usize].to_vec() }
// RECIPIENT_COMMITMENT.md §4.1: field 2 of LeapSealDatum = recipient_lock_hash (bounds-checked, fail-closed).
fn seal_recipient(d:&[u8])->Vec<u8>{
    let (_t,_x,ti)=hdr(d,0); let (_a,_n,ai)=hdr(d,ti);
    let j0=skip(d,ai);            // skip field 0 (owner)
    let j1=skip(d,j0);           // skip field 1 (commitment)
    let (_c,cl,ca)=hdr(d,j1);    // field 2 = recipient bytes
    if ca + cl as usize > d.len() { return Vec::new(); }
    d[ca..ca+cl as usize].to_vec()
}

const A3_MAX_DEPTH: usize = 64;
fn ohdr(b:&[u8], i:usize) -> Option<(u8,u64,usize)> {
    let ib = *b.get(i)?; let m = ib>>5; let lo = ib&0x1f;
    match lo {
        0..=23 => Some((m, lo as u64, i+1)),
        24 => { if i+1>=b.len(){return None;} Some((m, b[i+1] as u64, i+2)) }
        25 => { if i+2>=b.len(){return None;} Some((m, u16::from_be_bytes([b[i+1],b[i+2]]) as u64, i+3)) }
        26 => { if i+4>=b.len(){return None;} Some((m, u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64, i+5)) }
        27 => { if i+8>=b.len(){return None;} Some((m, u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]), i+9)) }
        _ => None,
    }
}
fn oskip(b:&[u8], i:usize, depth:usize) -> Option<usize> {
    if depth > A3_MAX_DEPTH { return None; }
    let (m,a,j)=ohdr(b,i)?;
    match m {
        0|1|7 => Some(j),
        2|3 => { let e=j.checked_add(a as usize)?; if e>b.len(){None}else{Some(e)} }
        4 => { let mut k=j; for _ in 0..a { k=oskip(b,k,depth+1)?; } Some(k) }
        5 => { let mut k=j; for _ in 0..a { k=oskip(b,k,depth+1)?; k=oskip(b,k,depth+1)?; } Some(k) }
        6 => oskip(b,j,depth+1),
        _ => None,
    }
}
fn val_has_policy(b:&[u8], va:usize, seal_policy:&[u8]) -> Option<bool> {
    let (vm,vlen,vj)=ohdr(b,va)?;
    if vm==0 { return Some(false); }
    if vm!=4 || vlen<2 { return None; }
    let ca = oskip(b,vj,0)?;
    let (mm,mc,mut p)=ohdr(b,ca)?;
    if mm!=5 { return None; }
    for _ in 0..mc {
        let (pm,pl,pa)=ohdr(b,p)?;
        if pm!=2 { return None; }
        let pend = pa.checked_add(pl as usize)?; if pend>b.len() { return None; }
        let is_seal = pl as usize==seal_policy.len() && &b[pa..pend]==seal_policy;
        let after = oskip(b,pend,0)?;
        if is_seal { return Some(true); }
        p = after;
    }
    Some(false)
}
fn seal_at_lock(b:&[u8], lock_addr:&[u8], seal_policy:&[u8]) -> Option<bool> {
    let (m,n,mut i)=ohdr(b,0)?;
    if m!=5 { return None; }
    for _ in 0..n {
        let (km,key,ki)=ohdr(b,i)?;
        if km!=0 { return None; }
        if key==1 {
            let (om,oc,oj)=ohdr(b,ki)?;
            if om!=4 { return None; }
            let mut j=oj; let mut found=false;
            for _ in 0..oc {
                let (otm,oarg,oi2)=ohdr(b,j)?;
                let (addr_lo,addr_hi,val_at,next);
                if otm==5 {
                    let mut k=oi2; let (mut a0,mut a1,mut v)=(0usize,0usize,0usize);
                    for _ in 0..oarg {
                        let (_em,ek,eki)=ohdr(b,k)?;
                        if ek==0 { let (am,al,aa)=ohdr(b,eki)?; if am!=2 {return None;}
                            let e=aa.checked_add(al as usize)?; if e>b.len(){return None;} a0=aa; a1=e; k=e; }
                        else if ek==1 { v=eki; k=oskip(b,eki,0)?; }
                        else { k=oskip(b,eki,0)?; }
                    }
                    addr_lo=a0; addr_hi=a1; val_at=v; next=k;
                } else if otm==4 {
                    if oarg<2 { return None; }
                    let (am,al,aa)=ohdr(b,oi2)?; if am!=2 {return None;}
                    let e=aa.checked_add(al as usize)?; if e>b.len(){return None;}
                    addr_lo=aa; addr_hi=e; val_at=e; next=oskip(b,j,0)?;
                } else { return None; }
                if addr_hi>addr_lo && addr_hi<=b.len() && &b[addr_lo..addr_hi]==lock_addr && val_at!=0 {
                    if val_has_policy(b,val_at,seal_policy)? { found=true; }
                }
                j=next;
            }
            return Some(found);
        } else { i=oskip(b,ki,0)?; }
    }
    None
}

// SEC M2: the LCKP checkpoint is "LCKP" ‖ tx_root(32) ‖ latest_block_number(8 LE) - the AUTHENTICATED Cardano
// finalized height the (upgraded) cert-verify publishes from the signed cert. Returns (root, height).
// RQ-4 hardening: the canonical checkpoint is a TYPE-ID SINGLETON, so at most one LIVE cell carries
// LCKP_TYPE_HASH and a leap can only reference the latest snapshot. Defense-in-depth: scan ALL cell-deps and
// fail closed if two trusted checkpoints DISAGREE - never silently pick a stale root from a smuggled-in dep.
fn checkpoint_root()->Result<(Vec<u8>, u64), i8>{
    let mut found: Option<(Vec<u8>, u64)> = None;
    let mut i=0usize;
    loop {
        // Check the cheap 32-byte type hash FIRST and only load the cell's data when it is a trusted
        // checkpoint. Loading every cell-dep's data here would OOM the script heap: a lock dep_group expands
        // into its referenced cells, and the secp256k1_data cell is 1 MiB -- load_cell_data on it aborts.
        match load_cell_type_hash(i, Source::CellDep) {
            Ok(Some(th)) if th==LCKP_TYPE_HASH => {
                if let Ok(d)=load_cell_data(i, Source::CellDep) {
                    if d.len()>=44 && &d[0..4]==b"LCKP" {
                        let mut hb=[0u8;8]; hb.copy_from_slice(&d[36..44]);
                        let cur=(d[4..36].to_vec(), u64::from_le_bytes(hb));
                        match &found {
                            Some(prev) if *prev != cur => return Err(53),   // RQ-4: conflicting checkpoints -> fail closed
                            Some(_) => {}                                    // exact-duplicate dep -> harmless
                            None => found = Some(cur),
                        }
                    }
                }
                i+=1;
            }
            Ok(_)=>{ i+=1; }            // no type / non-checkpoint type -> skip WITHOUT loading data
            Err(_)=>break,
        }
        if i>64 { break; }
    }
    found.ok_or(1)   // no trusted checkpoint present at all
}

// v2 cell tag check: version 0x02, tag ∈ {CARDANO_BOUND, CKB_OWNED}, min length 70.
fn tag_of(d:&[u8])->Result<u8,i8>{
    if d.len()<70 { return Err(7); }
    if d[0]!=0x02 { return Err(43); }                       // version gate keeps v1 cells out
    let t=d[1];
    if t!=CARDANO_BOUND && t!=CKB_OWNED { return Err(44); }
    Ok(t)
}
// RQ-8: serialize leaps across instances. Exactly one bound_asset_v2 cell (ANY per-instance args) may appear
// among the tx's inputs, and one among its outputs. Instances are identified by CODE hash (shared across all
// args) so this spans every type group. Forbidding the batch at the verifier closes the cross-type-group
// same-seal vector (two groups nullifying one Cardano seal via a single registry insert) - the deploy-time
// choice over a batch-aware registry (docs/LEAP_BRIEF_V2.md §10, RQ-8). Unrelated cells are ignored (only our
// own code counts), so legitimate co-occurring protocols are never griefed.
fn count_instances(source: Source, my_code:&[u8], my_ht:u8)->usize{
    let mut c=0usize; let mut i=0usize;
    loop {
        match load_cell_type(i, source) {
            Ok(Some(s))=>{ if s.code_hash().as_slice()==my_code && s.hash_type().as_slice()[0]==my_ht { c+=1; } i+=1; }
            Ok(None)=>{ i+=1; }
            Err(_)=>break,
        }
    }
    c
}
// Invariant LS (B3/F6): every produced CkbOwned cell's lock slot must equal its ACTUAL on-chain lock, and the
// actual lock must not be the well-known anyone-can-spend (all-zero) hash.
fn ls_pin(out:&[u8])->Result<(),i8>{
    let actual=match load_cell_lock_hash(0, Source::GroupOutput){ Ok(h)=>h, Err(_)=>return Err(45) };
    if actual==[0u8;32] { return Err(45); }                 // reject anyone-can-spend lock
    if actual[..] != out[38..70] { return Err(45); }
    Ok(())
}
// B4 (F2/F3): nullify the consumed SOURCE Cardano seal outpoint exactly once, in the ONE canonical registry
// (hardcoded type hash), keyed by the CERTIFIED (txid,idx). Single-key consumer (the same-tx cross-group batch
// is RQ-8). Mirrors burn_gated_unlock_v2::registry_inserts_key.
fn seal_nullifier_inserts(src_txid:&[u8], src_idx:u32)->bool{
    let idxb=src_idx.to_le_bytes();
    // SEC (domain separation): 1-byte leg tag (0x03 = χCKB-leap seal nullifier); keyspace disjoint from the
    // χADA-mint (0x01) and CKB-release (0x02) legs sharing this registry. Off-chain: reg_nullifier_witness.py.
    let key=b2b256(&[&[0x03u8], src_txid, &idxb[..]]);
    let mut i=0usize;
    loop {
        match load_cell_type_hash(i, Source::Input) {
            Ok(Some(th)) if th==LEAP_REGISTRY_TYPE_HASH => {
                if let Ok(w)=load_witness_args(i, Source::Input) {
                    if let Some(b)=w.input_type().to_opt() {
                        let d=b.raw_data();
                        return d.len()>=32 && &d[0..32]==&key[..];
                    }
                }
                return false;
            }
            Ok(_)=>{ i+=1; }
            Err(_)=>return false,                           // registry not spent in this tx -> fail closed
        }
    }
}

// ---- the five legal-shape branches ----
fn genesis(out:&[u8], th:&[u8;32], tx_body:&[u8], lock_addr:&[u8], seal_policy:&[u8], datum:&[u8])->i8{
    if &out[2..34] != &th[..] { return 8; }                 // new seal = THIS tx
    let out_state=&out[70..];
    if datum.is_empty() { return 9; }
    if seal_commitment(datum).as_slice() != &b2b256(&[out_state])[..] { return 10; }   // STATE-ONLY (live parity)
    if seal_at_lock(tx_body, lock_addr, seal_policy) != Some(true) { return 13; }       // seal positively minted at lock
    if let Err(e)=ls_pin(out) { return e; }                                            // invariant LS
    0
}
fn transition(inp:&[u8], out:&[u8], th:&[u8;32], ins:&[([u8;32],u32)], datum:&[u8])->i8{
    if &out[2..34] != &th[..] { return 8; }
    let out_state=&out[70..];
    if datum.is_empty() { return 9; }
    if seal_commitment(datum).as_slice() != &b2b256(&[out_state])[..] { return 10; }
    let mut old=[0u8;32]; old.copy_from_slice(&inp[2..34]);
    let oi=u32::from_le_bytes([inp[34],inp[35],inp[36],inp[37]]);
    if !ins.iter().any(|(t,i)| t==&old && *i==oi) { return 12; }                        // old seal consumed
    if let Err(e)=ls_pin(out) { return e; }                                            // invariant LS
    0
}
fn finalize(inp:&[u8], tx_body:&[u8], ins:&[([u8;32],u32)], lock_addr:&[u8], seal_policy:&[u8])->i8{
    let mut old=[0u8;32]; old.copy_from_slice(&inp[2..34]);
    let oi=u32::from_le_bytes([inp[34],inp[35],inp[36],inp[37]]);
    if !ins.iter().any(|(t,i)| t==&old && *i==oi) { return 22; }                        // certified tx consumed the seal
    if seal_at_lock(tx_body, lock_addr, seal_policy) != Some(false) { return 23; }      // ...and did NOT recreate it
    0
}
// S5 LEAP_TO_CKB (Cardano->CKB): the dangerous direction. Closes B1 (recipient binding) + B3 (lock pin) + B4.
fn leap_to_ckb(inp:&[u8], out:&[u8], th:&[u8;32], tx_body:&[u8], ins:&[([u8;32],u32)], datum:&[u8], lock_addr:&[u8], seal_policy:&[u8])->i8{
    if &out[2..34] != &th[..] { return 8; }                 // surviving cell names the dest seal re-parked this tx
    let out_state=&out[70..];
    let src_seal=&inp[2..38];                               // SOURCE (consumed) seal - folded into RC (F1)
    let mut src_txid=[0u8;32]; src_txid.copy_from_slice(&inp[2..34]);
    let src_idx=u32::from_le_bytes([inp[34],inp[35],inp[36],inp[37]]);
    if !ins.iter().any(|(t,i)| t==&src_txid && *i==src_idx) { return 24; }              // certified tx consumed THIS outpoint (F3)
    if seal_at_lock(tx_body, lock_addr, seal_policy) != Some(true) { return 25; }       // LeapToCkb re-parks the seal
    if &inp[70..] != out_state { return 47; }                                          // state unchanged (M3 symmetry)
    // KEYSTONE: recipient bound to (state, SOURCE seal), owner-signed + Mithril-certified (RECIPIENT_COMMITMENT §4)
    let rc_claimed=seal_commitment(datum);
    let r_claimed=seal_recipient(datum);
    if r_claimed.len()!=32 { return 26; }
    let rc_local=b2b256(&[out_state, src_seal, &r_claimed[..]]);
    if rc_claimed.as_slice() != &rc_local[..] { return 27; }
    if &out[38..70] != r_claimed.as_slice() { return 28; }                             // cell-data lock slot == recipient
    let actual=match load_cell_lock_hash(0, Source::GroupOutput){ Ok(h)=>h, Err(_)=>return 29 };
    if actual[..] != r_claimed[..] { return 29; }                                      // B3: ACTUAL lock == recipient
    if !seal_nullifier_inserts(&src_txid, src_idx) { return 50; }                       // B4: nullify the consumed seal
    0
}
// S4 LEAP_TO_CARDANO (CKB->Cardano): owner leaves CKB. NOTE: no certified-`ins` nullifier here - the CkbOwned
// input is a native CKB UTXO (single-use already) and `seal_prime` is one-shot (seal_nft(seed)), so the
// N-FIN-1 cross-leg vector is S5-only. This refines docs §6.2 (which conflated the CkbOwned cell outpoint with
// a Cardano `ins` entry; that key has no referent on the outbound flip).
fn leap_to_cardano(inp:&[u8], out:&[u8], th:&[u8;32], tx_body:&[u8], _ins:&[([u8;32],u32)], datum:&[u8], lock_addr:&[u8], seal_policy:&[u8])->i8{
    let in_lock=match load_cell_lock_hash(0, Source::GroupInput){ Ok(h)=>h, Err(_)=>return 30 };
    if in_lock[..] != inp[38..70] { return 31; }                                       // input-lock auth (owner signs)
    if &inp[70..] != &out[70..] { return 32; }                                         // state unchanged (M3)
    if seal_at_lock(tx_body, lock_addr, seal_policy) != Some(true) { return 33; }       // seal_prime minted at lock (M1)
    if &out[2..34] != &th[..] { return 34; }                                           // CardanoBound names seal_prime
    let mut zero=true; let mut k=38; while k<70 { if out[k]!=0 { zero=false; break; } k+=1; }
    if !zero { return 35; }                                                            // CardanoBound lock slot zeroed
    let out_state=&out[70..];
    if datum.is_empty() { return 48; }
    if seal_commitment(datum).as_slice() != &b2b256(&[out_state])[..] { return 49; }    // F9: STATE-ONLY (live parity)
    0
}

fn program_entry()->i8{
    let script = load_script().unwrap();
    let args = script.args().raw_data();
    if args.len() < 57 { return 30; }
    let seal_policy = &args[0..28];
    let lock_addr = &args[28..];
    // A6 (renumbered to 38/39, RQ-9): exactly one bound cell in this type group.
    if load_cell_data(1, Source::GroupInput).is_ok() { return 38; }
    if load_cell_data(1, Source::GroupOutput).is_ok() { return 39; }
    // RQ-8: one bound cell of THIS code among inputs, one among outputs - across ALL type groups (serialize
    // leaps; closes the cross-group same-seal batch by forbidding batching here). Runs before the cert so a
    // batched tx is rejected cheaply (51/52) regardless of whose certificate it carries.
    let code = script.code_hash();
    let my_ht = script.hash_type().as_slice()[0];
    if count_instances(Source::Input, code.as_slice(), my_ht) > 1 { return 51; }
    if count_instances(Source::Output, code.as_slice(), my_ht) > 1 { return 52; }
    // SEC M2: bind the leap to a checkpoint carrying an AUTHENTICATED, finalized Cardano height (the upgraded
    // cert-verify requires + monotonically advances it). A height of 0 is not a real finalized snapshot.
    let (cert_root, cert_height) = match checkpoint_root() { Ok(r)=>r, Err(e)=>return e };
    if cert_height == 0 { return 6; }
    let w = match load_witness_args(0, Source::GroupInput) {
        Ok(w)=>w, Err(_)=> match load_witness_args(0, Source::GroupOutput) { Ok(w)=>w, Err(_)=>return 2 } };
    let lock = match w.input_type().to_opt() { Some(l)=>l.raw_data(), None=>return 3 };
    let mut r=R{b:&lock,i:0};
    let tx_body=r.lp().to_vec();
    let sub_root=r.lp().to_vec(); let sub_pos=r.u64(); let sub_size=r.u64(); let sub_items=r.items();
    let range_key=r.lp().to_vec();
    let master_pos=r.u64(); let master_size=r.u64(); let master_items=r.items();

    // cardano_tx_is_certified(tx) against the checkpoint root, via MKMapProof (all modes).
    let th=b2b256(&[&tx_body]); let leaf=N(hexb(&th));
    if !MerkleProof::<N,MB>::new(sub_size,sub_items).verify(N(sub_root.clone()),[(sub_pos,leaf)].to_vec()).unwrap_or(false) { return 4; }
    let master_leaf=N(b2s(&[&range_key,&sub_root]));
    if !MerkleProof::<N,MB>::new(master_size,master_items).verify(N(cert_root),[(master_pos,master_leaf)].to_vec()).unwrap_or(false) { return 5; }
    let (ins,datum)=parse(&tx_body);

    // v2 tag-first dispatch (closes B2): tag is authenticated cell data; the whitelist is exhaustive.
    let out = load_cell_data(0, Source::GroupOutput).ok();
    let inp = load_cell_data(0, Source::GroupInput).ok();
    let out_tag = match out.as_deref() { Some(d)=>match tag_of(d){ Ok(t)=>Some(t), Err(e)=>return e }, None=>None };
    let in_tag  = match inp.as_deref() { Some(d)=>match tag_of(d){ Ok(t)=>Some(t), Err(e)=>return e }, None=>None };
    match (in_tag, out_tag) {
        (None,                Some(CKB_OWNED))     => genesis(out.as_deref().unwrap(), &th, &tx_body, lock_addr, seal_policy, &datum),               // S1
        (Some(CKB_OWNED),     Some(CKB_OWNED))     => transition(inp.as_deref().unwrap(), out.as_deref().unwrap(), &th, &ins, &datum),               // S2
        (Some(CKB_OWNED),     None)                => finalize(inp.as_deref().unwrap(), &tx_body, &ins, lock_addr, seal_policy),                      // S3
        (Some(CKB_OWNED),     Some(CARDANO_BOUND)) => leap_to_cardano(inp.as_deref().unwrap(), out.as_deref().unwrap(), &th, &tx_body, &ins, &datum, lock_addr, seal_policy), // S4
        (Some(CARDANO_BOUND), Some(CKB_OWNED))     => leap_to_ckb(inp.as_deref().unwrap(), out.as_deref().unwrap(), &th, &tx_body, &ins, &datum, lock_addr, seal_policy),     // S5
        (Some(CARDANO_BOUND), None)                => 41,   // a CardanoBound anchor cannot just vanish
        (None,                Some(CARDANO_BOUND)) => 42,   // a genesis must land CkbOwned
        _                                          => 40,   // any other illegal shape - fail closed
    }
}

// --- single-hart __sync_* atomic polyfills (CKB-VM has no A-extension; built with -a,+forced-atomics).
#[allow(non_snake_case)]
mod sync_polyfill {
    use core::ptr::{read_volatile, write_volatile};
    macro_rules! sync_ops {
        ($ty:ty, $cas:ident, $bcas:ident, $tas:ident, $faa:ident, $fas:ident, $fao:ident, $faand:ident, $fax:ident) => {
            #[no_mangle] pub unsafe extern "C" fn $cas(p:*mut $ty,old:$ty,new:$ty)->$ty{let c=read_volatile(p);if c==old{write_volatile(p,new);}c}
            #[no_mangle] pub unsafe extern "C" fn $bcas(p:*mut $ty,old:$ty,new:$ty)->bool{let c=read_volatile(p);if c==old{write_volatile(p,new);true}else{false}}
            #[no_mangle] pub unsafe extern "C" fn $tas(p:*mut $ty,new:$ty)->$ty{let c=read_volatile(p);write_volatile(p,new);c}
            #[no_mangle] pub unsafe extern "C" fn $faa(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c.wrapping_add(v));c}
            #[no_mangle] pub unsafe extern "C" fn $fas(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c.wrapping_sub(v));c}
            #[no_mangle] pub unsafe extern "C" fn $fao(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c|v);c}
            #[no_mangle] pub unsafe extern "C" fn $faand(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c&v);c}
            #[no_mangle] pub unsafe extern "C" fn $fax(p:*mut $ty,v:$ty)->$ty{let c=read_volatile(p);write_volatile(p,c^v);c}
        };
    }
    sync_ops!(u8,  __sync_val_compare_and_swap_1,__sync_bool_compare_and_swap_1,__sync_lock_test_and_set_1,__sync_fetch_and_add_1,__sync_fetch_and_sub_1,__sync_fetch_and_or_1,__sync_fetch_and_and_1,__sync_fetch_and_xor_1);
    sync_ops!(u16, __sync_val_compare_and_swap_2,__sync_bool_compare_and_swap_2,__sync_lock_test_and_set_2,__sync_fetch_and_add_2,__sync_fetch_and_sub_2,__sync_fetch_and_or_2,__sync_fetch_and_and_2,__sync_fetch_and_xor_2);
    sync_ops!(u32, __sync_val_compare_and_swap_4,__sync_bool_compare_and_swap_4,__sync_lock_test_and_set_4,__sync_fetch_and_add_4,__sync_fetch_and_sub_4,__sync_fetch_and_or_4,__sync_fetch_and_and_4,__sync_fetch_and_xor_4);
    sync_ops!(u64, __sync_val_compare_and_swap_8,__sync_bool_compare_and_swap_8,__sync_lock_test_and_set_8,__sync_fetch_and_add_8,__sync_fetch_and_sub_8,__sync_fetch_and_or_8,__sync_fetch_and_and_8,__sync_fetch_and_xor_8);
    #[no_mangle] pub extern "C" fn __sync_synchronize() {}
}

// ---- host unit tests for the PURE byte-offset logic (the riskiest part of the v2 re-layout) ----
#[cfg(test)]
mod tests {
    use super::*;
    fn cbor_bstr(b:&[u8])->Vec<u8>{ let mut o=Vec::new(); let n=b.len();
        if n<24 { o.push(0x40+n as u8); } else { o.push(0x58); o.push(n as u8); } o.extend_from_slice(b); o }
    // Constr 121 [owner, commitment, recipient] = the v2 LeapSealDatum wire shape (RECIPIENT_COMMITMENT §7.2)
    fn leap_datum(owner:&[u8], commitment:&[u8], recipient:&[u8])->Vec<u8>{
        let mut o=Vec::new(); o.push(0xD8); o.push(0x79); o.push(0x83);   // tag 121, array(3)
        o.extend(cbor_bstr(owner)); o.extend(cbor_bstr(commitment)); o.extend(cbor_bstr(recipient)); o }

    #[test]
    fn tag_of_accepts_valid_v2_cells() {
        let mut d=[0u8;70].to_vec(); d[0]=0x02; d[1]=CKB_OWNED;
        assert_eq!(tag_of(&d), Ok(CKB_OWNED));
        d[1]=CARDANO_BOUND; assert_eq!(tag_of(&d), Ok(CARDANO_BOUND));
    }
    #[test]
    fn tag_of_rejects_bad_version_tag_and_short() {
        let mut d=[0u8;70].to_vec(); d[0]=0x01; d[1]=CKB_OWNED;
        assert_eq!(tag_of(&d), Err(43));                 // v1 cell (version != 0x02) kept out
        d[0]=0x02; d[1]=0x03; assert_eq!(tag_of(&d), Err(44));   // illegal tag
        assert_eq!(tag_of(&[0x02u8,0x02]), Err(7));      // len < 70
    }
    #[test]
    fn seal_readers_hit_field1_and_field2() {
        let owner=[0x0bu8;28]; let commitment=[0x11u8;32]; let recipient=[0x33u8;32];
        let d=leap_datum(&owner,&commitment,&recipient);
        assert_eq!(seal_commitment(&d), commitment.to_vec());   // field 1
        assert_eq!(seal_recipient(&d), recipient.to_vec());     // field 2 (the NEW reader)
    }
    #[test]
    fn rc_preimage_is_state_seal_recipient_concatenation() {
        // RC = blake2b256(state ‖ SOURCE seal ‖ recipient); multi-part == single concatenated buffer.
        let state=[0xAAu8;10]; let seal=[0xBBu8;36]; let recip=[0x33u8;32];
        let rc=b2b256(&[&state,&seal,&recip]);
        let mut cat=Vec::new(); cat.extend_from_slice(&state); cat.extend_from_slice(&seal); cat.extend_from_slice(&recip);
        assert_eq!(rc, b2b256(&[&cat]));
        assert_ne!(rc, b2b256(&[&state,&seal]));        // recipient genuinely enters the digest
    }
    #[test]
    fn layout_vector_matches_offchain_builder() {
        // CROSS-LANGUAGE vector shared with relayer/v2_cell.test.mjs: the off-chain builder must emit
        // byte-identical cells, else it produces cells this verifier won't parse.
        let mut d = vec![0x02u8, CKB_OWNED];
        d.extend_from_slice(&[0xABu8; 32]); d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&[0x33u8; 32]); d.extend_from_slice(&[0xEEu8; 8]);
        let hex: alloc::string::String = d.iter().map(|b| alloc::format!("{:02x}", b)).collect();
        let expected = alloc::format!("0202{}00000000{}{}", "ab".repeat(32), "33".repeat(32), "ee".repeat(8));
        assert_eq!(hex, expected);
        assert_eq!(tag_of(&d), Ok(CKB_OWNED));
    }
    #[test]
    fn cross_language_rc_and_stateonly_vectors() {
        // CROSS-LANGUAGE vectors shared with relayer/cardano_leap_v2.test.mjs: the Cardano builder must compute
        // byte-identical commitments (plain BLAKE2b-256, NO personalization), else the certified datum won't
        // match the verifier's RC (S5) / state-only commitment (S1/S2/S4) checks.
        let state = b"leap-demo-state";
        let mut seal36 = [0xABu8; 36]; for k in 32..36 { seal36[k] = 0; }   // "ab"*32 ‖ 0u32 LE
        let recip = [0x33u8; 32];
        let rc: alloc::string::String = b2b256(&[state, &seal36, &recip]).iter().map(|b| alloc::format!("{:02x}", b)).collect();
        assert_eq!(rc, "c08948bc1439930d9007793543b88abf866d712e2f9cbccce3c7fea86775fbc7");
        let so: alloc::string::String = b2b256(&[b"leap-out-state"]).iter().map(|b| alloc::format!("{:02x}", b)).collect();
        assert_eq!(so, "10f5119872cc031eba985be57ac53ab22972c1b25066edb31932aa6d2c21c092");
    }
    #[test]
    fn v2_layout_offsets() {
        // version(1) tag(1) seal_txid(32) seal_idx(4) lock(32) state -> seal=[2..38], lock=[38..70], state=[70..]
        let mut d=[0u8;78].to_vec(); d[0]=0x02; d[1]=CKB_OWNED;
        for k in 2..34 { d[k]=0xCC; }   // seal txid
        for k in 38..70 { d[k]=0xDD; }  // lock slot
        for k in 70..78 { d[k]=0xEE; }  // state
        assert_eq!(&d[2..34], &[0xCCu8;32][..]);
        assert_eq!(&d[38..70], &[0xDDu8;32][..]);
        assert_eq!(&d[70..], &[0xEEu8;8][..]);
    }
}
