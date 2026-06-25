//! bound_asset_unified.rs - unified, witness-driven BoundAsset type script (Phase 1 + Phase 3).
//! Deployed ONCE, referenced by every bound cell. Per-transfer proof rides in the WITNESS; the
//! certified Cardano tx-set root is read from a referenced LIGHT-CLIENT CHECKPOINT cell (cell dep
//! data = "LCKP" || root). Handles GENESIS (bind), TRANSITION (consume old -> create new), and
//! FINALIZE (leap-out: consume the bound cell with NO output, when the certified Cardano tx consumed
//! the seal and did NOT recreate it at the binding_lock). Bound cell data = seal_txid(32)||seal_idx(u32 LE)||state.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use alloc::vec::Vec;
use ckb_std::{ckb_constants::Source, high_level::{load_witness_args, load_cell_data, load_cell_type_hash, load_script}};
// SEC A1: the ONLY trusted checkpoint is one carrying the TxSetCert verifier's type script (its root was
// cert-verified in-VM). Mirrors burn_gated_unlock's EXPECTED_TYPE_HASH. Without this, any "LCKP" cell-dep
// (a hand-made root) was accepted -> forged leaps.
const LCKP_TYPE_HASH: [u8;32] = [133,82,49,179,57,175,212,62,166,215,227,196,181,212,68,27,38,60,90,54,42,71,159,85,234,239,130,153,203,135,121,185];
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

// SEC A4: the binding-lock instance params (seal NFT policy + binding_lock address) are now read from the
// type script's ARGS (seal_policy(28) ‖ lock_addr(28)) - NOT hardcoded consts - so each bound-cell instance
// is distinct and a proof crafted for one instance can't be reused against another.

#[derive(Clone,PartialEq,Eq,Debug)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item=N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2s(p:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for x in p {h.update(x);} h.finalize().to_vec() }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::new(); for &x in b {o.push(hx[(x>>4)as usize]);o.push(hx[(x&0xf)as usize]);} o }
// SEC A2/C6: bounds-checked witness reader - on a malformed/over-long length it returns empty/zero and
// parks at the end, so the downstream MMR verify fails CLEANLY (reject) instead of panicking (OOB).
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
fn seal_commitment(d:&[u8])->Vec<u8>{ let (_t,_x,ti)=hdr(d,0); let (_a,_n,ai)=hdr(d,ti); let j=skip(d,ai); let (_c,cl,ca)=hdr(d,j); d[ca..ca+cl as usize].to_vec() }

// SEC A3: a SOUND, canonical, bounds-checked Conway-output decoder. The old `seal_recreated_at_lock` was a
// best-effort scanner: a value/output/address form it didn't model could make it MISS a real seal recreation
// (a false negative on FINALIZE ⇒ leap out AND keep the bound asset). This version returns `Option<bool>`:
// `Some(true)`  - PROVEN the seal NFT (seal_policy) is recreated at lock_addr in some output;
// `Some(false)` - PROVEN no output recreates it (every output fully + canonically parsed);
// `None`        - the body could not be canonically parsed (OOB / indefinite length / unexpected major).
// Callers then demand PROOF in their safety direction: GENESIS needs Some(true), FINALIZE needs Some(false),
// so any ambiguity (None) fails CLOSED in BOTH directions - there is no encoding that silently evades.
const A3_MAX_DEPTH: usize = 64;
fn ohdr(b:&[u8], i:usize) -> Option<(u8,u64,usize)> {
    let ib = *b.get(i)?; let m = ib>>5; let lo = ib&0x1f;
    match lo {
        0..=23 => Some((m, lo as u64, i+1)),
        24 => { if i+1>=b.len(){return None;} Some((m, b[i+1] as u64, i+2)) }
        25 => { if i+2>=b.len(){return None;} Some((m, u16::from_be_bytes([b[i+1],b[i+2]]) as u64, i+3)) }
        26 => { if i+4>=b.len(){return None;} Some((m, u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64, i+5)) }
        27 => { if i+8>=b.len(){return None;} Some((m, u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]), i+9)) }
        _ => None, // 28..31 incl. indefinite-length (31): reject - fail-closed, not best-effort.
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
/// Does the value at `va` carry `seal_policy` in its multiasset? uint coin ⇒ Some(false); [coin, ma] ⇒ scan ma.
fn val_has_policy(b:&[u8], va:usize, seal_policy:&[u8]) -> Option<bool> {
    let (vm,vlen,vj)=ohdr(b,va)?;
    if vm==0 { return Some(false); }                 // coin only, no assets
    if vm!=4 || vlen<2 { return None; }              // a value is uint OR [coin, multiasset]
    let ca = oskip(b,vj,0)?;                          // skip coin -> multiasset map
    let (mm,mc,mut p)=ohdr(b,ca)?;
    if mm!=5 { return None; }                        // multiasset must be a map
    for _ in 0..mc {
        let (pm,pl,pa)=ohdr(b,p)?;
        if pm!=2 { return None; }                    // policy id must be a byte string
        let pend = pa.checked_add(pl as usize)?; if pend>b.len() { return None; }
        let is_seal = pl as usize==seal_policy.len() && &b[pa..pend]==seal_policy;
        let after = oskip(b,pend,0)?;                // skip the { asset_name: amount } map
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
        if km!=0 { return None; }                    // tx-body keys are uints
        if key==1 {                                  // outputs
            let (om,oc,oj)=ohdr(b,ki)?;
            if om!=4 { return None; }                // outputs is an array
            let mut j=oj; let mut found=false;
            for _ in 0..oc {
                let (otm,oarg,oi2)=ohdr(b,j)?;
                let (addr_lo,addr_hi,val_at,next);
                if otm==5 {                          // Babbage map output { 0:addr, 1:value, .. }
                    let mut k=oi2; let (mut a0,mut a1,mut v)=(0usize,0usize,0usize);
                    for _ in 0..oarg {
                        let (_em,ek,eki)=ohdr(b,k)?;
                        if ek==0 { let (am,al,aa)=ohdr(b,eki)?; if am!=2 {return None;}
                            let e=aa.checked_add(al as usize)?; if e>b.len(){return None;} a0=aa; a1=e; k=e; }
                        else if ek==1 { v=eki; k=oskip(b,eki,0)?; }
                        else { k=oskip(b,eki,0)?; }
                    }
                    addr_lo=a0; addr_hi=a1; val_at=v; next=k;
                } else if otm==4 {                   // legacy array output [addr, value, ..]
                    if oarg<2 { return None; }
                    let (am,al,aa)=ohdr(b,oi2)?; if am!=2 {return None;}
                    let e=aa.checked_add(al as usize)?; if e>b.len(){return None;}
                    addr_lo=aa; addr_hi=e; val_at=e; next=oskip(b,j,0)?;
                } else { return None; }              // unexpected output form -> fail-closed
                if addr_hi>addr_lo && addr_hi<=b.len() && &b[addr_lo..addr_hi]==lock_addr && val_at!=0 {
                    if val_has_policy(b,val_at,seal_policy)? { found=true; }
                }
                j=next;
            }
            return Some(found);
        } else { i=oskip(b,ki,0)?; }
    }
    None                                             // no outputs field -> cannot determine -> fail-closed
}

fn checkpoint_root()->Option<Vec<u8>>{
    let mut i=0;
    loop {
        match load_cell_data(i, Source::CellDep) {
            Ok(d)=>{
                // SEC A1: accept the root ONLY from an authenticated checkpoint cell (TxSetCert type hash).
                if d.len()>=36 && &d[0..4]==b"LCKP" {
                    if let Ok(Some(th))=load_cell_type_hash(i, Source::CellDep) {
                        if th==LCKP_TYPE_HASH { return Some(d[4..36].to_vec()); }
                    }
                }
                i+=1;
            }
            Err(_)=>return None,
        }
        if i>64 { return None; }
    }
}

fn program_entry()->i8{
    // SEC A4: per-instance params from the type script args (seal_policy(28) ‖ lock_addr(28)).
    let script = load_script().unwrap();
    let args = script.args().raw_data();
    if args.len() < 57 { return 30; }
    let seal_policy = &args[0..28];
    // lock_addr = the FULL Cardano output address bytes (header+payload; 29B for an enterprise script
    // address), compared to the certified tx's output address in seal_at_lock. The upstream source sliced
    // [28..56] (28B) which can never equal a real 29B address; take all trailing bytes instead.
    let lock_addr = &args[28..];
    // SEC A6: exactly one bound cell in this type group (reject decoy 2nd input/output riding free).
    if load_cell_data(1, Source::GroupInput).is_ok() { return 31; }
    if load_cell_data(1, Source::GroupOutput).is_ok() { return 32; }
    let cert_root = match checkpoint_root() { Some(r)=>r, None=>return 1 };
    let w = match load_witness_args(0, Source::GroupInput) {
        Ok(w)=>w, Err(_)=> match load_witness_args(0, Source::GroupOutput) { Ok(w)=>w, Err(_)=>return 2 } };
    let lock = match w.input_type().to_opt() { Some(l)=>l.raw_data(), None=>return 3 };
    let mut r=R{b:&lock,i:0};
    let tx_body=r.lp().to_vec();
    let sub_root=r.lp().to_vec(); let sub_pos=r.u64(); let sub_size=r.u64(); let sub_items=r.items();
    let range_key=r.lp().to_vec();
    let master_pos=r.u64(); let master_size=r.u64(); let master_items=r.items();

    // 1) cardano_tx_is_certified(tx) against the checkpoint root, via MKMapProof (all modes).
    let th=b2b256(&[&tx_body]); let leaf=N(hexb(&th));
    if !MerkleProof::<N,MB>::new(sub_size,sub_items).verify(N(sub_root.clone()),[(sub_pos,leaf)].to_vec()).unwrap_or(false) { return 4; }
    let master_leaf=N(b2s(&[&range_key,&sub_root]));
    if !MerkleProof::<N,MB>::new(master_size,master_items).verify(N(cert_root),[(master_pos,master_leaf)].to_vec()).unwrap_or(false) { return 5; }
    let (ins,datum)=parse(&tx_body);

    match load_cell_data(0, Source::GroupOutput) {
        // ---- GENESIS / TRANSITION: a bound cell continues ----
        Ok(out_data)=>{
            if out_data.len()<36 { return 7; }
            let out_seal_txid=&out_data[0..32]; let out_state=&out_data[36..];
            if out_seal_txid != &th[..] { return 8; }                                   // new seal created by THIS tx
            if datum.is_empty() { return 9; }
            if seal_commitment(&datum).as_slice() != &b2b256(&[out_state])[..] { return 10; } // commitment binds new state
            match load_cell_data(0, Source::GroupInput) {
                Ok(in_data)=>{                                                            // TRANSITION
                    if in_data.len()<36 { return 11; }
                    let mut old=[0u8;32]; old.copy_from_slice(&in_data[0..32]);
                    let oi=u32::from_le_bytes([in_data[32],in_data[33],in_data[34],in_data[35]]);
                    if !ins.iter().any(|(t,i)| t==&old && *i==oi) { return 12; }          // old seal consumed
                }
                Err(_)=>{                                                                 // GENESIS
                    // SEC A5: the certified tx must POSITIVELY mint the seal NFT to the binding lock -
                    // a bound cell can't be genesis-bound off an arbitrary certified tx.
                    // SEC A3: require PROOF the seal is recreated (Some(true)); None (unparsable) fails closed.
                    if seal_at_lock(&tx_body, lock_addr, seal_policy) != Some(true) { return 13; }
                }
            }
            0
        }
        // ---- FINALIZE (leap-out): bound cell destroyed (no output) ----
        Err(_)=>{
            let in_data = match load_cell_data(0, Source::GroupInput) { Ok(d)=>d, Err(_)=>return 20 };
            if in_data.len()<36 { return 21; }
            let mut old=[0u8;32]; old.copy_from_slice(&in_data[0..32]);
            let oi=u32::from_le_bytes([in_data[32],in_data[33],in_data[34],in_data[35]]);
            if !ins.iter().any(|(t,i)| t==&old && *i==oi) { return 22; }                  // certified tx consumed the seal
            // SEC A3: require PROOF the seal is NOT recreated (Some(false)); Some(true) OR None fails closed.
            if seal_at_lock(&tx_body, lock_addr, seal_policy) != Some(false) { return 23; } // ...and did NOT recreate it at the lock
            0
        }
    }
}

// --- single-hart __sync_* atomic polyfills (CKB-VM has no A-extension; built with -a,+forced-atomics).
// LLVM lowers atomic load/store inline but emits legacy __sync_* RMW/CAS libcalls; provide them here.
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
