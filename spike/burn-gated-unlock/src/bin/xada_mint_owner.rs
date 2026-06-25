//! xada_mint_owner.rs - the χADA xUDT OWNER lock (the bridge mint authority). This makes χADA a STANDARD,
//! ecosystem-recognized xUDT instead of a bespoke type script: the χADA token IS the canonical xUDT
//! (`xUDT(args = THIS lock's hash)`), and minting is authorized via xUDT *owner mode* - the xUDT type script
//! bypasses its amount check when an input carries the owner lock, and THIS lock then enforces the exact bound
//! mint. So wallets/DEXes/explorers see a real xUDT, while issuance stays bridge-gated. (Supersedes the
//! type-script `xada_mint.rs`, which minted a non-standard custom-typed cell.)
//!
//! A mint (xUDT owner mode) is authorized iff a Mithril-certified Cardano ADA-lock is proven in-VM, bound 1:1
//! to the locked lovelace + the committed CKB recipient, nullified replay-once - the SAME verification as
//! xada_mint, re-homed into a lock. The χADA cells are found by XUDT_CODE + type.args[0..32] == self_hash
//! (self_hash = this lock's script hash = the xUDT args), so there is no genesis cycle.
//!
//! args = LCKP_type_hash(32) ‖ registry_type_hash(32) ‖ escrow_addr(rest).
//! witness.lock (this lock's GroupInput[0]) = the R-layout MKMap proof (lp(escrow_tx_body) ‖ … ).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)] extern crate alloc;
use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{Merge, MerkleProof, Result as MMRResult};
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{load_cell_data, load_cell_lock_hash, load_cell_type, load_cell_type_hash, load_script, load_script_hash, load_witness_args};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

// the canonical xUDT type-id code hash (CKB testnet/Pudge). The χADA token = xUDT(args = this lock's hash).
// Overridable at build for the in-VM tests (which stand in a mock xUDT). A type-id code hash is globally
// unique, so matching cells by code_hash + args (below) reliably identifies the χADA xUDT.
const fn hexv(c:u8)->u8{ match c { b'0'..=b'9'=>c-b'0', b'a'..=b'f'=>c-b'a'+10, b'A'..=b'F'=>c-b'A'+10, _=>0 } }
const fn hex32(s:&str)->[u8;32]{ let b=s.as_bytes(); let off=if b.len()>=2 && b[0]==b'0' && (b[1]==b'x'||b[1]==b'X') {2} else {0}; let mut o=[0u8;32]; let mut i=0; while i<32 { o[i]=(hexv(b[off+2*i])<<4)|hexv(b[off+2*i+1]); i+=1; } o }
const XUDT_CODE: [u8;32] = match option_env!("CHIRAL_XUDT_TH") {
    Some(h) => hex32(h),
    None => hex32("0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb"),
};

#[derive(Clone,PartialEq,Eq)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item=N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2s(p:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for x in p {h.update(x);} h.finalize().to_vec() }
fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::with_capacity(b.len()*2); for &x in b {o.push(hx[(x>>4)as usize]);o.push(hx[(x&0xf)as usize]);} o }

struct R<'a>{ b:&'a[u8], i:usize }
impl<'a> R<'a>{
    fn u32(&mut self)->usize{ if self.i+4>self.b.len(){ self.i=self.b.len(); return 0; } let v=u32::from_le_bytes([self.b[self.i],self.b[self.i+1],self.b[self.i+2],self.b[self.i+3]]) as usize; self.i+=4; v }
    fn u64(&mut self)->u64{ if self.i+8>self.b.len(){ self.i=self.b.len(); return 0; } let mut a=[0u8;8]; a.copy_from_slice(&self.b[self.i..self.i+8]); self.i+=8; u64::from_le_bytes(a) }
    fn lp(&mut self)->&'a[u8]{ let n=self.u32(); if self.i+n>self.b.len(){ self.i=self.b.len(); return &[]; } let s=&self.b[self.i..self.i+n]; self.i+=n; s }
    fn items(&mut self)->Vec<N>{ let n=self.u32(); if n>self.b.len(){ return Vec::new(); } (0..n).map(|_| N(self.lp().to_vec())).collect() }
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
// EscrowDatum = Constr 121 [recipient:bytes32, amount:int, nonce:int]; the inner array may be indefinite-length
// (0x9f…0xff, the Plutus/pycardano default) OR definite - accept both.
fn constr_fields_start(d:&[u8]) -> Option<usize> {
    let (t,_v,ti)=ohdr(d,0)?;
    if t!=6 { return None; }
    match *d.get(ti)? {
        0x9f => Some(ti+1),
        b if (b>>5)==4 => { let (_,_,a)=ohdr(d,ti)?; Some(a) }
        _ => None,
    }
}
fn datum_recipient(d:&[u8]) -> Option<Vec<u8>> {
    let ai = constr_fields_start(d)?;
    let (rm,rl,ra)=ohdr(d,ai)?;
    if rm!=2 { return None; }
    let e=ra.checked_add(rl as usize)?; if e>d.len(){ return None; }
    Some(d[ra..e].to_vec())
}
fn datum_amount(d:&[u8]) -> Option<i128> {
    let ai = constr_fields_start(d)?;
    let j0=oskip(d,ai,0)?;
    let (m,a,_)=ohdr(d,j0)?;
    match m { 0 => Some(a as i128), 1 => Some(-1i128 - a as i128), _ => None }
}
fn escrow_output(b:&[u8], escrow_addr:&[u8]) -> Option<(u128, Vec<u8>)> {
    let (m,n,mut i)=ohdr(b,0)?;
    if m!=5 { return None; }
    for _ in 0..n {
        let (km,key,ki)=ohdr(b,i)?;
        if km!=0 { return None; }
        if key==1 {
            let (om,oc,oj)=ohdr(b,ki)?;
            if om!=4 { return None; }
            let mut j=oj;
            for _ in 0..oc {
                let (otm,oarg,oi2)=ohdr(b,j)?;
                if otm==5 {
                    let mut k=oi2;
                    let (mut a0,mut a1)=(0usize,0usize);
                    let mut coin:u128=0; let mut have_val=false;
                    let mut datum:Option<Vec<u8>>=None;
                    for _ in 0..oarg {
                        let (_em,ek,eki)=ohdr(b,k)?;
                        if ek==0 {
                            let (am,al,aa)=ohdr(b,eki)?; if am!=2 { return None; }
                            let e=aa.checked_add(al as usize)?; if e>b.len(){ return None; }
                            a0=aa; a1=e; k=e;
                        } else if ek==1 {
                            let (vm,va,vj)=ohdr(b,eki)?;
                            if vm==0 { coin=va as u128; have_val=true; k=vj; }
                            else if vm==4 {
                                let (cm,cv,cj)=ohdr(b,vj)?; if cm!=0 { return None; }
                                coin=cv as u128; have_val=true;
                                k=oskip(b,cj,0)?;
                            } else { return None; }
                        } else if ek==2 {
                            let (dm,_da,di)=ohdr(b,eki)?;
                            if dm!=4 { return None; }
                            let nk=oskip(b,di,0)?;
                            let (tm,t24,ta)=ohdr(b,nk)?;
                            if tm!=6 || t24!=24 { return None; }
                            let (bm,bl,ba)=ohdr(b,ta)?; if bm!=2 { return None; }
                            let e=ba.checked_add(bl as usize)?; if e>b.len(){ return None; }
                            datum=Some(b[ba..e].to_vec());
                            k=e;
                        } else { k=oskip(b,eki,0)?; }
                    }
                    if have_val && a1>a0 && a1<=b.len() && &b[a0..a1]==escrow_addr {
                        if let Some(dat)=datum { return Some((coin, dat)); }
                    }
                    j=k;
                } else if otm==4 {
                    j=oskip(b,j,0)?;
                } else { return None; }
            }
            return None;
        } else { i=oskip(b,ki,0)?; }
    }
    None
}

fn checkpoint_root(lckp_type:&[u8;32]) -> Result<(Vec<u8>, u64), i8> {
    let mut found: Option<(Vec<u8>, u64)> = None;
    let mut i=0usize;
    loop {
        match load_cell_type_hash(i, Source::CellDep) {
            Ok(Some(th)) if &th==lckp_type => {
                if let Ok(d)=load_cell_data(i, Source::CellDep) {
                    if d.len()>=44 && &d[0..4]==b"LCKP" {
                        let mut hb=[0u8;8]; hb.copy_from_slice(&d[36..44]);
                        let cur=(d[4..36].to_vec(), u64::from_le_bytes(hb));
                        match &found {
                            Some(prev) if *prev != cur => return Err(53),
                            Some(_) => {}
                            None => found = Some(cur),
                        }
                    }
                }
                i+=1;
            }
            Ok(_)=>{ i+=1; }
            Err(_)=>break,
        }
        if i>64 { break; }
    }
    found.ok_or(10)
}
fn registry_inserts_key(reg_type:&[u8;32], key:&[u8;32]) -> bool {
    let mut i=0usize;
    loop {
        match load_cell_type_hash(i, Source::Input) {
            Ok(Some(th)) if &th==reg_type => {
                if let Ok(w)=load_witness_args(i, Source::Input) {
                    if let Some(b)=w.input_type().to_opt() {
                        let d=b.raw_data();
                        return d.len()>=32 && &d[0..32]==&key[..];
                    }
                }
                return false;
            }
            Ok(_)=>{ i+=1; }
            Err(_)=>return false,
        }
    }
}

// is the cell at (source,i) a χADA xUDT cell? (canonical xUDT code_hash + type.args[0..32] == owner)
fn is_xada(source: Source, i: usize, owner:&[u8;32]) -> bool {
    match load_cell_type(i, source) {
        Ok(Some(t)) => {
            let args = t.args().raw_data();
            t.code_hash().as_slice()==&XUDT_CODE[..] && args.len()>=32 && &args[0..32]==&owner[..]
        }
        _ => false,
    }
}
// Σ χADA xUDT amounts (data[0..16] u128 LE) in `source`.
fn sum_xada(source: Source, owner:&[u8;32]) -> Option<u128> {
    let mut sum:u128=0; let mut i=0usize;
    loop {
        match load_cell_type(i, source) {
            Ok(_)=>{
                if is_xada(source, i, owner) {
                    let d=load_cell_data(i, source).ok()?;
                    if d.len()<16 { return None; }
                    let mut a=[0u8;16]; a.copy_from_slice(&d[0..16]); sum=sum.checked_add(u128::from_le_bytes(a))?;
                }
                i+=1;
            }
            Err(_)=>break,
        }
    }
    Some(sum)
}
// every freshly-minted χADA xUDT output is locked at the certified recipient (not the all-zero lock).
fn xada_outputs_at(owner:&[u8;32], recipient:&[u8]) -> Result<(),i8> {
    let mut i=0usize;
    loop {
        match load_cell_type(i, Source::Output) {
            Ok(_)=>{
                if is_xada(Source::Output, i, owner) {
                    let lh=match load_cell_lock_hash(i, Source::Output){ Ok(h)=>h, Err(_)=>return Err(28) };
                    if lh==[0u8;32] || &lh[..]!=recipient { return Err(28); }
                }
                i+=1;
            }
            Err(_)=>break,
        }
    }
    Ok(())
}

fn program_entry()->i8{
    let args = load_script().unwrap().args().raw_data();
    // args = salt(1) ‖ lckp_type(32) ‖ reg_type(32) ‖ escrow_addr(rest). args[0] is a logic-neutral salt/version
    // byte: it lets a fresh owner instance take a DISTINCT lock hash → a DISTINCT χADA xUDT token id WITHOUT
    // touching the bridge verification. Needed because Magickbase fixes a token's info at its FIRST on-chain
    // sighting; the original χADA id was first seen without an info cell, so it is permanently un-namable. Same
    // bridge logic, new identity. (The salt is parsed but never used below.)
    if args.len() < 1+64+1 { return 2; }
    let _salt = args[0];
    let mut lckp_type=[0u8;32]; lckp_type.copy_from_slice(&args[1..33]);
    let mut reg_type=[0u8;32];  reg_type.copy_from_slice(&args[33..65]);
    let escrow_addr=&args[65..];
    // owner = THIS lock's script hash == the χADA xUDT's args.
    let owner = match load_script_hash() { Ok(h)=>h, Err(_)=>return 1 };

    let in_sum  = match sum_xada(Source::Input,  &owner) { Some(v)=>v, None=>return 16 };
    let out_sum = match sum_xada(Source::Output, &owner) { Some(v)=>v, None=>return 17 };
    // BURN path (χADA RETURN leg): a NET REDUCTION of χADA is PERMISSIONLESS - burning tokens you already hold
    // needs no authorization here. The cross-chain release is enforced DOWNSTREAM (the xada_burn_receipt type
    // script self-enforces Σin−Σout == the receipt's bound amount; the return Groth16 proof + ada_escrow release
    // the ADA against a replay-once seal), NOT in this lock. So owner mode may carry a burn - no mint check.
    if out_sum < in_sum { return 0; }
    // Otherwise this owner lock authorizes ONLY mints (xUDT owner mode bypasses xUDT's amount check, so the exact
    // mint is enforced HERE). out==in (owner mode, no net change) is not a mint → reject (no free unlock).
    if out_sum == in_sum { return 18; }
    let minted = out_sum - in_sum;
    if in_sum != 0 { return 19; }                       // mint-only tx (no χADA inputs)

    let (cert_root, cert_height) = match checkpoint_root(&lckp_type) { Ok(r)=>r, Err(e)=>return e };
    if cert_height == 0 { return 6; }

    // the MKMap proof rides THIS lock's witness (.lock on its GroupInput[0]).
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w)=>w, Err(_)=>return 3 };
    let lock = match w.lock().to_opt() { Some(l)=>l.raw_data(), None=>return 4 };
    let mut r=R{b:&lock,i:0};
    let tx_body=r.lp().to_vec();
    let sub_root=r.lp().to_vec(); let sub_pos=r.u64(); let sub_size=r.u64(); let sub_items=r.items();
    let range_key=r.lp().to_vec();
    let master_pos=r.u64(); let master_size=r.u64(); let master_items=r.items();

    let leaf=N(hexb(&b2b256(&[&tx_body])));
    if !MerkleProof::<N,MB>::new(sub_size,sub_items).verify(N(sub_root.clone()),[(sub_pos,leaf)].to_vec()).unwrap_or(false) { return 5; }
    let master_leaf=N(b2s(&[&range_key,&sub_root]));
    if !MerkleProof::<N,MB>::new(master_size,master_items).verify(N(cert_root),[(master_pos,master_leaf)].to_vec()).unwrap_or(false) { return 7; }

    let (locked, datum) = match escrow_output(&tx_body, escrow_addr) { Some(x)=>x, None=>return 20 };
    let recipient = match datum_recipient(&datum) { Some(x)=>x, None=>return 21 };
    if recipient.len()!=32 { return 21; }
    let dat_amount = match datum_amount(&datum) { Some(a)=>a, None=>return 22 };
    if dat_amount < 0 || dat_amount as u128 != locked { return 23; }
    if minted != locked { return 24; }                  // conservation: χADA minted 1:1 with lovelace

    if let Err(e)=xada_outputs_at(&owner, &recipient) { return e; }

    // SEC (domain separation): prefix a 1-byte leg tag (0x01 = χADA-mint escrow nullifier) so this leg's
    // keyspace is disjoint from the CKB-release (0x02) and χCKB-leap (0x03) legs sharing this registry -
    // defense-in-depth so no future Cardano tx-body shape can collide across legs. Off-chain match:
    // xada_reg_witness.py (blake2b(0x01 ‖ tx_body)). The cert leaf above stays UNtagged (= Cardano tx hash).
    let key=b2b256(&[&[0x01u8], &tx_body]);
    if !registry_inserts_key(&reg_type, &key) { return 25; }
    0
}

// --- single-hart __sync_* atomic polyfills (CKB-VM has no A-extension; built with -a,+forced-atomics). ---
#[cfg(not(test))]
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

#[cfg(test)]
mod tests {
    use super::*;
    fn bstr(b:&[u8])->Vec<u8>{ let mut o=Vec::new(); let n=b.len();
        if n<24 { o.push(0x40+n as u8); } else if n<256 { o.push(0x58); o.push(n as u8); } else { o.push(0x59); o.extend_from_slice(&(n as u16).to_be_bytes()); }
        o.extend_from_slice(b); o }
    fn uint(n:u64)->Vec<u8>{ let mut o=Vec::new();
        if n<24 { o.push(n as u8); } else if n<256 { o.push(0x18); o.push(n as u8); }
        else if n<65536 { o.push(0x19); o.extend_from_slice(&(n as u16).to_be_bytes()); }
        else if n<(1u64<<32) { o.push(0x1a); o.extend_from_slice(&(n as u32).to_be_bytes()); }
        else { o.push(0x1b); o.extend_from_slice(&n.to_be_bytes()); } o }
    fn escrow_datum(recipient:&[u8], amount:u64, nonce:u64)->Vec<u8>{
        let mut o=vec![0xd8u8,0x79,0x9f]; o.extend(bstr(recipient)); o.extend(uint(amount)); o.extend(uint(nonce)); o.push(0xff); o }

    #[test]
    fn datum_readers_indefinite_and_definite() {
        let recip=[0x33u8;32];
        let d=escrow_datum(&recip, 5_000_000, 1);
        assert_eq!(datum_recipient(&d).unwrap(), recip.to_vec());
        assert_eq!(datum_amount(&d).unwrap(), 5_000_000i128);
    }
    #[test]
    fn escrow_output_parses_live_shape() {
        // a minimal tx body {0:[],1:[escrow_output]} with the ADA-only coin + inline indefinite datum.
        let addr=[0x70u8].iter().chain([0xAB;28].iter()).cloned().collect::<Vec<u8>>();
        let recip=[0x33u8;32];
        let dat=escrow_datum(&recip, 5_000_000, 1);
        let mut inline=vec![0x82u8,0x01,0xd8,0x18]; inline.extend(bstr(&dat));
        let mut out=vec![0xa3u8]; out.push(0x00); out.extend(bstr(&addr)); out.push(0x01); out.extend(uint(5_000_000)); out.push(0x02); out.extend(inline);
        let mut body=vec![0xa2u8]; body.push(0x00); body.push(0x80); body.push(0x01); body.push(0x81); body.extend(out);
        let (coin,d)=escrow_output(&body,&addr).unwrap();
        assert_eq!(coin, 5_000_000u128);
        assert_eq!(datum_recipient(&d).unwrap(), recip.to_vec());
    }
}
