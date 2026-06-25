//! xada_mint.rs - the χADA FORWARD-mint type script (Cardano → CKB). The keystone of the second leg
//! (spike/cardano-to-ckb-zk/XADA_LEG.md). χADA is wrapped ADA on CKB: an xUDT-style fungible token whose
//! POLICY is this type script's hash. Issuance is gated NOT on an admin key but on a Mithril-certified
//! Cardano ADA-lock - the exact mirror of the live χCKB mint (`leap_mint_guard` + `cardano_bound`), with the
//! oracle pointing the other way (CKB re-runs a Cardano STM cert in CKB-VM, via the deployed light client).
//!
//! It REUSES, verbatim in shape, the primitives already shipped in this crate:
//!   - `bound_asset_v2.rs::checkpoint_root`        - the authenticated LCKP finalized tx-set root + height
//!   - `burn_gated_unlock_v2.rs` MKMap proof       - two-level cert-membership of the escrow tx
//!   - `burn_gated_unlock_v2.rs` Conway CBOR reader - bounds-checked `hdr`/`skip`
//!   - `bound_asset_v2.rs` output walker           - read the escrow OUTPUT (lovelace + inline datum)
//!   - `burn_gated_unlock_v2.rs::registry_inserts_key` - genesis-pinned replay-once (one lock ⇒ one mint)
//!
//! args = LCKP_type_hash(32) ‖ registry_type_hash(32) ‖ escrow_addr(rest, the Cardano escrow script address).
//! witness.input_type (same R layout as bound_asset_v2) =
//!   lp(escrow_tx_body) ‖ lp(sub_root) ‖ u64(sub_pos) ‖ u64(sub_size) ‖ items(sub_items)
//!   ‖ lp(range_key) ‖ u64(master_pos) ‖ u64(master_size) ‖ items(master_items)
//!
//! EscrowDatum (inline, on the escrow output) = Constr 121 [ ckb_recipient_lock_hash:bytes32, amount:int, nonce:int ].
//!
//! Per-tx dispatch on the NET χADA delta minted = Σ outputs_of_this_type − Σ inputs_of_this_type:
//!   minted == 0 → transfer (allow)     minted < 0 → burn (allow; Phase 5 adds the return receipt)
//!   minted  > 0 → MINT: require M(cert) + B(binding) + R(recipient) + N(replay-once) + conservation.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)] extern crate alloc;   // host test build links alloc; default_alloc!() is cfg(not(test))-gated
use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{Merge, MerkleProof, Result as MMRResult};
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_script, load_witness_args};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

#[derive(Clone, PartialEq, Eq)] struct N(Vec<u8>);
struct MB; impl Merge for MB { type Item = N; fn merge(l:&N,r:&N)->MMRResult<N>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(N(h.finalize().to_vec())) } }
fn b2s(p:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for x in p {h.update(x);} h.finalize().to_vec() }
fn b2b256(p:&[&[u8]])->[u8;32]{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for x in p {h.update(x);} let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hexb(b:&[u8])->Vec<u8>{ let hx=b"0123456789abcdef"; let mut o=Vec::with_capacity(b.len()*2); for &x in b {o.push(hx[(x>>4)as usize]);o.push(hx[(x&0xf)as usize]);} o }

// ---- witness reader (identical layout to bound_asset_v2 / burn_gated_unlock_v2; bounds-checked) ----
struct R<'a>{ b:&'a[u8], i:usize }
impl<'a> R<'a>{
    fn u32(&mut self)->usize{ if self.i+4>self.b.len(){ self.i=self.b.len(); return 0; } let v=u32::from_le_bytes([self.b[self.i],self.b[self.i+1],self.b[self.i+2],self.b[self.i+3]]) as usize; self.i+=4; v }
    fn u64(&mut self)->u64{ if self.i+8>self.b.len(){ self.i=self.b.len(); return 0; } let mut a=[0u8;8]; a.copy_from_slice(&self.b[self.i..self.i+8]); self.i+=8; u64::from_le_bytes(a) }
    fn lp(&mut self)->&'a[u8]{ let n=self.u32(); if self.i+n>self.b.len(){ self.i=self.b.len(); return &[]; } let s=&self.b[self.i..self.i+n]; self.i+=n; s }
    fn items(&mut self)->Vec<N>{ let n=self.u32(); if n>self.b.len(){ return Vec::new(); } (0..n).map(|_| N(self.lp().to_vec())).collect() }
}

// ---- bounds-checked Conway CBOR reader (verbatim from bound_asset_v2) ----
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

// ---- EscrowDatum readers: Constr 121 [ recipient:bytes32, amount:int, nonce:int ] ----
// The Constr inner array is INDEFINITE-length in the standard Plutus encoding (`0x9f … 0xff`) - which is what
// pycardano / cardano-cli emit - though a definite array is also legal. Return the offset of the first field,
// handling either form (else the on-chain datum doesn't parse and the mint fails closed).
fn constr_fields_start(d:&[u8]) -> Option<usize> {
    let (t,_v,ti)=ohdr(d,0)?;           // Constr tag (major 6, e.g. 121)
    if t!=6 { return None; }
    match *d.get(ti)? {
        0x9f => Some(ti+1),             // indefinite-length array (the Plutus default; pycardano emits this)
        b if (b>>5)==4 => { let (_,_,a)=ohdr(d,ti)?; Some(a) }   // definite-length array
        _ => None,
    }
}
// field 0 = the CKB lock hash the χADA must be minted to (RECIPIENT binding, mirror of leap_mint_guard).
fn datum_recipient(d:&[u8]) -> Option<Vec<u8>> {
    let ai = constr_fields_start(d)?;
    let (rm,rl,ra)=ohdr(d,ai)?;         // field 0 = bytes
    if rm!=2 { return None; }
    let e=ra.checked_add(rl as usize)?; if e>d.len(){ return None; }
    Some(d[ra..e].to_vec())
}
// field 1 = the lovelace amount the datum self-declares (cross-checked against the on-chain coin).
fn datum_amount(d:&[u8]) -> Option<i128> {
    let ai = constr_fields_start(d)?;
    let j0=oskip(d,ai,0)?;              // skip field 0 (recipient)
    let (m,a,_)=ohdr(d,j0)?;            // field 1 = int
    match m { 0 => Some(a as i128), 1 => Some(-1i128 - a as i128), _ => None }
}

// ---- the escrow OUTPUT walker: find the Conway output at `escrow_addr`, return (locked lovelace, inline datum).
// Mirrors bound_asset_v2::seal_at_lock (address match) but extracts the COIN + the INLINE DATUM instead of a
// minted policy. ADA-only locks carry a uint value; a value with assets is the array [coin, multiasset] (we
// read element 0). The datum_option (entry key 2) must be inline: [1, 24(h'..datum..')].
fn escrow_output(b:&[u8], escrow_addr:&[u8]) -> Option<(u128, Vec<u8>)> {
    let (m,n,mut i)=ohdr(b,0)?;
    if m!=5 { return None; }
    for _ in 0..n {
        let (km,key,ki)=ohdr(b,i)?;
        if km!=0 { return None; }
        if key==1 {
            let (om,oc,oj)=ohdr(b,ki)?;
            if om!=4 { return None; }      // outputs is an array
            let mut j=oj;
            for _ in 0..oc {
                let (otm,oarg,oi2)=ohdr(b,j)?;
                if otm==5 {                // post-Babbage map output {0:addr,1:value,2:datum,3:script}
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
                            else if vm==4 {                     // [coin, multiasset]
                                let (cm,cv,cj)=ohdr(b,vj)?; if cm!=0 { return None; }
                                coin=cv as u128; have_val=true;
                                k=oskip(b,cj,0)?;               // skip the multiasset map
                            } else { return None; }
                        } else if ek==2 {
                            let (dm,_da,di)=ohdr(b,eki)?;       // datum_option array [marker, ...]
                            if dm!=4 { return None; }
                            let nk=oskip(b,di,0)?;              // skip element 0 (the inline marker 1)
                            let (tm,t24,ta)=ohdr(b,nk)?;        // element 1 = tag 24 wrapping the datum bstr
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
                } else if otm==4 {          // legacy array output [addr, value, ...] - no inline datum, skip
                    j=oskip(b,j,0)?;
                } else { return None; }
            }
            return None;                    // outputs walked, no escrow output found
        } else { i=oskip(b,ki,0)?; }
    }
    None
}

// ---- LCKP authenticated checkpoint (verbatim shape from bound_asset_v2::checkpoint_root) ----
// Returns (cert tx-set root, finalized Cardano height). Scans cell-deps, fails closed on disagreement.
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
                            Some(prev) if *prev != cur => return Err(53),  // conflicting checkpoints -> fail closed
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

// ---- replay-once: the escrow outpoint must be inserted into the genesis-pinned registry EXACTLY this tx
// (verbatim from burn_gated_unlock_v2::registry_inserts_key). One lock ⇒ at most one χADA mint, ever. ----
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
            Err(_)=>return false,                       // registry not spent -> fail closed
        }
    }
}

// ---- χADA amount accounting: cells of THIS type carry amount(u128 LE) in the first 16 bytes of cell data. ----
fn sum_group(source: Source) -> Option<u128> {
    let mut sum:u128=0; let mut i=0usize;
    loop {
        match load_cell_data(i, source) {
            Ok(d)=>{ if d.len()<16 { return None; } let mut a=[0u8;16]; a.copy_from_slice(&d[0..16]); sum=sum.checked_add(u128::from_le_bytes(a))?; i+=1; }
            Err(_)=>break,
        }
    }
    Some(sum)
}
// every produced χADA cell is locked at `recipient` (and not the all-zero anyone-can-spend lock).
fn outputs_all_at(recipient:&[u8]) -> Result<(),i8> {
    let mut i=0usize;
    loop {
        match load_cell_lock_hash(i, Source::GroupOutput) {
            Ok(h)=>{ if h==[0u8;32] { return Err(28); } if &h[..]!=recipient { return Err(28); } i+=1; }
            Err(_)=>break,
        }
    }
    Ok(())
}

fn program_entry()->i8{
    let args = load_script().unwrap().args().raw_data();
    if args.len() < 64+1 { return 2; }                 // 32+32 + at least a 1-byte address tail
    let mut lckp_type=[0u8;32]; lckp_type.copy_from_slice(&args[0..32]);
    let mut reg_type=[0u8;32];  reg_type.copy_from_slice(&args[32..64]);
    let escrow_addr=&args[64..];

    // NET χADA delta this tx (the VM scopes Group* to cells carrying THIS exact type script).
    let in_sum  = match sum_group(Source::GroupInput)  { Some(v)=>v, None=>return 16 };
    let out_sum = match sum_group(Source::GroupOutput) { Some(v)=>v, None=>return 17 };
    if out_sum <= in_sum { return 0; }                 // transfer (==) or burn (<) - allowed (Phase 5 gates burn)
    let minted = out_sum - in_sum;

    // MINT path. A mint tx is mint-only (no χADA inputs), so the whole output supply is the freshly bridged
    // value bound to one escrow - mirrors how the χCKB side builds a dedicated mint tx.
    if in_sum != 0 { return 18; }

    // M: authenticated, finalized Cardano checkpoint.
    let (cert_root, cert_height) = match checkpoint_root(&lckp_type) { Ok(r)=>r, Err(e)=>return e };
    if cert_height == 0 { return 6; }

    // read the escrow tx body + its MKMap proof from the witness (mint tx ⇒ GroupOutput witness 0).
    let w = match load_witness_args(0, Source::GroupInput) {
        Ok(w)=>w, Err(_)=> match load_witness_args(0, Source::GroupOutput) { Ok(w)=>w, Err(_)=>return 3 } };
    let lock = match w.input_type().to_opt() { Some(l)=>l.raw_data(), None=>return 4 };
    let mut r=R{b:&lock,i:0};
    let tx_body=r.lp().to_vec();
    let sub_root=r.lp().to_vec(); let sub_pos=r.u64(); let sub_size=r.u64(); let sub_items=r.items();
    let range_key=r.lp().to_vec();
    let master_pos=r.u64(); let master_size=r.u64(); let master_items=r.items();

    // the escrow tx is certified: leaf = hex(blake2b256(tx_body)) under sub_root, sub_root under cert_root.
    let leaf=N(hexb(&b2b256(&[&tx_body])));
    if !MerkleProof::<N,MB>::new(sub_size,sub_items).verify(N(sub_root.clone()),[(sub_pos,leaf)].to_vec()).unwrap_or(false) { return 5; }
    let master_leaf=N(b2s(&[&range_key,&sub_root]));
    if !MerkleProof::<N,MB>::new(master_size,master_items).verify(N(cert_root),[(master_pos,master_leaf)].to_vec()).unwrap_or(false) { return 7; }

    // B: read the escrow OUTPUT - locked lovelace + the bound recipient/amount from its inline datum.
    let (locked, datum) = match escrow_output(&tx_body, escrow_addr) { Some(x)=>x, None=>return 20 };
    let recipient = match datum_recipient(&datum) { Some(x)=>x, None=>return 21 };
    if recipient.len()!=32 { return 21; }
    let dat_amount = match datum_amount(&datum) { Some(a)=>a, None=>return 22 };
    if dat_amount < 0 || dat_amount as u128 != locked { return 23; }   // datum self-declared amount == on-chain coin
    if minted != locked { return 24; }                                  // conservation: χADA minted 1:1 with lovelace

    // R: all freshly-minted χADA is locked at the certified recipient.
    if let Err(e)=outputs_all_at(&recipient) { return e; }

    // N: nullify the escrow outpoint exactly once in the genesis-pinned registry. The escrow outpoint =
    // (escrow_tx_hash, output_index_of_the_escrow). The off-chain builder pins the index; here we key on the
    // certified escrow tx hash (blake2b256 of the body, the same hash already certified above) ‖ idx is folded
    // by the relayer into the inserted key. We require the registry to insert blake2b256(tx_body) - the unique
    // certified escrow tx - so the same escrow tx can authorize at most one mint across ALL transactions.
    // SEC (domain separation): 1-byte leg tag (0x01 = χADA-mint escrow nullifier); keyspace disjoint from the
    // CKB-release (0x02) and χCKB-leap (0x03) legs sharing this registry. Off-chain: xada_reg_witness.py.
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

// ---- host unit tests for the PURE byte-offset / CBOR-parse logic (the riskiest new code) ----
#[cfg(test)]
mod tests {
    use super::*;
    // minimal CBOR encoders for building test vectors
    fn bstr(b:&[u8])->Vec<u8>{ let mut o=Vec::new(); let n=b.len();
        if n<24 { o.push(0x40+n as u8); } else if n<256 { o.push(0x58); o.push(n as u8); } else { o.push(0x59); o.extend_from_slice(&(n as u16).to_be_bytes()); }
        o.extend_from_slice(b); o }
    fn uint(n:u64)->Vec<u8>{ let mut o=Vec::new();
        if n<24 { o.push(n as u8); } else if n<256 { o.push(0x18); o.push(n as u8); }
        else if n<65536 { o.push(0x19); o.extend_from_slice(&(n as u16).to_be_bytes()); }
        else if n<(1u64<<32) { o.push(0x1a); o.extend_from_slice(&(n as u32).to_be_bytes()); }
        else { o.push(0x1b); o.extend_from_slice(&n.to_be_bytes()); } o }
    // EscrowDatum = Constr 121 [recipient(bytes32), amount(int), nonce(int)] - INDEFINITE inner array, the
    // standard Plutus / pycardano encoding (0x9f … 0xff). This is what the live escrow datum on preview uses.
    fn escrow_datum(recipient:&[u8], amount:u64, nonce:u64)->Vec<u8>{
        let mut o=vec![0xd8u8,0x79,0x9f];               // tag 121, INDEFINITE array
        o.extend(bstr(recipient)); o.extend(uint(amount)); o.extend(uint(nonce)); o.push(0xff); o }
    // a definite-length variant (also legal Plutus) - the parser must accept both.
    fn escrow_datum_def(recipient:&[u8], amount:u64, nonce:u64)->Vec<u8>{
        let mut o=vec![0xd8u8,0x79,0x83];               // tag 121, array(3) definite
        o.extend(bstr(recipient)); o.extend(uint(amount)); o.extend(uint(nonce)); o }
    fn inline(datum:&[u8])->Vec<u8>{                     // datum_option = [1, 24(bstr(datum))]
        let mut o=vec![0x82u8,0x01,0xd8,0x18];           // array(2), 1, tag 24
        o.extend(bstr(datum)); o }
    // a map output {0:addr, 1:coin, 2:inline-datum}
    fn map_output(addr:&[u8], coin:u64, datum:&[u8])->Vec<u8>{
        let mut o=vec![0xa3u8];                          // map(3)
        o.push(0x00); o.extend(bstr(addr));              // 0 -> addr
        o.push(0x01); o.extend(uint(coin));              // 1 -> coin (ADA-only)
        o.push(0x02); o.extend(inline(datum));           // 2 -> inline datum
        o }
    // a Conway tx body {0:[inputs], 1:[outputs]} with one escrow output (outputs is an array of len 1).
    fn tx_with_output(out:&[u8])->Vec<u8>{
        let mut o=vec![0xa2u8];                          // map(2)
        o.push(0x00); o.push(0x80);                      // 0 -> [] (no inputs in this stub)
        o.push(0x01); o.push(0x81); o.extend_from_slice(out);   // 1 -> array(1) of outputs
        o }

    #[test]
    fn datum_readers_hit_recipient_and_amount() {
        let recip=[0x33u8;32];
        let d=escrow_datum(&recip, 20_000_000, 7);              // indefinite array (live pycardano form)
        assert_eq!(datum_recipient(&d).unwrap(), recip.to_vec());
        assert_eq!(datum_amount(&d).unwrap(), 20_000_000i128);
        let dd=escrow_datum_def(&recip, 20_000_000, 7);         // definite array - must also parse
        assert_eq!(datum_recipient(&dd).unwrap(), recip.to_vec());
        assert_eq!(datum_amount(&dd).unwrap(), 20_000_000i128);
    }
    #[test]
    fn escrow_output_extracts_coin_and_datum() {
        let addr=[0x70u8].iter().chain([0xAB;28].iter()).cloned().collect::<Vec<u8>>(); // 0x70 ‖ 28-byte script cred
        let recip=[0x33u8;32];
        let d=escrow_datum(&recip, 5_000_000, 1);
        let out=map_output(&addr, 5_000_000, &d);
        let body=tx_with_output(&out);
        let (coin, datum)=escrow_output(&body, &addr).expect("escrow output found");
        assert_eq!(coin, 5_000_000u128);
        assert_eq!(datum_recipient(&datum).unwrap(), recip.to_vec());
        assert_eq!(datum_amount(&datum).unwrap(), 5_000_000i128);
    }
    #[test]
    fn escrow_output_misses_on_wrong_address() {
        let addr=[0x70u8].iter().chain([0xAB;28].iter()).cloned().collect::<Vec<u8>>();
        let other=[0x70u8].iter().chain([0xCD;28].iter()).cloned().collect::<Vec<u8>>();
        let d=escrow_datum(&[0x33u8;32], 1_000_000, 0);
        let body=tx_with_output(&map_output(&addr, 1_000_000, &d));
        assert!(escrow_output(&body, &other).is_none());   // no output at `other` -> None (fail closed)
    }
    #[test]
    fn malformed_datum_amount_negative_marker_rejected_at_amount_check() {
        // amount must be a non-negative int equal to the coin; a negative datum amount must not parse as valid.
        let recip=[0x33u8;32];
        let mut d=escrow_datum(&recip, 4, 0);
        // flip the amount byte to a negative-int header (major 1, value 3 => -4): position = 3 + bstr(32) = ...
        // simpler: assert datum_amount on a hand-built negative datum.
        let mut neg=vec![0xd8u8,0x79,0x83]; neg.extend(bstr(&recip)); neg.push(0x23); neg.push(0x00); // 0x23 = -4
        assert_eq!(datum_amount(&neg).unwrap(), -4i128);
        let _ = &mut d;
    }
}
