//! cert_verify.rs - PARAMETERIZED Mithril cert verifier for CKB-VM. Instead of an embedded fixture cert,
//! it parses the cert from a WITNESS cell (a cellDep whose data starts "MWIT", produced by the relayer's
//! transcode_witness). So the light client can verify ANY live Mithril CardanoTransactions cert. Checks:
//! M1 (signed_message=Sha256(parts)) + BLS-STM aggregate + per-signer stake lottery + Merkle batch + quorum.
//! Standalone build: verifies the witness self-consistently (avk from the witness), returns 0 iff valid.
//! Deploy build: additionally binds the witness avk_root to an authenticated AVK checkpoint cellDep and
//! publishes LCKP||tx_root in the output (an authenticated tx-set checkpoint).
#![no_std]
#![no_main]
use alloc::{vec::Vec, vec};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, pairing, hash_to_curve::{HashToCurve, ExpandMsgXmd}};
use num_bigint::{BigInt, Sign};
use sha2::{Sha256, Digest as _};
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::load_cell_data;
use ckb_std::error::SysError;
// the canonical (genesis-pinned) advance-verifier's TYPE-SCRIPT HASH - used ONLY by the TxSetCert/deploy
// mode (cfg-gated so it can't change the advance binary's own codeHash). The avk is trusted ONLY from a
// checkpoint cell carrying this type, so it traces to the one pinned genesis chain, not an attacker cell.
#[cfg(all(not(feature="standalone"),not(feature="embedtest"),not(feature="advance")))]
const ADV_TYPEHASH: [u8;32] = [61,46,217,28,220,35,177,114,122,24,154,143,88,60,80,37,36,200,137,112,46,65,80,40,251,149,205,87,41,246,49,40]; // = type-hash of the canonical advance verifier (re-baked for the STM-pinned + singleton-guarded cv_advance 0x97c650d0)
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

const C_NUM: i64 = -251237303637201; const C_DEN: i64 = 1125899906842624; const SHIFT: u32 = 768;
// SEC (STM quorum hardening): the network STM protocol parameters are PINNED, not taken from the witness.
// Without this, a forged MWIT witness can set k=1 and/or out-of-range lottery indices and pass `check_lottery`
// with SUB-QUORUM stake - collapsing the security from "stake majority" to "a single compromised SPO key".
// preview: k=1944, m=16948, phi_f=0.2 (phi_f IS the C_NUM/C_DEN ratio = ln(0.8)). Build-overridable per
// network via CHIRAL_STM_K / CHIRAL_STM_M (mainnet has different k/m).
const fn cdec(s:&str)->u64{ let b=s.as_bytes(); let mut v=0u64; let mut i=0; while i<b.len(){ v=v*10+(b[i]-b'0') as u64; i+=1; } v }
const STM_K: usize = match option_env!("CHIRAL_STM_K"){ Some(s)=>cdec(s) as usize, None=>1944 };
const STM_M: u64   = match option_env!("CHIRAL_STM_M"){ Some(s)=>cdec(s),          None=>16948 };

struct Signer { sigma: Vec<u8>, mvk: Vec<u8>, stake: u64, idx: Vec<u32> }
#[allow(dead_code)] // some fields (e.g. tx_root) are read only in deploy/txset mode, not in advance/standalone
struct Cert {
    signed_message: Vec<u8>, avk_root: Vec<u8>, total: u64, k: usize,
    parts: Vec<(Vec<u8>,Vec<u8>)>, signers: Vec<Signer>,
    nr_leaves: usize, mindices: Vec<usize>, bvals: Vec<Vec<u8>>, tx_root: Vec<u8>,
}
struct Cur<'a>{ b:&'a[u8], p:usize }
impl<'a> Cur<'a>{
    fn u8(&mut self)->usize{ let v=self.b[self.p] as usize; self.p+=1; v }
    fn u16(&mut self)->usize{ let v=self.b[self.p] as usize | ((self.b[self.p+1] as usize)<<8); self.p+=2; v }
    fn u32(&mut self)->u32{ let s=&self.b[self.p..self.p+4]; self.p+=4; (s[0]as u32)|((s[1]as u32)<<8)|((s[2]as u32)<<16)|((s[3]as u32)<<24) }
    fn u64le(&mut self)->u64{ let mut v=0u64; for i in 0..8{v|=(self.b[self.p+i]as u64)<<(8*i);} self.p+=8; v }
    fn u64be(&mut self)->u64{ let mut v=0u64; for i in 0..8{v=(v<<8)|self.b[self.p+i]as u64;} self.p+=8; v }
    fn take(&mut self,n:usize)->Vec<u8>{ let v=self.b[self.p..self.p+n].to_vec(); self.p+=n; v }
}
fn parse(w:&[u8])->Option<Cert>{
    if w.len()<4 || &w[0..4]!=b"MWIT" { return None; }
    let mut c=Cur{b:w,p:4};
    let signed_message=c.take(32); let avk_root=c.take(32); let total=c.u64le(); let k=c.u64le() as usize;
    let np=c.u8(); let mut parts=Vec::new();
    for _ in 0..np { let kl=c.u8(); let key=c.take(kl); let vl=c.u16(); let val=c.take(vl); parts.push((key,val)); }
    let ns=c.u8(); let mut signers=Vec::new();
    for _ in 0..ns { let sigma=c.take(48); let mvk=c.take(96); let stake=c.u64be(); let ni=c.u16();
        let mut idx=Vec::with_capacity(ni); for _ in 0..ni { idx.push(c.u32()); } signers.push(Signer{sigma,mvk,stake,idx}); }
    let nr_leaves=c.u16(); let nm=c.u8(); let mut mindices=Vec::new(); for _ in 0..nm { mindices.push(c.u16()); }
    let nb=c.u8(); let mut bvals=Vec::new(); for _ in 0..nb { bvals.push(c.take(32)); }
    let tx_root=c.take(32);
    Some(Cert{signed_message,avk_root,total,k,parts,signers,nr_leaves,mindices,bvals,tx_root})
}
fn b2b256(parts:&[&[u8]])->Vec<u8>{ let mut h=blake2b_ref::Blake2bBuilder::new(32).build(); for p in parts{h.update(p);} let mut o=[0u8;32]; h.finalize(&mut o); o.to_vec() }
fn ev_le(msgp:&[u8],index:u64,sigma:&[u8])->[u8;64]{ let mut h=blake2b_ref::Blake2bBuilder::new(64).build(); h.update(b"map"); h.update(msgp); h.update(&index.to_le_bytes()); h.update(sigma); let mut o=[0u8;64]; h.finalize(&mut o); o }
fn hexlow(b:&[u8])->Vec<u8>{ let h=b"0123456789abcdef"; let mut o=vec![0u8;b.len()*2]; for(i,&x)in b.iter().enumerate(){o[2*i]=h[(x>>4)as usize];o[2*i+1]=h[(x&0xf)as usize];} o }
fn compute_target(stake:u64,total:u64)->BigInt{
    let s=BigInt::from(1u8)<<SHIFT; let xa=BigInt::from(stake)*BigInt::from(C_NUM); let xb=BigInt::from(total)*BigInt::from(C_DEN);
    let mut t=s.clone(); let mut acc=s.clone(); let mut n:u64=0;
    loop{ n+=1; t=&t*&xa; t=&t/&xb; t=&t/&BigInt::from(n); if t==BigInt::from(0u8){break;} acc+=&t; if n>400{break;} }
    let e=&acc>>(SHIFT-512); (BigInt::from(1u8)<<512)-e
}
#[allow(deprecated)] // sha2 0.9 GenericArray::as_slice (view, behavior-identical); upgrade generic-array to drop
fn check_m1(ct:&Cert)->bool{
    let mut h=Sha256::new(); for(k,v)in &ct.parts{ sha2::Digest::update(&mut h,k); sha2::Digest::update(&mut h,v); }
    let d=h.finalize();
    d.as_slice()==ct.signed_message.as_slice()   // base M1: signed_message = Sha256(parts) - any cert type
}
fn check_bls(ct:&Cert,msgp:&[u8])->bool{
    let mut agg_sig=G1Projective::identity(); let mut agg_mvk=G2Projective::identity();
    for s in &ct.signers{
        let sg=G1Affine::from_compressed(&s.sigma.clone().try_into().ok().unwrap()); let mv=G2Affine::from_compressed(&s.mvk.clone().try_into().ok().unwrap());
        if bool::from(sg.is_none()|mv.is_none()){ return false; }
        agg_sig+=G1Projective::from(sg.unwrap()); agg_mvk+=G2Projective::from(mv.unwrap());
    }
    let hm:G1Affine=<G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msgp,b"").into();
    pairing(&G1Affine::from(agg_sig),&G2Affine::generator())==pairing(&hm,&G2Affine::from(agg_mvk))
}
fn check_lottery(ct:&Cert,msgp:&[u8])->bool{
    // SEC (quorum pin): the witness-declared k must equal the PINNED network k. A real cert always carries the
    // network k (= STM_K); a forged witness that sets k=1 to pass a sub-quorum is rejected here, fast.
    if ct.k != STM_K { return false; }
    // SEC A7: each signer's lottery indices MUST be STRICTLY INCREASING (hence unique). Otherwise a signer
    // repeats one winning index to inflate `count >= k` without genuinely controlling quorum stake - an STM
    // soundness break (a sub-quorum forges a "valid" cert).
    let mut count=0usize;
    for s in &ct.signers{ let t=compute_target(s.stake,ct.total);
        let mut prev: i64 = -1;
        for &i in &s.idx{
            if (i as i64) <= prev { return false; }   // not strictly increasing => duplicate/disordered
            prev = i as i64;
            // SEC (index bound): every lottery index MUST be within the m slots. Without this a low-stake
            // signer farms wins by trying indices beyond m until it accumulates k - defeating the threshold.
            if (i as u64) >= STM_M { return false; }
            if BigInt::from_bytes_le(Sign::Plus,&ev_le(msgp,i as u64,&s.sigma))>=t{ return false; } count+=1; } }
    count>=STM_K   // PINNED network quorum, NOT the witness-supplied ct.k
}
fn npow2(n:usize)->usize{ let mut p=1; while p<n{p<<=1;} p }
fn check_merkle(ct:&Cert)->bool{
    fn parent(i:usize)->usize{(i-1)/2} fn sibling(i:usize)->usize{ if i%2==1{i+1}else{i-1} }
    let npo=npow2(ct.nr_leaves); let nr_nodes=ct.nr_leaves+npo-1;
    let mut oi:Vec<usize>=ct.mindices.iter().map(|i| i+npo-1).collect();
    let mut leaves:Vec<Vec<u8>>=ct.signers.iter().map(|s| b2b256(&[&s.mvk,&s.stake.to_be_bytes()])).collect();
    let mut vals:Vec<Vec<u8>>=ct.bvals.clone();
    let zero=b2b256(&[&[0u8]]); let mut idx=oi[0];
    while idx>0{
        let mut nh:Vec<Vec<u8>>=Vec::new(); let mut ni:Vec<usize>=Vec::new(); let mut i=0; idx=parent(idx);
        while i<oi.len(){
            ni.push(parent(oi[i]));
            if oi[i]&1==0 { let h=b2b256(&[&vals[0],&leaves[i]]); nh.push(h); vals.remove(0); }
            else { let sib=sibling(oi[i]);
                if i<oi.len()-1 && oi[i+1]==sib { nh.push(b2b256(&[&leaves[i],&leaves[i+1]])); i+=1; }
                else if sib<nr_nodes { let h=b2b256(&[&leaves[i],&vals[0]]); nh.push(h); vals.remove(0); }
                else { nh.push(b2b256(&[&leaves[i],&zero])); } }
            i+=1;
        }
        leaves=nh; oi=ni;
    }
    leaves.len()==1 && leaves[0]==ct.avk_root
}
#[allow(dead_code)] // used by the deploy/txset + advance program_entry; not by the embedtest fixture mode
fn witness_from_celldep()->Option<Vec<u8>>{
    let mut i=0usize;
    loop{ match load_cell_data(i,Source::CellDep){
        Ok(d)=>{ if d.len()>=4 && &d[0..4]==b"MWIT"{ return Some(d); } i+=1; }
        Err(SysError::IndexOutOfBound)=>return None, Err(_)=>return None } }
}
#[cfg(all(not(feature="standalone"),not(feature="embedtest"),not(feature="advance")))]
fn avk_checkpoint()->Option<([u8;32],u64)>{
    let mut i=0usize;
    loop{ match load_cell_data(i,Source::CellDep){
        Ok(d)=>{ if d.len()==48 {
            // the 48-byte avk cell must be a real checkpoint: carry the canonical advance-verifier type
            if let Ok(Some(th))=ckb_std::high_level::load_cell_type_hash(i,Source::CellDep){
                // return BOTH the avk root (d[8..40]) AND the authenticated total stake (d[40..48], LE) so the
                // deploy path can anchor ct.total - else a forged witness deflates total to weaken the lottery.
                if th==ADV_TYPEHASH { let mut r=[0u8;32]; r.copy_from_slice(&d[8..40]); let mut t=[0u8;8]; t.copy_from_slice(&d[40..48]); return Some((r, u64::from_le_bytes(t))); }
            }
        } i+=1; }
        Err(SysError::IndexOutOfBound)=>return None, Err(_)=>return None } }
}
fn verify(ct:&Cert)->bool{
    let mut msgp=hexlow(&ct.signed_message); msgp.extend_from_slice(&ct.avk_root);
    check_m1(ct) && check_bls(ct,&msgp) && check_lottery(ct,&msgp) && check_merkle(ct)
}



// ---- AdvanceCert: extract the NEXT avk (root+total) from the signed next_aggregate_verification_key part ----
fn part_val<'a>(ct:&'a Cert, key:&[u8])->Option<&'a [u8]>{ for (k,v) in &ct.parts { if k.as_slice()==key { return Some(v); } } None }
#[allow(dead_code)] // AdvanceCert helper: used only by the cfg("advance") program_entry; dead in deploy/txset
fn hexdec(a:&[u8])->Vec<u8>{ fn nyb(c:u8)->u8{ match c { b'0'..=b'9'=>c-b'0', b'a'..=b'f'=>c-b'a'+10, b'A'..=b'F'=>c-b'A'+10, _=>0 } } let mut o=Vec::with_capacity(a.len()/2); let mut i=0; while i+1<a.len(){ o.push((nyb(a[i])<<4)|nyb(a[i+1])); i+=2; } o }
#[allow(dead_code)] // AdvanceCert helper (cfg("advance") only)
fn find(h:&[u8], n:&[u8])->Option<usize>{ if n.len()>h.len(){return None;} let mut i=0; while i+n.len()<=h.len(){ if &h[i..i+n.len()]==n { return Some(i); } i+=1; } None }
fn parse_uint(b:&[u8], mut i:usize)->(u64,usize){ let mut v=0u64; while i<b.len() && b[i]>=b'0' && b[i]<=b'9' { v=v*10+(b[i]-b'0')as u64; i+=1; } (v,i) }
#[allow(dead_code)] // AdvanceCert helper (cfg("advance") only)
fn extract_next(json:&[u8])->Option<([u8;32],u64)>{
    let pat_root:&[u8]=&[34,114,111,111,116,34,58,91];           // "root":[
    let pat_total:&[u8]=&[34,116,111,116,97,108,95,115,116,97,107,101,34,58]; // "total_stake":
    let r0=find(json, pat_root)?+pat_root.len();
    let mut root=[0u8;32]; let mut idx=0; let mut i=r0;
    while i<json.len() && idx<32 {
        if json[i]>=b'0' && json[i]<=b'9' { let (v,ni)=parse_uint(json,i); root[idx]=v as u8; idx+=1; i=ni; }
        else if json[i]==b']' { break; } else { i+=1; }
    }
    if idx!=32 { return None; }
    let t0=find(json, pat_total)?+pat_total.len(); let (total,_)=parse_uint(json,t0);
    Some((root,total))
}
#[allow(dead_code)] // AdvanceCert helper (cfg("advance") only)
fn read_ck(src:Source)->Option<(u64,[u8;32],u64)>{ let d=load_cell_data(0,src).ok()?; if d.len()!=48 {return None;} let mut e=[0u8;8]; e.copy_from_slice(&d[0..8]); let mut r=[0u8;32]; r.copy_from_slice(&d[8..40]); let mut t=[0u8;8]; t.copy_from_slice(&d[40..48]); Some((u64::from_le_bytes(e), r, u64::from_le_bytes(t))) }
#[allow(dead_code)] // AdvanceCert helper (cfg("advance") only)
fn epoch_of(ct:&Cert)->Option<u64>{ let v=part_val(ct,b"current_epoch")?; let (e,_)=parse_uint(v,0); Some(e) }
// The ONE canonical trusted genesis (epoch 1319, avk 0f3c0c7f.., total). Pinning it means a fake-avk
// checkpoint chain CANNOT be created - so any cell carrying this type traces to the real Cardano stake.
#[allow(dead_code)] // read only by the cfg("advance") program_entry (genesis branch); dead in deploy/txset
const PINNED_GENESIS: [u8;48] = [39,5,0,0,0,0,0,0,15,60,12,127,134,236,178,138,205,194,254,3,103,90,12,67,234,0,244,85,46,131,188,98,13,67,41,100,111,63,233,218,61,139,157,218,67,58,0,0];
#[cfg(feature="advance")]
fn program_entry()->i8{
    // GENESIS: no input checkpoint -> the output MUST be the one pinned canonical genesis.
    if read_ck(Source::GroupInput).is_none() {
        // SEC (singleton, RQ-SG): a CKB type script runs ONCE per group and here validated only
        // GroupOutput[0]. Without this guard an attacker rides a SECOND output carrying this same
        // trusted type but arbitrary (forged) avk data; deploy/txset consumers (avk_checkpoint) then
        // accept it by type-hash alone -> forged cert -> unbacked mint. Forbid any sibling cell.
        if load_cell_data(0,Source::GroupInput).is_ok() { return 41; }   // no input may wear this type at genesis
        if load_cell_data(1,Source::GroupOutput).is_ok() { return 40; }  // exactly one genesis output
        match load_cell_data(0,Source::GroupOutput) {
            Ok(od) if od.len()==48 && od.as_slice()==&PINNED_GENESIS[..] => return 0,
            _ => return 7,
        }
    }
    // ADVANCE: verify the cert against the input checkpoint's avk, roll forward to the next avk.
    // SEC (singleton, RQ-SG): exactly ONE checkpoint in this type group on each side - no forged sibling.
    if load_cell_data(1,Source::GroupInput).is_ok() { return 42; }
    if load_cell_data(1,Source::GroupOutput).is_ok() { return 43; }
    let w=match witness_from_celldep(){Some(w)=>w,None=>return 1};
    let ct=match parse(&w){Some(c)=>c,None=>return 2};
    let cert_epoch=match epoch_of(&ct){Some(e)=>e,None=>return 8};
    let out=match read_ck(Source::GroupOutput){Some(o)=>o,None=>return 4};
    let (ie,ia,it)=read_ck(Source::GroupInput).unwrap();
    if ie!=cert_epoch { return 10; }
    if ia[..]!=ct.avk_root[..] || it!=ct.total { return 11; }
    if !verify(&ct){ return 20; }
    let nx=match part_val(&ct,b"next_aggregate_verification_key"){Some(v)=>v,None=>return 12};
    let (nroot,ntotal)=match extract_next(&hexdec(nx)){Some(x)=>x,None=>return 13};
    if out.0==ie+1 && out.1==nroot && out.2==ntotal { 0 } else { 5 }
}

#[cfg(feature="embedtest")]
fn program_entry()->i8{
    let w=include_bytes!("/tmp/cert_witness.bin");
    let ct=match parse(w){Some(c)=>c,None=>return 2};
    if verify(&ct){0}else{20}
}
#[cfg(all(feature="standalone",not(feature="embedtest"),not(feature="advance")))]
fn program_entry()->i8{
    let w=match witness_from_celldep(){Some(w)=>w,None=>return 1};
    let ct=match parse(&w){Some(c)=>c,None=>return 2};
    if verify(&ct){0}else{20}
}
#[cfg(all(not(feature="standalone"),not(feature="embedtest"),not(feature="advance")))]
fn program_entry()->i8{
    // SEC (singleton, RQ-SG): this LCKP type validated only GroupOutput[0]; forbid a forged sibling
    // checkpoint riding a SECOND group output (or input). Downstream (xada_mint/bound_asset) trusts an
    // LCKP cell by its type-hash, so an unvalidated sibling would be a forged certified snapshot.
    if load_cell_data(1,Source::GroupInput).is_ok() { return 44; }
    if load_cell_data(1,Source::GroupOutput).is_ok() { return 45; }
    let w=match witness_from_celldep(){Some(w)=>w,None=>return 1};
    let ct=match parse(&w){Some(c)=>c,None=>return 2};
    // bind the witness avk AND total stake to an authenticated AVK checkpoint cellDep
    let (avk, ck_total)=match avk_checkpoint(){Some(a)=>a,None=>return 3};
    if ct.avk_root.as_slice()!=&avk[..]{ return 6; }
    if ct.total != ck_total { return 17; }   // SEC: anchor total stake (deflating it weakens the lottery target)
    if !verify(&ct){ return 20; }
    // bind tx_root to the signed cardano_transactions_merkle_root part (so the published root is the cert's)
    match part_val(&ct, b"cardano_transactions_merkle_root") { Some(v) if v==hexlow(&ct.tx_root).as_slice() => {}, _ => return 14 }
    // SEC M2: the Cardano tip height is AUTHENTICATED - `latest_block_number` is a signed cert part (committed
    // by check_m1's Sha256(parts)==signed_message + the BLS aggregate). Publish it next to the root so leap
    // consumers bind to the certified snapshot's EXPLICIT finalized height (Mithril certifies immutable data,
    // so this height is final; surfacing it makes the inherited finality on-chain-checkable, not assumed).
    let height = match part_val(&ct, b"latest_block_number") { Some(v) => parse_uint(v, 0).0, None => return 15 };
    let hb = height.to_le_bytes();
    // M2 monotonic: when this checkpoint is ADVANCED (a previous LCKP is spent in the same group), the new
    // height must NOT regress - so the canonical checkpoint cannot roll back to a staler snapshot.
    if let Ok(prev) = load_cell_data(0, Source::GroupInput) {
        if prev.len() >= 44 && &prev[0..4]==b"LCKP" {
            let mut ph=[0u8;8]; ph.copy_from_slice(&prev[36..44]);
            if height < u64::from_le_bytes(ph) { return 16; }
        }
    }
    // publish LCKP || tx_root(32) || latest_block_number(8 LE)  (44 bytes)
    match load_cell_data(0,Source::GroupOutput){
        Ok(o)=> if o.len()==44 && &o[0..4]==b"LCKP" && &o[4..36]==ct.tx_root.as_slice() && o[36..44]==hb {0} else {5},
        Err(_)=>4 }
}
