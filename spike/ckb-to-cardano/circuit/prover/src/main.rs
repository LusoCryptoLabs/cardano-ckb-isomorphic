//! Differential tests + constraint counts for the CKB-consensus gadgets vs native references.
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget, merkle_gadget};

use ark_bls12_381::Fr;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use eaglesong::eaglesong as native_eaglesong;
use blake2b_rs::Blake2bBuilder;

fn ckbhash(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(data); let mut o = [0u8; 32]; h.finalize(&mut o); o
}

// ---------- Eaglesong ----------
struct EaglesongCircuit { input: Vec<u8>, expected: [u8;32] }
impl ConstraintSynthesizer<Fr> for EaglesongCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let inv: Vec<UInt8<Fr>> = self.input.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
        let out = eaglesong_gadget::eaglesong(&inv)?;
        for k in 0..32 { let e = UInt8::new_input(cs.clone(), || Ok(self.expected[k]))?; out[k].enforce_equal(&e)?; }
        Ok(())
    }
}
fn run_eag(input: Vec<u8>) -> (bool, usize) {
    let mut expected = [0u8;32]; native_eaglesong(&input, &mut expected);
    let cs = ConstraintSystem::<Fr>::new_ref();
    EaglesongCircuit { input, expected }.generate_constraints(cs.clone()).unwrap();
    (cs.is_satisfied().unwrap(), cs.num_constraints())
}

// ---------- Blake2b / ckbhash ----------
struct Blake2bCircuit { input: Vec<u8>, expected:[u8;32] }
impl ConstraintSynthesizer<Fr> for Blake2bCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let inv: Vec<UInt8<Fr>> = self.input.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
        let out = blake2b_gadget::blake2b256(&inv, b"ckb-default-hash")?;
        for k in 0..32 { let e=UInt8::new_input(cs.clone(), || Ok(self.expected[k]))?; out[k].enforce_equal(&e)?; }
        Ok(())
    }
}
fn run_blake(input: Vec<u8>) -> (bool, usize) {
    let expected = ckbhash(&input);
    let cs = ConstraintSystem::<Fr>::new_ref();
    Blake2bCircuit { input, expected }.generate_constraints(cs.clone()).unwrap();
    (cs.is_satisfied().unwrap(), cs.num_constraints())
}

// ---------- Merkle membership (CBMT/MMR mechanism) ----------
fn native_merkle_root(leaf: [u8;32], path: &[([u8;32], bool)]) -> [u8;32] {
    let mut cur = leaf;
    for (sib, leaf_is_left) in path {
        let mut c = Vec::with_capacity(64);
        if *leaf_is_left { c.extend_from_slice(&cur); c.extend_from_slice(sib); }
        else { c.extend_from_slice(sib); c.extend_from_slice(&cur); }
        cur = ckbhash(&c);
    }
    cur
}
struct MerkleCircuit { leaf:[u8;32], path: Vec<([u8;32],bool)>, root:[u8;32] }
impl ConstraintSynthesizer<Fr> for MerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let leaf: Vec<UInt8<Fr>> = self.leaf.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
        let mut path = Vec::new();
        for (sib, d) in &self.path {
            let sv: Vec<UInt8<Fr>> = sib.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
            let dv = Boolean::new_witness(cs.clone(), || Ok(*d))?;
            path.push((sv, dv));
        }
        let got = merkle_gadget::merkle_root(&leaf, &path)?;
        for k in 0..32 { let e=UInt8::new_input(cs.clone(), || Ok(self.root[k]))?; got[k].enforce_equal(&e)?; }
        Ok(())
    }
}
fn run_merkle(depth: usize) -> (bool, usize) {
    let leaf=[7u8;32];
    let path: Vec<([u8;32],bool)> = (0..depth).map(|i| ([(i as u8)+1;32], i%2==0)).collect();
    let root = native_merkle_root(leaf, &path);
    let cs = ConstraintSystem::<Fr>::new_ref();
    MerkleCircuit { leaf, path, root }.generate_constraints(cs.clone()).unwrap();
    (cs.is_satisfied().unwrap(), cs.num_constraints())
}

// ---------- target compare (PoW <= target) ----------
struct LeqCircuit { a:[u8;32], b:[u8;32] }
impl ConstraintSynthesizer<Fr> for LeqCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a: Vec<UInt8<Fr>> = self.a.iter().map(|x| UInt8::new_witness(cs.clone(), || Ok(*x))).collect::<Result<_,_>>()?;
        let b: Vec<UInt8<Fr>> = self.b.iter().map(|x| UInt8::new_input(cs.clone(), || Ok(*x))).collect::<Result<_,_>>()?;
        merkle_gadget::enforce_leq_be(&a, &b)
    }
}
fn run_leq(a:[u8;32], b:[u8;32]) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    LeqCircuit { a, b }.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}


// ---------- compact-target decode (R1) ----------
fn target_from_compact(c:u32)->[u8;32]{ let exp=(c>>24)as usize; let m=c&0x007fffff; let mut t=[0u8;32]; let mb=m.to_be_bytes(); for k in 0..3 { let pos=32-exp+k; if pos<32 { t[pos]=mb[1+k]; } } t }
struct CompactCircuit { compact:u32, expected:[u8;32] }
impl ConstraintSynthesizer<Fr> for CompactCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let le = self.compact.to_le_bytes();
        let cle: Vec<UInt8<Fr>> = le.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
        let t = merkle_gadget::compact_to_target(&cle)?;
        for k in 0..32 { let e=UInt8::new_input(cs.clone(), || Ok(self.expected[k]))?; t[k].enforce_equal(&e)?; }
        Ok(())
    }
}
fn run_compact(c:u32)->(bool,usize){ let cs=ConstraintSystem::<Fr>::new_ref(); CompactCircuit{compact:c,expected:target_from_compact(c)}.generate_constraints(cs.clone()).unwrap(); (cs.is_satisfied().unwrap(), cs.num_constraints()) }

// ---------- R3: tx -> transactions_root on REAL block 21,341,101 ----------
struct R3Circuit;
impl ConstraintSynthesizer<Fr> for R3Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let leaf_b: [u8;32] = [228,20,131,34,107,220,81,60,134,205,207,151,233,167,190,231,131,84,44,174,42,202,220,10,63,200,249,144,222,250,165,32];
        let wit_b: [u8;32] = [196,253,25,161,96,200,165,76,9,83,44,8,238,49,73,2,34,192,89,211,170,60,211,45,209,115,72,111,20,249,87,9];
        let troot_b: [u8;32] = [126,159,107,10,155,42,132,170,123,143,217,207,244,46,246,217,153,171,34,245,236,76,62,116,100,57,233,177,175,152,29,79];
        let path_b: Vec<([u8;32],bool)> = vec![([211,8,125,37,133,23,114,23,48,33,54,145,206,15,102,223,39,228,246,172,192,105,200,248,158,193,153,13,73,36,214,108], false),([0,61,254,175,201,25,154,15,60,196,246,239,71,234,58,113,131,174,56,72,57,41,198,229,233,59,31,12,221,194,18,72], true)];
        let leaf: Vec<UInt8<Fr>> = leaf_b.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
        let wit: Vec<UInt8<Fr>> = wit_b.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?;
        let mut path=Vec::new();
        for (s,d) in &path_b { let sv: Vec<UInt8<Fr>> = s.iter().map(|b| UInt8::new_witness(cs.clone(), || Ok(*b))).collect::<Result<_,_>>()?; path.push((sv, Boolean::new_witness(cs.clone(), || Ok(*d))?)); }
        let got = merkle_gadget::tx_root_from_proof(&leaf, &path, &wit)?;
        for k in 0..32 { let e=UInt8::new_input(cs.clone(), || Ok(troot_b[k]))?; got[k].enforce_equal(&e)?; }
        Ok(())
    }
}
fn run_r3()->(bool,usize){ let cs=ConstraintSystem::<Fr>::new_ref(); R3Circuit.generate_constraints(cs.clone()).unwrap(); (cs.is_satisfied().unwrap(), cs.num_constraints()) }


use ckb_consensus_circuit::{ckb_mmr, mmr_gadget};
struct MmrCircuit;
impl ConstraintSynthesizer<Fr> for MmrCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
    let lh0:[u8;32]=[148,186,140,17,131,170,155,181,47,7,5,243,123,217,181,225,170,120,114,23,116,170,95,109,238,190,179,26,100,11,140,24];
    let l0=ckb_mmr::leaf(lh0, [0u8;32], 21341101, 1979133747803051, 1780789357828, 487079700);
    let lh1:[u8;32]=[165,223,32,146,62,176,137,47,15,27,2,176,189,71,75,33,72,130,113,119,154,146,34,47,251,11,19,137,42,110,212,145];
    let l1=ckb_mmr::leaf(lh1, [0u8;32], 21341102, 1979133764580267, 1780789359155, 487079700);
    let lh2:[u8;32]=[110,152,215,86,190,44,171,133,87,246,31,19,143,214,122,11,35,161,220,112,36,241,124,38,227,96,128,30,170,192,3,255];
    let l2=ckb_mmr::leaf(lh2, [0u8;32], 21341103, 1979133781357483, 1780789369508, 487079700);
    let lh3:[u8;32]=[249,37,80,48,196,177,80,102,9,210,164,203,59,49,206,160,135,190,73,209,74,87,226,163,143,223,17,222,241,239,1,66];
    let l3=ckb_mmr::leaf(lh3, [0u8;32], 21341104, 1979133798134699, 1780789379908, 487079700);
        let n01=ckb_mmr::merge(&l0,&l1); let n23=ckb_mmr::merge(&l2,&l3); let root=ckb_mmr::merge(&n01,&n23);
        let chain_root=ckb_mmr::mmr_hash(&root);
        // membership of leaf 1: (sibling, cur_is_left, parent)
        let path_native: Vec<([u8;120],bool,[u8;120])> = vec![ (l0,false,n01), (n23,true,root) ];
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let leaf=w(&l1,&cs)?;
        let mut path=Vec::new();
        for (s,d,p) in &path_native { path.push((w(s,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?, w(p,&cs)?)); }
        let cr: Vec<UInt8<Fr>> = chain_root.iter().map(|x| UInt8::new_input(cs.clone(),||Ok(*x))).collect::<Result<_,_>>()?;
        mmr_gadget::enforce_membership(&cs,&leaf,&path,&cr)
    }
}
fn run_mmr()->(bool,usize){ let cs=ConstraintSystem::<Fr>::new_ref(); MmrCircuit.generate_constraints(cs.clone()).unwrap(); (cs.is_satisfied().unwrap(), cs.num_constraints()) }


use ckb_consensus_circuit::difficulty_gadget;
use num_bigint::BigUint;
fn native_difficulty(compact:u32)->[u8;32]{
    let tb=target_from_compact(compact); // BE
    let target=BigUint::from_bytes_be(&tb);
    let max=(BigUint::from(1u8)<<256usize) - BigUint::from(1u8);
    let diff = if target==BigUint::from(0u8) { max.clone() } else { &max / &target };
    let mut o=[0u8;32]; let db=diff.to_bytes_be(); o[32-db.len()..].copy_from_slice(&db); o
}
struct DiffCircuit { target:[u8;32], diff:[u8;32] }
impl ConstraintSynthesizer<Fr> for DiffCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let t: Vec<UInt8<Fr>> = self.target.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        let d: Vec<UInt8<Fr>> = self.diff.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        difficulty_gadget::difficulty_verify(&cs, &t, &d)
    }
}
fn run_diff(compact:u32, tamper:bool)->(bool,usize){
    let t=target_from_compact(compact); let mut d=native_difficulty(compact);
    if tamper { // diff+1 must fail
        let mut i=31; loop { if d[i]==0xff {d[i]=0;i-=1;} else {d[i]+=1; break;} }
    }
    let cs=ConstraintSystem::<Fr>::new_ref();
    DiffCircuit{target:t,diff:d}.generate_constraints(cs.clone()).unwrap();
    (cs.is_satisfied().unwrap(), cs.num_constraints())
}


use ckb_consensus_circuit::ckb_mmr as mmr2;
fn mkleaf(hash_hex:&str, compact:u32, number:u64, epoch:u64, ts:u64)->[u8;120]{
    let h:[u8;32]=hxx(hash_hex); let mut d=native_difficulty(compact); d.reverse(); // LE
    mmr2::leaf(h, d, number, epoch, ts, compact)
}
fn hxx(s:&str)->[u8;32]{ (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect::<Vec<_>>().try_into().unwrap() }
struct AppendVarCircuit;
impl ConstraintSynthesizer<Fr> for AppendVarCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let hdrs: [(&str,u32,u64,u64,u64);6] = [("94ba8c1183aa9bb52f0705f37bd9b5e1aa78721774aa5f6deebeb31a640b8c18", 487079700u32, 21341101u64, 1979133747803051u64, 1780789357828u64),("a5df20923eb0892f0f1b02b0bd474b21488271779a92222ffb0b13892a6ed491", 487079700u32, 21341102u64, 1979133764580267u64, 1780789359155u64),("6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff", 487079700u32, 21341103u64, 1979133781357483u64, 1780789369508u64),("f9255030c4b1506609d2a4cb3b31cea087be49d14a57e2a38fdf11def1ef0142", 487079700u32, 21341104u64, 1979133798134699u64, 1780789379908u64),("16fe6f664c1a62e5b0459d1d24a16ea505f8d8cfd009ecbbddff048b57328640", 487079700u32, 21341105u64, 1979133814911915u64, 1780789380420u64),("a137ba2172c45abb4cfa8eed49b2ebe305c7b2e99c90e5138b8efe7ac3e1b94b", 487079700u32, 21341106u64, 1979133831689131u64, 1780789386545u64)];
        let leaves: Vec<[u8;120]> = hdrs.iter().map(|(h,c,n,e,t)| mkleaf(h,*c,*n,*e,*t)).collect();
        const HMAX:usize=4;
        // old MMR = first 5 leaves (leaf_count=5=0b101 -> peaks at h0,h2); append the 6th
        let old=mmr2::build(&leaves[0..5]);
        let mut new=old.clone(); mmr2::append(&mut new, leaves[5]);
        let old_root=mmr2::mmr_hash(&mmr2::bag(&old).unwrap());
        let new_root=mmr2::mmr_hash(&mmr2::bag(&new).unwrap());
        let zero=[0u8;120];
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let mut pres=Vec::new(); let mut peak=Vec::new();
        for h in 0..HMAX {
            let present = old.get(h).map(|o| o.is_some()).unwrap_or(false);
            pres.push(Boolean::new_witness(cs.clone(),||Ok(present))?);
            let d = old.get(h).and_then(|o| *o).unwrap_or(zero);
            peak.push(w(&d,&cs)?);
        }
        let leaf=w(&leaves[5],&cs)?;
        let (npres,npeak)=mmr_gadget::append_var(&cs,&pres,&peak,&leaf)?;
        let obag=mmr_gadget::bag_var(&cs,&pres,&peak)?; let or_g=mmr_gadget::root_hash(&obag)?;
        let nbag=mmr_gadget::bag_var(&cs,&npres,&npeak)?; let nr_g=mmr_gadget::root_hash(&nbag)?;
        let ori: Vec<UInt8<Fr>> = old_root.iter().map(|x| UInt8::new_input(cs.clone(),||Ok(*x))).collect::<Result<_,_>>()?;
        let nri: Vec<UInt8<Fr>> = new_root.iter().map(|x| UInt8::new_input(cs.clone(),||Ok(*x))).collect::<Result<_,_>>()?;
        for i in 0..32 { or_g[i].enforce_equal(&ori[i])?; nr_g[i].enforce_equal(&nri[i])?; }
        Ok(())
    }
}
fn run_append_var()->(bool,usize){ let cs=ConstraintSystem::<Fr>::new_ref(); AppendVarCircuit.generate_constraints(cs.clone()).unwrap(); (cs.is_satisfied().unwrap(), cs.num_constraints()) }

fn main() {
    println!("CKB-consensus gadgets - differential tests vs native + constraint counts\n");
    println!("[Eaglesong / PoW]");
    for (n,i) in [("empty",vec![]),("32 B",(0u8..32).collect()),("48 B (PoW msg)",(0u8..48).collect::<Vec<_>>())] {
        let (ok,c)=run_eag(i); println!("  {n:<22} match:{ok} constraints:{c}"); assert!(ok);
    }
    println!("[Blake2b-256 / ckbhash]");
    for (n,i) in [("empty",vec![]),("\"abc\"",b"abc".to_vec()),("192 B (RawHeader)",(0u8..192).collect::<Vec<_>>())] {
        let (ok,c)=run_blake(i); println!("  {n:<22} match:{ok} constraints:{c}"); assert!(ok);
    }
    println!("[Merkle membership (CBMT/MMR) - merge=ckbhash(l||r)]");
    for d in [1usize,4,8,25] {
        let (ok,c)=run_merkle(d); println!("  depth {d:<16} match:{ok} constraints:{c}"); assert!(ok);
    }
    println!("[Target compare (PoW <= target), big-endian]");
    let mut small=[0u8;32]; small[3]=0x04; let mut big=[0u8;32]; big[3]=0x08;
    println!("  04.. <= 08..            satisfied:{}", run_leq(small,big)); assert!(run_leq(small,big));
    println!("  08.. <= 04.. (must fail) satisfied:{}", run_leq(big,small)); assert!(!run_leq(big,small));
    println!("  equal <= equal           satisfied:{}", run_leq(big,big)); assert!(run_leq(big,big));
    println!("[compact-target decode -> 32B BE]");
    for c in [0x1d083f14u32, 0x1e00ffffu32, 0x1b0404cbu32] {{ let (ok,n)=run_compact(c); println!("  compact {c:#010x}  match:{ok} constraints:{n}"); assert!(ok); }}
    // SEC D7: a non-canonical compact whose mantissa overflows past 2^256 (huge exponent + non-zero mantissa)
    // must be REJECTED, not silently truncated.
    { let (ok,_)=run_compact(0xff7fffffu32); println!("  overflow compact 0xff7fffff (must fail) satisfied:{ok}"); assert!(!ok); }
    { let (ok,_)=run_compact(0x217fffffu32); println!("  overflow compact 0x217fffff exp=33 (must fail) satisfied:{ok}"); assert!(!ok); }
    println!("[R3: tx -> transactions_root, REAL block 21,341,101]");
    let (ok,n)=run_r3(); println!("  real CBMT path + ckbhash(raw||wit)  match:{ok} constraints:{n}"); assert!(ok);
    println!("[R2: ChainRootMMR (HeaderDigest) membership - REAL headers 21,341,101..104]");
    let (ok,n)=run_mmr(); println!("  4-leaf MMR membership  match:{ok} constraints:{n}"); assert!(ok);
    println!("[difficulty_verify: diff == floor((2^256-1)/target)]");
    for c in [0x1d083f14u32, 0x1b0404cbu32] { let (ok,n)=run_diff(c,false); println!("  compact {c:#010x} valid diff  match:{ok} constraints:{n}"); assert!(ok); }
    let (bad,_)=run_diff(0x1d083f14,true); println!("  tampered diff+1 (must fail) satisfied:{bad}"); assert!(!bad);
    println!("[variable-carry MMR append (general leaf_count) + bag - REAL headers, old leaf_count=5]");
    let (ok,n)=run_append_var(); println!("  append leaf #6 (carry stops at h1) gadget==native:{ok} constraints:{n}"); assert!(ok);
    println!("\nAll gadgets validated against native references, in-circuit.");
}
