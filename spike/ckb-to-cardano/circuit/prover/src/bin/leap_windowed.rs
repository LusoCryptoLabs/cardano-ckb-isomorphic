//! RESTRUCTURED leap circuit (see ../../RESTRUCTURE.md): R2 chain-membership is proven against a
//! shallow **window root** (a Merkle root over the last W validated header hashes, maintained by
//! AdvanceCKBCert) instead of the ~25-deep full chain-MMR. Everything else (R1 PoW, R3 tx-CBMT, R4
//! seal/commitment) is identical to leap_prove. Public inputs (3): (window_root, seal, commitment).
//!
//!   COUNT_ONLY=1 [WINDOW_DEPTH=6] cargo run --release --bin leap_windowed   # report R1CS size
//!   cargo run --release --bin leap_windowed                                  # setup+prove+verify
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder;
use eaglesong::eaglesong as native_eaglesong;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget};

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2b(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hx(s:&str)->Vec<u8>{ (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }

// REAL block 21,341,101 (same as leap_prove)
fn raw_header()->([u8;192],[u8;16]){
    let mut r=Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&0x1d083f14u32.to_le_bytes());
    r.extend_from_slice(&0x19e9f512d04u64.to_le_bytes());
    r.extend_from_slice(&0x145a3adu64.to_le_bytes());
    r.extend_from_slice(&0x70802fc0033abu64.to_le_bytes());
    r.extend_from_slice(&hx("d33b041d4f08e5510692dd0adbdd0be325db777a7fff1aef237a845f3058d60a"));
    r.extend_from_slice(&hx("7e9f6b0a9b2a84aa7b8fd9cff42ef6d999ab22f5ec4c3e746439e9b1af981d4f"));
    r.extend_from_slice(&hx("0000000000000000000000000000000000000000000000000000000000000000"));
    r.extend_from_slice(&hx("a7f0a504f0b8e334a6e66548347affbe55ee4207bc2b3bddc69cd0eff8eca72c"));
    r.extend_from_slice(&hx("105ee644c39127572a332bb93f132a006fafe4cf2dc3e10900ba21e2b0d55709"));
    let mut raw=[0u8;192]; raw.copy_from_slice(&r);
    let mut n=[0u8;16]; n.copy_from_slice(&0x2e24d7131728615efc333b1b2a26860cu128.to_le_bytes());
    (raw,n)
}
fn cbmt()->([u8;32], Vec<([u8;32],bool)>, [u8;32]){
    let leaf:[u8;32]=hx("e41483226bdc513c86cdcf97e9a7bee783542cae2acadc0a3fc8f990defaa520").try_into().unwrap();
    let wit:[u8;32]=hx("c4fd19a160c8a54c09532c08ee31490222c059d3aa3cd32dd173486f14f95709").try_into().unwrap();
    let path=vec![ (hx("d3087d258517721730213691ce0f66df27e4f6acc069c8f89ec1990d4924d66c").try_into().unwrap(), false), (hx("003dfeafc9199a0f3cc4f6ef47ea3a7183ae38483929c6e5e93b1f0cddc21248").try_into().unwrap(), true) ];
    (leaf, path, wit)
}

// Off-circuit: build a binary window-Merkle over `leaves` (power-of-two) and return (root, membership
// path for `idx` as (sibling, leaf_is_left)). Merge = ckbhash(left || right). Matches merkle_gadget.
fn window_root_path(leaves:&[[u8;32]], idx:usize)->([u8;32], Vec<([u8;32],bool)>){
    let mut level:Vec<[u8;32]>=leaves.to_vec();
    let mut i=idx; let mut path=Vec::new();
    while level.len()>1 {
        let leaf_is_left = i%2==0;
        let sib = if leaf_is_left { level[i+1] } else { level[i-1] };
        path.push((sib, leaf_is_left));
        let mut next=Vec::new(); let mut j=0;
        while j<level.len(){ let mut c=level[j].to_vec(); c.extend_from_slice(&level[j+1]); next.push(ckbhash(&c)); j+=2; }
        level=next; i/=2;
    }
    (level[0], path)
}

#[derive(Clone)]
struct WindowedLeap { raw:[u8;192], nonce:[u8;16], leaf:[u8;32], path:Vec<([u8;32],bool)>, wit:[u8;32],
    new_state:Vec<u8>, seal:[u8;32], window_root:[u8;32], window_path:Vec<([u8;32],bool)> }
fn bytes_to_fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{
    let mut acc=FpVar::<F>::zero(); let mut c=F::one();
    for byte in b { for bit in byte.to_bits_le()? { acc += FpVar::from(bit)*c; c.double_in_place(); } }
    Ok(acc)
}
impl ConstraintSynthesizer<Fr> for WindowedLeap {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let raw=w(&self.raw,&cs)?;
        let nonce=w(&self.nonce,&cs)?;
        // R1 PoW with in-circuit compact-target decode (unchanged)
        let pow_hash = blake2b256(&raw, b"ckb-default-hash")?;
        let mut ei=pow_hash.clone(); ei.extend(nonce.clone());
        let eag=eaglesong_gadget::eaglesong(&ei)?;
        let pow_out=blake2b256(&eag, b"ckb-default-hash")?;
        let target=merkle_gadget::compact_to_target(&raw[4..8])?;
        merkle_gadget::enforce_leq_be(&pow_out, &target)?;
        // R3 bind tx to transactions_root via the real CBMT path (unchanged)
        let leaf=w(&self.leaf,&cs)?;
        let wit=w(&self.wit,&cs)?;
        let mut path=Vec::new();
        for (s,d) in &self.path { path.push((w(s,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?)); }
        let troot=merkle_gadget::tx_root_from_proof(&leaf,&path,&wit)?;
        for i in 0..32 { troot[i].enforce_equal(&raw[64+i])?; }
        // R2' WINDOWED membership: block_hash = ckbhash(RawHeader || nonce) is a leaf of the window root.
        let mut hin = raw.clone(); hin.extend(nonce);
        let block_hash = blake2b256(&hin, b"ckb-default-hash")?;
        let mut wpath=Vec::new();
        for (sib,d) in &self.window_path { wpath.push((w(sib,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?)); }
        let wroot = merkle_gadget::merkle_root(&block_hash, &wpath)?;   // depth = log2(W), not ~25
        // R4 commitment + public inputs (window_root replaces chain_root)
        let ns=w(&self.new_state,&cs)?;
        let seal=w(&self.seal,&cs)?;
        for i in 0..32 { seal[i].enforce_equal(&leaf[i])?; }            // SEC D2: seal == block-included tx
        let mut ci=ns; ci.extend(seal.clone());
        let comm=blake2b256(&ci, &[0u8;16])?;                          // SEC D1: standard blake2b
        let comm_bytes:[u8;32]={ let mut c=self.new_state.clone(); c.extend_from_slice(&self.seal); b2b(&c) };
        let pi_wr=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.window_root)))?;
        let pi_seal=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.seal)))?;
        let pi_comm=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&comm_bytes)))?;
        bytes_to_fp(&wroot)?.enforce_equal(&pi_wr)?;                   // membership + bind in one
        bytes_to_fp(&seal)?.enforce_equal(&pi_seal)?;
        bytes_to_fp(&comm)?.enforce_equal(&pi_comm)?;
        Ok(())
    }
}

fn main(){
    let (raw,nonce)=raw_header(); let (leaf,path,wit)=cbmt();
    let ph=ckbhash(&raw); let mut ei=ph.to_vec(); ei.extend_from_slice(&nonce); let mut eag=[0u8;32]; native_eaglesong(&ei,&mut eag); let pow=ckbhash(&eag);
    eprintln!("native pow_out = {}", pow.iter().map(|x|format!("{:02x}",x)).collect::<String>());
    let new_state=b"ckb-anchored:demo:v1".to_vec(); let seal=leaf;
    // block hash of the proven header = ckbhash(RawHeader || nonce); it is leaf 0 of the window.
    let mut hin=raw.to_vec(); hin.extend_from_slice(&nonce); let block_hash=ckbhash(&hin);
    let depth: u32 = std::env::var("WINDOW_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let wsize = 1usize << depth;                                       // W = 2^depth (default 64)
    let mut leaves=vec![[0u8;32]; wsize]; leaves[0]=block_hash;
    for k in 1..wsize { leaves[k]=ckbhash(&(k as u64).to_le_bytes()); } // stand-in recent header hashes
    let (window_root, window_path)=window_root_path(&leaves, 0);
    let circ=WindowedLeap{raw,nonce,leaf,path,wit,new_state:new_state.clone(),seal,window_root,window_path};
    {
        let cs=ConstraintSystem::<Fr>::new_ref();
        circ.clone().generate_constraints(cs.clone()).unwrap();
        eprintln!("WINDOW_DEPTH={} CONSTRAINTS={} witness_vars={} next_pow2={}",
            depth, cs.num_constraints(), cs.num_witness_variables(), (cs.num_constraints() as u64).next_power_of_two());
        if std::env::var("COUNT_ONLY").is_ok() { return; }
    }
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    eprintln!("Groth16 setup over the WINDOWED leap circuit...");
    let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(), &mut rng).unwrap();
    let proof=Groth16::<Bls12_381>::prove(&pk, circ.clone(), &mut rng).unwrap();
    let mut cc=new_state.clone(); cc.extend_from_slice(&seal); let commitment=b2b(&cc);
    let inputs=vec![Fr::from_le_bytes_mod_order(&window_root), Fr::from_le_bytes_mod_order(&seal), Fr::from_le_bytes_mod_order(&commitment)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap();
    eprintln!("arkworks verify = {ok}"); assert!(ok, "windowed leap proof must verify");
    println!("WINDOWED_LEAP_OK depth={} verify={}", depth, ok);
}
