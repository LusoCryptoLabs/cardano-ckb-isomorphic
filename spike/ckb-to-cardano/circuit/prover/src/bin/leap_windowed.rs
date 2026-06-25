//! RESTRUCTURED leap circuit (see ../../RESTRUCTURE.md): R2 chain-membership is proven against a
//! shallow **window root** (a Merkle root over the last W validated header hashes, maintained by
//! AdvanceCKBCert) instead of the ~25-deep full chain-MMR. Everything else (R1 PoW, R3 tx-CBMT, R4
//! seal/commitment) is identical to leap_prove. Public inputs (5): (window_root, seal, commitment,
//! tip_height, K) - K is the SEC D6 confirmation-depth bound (tip_height - height >= K).
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
    new_state:Vec<u8>, seal:[u8;32], window_root:[u8;32], siblings:Vec<[u8;32]>, tip_height:u64, k:u64, kmin:u64 }
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
        // R2' WINDOWED membership with the slot BOUND to the header's own height (mod W).
        let mut hin = raw.clone(); hin.extend(nonce);
        let block_hash = blake2b256(&hin, b"ckb-default-hash")?;
        // header height = raw[16..24] little-endian -> 64 bits LE
        let mut height_bits: Vec<Boolean<Fr>> = Vec::new();
        for i in 16..24 { for b in raw[i].to_bits_le()? { height_bits.push(b); } }
        // membership path: directions are the low log2(W) bits of height (leaf_is_left = !bit_k); siblings witnessed.
        let mut wpath=Vec::new();
        for (k, sib) in self.siblings.iter().enumerate() { wpath.push((w(sib,&cs)?, height_bits[k].clone().not())); }
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
        // HEIGHT-BOUND (soundness crux): tip_height - W < height <= tip_height, so the slot the membership
        // used has not been overwritten since this header was written. Enforce tip = height + diff with
        // diff in [0, 2^depth) = [0, W) via a depth-bit witness.
        let depth = self.siblings.len();
        let height_val = u64::from_le_bytes(self.raw[16..24].try_into().unwrap());
        let diff_val = self.tip_height - height_val;
        let mut height_fp = FpVar::<Fr>::zero(); let mut c = Fr::from(1u64);
        for b in &height_bits { height_fp += FpVar::from(b.clone())*c; c = c + c; }
        let mut diff_fp = FpVar::<Fr>::zero(); let mut c2 = Fr::from(1u64);
        let mut diff_bits: Vec<Boolean<Fr>> = Vec::with_capacity(depth);   // LSB-first, diff in [0,W)
        for k in 0..depth { let bit=Boolean::new_witness(cs.clone(),||Ok((diff_val>>k)&1==1))?; diff_fp += FpVar::from(bit.clone())*c2; c2 = c2 + c2; diff_bits.push(bit); }
        let pi_tip=FpVar::new_input(cs.clone(),||Ok(Fr::from(self.tip_height)))?;
        (height_fp + diff_fp).enforce_equal(&pi_tip)?;
        // SEC D6 (CKB-reorg defense): confirmation-depth bound  tip_height - height >= K.  K is PUBLIC
        // INPUT #5 (governance-pinned by cardano_bound), range-checked to `depth` bits so 0 <= K < W; with
        // diff also in [0,W) the bit-compare is exact. diff in [0,W) already => band becomes [H+K, H+W-1].
        // A leap can no longer be proven at depth < K (was depth 0), so a shallow reorg cannot mint.
        let pi_k=FpVar::new_input(cs.clone(),||Ok(Fr::from(self.k)))?;
        let mut k_fp = FpVar::<Fr>::zero(); let mut ck = Fr::from(1u64);
        let mut k_bits: Vec<Boolean<Fr>> = Vec::with_capacity(depth);
        for j in 0..depth { let bit=Boolean::new_witness(cs.clone(),||Ok((self.k>>j)&1==1))?; k_fp += FpVar::from(bit.clone())*ck; ck = ck + ck; k_bits.push(bit); }
        k_fp.enforce_equal(&pi_k)?;                                        // bind K to its depth bits => K in [0,W)
        merkle_gadget::enforce_geq_bits(&diff_bits, &k_bits)?;             // diff >= K
        // SEC (reorg floor, fixes GOV-1): K must be >= a PINNED minimum confirmation depth, NOT a
        // witness/governance-chosen 0. Without this the depth bound is vacuous (K=0 accepts the tip), so a
        // 1-block reorg could mint. Mirrors the Mithril-side quorum pin: the security parameter is baked into
        // the circuit (=> the VK), not supplied. kmin is a circuit constant for this build.
        let kmin_bits: Vec<Boolean<Fr>> = (0..depth).map(|j| Boolean::constant((self.kmin>>j)&1==1)).collect();
        merkle_gadget::enforce_geq_bits(&k_bits, &kmin_bits)?;             // K >= K_MIN  (no K=0)
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
    let height: u64 = u64::from_le_bytes(raw[16..24].try_into().unwrap()); // 21,341,101
    let slot = (height % wsize as u64) as usize;                       // ring-buffer slot = height mod W
    // TIP_OFFSET (test only): place the checkpoint tip `offset` blocks above this header so diff=offset,
    // exercising the SEC D6 depth-K bound (diff must be >= K). Default 0 = legacy (header IS the tip).
    let tip_height = height + std::env::var("TIP_OFFSET").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(12);
    let mut leaves=vec![[0u8;32]; wsize];
    for k in 0..wsize { leaves[k]=ckbhash(&((k as u64)+1).to_le_bytes()); } // stand-in recent header hashes
    leaves[slot]=block_hash;                                           // this header sits at its slot
    let (window_root, wpath_off)=window_root_path(&leaves, slot);
    let siblings:Vec<[u8;32]>=wpath_off.iter().map(|(s,_)|*s).collect();
    // SEC D6: confirmation depth K (public input). 0..W-1; default 0 keeps legacy behaviour for benches.
    // The real proof against a live checkpoint sets K = the governance min_confirmations and proves a
    // header at depth >= K. The fixture uses diff=0 (tip==height), so a real K>0 here would be unprovable
    // for THIS demo header; K is exercised by the relayer against a genuinely K-deep checkpoint.
    let k: u64 = std::env::var("K").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
    // SEC reorg floor (GOV-1): the PINNED minimum confirmation depth, baked into the circuit (=> the VK).
    // Deployment parameter set to CKB's settlement guarantee; default 12. K=0 is no longer provable.
    let kmin: u64 = std::env::var("CHIRAL_K_MIN").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
    let circ=WindowedLeap{raw,nonce,leaf,path,wit,new_state:new_state.clone(),seal,window_root,siblings,tip_height,k,kmin};
    {
        let cs=ConstraintSystem::<Fr>::new_ref();
        circ.clone().generate_constraints(cs.clone()).unwrap();
        eprintln!("WINDOW_DEPTH={} CONSTRAINTS={} witness_vars={} next_pow2={} K={} diff={} is_satisfied={}",
            depth, cs.num_constraints(), cs.num_witness_variables(), (cs.num_constraints() as u64).next_power_of_two(),
            k, tip_height - height, cs.is_satisfied().unwrap());
        if std::env::var("COUNT_ONLY").is_ok() { return; }
    }
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    let (pk,vk) = if let Ok(dir)=std::env::var("CEREMONY_OUT") {
        let (pk,transcript)=ckb_consensus_circuit::setup_mpc::run_ceremony(circ.clone(), 3, 3, "leap_windowed");
        ckb_consensus_circuit::setup_mpc::save_pk(&pk, &format!("{dir}/leap_windowed_pk.bin"));
        let _ = std::fs::write(format!("{dir}/leap_windowed_transcript.json"), serde_json::to_string_pretty(&transcript).unwrap());
        let vk=pk.vk.clone(); (pk,vk)
    } else if let Ok(p)=std::env::var("CEREMONY_PK") {
        eprintln!("loading ceremony key from {p}"); let pk=ckb_consensus_circuit::setup_mpc::load_pk(&p); let vk=pk.vk.clone(); (pk,vk)
    } else {
        eprintln!("Groth16 setup over the WINDOWED leap circuit...");
        Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(), &mut rng).unwrap()
    };
    let proof=Groth16::<Bls12_381>::prove(&pk, circ.clone(), &mut rng).unwrap();
    let mut cc=new_state.clone(); cc.extend_from_slice(&seal); let commitment=b2b(&cc);
    let inputs=vec![Fr::from_le_bytes_mod_order(&window_root), Fr::from_le_bytes_mod_order(&seal), Fr::from_le_bytes_mod_order(&commitment), Fr::from(tip_height), Fr::from(k)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap();
    eprintln!("arkworks verify = {ok} (WINDOWED_LEAP_OK depth={depth} K={k})"); assert!(ok, "windowed leap proof must verify");
    println!("{}", serde_json::to_string_pretty(&ckb_consensus_circuit::setup_mpc::emit_redeemer(&vk,&proof,&inputs)).unwrap());
}
