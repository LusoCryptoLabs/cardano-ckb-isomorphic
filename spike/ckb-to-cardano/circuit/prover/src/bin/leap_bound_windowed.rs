//! leap_bound_windowed — THE PRODUCTION leap prover: the windowed K-floor consensus circuit
//! (leap_windowed: R1 PoW + R2' shallow window-root membership + R3 tx-CBMT + SEC-D6 depth-K bound with a
//! PINNED K-floor) AND the value binding (relay_bind / VALUE_BINDING_FIX.md) IN ONE PROOF. A single Groth16
//! proof now attests, simultaneously, that:
//!   * the leaped header has real Eaglesong PoW and sits >= K_MIN deep below the checkpoint tip (no shallow
//!     reorg can mint), and
//!   * the minted amount/recipient are DERIVED from the on-chain bridge_lock_v1 receipt's own body (no free
//!     witness => a relayer cannot mint unbacked χCKB).
//!
//! Public inputs (5, same shape as leap_windowed so the on-chain cardano_bound verifier is unchanged):
//!   (window_root, seal, commitment, tip_height, K).  `commitment` is DERIVED in-circuit from the receipt
//!   body's amount(16 LE)+recipient(28); it is NOT a free witness.
//!
//! Data: witness_bridge.json (relayer: real header[3]+CBMT for the receipt tx) + bridge_lock_live.json
//! (captured RawTransaction body + verified offsets + pinned bridge_lock_v1 code-hash). The window membership
//! uses stand-in recent-header leaves with the REAL receipt block at its height-derived slot — same fidelity
//! as the leap_windowed demo for the window itself (in production AdvanceCKBCert maintains the real window
//! root); the header, CBMT, body, amount/recipient and the K-floor are all REAL/enforced.
//!
//!   cargo run --release --bin leap_bound_windowed              # is_satisfied + 5-case differential audit
//!   PROVE=1 cargo run --release --bin leap_bound_windowed      # + full Groth16 setup/prove/verify + redeemer
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder;
use serde_json::Value;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget};

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2b(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hx(s:&str)->Vec<u8>{ let s=s.trim_start_matches("0x"); (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn hx32(s:&str)->[u8;32]{ hx(s).try_into().unwrap() }
fn uh(v:&Value,k:&str)->u128{ u128::from_str_radix(v[k].as_str().unwrap().trim_start_matches("0x"),16).unwrap() }
fn raw_of(h:&Value)->([u8;192],[u8;16]){
    let mut r=Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&(uh(h,"compact_target") as u32).to_le_bytes());
    r.extend_from_slice(&(uh(h,"timestamp") as u64).to_le_bytes());
    r.extend_from_slice(&(uh(h,"number") as u64).to_le_bytes());
    r.extend_from_slice(&(uh(h,"epoch") as u64).to_le_bytes());
    r.extend_from_slice(&hx(h["parent_hash"].as_str().unwrap()));
    r.extend_from_slice(&hx(h["transactions_root"].as_str().unwrap()));
    r.extend_from_slice(&hx(h["proposals_hash"].as_str().unwrap()));
    r.extend_from_slice(&hx(h["extra_hash"].as_str().unwrap()));
    r.extend_from_slice(&hx(h["dao"].as_str().unwrap()));
    let mut raw=[0u8;192]; raw.copy_from_slice(&r);
    let mut n=[0u8;16]; n.copy_from_slice(&uh(h,"nonce").to_le_bytes()); (raw,n)
}

// Off-circuit window-Merkle (matches leap_windowed): merge = ckbhash(left||right).
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
struct BoundWindowedLeap {
    raw:[u8;192], nonce:[u8;16],
    cbmt_leaf:[u8;32], cbmt_path:Vec<([u8;32],bool)>, wit:[u8;32],
    seal:[u8;32],
    window_root:[u8;32], siblings:Vec<[u8;32]>, tip_height:u64, k:u64, kmin:u64,
    body:Vec<u8>, bridge_code:[u8;32], type_off:usize, amount_off:usize, recip_off:usize,
}
fn b2fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{
    let mut a=FpVar::<F>::zero(); let mut c=F::one();
    for byte in b { for bit in byte.to_bits_le()? { a+=FpVar::from(bit)*c; c.double_in_place(); } } Ok(a) }
impl ConstraintSynthesizer<Fr> for BoundWindowedLeap {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let raw=w(&self.raw,&cs)?; let nonce=w(&self.nonce,&cs)?;
        // R1 PoW with in-circuit compact-target decode
        let pow_hash = blake2b256(&raw, b"ckb-default-hash")?;
        let mut ei=pow_hash.clone(); ei.extend(nonce.clone());
        let eag=eaglesong_gadget::eaglesong(&ei)?;
        let pow_out=blake2b256(&eag, b"ckb-default-hash")?;
        let target=merkle_gadget::compact_to_target(&raw[4..8])?;
        merkle_gadget::enforce_leq_be(&pow_out, &target)?;
        // R3 bind tx to transactions_root via the real CBMT path
        let leaf=w(&self.cbmt_leaf,&cs)?;
        let wit=w(&self.wit,&cs)?;
        let mut path=Vec::new();
        for (s,d) in &self.cbmt_path { path.push((w(s,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?)); }
        let troot=merkle_gadget::tx_root_from_proof(&leaf,&path,&wit)?;
        for i in 0..32 { troot[i].enforce_equal(&raw[64+i])?; }
        // R2' WINDOWED membership; slot BOUND to the header's own height (mod W)
        let mut hin = raw.clone(); hin.extend(nonce);
        let block_hash = blake2b256(&hin, b"ckb-default-hash")?;
        let mut height_bits: Vec<Boolean<Fr>> = Vec::new();
        for i in 16..24 { for b in raw[i].to_bits_le()? { height_bits.push(b); } }
        let mut wpath=Vec::new();
        for (k, sib) in self.siblings.iter().enumerate() { wpath.push((w(sib,&cs)?, height_bits[k].clone().not())); }
        let wroot = merkle_gadget::merkle_root(&block_hash, &wpath)?;
        // seal == the block-included tx (SEC D2)
        let seal=w(&self.seal,&cs)?;
        for i in 0..32 { seal[i].enforce_equal(&leaf[i])?; }
        // ---- VALUE BINDING (the fix; relay_bind, now under the windowed circuit) ----
        let body=w(&self.body,&cs)?;
        // (a) body authenticity: ckbhash(full RawTransaction) == the proven tx hash (== seal == leaf)
        let bh2=blake2b256(&body,b"ckb-default-hash")?;
        for i in 0..32 { bh2[i].enforce_equal(&seal[i])?; }
        // (b) the receipt output carries bridge_lock_v1 (type Script code-hash == the pinned constant)
        for i in 0..32 { body[self.type_off+i].enforce_equal(&UInt8::constant(self.bridge_code[i]))?; }
        // (c) DERIVE new_state = amount(16 LE) ‖ recipient(28) from the receipt body; commitment from it.
        let mut new_state:Vec<UInt8<Fr>>=Vec::with_capacity(44);
        for i in 0..16 { new_state.push(body[self.amount_off+i].clone()); }
        for i in 0..28 { new_state.push(body[self.recip_off+i].clone()); }
        let mut ci=new_state; ci.extend(seal.clone());
        let comm=blake2b256(&ci, &[0u8;16])?;                            // SEC D1: standard blake2b
        // R4 public inputs (window_root, seal, commitment[derived], tip_height, K)
        let amt:Vec<u8>=self.body[self.amount_off..self.amount_off+16].to_vec();
        let rcp:Vec<u8>=self.body[self.recip_off..self.recip_off+28].to_vec();
        let mut ns=amt; ns.extend_from_slice(&rcp); let mut cc=ns; cc.extend_from_slice(&self.seal); let comm_native=b2b(&cc);
        let pi_wr=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.window_root)))?;
        let pi_seal=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.seal)))?;
        let pi_comm=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&comm_native)))?;
        b2fp(&wroot)?.enforce_equal(&pi_wr)?;
        b2fp(&seal)?.enforce_equal(&pi_seal)?;
        b2fp(&comm)?.enforce_equal(&pi_comm)?;
        // HEIGHT-BOUND: tip = height + diff, diff in [0,W) via depth-bit witness.
        let depth = self.siblings.len();
        let height_val = u64::from_le_bytes(self.raw[16..24].try_into().unwrap());
        let diff_val = self.tip_height.wrapping_sub(height_val);
        let mut height_fp = FpVar::<Fr>::zero(); let mut c = Fr::from(1u64);
        for b in &height_bits { height_fp += FpVar::from(b.clone())*c; c = c + c; }
        let mut diff_fp = FpVar::<Fr>::zero(); let mut c2 = Fr::from(1u64);
        let mut diff_bits: Vec<Boolean<Fr>> = Vec::with_capacity(depth);
        for k in 0..depth { let bit=Boolean::new_witness(cs.clone(),||Ok((diff_val>>k)&1==1))?; diff_fp += FpVar::from(bit.clone())*c2; c2 = c2 + c2; diff_bits.push(bit); }
        let pi_tip=FpVar::new_input(cs.clone(),||Ok(Fr::from(self.tip_height)))?;
        (height_fp + diff_fp).enforce_equal(&pi_tip)?;
        // SEC D6: confirmation-depth bound tip_height - height >= K; K is PUBLIC INPUT #5, range-checked to
        // `depth` bits so 0 <= K < W; with diff also in [0,W) the bit-compare is exact.
        let pi_k=FpVar::new_input(cs.clone(),||Ok(Fr::from(self.k)))?;
        let mut k_fp = FpVar::<Fr>::zero(); let mut ck = Fr::from(1u64);
        let mut k_bits: Vec<Boolean<Fr>> = Vec::with_capacity(depth);
        for j in 0..depth { let bit=Boolean::new_witness(cs.clone(),||Ok((self.k>>j)&1==1))?; k_fp += FpVar::from(bit.clone())*ck; ck = ck + ck; k_bits.push(bit); }
        k_fp.enforce_equal(&pi_k)?;
        merkle_gadget::enforce_geq_bits(&diff_bits, &k_bits)?;             // diff >= K
        // SEC reorg floor (GOV-1): K >= a PINNED minimum (baked into the circuit => the VK), not witness 0.
        let kmin_bits: Vec<Boolean<Fr>> = (0..depth).map(|j| Boolean::constant((self.kmin>>j)&1==1)).collect();
        merkle_gadget::enforce_geq_bits(&k_bits, &kmin_bits)?;             // K >= K_MIN  (no K=0)
        Ok(())
    }
}

fn sat(c:&BoundWindowedLeap)->bool{ let cs=ConstraintSystem::<Fr>::new_ref(); c.clone().generate_constraints(cs.clone()).unwrap(); cs.is_satisfied().unwrap() }

fn main(){
    let wpath=std::env::args().nth(1).unwrap_or("/tmp/witness_bridge.json".into());
    let bpath=std::env::args().nth(2).unwrap_or("/mnt/c/Users/telmo/chiral-study/relayer/onchain/bridge_lock_live.json".into());
    let v:Value=serde_json::from_reader(std::fs::File::open(&wpath).unwrap()).unwrap();
    let lj:Value=serde_json::from_reader(std::fs::File::open(&bpath).unwrap()).unwrap();
    let hs=v["headers"].as_array().unwrap();
    let (raw,nonce)=raw_of(&hs[3]);
    let block_hash=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
    assert_eq!(block_hash.iter().map(|x|format!("{:02x}",x)).collect::<String>(), hs[3]["hash"].as_str().unwrap().trim_start_matches("0x"), "block hash mismatch");
    // CBMT path (relayer)
    let cb=&v["cbmt"]; let mut node=u64::from_str_radix(cb["indices"][0].as_str().unwrap().trim_start_matches("0x"),16).unwrap();
    let mut cbmt_path=Vec::new(); for l in cb["lemmas"].as_array().unwrap() { cbmt_path.push((hx32(l.as_str().unwrap()), node%2==1)); node=(node-1)/2; }
    let cbmt_leaf=hx32(v["tx_hash"].as_str().unwrap()); let wit=hx32(cb["witnesses_root"].as_str().unwrap());
    let seal=cbmt_leaf;
    // the captured receipt body + offsets (verified on the real tx by bridge_deploy_lock.mjs)
    let body=hx(lj["body_hex"].as_str().unwrap());
    let bridge_code=hx32(lj["bridge_code_hash"].as_str().unwrap());
    let off=&lj["offsets"]; let type_off=off["type_code"].as_u64().unwrap() as usize;
    let amount_off=off["amount"].as_u64().unwrap() as usize; let recip_off=off["recipient"].as_u64().unwrap() as usize;
    assert_eq!(ckbhash(&body).iter().map(|x|format!("{:02x}",x)).collect::<String>(),
               seal.iter().map(|x|format!("{:02x}",x)).collect::<String>(), "captured body does not hash to the proven tx");
    // window: real receipt block at its height-derived slot; stand-in leaves elsewhere (= leap_windowed demo).
    let depth: usize = std::env::var("WINDOW_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let wsize = 1usize << depth;
    let height: u64 = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    let slot = (height % wsize as u64) as usize;
    let kmin: u64 = std::env::var("CHIRAL_K_MIN").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
    // Window leaves + tip: REAL (relayer_window.py via CHIRAL_WINDOW = W real recent CKB header hashes placed
    // at ring slot h%W) or stand-in (demo). The circuit is identical; only the leaf SOURCE differs. In
    // production AdvanceCKBCert maintains this window root on the Cardano ckbcert checkpoint.
    let real_window = std::env::var("CHIRAL_WINDOW").ok();
    let (mut leaves, tip_height) = if let Some(wp) = real_window.clone() {
        let wj: Value = serde_json::from_reader(std::fs::File::open(&wp).unwrap()).unwrap();
        assert_eq!(wj["window_depth"].as_u64().unwrap() as usize, depth, "CHIRAL_WINDOW depth != WINDOW_DEPTH");
        assert_eq!(wj["receipt_height"].as_u64().unwrap(), height, "CHIRAL_WINDOW receipt height != proven header");
        let lv: Vec<[u8;32]> = wj["leaves"].as_array().unwrap().iter().map(|x| hx32(x.as_str().unwrap())).collect();
        assert_eq!(lv.len(), wsize, "CHIRAL_WINDOW leaf count != W");
        (lv, wj["tip_height"].as_u64().unwrap())
    } else {
        let mut lv = vec![[0u8;32]; wsize];
        for kk in 0..wsize { lv[kk]=ckbhash(&((kk as u64)+1).to_le_bytes()); }
        (lv, height + std::env::var("TIP_OFFSET").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(kmin))
    };
    if real_window.is_some() {
        assert_eq!(leaves[slot], block_hash, "real window leaf at slot != the proven block hash");
    } else {
        leaves[slot] = block_hash;
    }
    eprintln!("[window] {} W={wsize} slot={slot} tip={tip_height} diff={}",
        if real_window.is_some() {"REAL CKB headers"} else {"stand-in (demo)"}, tip_height - height);
    let k: u64 = std::env::var("K").ok().and_then(|s| s.parse().ok()).unwrap_or(kmin);
    let (window_root, wpath_off)=window_root_path(&leaves, slot);
    let siblings:Vec<[u8;32]>=wpath_off.iter().map(|(s,_)|*s).collect();
    let mk=|k:u64,kmin:u64,tip:u64,body:Vec<u8>,bridge:[u8;32]| BoundWindowedLeap{
        raw,nonce,cbmt_leaf,cbmt_path:cbmt_path.clone(),wit,seal,window_root,siblings:siblings.clone(),
        tip_height:tip,k,kmin,body,bridge_code:bridge,type_off,amount_off,recip_off };
    let real=mk(k,kmin,tip_height,body.clone(),bridge_code);

    // ---- DIFFERENTIAL AUDIT (fast; no proving) ----
    let pos = sat(&real);
    eprintln!("[audit] positive (real receipt, K={k} kmin={kmin} diff={})        is_satisfied={pos}", tip_height-height);
    assert!(pos, "real value-bound windowed leap must be satisfiable");
    // 1) inflate/redirect: flip a byte in the receipt body's amount field -> body no longer hashes to seal
    let mut tb=body.clone(); tb[amount_off]^=1;
    let n1=sat(&mk(k,kmin,tip_height,tb,bridge_code));
    eprintln!("[audit] tamper body amount (inflate/redirect)                      is_satisfied={n1}"); assert!(!n1);
    // 2) non-bridge receipt: pin a wrong bridge_lock code-hash
    let mut wc=bridge_code; wc[0]^=1;
    let n2=sat(&mk(k,kmin,tip_height,body.clone(),wc));
    eprintln!("[audit] non-bridge receipt (wrong type code-hash)                  is_satisfied={n2}"); assert!(!n2);
    // 3) GOV-1 floor: K=0 below the pinned K_MIN
    let n3=sat(&mk(0,kmin,tip_height,body.clone(),bridge_code));
    eprintln!("[audit] K=0 (below pinned K_MIN={kmin})                            is_satisfied={n3}"); assert!(!n3);
    // 4) shallow reorg: tip == height (diff=0) with K=kmin -> diff < K
    let n4=sat(&mk(k,kmin,height,body.clone(),bridge_code));
    eprintln!("[audit] shallow (diff=0 < K={k})                                   is_satisfied={n4}"); assert!(!n4);
    eprintln!("[audit] ALL 5 CASES OK: 1 accept + 4 reject (inflate/redirect, non-bridge, K=0, shallow)");

    if std::env::var("PROVE").is_err() { return; }
    // ---- FULL GROTH16 (gated; the ceremony/VK refresh is a separate deploy step) ----
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    eprintln!("Groth16 setup over the BOUND WINDOWED leap circuit...");
    let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(real.clone(),&mut rng).unwrap();
    let proof=Groth16::<Bls12_381>::prove(&pk,real.clone(),&mut rng).unwrap();
    let amt=&body[amount_off..amount_off+16]; let rcp=&body[recip_off..recip_off+28];
    let mut ns=amt.to_vec(); ns.extend_from_slice(rcp); let mut cc=ns.clone(); cc.extend_from_slice(&seal); let commitment=b2b(&cc);
    let inputs=vec![Fr::from_le_bytes_mod_order(&window_root), Fr::from_le_bytes_mod_order(&seal),
                    Fr::from_le_bytes_mod_order(&commitment), Fr::from(tip_height), Fr::from(k)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap();
    eprintln!("arkworks verify = {ok} (BOUND_WINDOWED_LEAP_OK depth={depth} K={k} amount {} recipient {})",
        u128::from_le_bytes(amt.try_into().unwrap()), rcp.iter().map(|x|format!("{:02x}",x)).collect::<String>());
    assert!(ok, "bound windowed leap proof must verify");
    println!("{}", serde_json::to_string_pretty(&ckb_consensus_circuit::setup_mpc::emit_redeemer(&vk,&proof,&inputs)).unwrap());
}
