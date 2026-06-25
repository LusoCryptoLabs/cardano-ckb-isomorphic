//! leap_bound_windowed - THE PRODUCTION leap prover: the windowed K-floor consensus circuit
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
//! uses stand-in recent-header leaves with the REAL receipt block at its height-derived slot - same fidelity
//! as the leap_windowed demo for the window itself (in production AdvanceCKBCert maintains the real window
//! root); the header, CBMT, body, amount/recipient and the K-floor are all REAL/enforced.
//!
//!   CHIRAL_AUDIT=1 cargo run --release --bin leap_bound_windowed   # is_satisfied + 5-case differential audit
//!   PROVE=1 cargo run --release --bin leap_bound_windowed          # full Groth16 setup/prove/verify + redeemer
//!                                                                  # (audit is OFF unless CHIRAL_AUDIT=1)
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

const MAX_CBMT_DEPTH: usize = 16;   // fixed CBMT proof depth -> circuit size invariant to the block's tx count
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
    cbmt_leaf:[u8;32], cbmt_path:Vec<([u8;32],bool,bool)>, wit:[u8;32],
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
        // FIXED-DEPTH CBMT (see merkle_gadget::merkle_root_fixed): constant constraint count regardless of how
        // many txs share the burn's block, so one deployed vk verifies any burn.
        for (s,d,a) in &self.cbmt_path { path.push((w(s,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?, Boolean::new_witness(cs.clone(),||Ok(*a))?)); }
        let troot=merkle_gadget::tx_root_from_proof_fixed(&leaf,&path,&wit)?;
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

// Assemble the BoundWindowedLeap instance from the relayer artifacts (witness_bridge + bridge_lock_live +
// optional real window). Mirrors the cold main()'s inline assembly EXACTLY so the warm serve loop produces the
// identical circuit (=> the same ceremony vk verifies it). Used only by the warm path; the cold path is
// untouched. A drifted assembly would simply fail the in-process Groth16::verify under the ceremony vk.
fn build_circuit(wpath:&str, bpath:&str, window:Option<&str>, depth:usize, k_override:Option<u64>, kmin:u64, tip_offset:u64) -> BoundWindowedLeap {
    let wsize = 1usize << depth;
    let v:Value=serde_json::from_reader(std::fs::File::open(wpath).unwrap()).unwrap();
    let lj:Value=serde_json::from_reader(std::fs::File::open(bpath).unwrap()).unwrap();
    let hs=v["headers"].as_array().unwrap();
    let (raw,nonce)=raw_of(&hs[3]);
    let block_hash=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
    assert_eq!(block_hash.iter().map(|x|format!("{:02x}",x)).collect::<String>(), hs[3]["hash"].as_str().unwrap().trim_start_matches("0x"), "block hash mismatch");
    let cb=&v["cbmt"]; let mut node=u64::from_str_radix(cb["indices"][0].as_str().unwrap().trim_start_matches("0x"),16).unwrap();
    let mut cbmt_path=Vec::new(); for l in cb["lemmas"].as_array().unwrap() { cbmt_path.push((hx32(l.as_str().unwrap()), node%2==1, true)); node=(node-1)/2; }
    assert!(cbmt_path.len() <= MAX_CBMT_DEPTH, "CBMT proof depth {} exceeds MAX_CBMT_DEPTH {}", cbmt_path.len(), MAX_CBMT_DEPTH);
    while cbmt_path.len() < MAX_CBMT_DEPTH { cbmt_path.push(([0u8;32], false, false)); }
    let cbmt_leaf=hx32(v["tx_hash"].as_str().unwrap()); let wit=hx32(cb["witnesses_root"].as_str().unwrap());
    let seal=cbmt_leaf;
    let body=hx(lj["body_hex"].as_str().unwrap());
    let bridge_code=hx32(lj["bridge_code_hash"].as_str().unwrap());
    let off=&lj["offsets"]; let type_off=off["type_code"].as_u64().unwrap() as usize;
    let amount_off=off["amount"].as_u64().unwrap() as usize; let recip_off=off["recipient"].as_u64().unwrap() as usize;
    assert_eq!(ckbhash(&body).iter().map(|x|format!("{:02x}",x)).collect::<String>(),
               seal.iter().map(|x|format!("{:02x}",x)).collect::<String>(), "captured body does not hash to the proven tx");
    let height: u64 = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    let slot = (height % wsize as u64) as usize;
    let (mut leaves, tip_height) = if let Some(wp)=window {
        let wj:Value=serde_json::from_reader(std::fs::File::open(wp).unwrap()).unwrap();
        assert_eq!(wj["window_depth"].as_u64().unwrap() as usize, depth, "CHIRAL_WINDOW depth != depth");
        assert_eq!(wj["receipt_height"].as_u64().unwrap(), height, "CHIRAL_WINDOW receipt height != proven header");
        let lv:Vec<[u8;32]>=wj["leaves"].as_array().unwrap().iter().map(|x| hx32(x.as_str().unwrap())).collect();
        assert_eq!(lv.len(), wsize, "CHIRAL_WINDOW leaf count != W");
        (lv, wj["tip_height"].as_u64().unwrap())
    } else {
        let mut lv=vec![[0u8;32]; wsize]; for kk in 0..wsize { lv[kk]=ckbhash(&((kk as u64)+1).to_le_bytes()); }
        (lv, height + tip_offset)
    };
    if window.is_some() { assert_eq!(leaves[slot], block_hash, "real window leaf at slot != the proven block hash"); }
    else { leaves[slot]=block_hash; }
    let k = k_override.unwrap_or(kmin);
    let (window_root, wpath_off)=window_root_path(&leaves, slot);
    let siblings:Vec<[u8;32]>=wpath_off.iter().map(|(s,_)|*s).collect();
    BoundWindowedLeap{ raw,nonce,cbmt_leaf,cbmt_path,wit,seal,window_root,siblings,tip_height,k,kmin,body,bridge_code,type_off,amount_off,recip_off }
}

// the 5 public inputs (window_root, seal, commitment[native], tip_height, K) of a circuit instance.
fn inputs_of(c:&BoundWindowedLeap)->Vec<Fr>{
    let amt=&c.body[c.amount_off..c.amount_off+16]; let rcp=&c.body[c.recip_off..c.recip_off+28];
    let mut ns=amt.to_vec(); ns.extend_from_slice(rcp); let mut cc=ns; cc.extend_from_slice(&c.seal); let commitment=b2b(&cc);
    vec![Fr::from_le_bytes_mod_order(&c.window_root), Fr::from_le_bytes_mod_order(&c.seal),
         Fr::from_le_bytes_mod_order(&commitment), Fr::from(c.tip_height), Fr::from(c.k)]
}

// CHIRAL_SERVE=<unix socket>: load the (~480MB) ceremony pk ONCE and prove many requests, so a return no
// longer reloads the key (~5 min) every time. Request (one JSON line): {wit,bridge,window?,depth?,k?,kmin?,out}.
// Response: {"ok":true,"out":...} | {"error":...}; the redeemer is written to `out`. This is the warm prover.
fn serve(sock:&str){
    let depth0: usize = std::env::var("WINDOW_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let kmin0: u64 = std::env::var("CHIRAL_K_MIN").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
    let pk_path=std::env::var("CEREMONY_PK").expect("CHIRAL_SERVE needs CEREMONY_PK (the ceremony proving key)");
    // The socket loop + ping/shutdown + catch_unwind live in setup_mpc::serve_warm; here we only supply the
    // leap-specific assembly (build_circuit + inputs_of), so the forward/advance legs reuse the same loop.
    ckb_consensus_circuit::setup_mpc::serve_warm(sock, &pk_path, move |req, pk, vk| {
        let wit=req["wit"].as_str().ok_or("missing wit")?;
        let bridge=req["bridge"].as_str().ok_or("missing bridge")?;
        let out=req["out"].as_str().ok_or("missing out")?;
        let window=req["window"].as_str();
        let d=req["depth"].as_u64().map(|x| x as usize).unwrap_or(depth0);
        let km=req["kmin"].as_u64().unwrap_or(kmin0);
        let kov=req["k"].as_u64();
        let circ=build_circuit(wit,bridge,window,d,kov,km,km);
        let inputs=inputs_of(&circ);
        let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let proof=Groth16::<Bls12_381>::prove(pk,circ.clone(),&mut rng).map_err(|e| format!("{e:?}"))?;
        if !Groth16::<Bls12_381>::verify(vk,&inputs,&proof).map_err(|e| format!("{e:?}"))? { return Err("warm proof did not verify under ceremony vk".into()); }
        let red=ckb_consensus_circuit::setup_mpc::emit_redeemer(vk,&proof,&inputs);
        std::fs::write(out, serde_json::to_string_pretty(&red).unwrap()).map_err(|e| e.to_string())?;
        Ok(out.to_string())
    });
}

fn main(){
    if let Ok(sock)=std::env::var("CHIRAL_SERVE") { serve(&sock); return; }
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
    let mut cbmt_path=Vec::new(); for l in cb["lemmas"].as_array().unwrap() { cbmt_path.push((hx32(l.as_str().unwrap()), node%2==1, true)); node=(node-1)/2; }
    assert!(cbmt_path.len() <= MAX_CBMT_DEPTH, "CBMT proof depth {} exceeds MAX_CBMT_DEPTH {}", cbmt_path.len(), MAX_CBMT_DEPTH);
    while cbmt_path.len() < MAX_CBMT_DEPTH { cbmt_path.push(([0u8;32], false, false)); }
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

    // ---- DIFFERENTIAL AUDIT (no proving) - GATED behind CHIRAL_AUDIT. It re-verifies FIXED circuit
    // properties (soundness of reject cases), not the request, so re-running it on every cold prove just
    // re-synthesizes ~1.39M constraints 5x for nothing. A bad witness still fails in `prove` below. Opt in
    // with CHIRAL_AUDIT=1 during development; production cold proves skip it.
    if std::env::var("CHIRAL_AUDIT").is_ok() {
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
    }

    if std::env::var("PROVE").is_err() { return; }
    // ---- FULL GROTH16: MPC ceremony (CEREMONY_OUT => production VK) / load (CEREMONY_PK) / test setup ----
    // This is the production VK source for d6_deploy's `vk` param (the value-bound transition circuit).
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    let (pk,vk) = if let Ok(dir)=std::env::var("CEREMONY_OUT") {
        eprintln!("running the MPC trusted-setup ceremony over the BOUND WINDOWED leap circuit -> {dir} ...");
        let (pk,transcript)=ckb_consensus_circuit::setup_mpc::run_ceremony(real.clone(), 3, 3, "leap_bound_windowed");
        ckb_consensus_circuit::setup_mpc::save_pk(&pk, &format!("{dir}/leap_bound_windowed_pk.bin"));
        let _ = std::fs::write(format!("{dir}/leap_bound_windowed_transcript.json"), serde_json::to_string_pretty(&transcript).unwrap());
        let vk=pk.vk.clone(); (pk,vk)
    } else if let Ok(out)=std::env::var("CHIRAL_SECURE_SETUP") {
        // SECURE single-party setup: arkworks-native circuit_specific_setup seeded from OS entropy (read once
        // from /dev/urandom, then dropped). Non-forgeable (toxic waste discarded, NOT a public seed) and
        // proven-correct (the custom MPC derive_pk yields inconsistent keys). Saves the pk for CEREMONY_PK loads.
        use std::io::Read;
        let mut seed=[0u8;32]; std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed).unwrap();
        let mut secure=ark_std::rand::rngs::StdRng::from_seed(seed);
        eprintln!("leap_bound_windowed: SECURE single-party setup (OS entropy, discarded) -> {out}");
        let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(real.clone(),&mut secure).unwrap();
        ckb_consensus_circuit::setup_mpc::save_pk(&pk,&out);
        (pk,vk)
    } else if let Ok(p)=std::env::var("CEREMONY_PK") {
        eprintln!("loading ceremony key from {p}"); let pk=ckb_consensus_circuit::setup_mpc::load_pk(&p); let vk=pk.vk.clone(); (pk,vk)
    } else {
        eprintln!("Groth16 (test) setup over the BOUND WINDOWED leap circuit...");
        Groth16::<Bls12_381>::circuit_specific_setup(real.clone(),&mut rng).unwrap()
    };
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
