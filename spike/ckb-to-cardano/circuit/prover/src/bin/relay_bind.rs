//! relay_bind - the VALUE-BOUND live leap prover (VALUE_BINDING_FIX.md). relay_prove + the fix: bring the
//! real bridge-receipt RawTransaction body in-circuit, ckbhash it == the proven tx (seal), require the
//! receipt output's type code-hash == the pinned bridge_lock_v1, and DERIVE the commitment from the receipt's
//! own amount(16 LE)+recipient(28) read out of that body. So the public-input commitment provably binds the
//! amount/recipient that were actually locked on CKB - a relayer can no longer mint unbacked χCKB.
//! Reads witness.json (relayer.py: real header+CBMT for the receipt tx) + bridge_lock_live.json (the captured
//! body + offsets). Proves R1 PoW + R2 MMR + R3 CBMT (+ seal==tx) + the value binding, on the LIVE chain.
use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr; use ark_ff::{PrimeField, BigInteger};
use ark_groth16::{Groth16, VerifyingKey, Proof};
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK; use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder; use num_bigint::BigUint; use serde_json::Value;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget, ckb_mmr, mmr_gadget};

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn b2b(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hx(s:&str)->Vec<u8>{ let s=s.trim_start_matches("0x"); (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn hx32(s:&str)->[u8;32]{ hx(s).try_into().unwrap() }
fn uh(v:&Value,k:&str)->u128{ u128::from_str_radix(v[k].as_str().unwrap().trim_start_matches("0x"),16).unwrap() }
fn tfc(c:u32)->[u8;32]{ let e=(c>>24)as usize; let m=c&0x007fffff; let mut t=[0u8;32]; let mb=m.to_be_bytes(); for k in 0..3 { let p=32-e+k; if p<32 {t[p]=mb[1+k];} } t }
fn ndiff_le(c:u32)->[u8;32]{ let tg=BigUint::from_bytes_be(&tfc(c)); let mx=(BigUint::from(1u8)<<256usize)-BigUint::from(1u8); let d=&mx/&tg; let mut be=[0u8;32]; let db=d.to_bytes_be(); be[32-db.len()..].copy_from_slice(&db); be.reverse(); be }
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
fn mkleaf(h:&Value, hash:[u8;32])->[u8;120]{
    ckb_mmr::leaf(hash, ndiff_le(uh(h,"compact_target") as u32), uh(h,"number") as u64, uh(h,"epoch") as u64, uh(h,"timestamp") as u64, uh(h,"compact_target") as u32)
}

#[derive(Clone)]
struct RelayBind { raw:[u8;192], nonce:[u8;16], cbmt_leaf:[u8;32], cbmt_path:Vec<([u8;32],bool,bool)>, wit:[u8;32],
    leaf0:[u8;120], mpath:Vec<([u8;120],bool,[u8;120])>, chain_root:[u8;32], seal:[u8;32],
    body:Vec<u8>, bridge_code:[u8;32], type_off:usize, amount_off:usize, recip_off:usize }
fn b2fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{ let mut a=FpVar::<F>::zero(); let mut c=F::one(); for byte in b { for bit in byte.to_bits_le()? { a+=FpVar::from(bit)*c; c.double_in_place(); } } Ok(a) }
impl ConstraintSynthesizer<Fr> for RelayBind {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let raw=w(&self.raw,&cs)?; let nonce=w(&self.nonce,&cs)?;
        // R1 PoW
        let ph=blake2b256(&raw,b"ckb-default-hash")?; let mut ei=ph.clone(); ei.extend(nonce.clone());
        let eag=eaglesong_gadget::eaglesong(&ei)?; let pow=blake2b256(&eag,b"ckb-default-hash")?;
        let target=merkle_gadget::compact_to_target(&raw[4..8])?;
        merkle_gadget::enforce_leq_be(&pow,&target)?;
        // R3 tx inclusion -> transactions_root
        let leaf=w(&self.cbmt_leaf,&cs)?; let wit=w(&self.wit,&cs)?;
        // FIXED-DEPTH CBMT: each level carries an `active` flag; the path is padded to a constant MAX so the
        // circuit size is invariant to the block's tx count (one deployed vk verifies any lock).
        let mut path=Vec::new(); for (s,d,a) in &self.cbmt_path { path.push((w(s,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?, Boolean::new_witness(cs.clone(),||Ok(*a))?)); }
        let troot=merkle_gadget::tx_root_from_proof_fixed(&leaf,&path,&wit)?;
        for i in 0..32 { troot[i].enforce_equal(&raw[64+i])?; }
        // R2 MMR membership; leaf0.children_hash == block hash
        let mut hin=raw.clone(); hin.extend(nonce.clone()); let bh=blake2b256(&hin,b"ckb-default-hash")?;
        let leaf0=w(&self.leaf0,&cs)?; for i in 0..32 { leaf0[i].enforce_equal(&bh[i])?; }
        let mut mpath=Vec::new(); for (sib,d,par) in &self.mpath { mpath.push((w(sib,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?, w(par,&cs)?)); }
        let cr=w(&self.chain_root,&cs)?;
        mmr_gadget::enforce_membership(&cs,&leaf0,&mpath,&cr)?;
        // SEC D2: seal == the block-included tx (the CBMT leaf), not a free witness
        let seal=w(&self.seal,&cs)?;
        for i in 0..32 { seal[i].enforce_equal(&leaf[i])?; }
        // ---- VALUE BINDING (the fix) ----
        let body=w(&self.body,&cs)?;
        // (a) body authenticity: ckbhash(full RawTransaction) == the proven tx hash (== seal == leaf)
        let bh2=blake2b256(&body,b"ckb-default-hash")?;
        for i in 0..32 { bh2[i].enforce_equal(&seal[i])?; }
        // (b) the receipt output carries bridge_lock_v1 (type Script code-hash == the pinned constant)
        for i in 0..32 { body[self.type_off+i].enforce_equal(&UInt8::constant(self.bridge_code[i]))?; }
        // (c) DERIVE new_state = amount(16 LE) ‖ recipient(28) from the receipt's own data, and the commitment
        //     from it - so the public-input commitment binds exactly the locked amount/recipient.
        let mut new_state:Vec<UInt8<Fr>>=Vec::with_capacity(44);
        for i in 0..16 { new_state.push(body[self.amount_off+i].clone()); }
        for i in 0..28 { new_state.push(body[self.recip_off+i].clone()); }
        let mut ci=new_state.clone(); ci.extend(seal.clone());
        let comm=blake2b256(&ci,&[0u8;16])?;                            // SEC D1: standard blake2b
        // R4 public inputs: (chain_root, seal, commitment[derived])
        let pi_cr=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.chain_root)))?;
        let pi_seal=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.seal)))?;
        let amt:Vec<u8>=self.body[self.amount_off..self.amount_off+16].to_vec();
        let rcp:Vec<u8>=self.body[self.recip_off..self.recip_off+28].to_vec();
        let mut ns=amt.clone(); ns.extend_from_slice(&rcp); let mut cc=ns.clone(); cc.extend_from_slice(&self.seal); let comm_native=b2b(&cc);
        let pi_comm=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&comm_native)))?;
        b2fp(&cr)?.enforce_equal(&pi_cr)?; b2fp(&seal)?.enforce_equal(&pi_seal)?; b2fp(&comm)?.enforce_equal(&pi_comm)?;
        Ok(())
    }
}
fn fq_be(x:&Fq)->[u8;48]{ let mut o=[0u8;48]; let v=x.into_bigint().to_bytes_be(); o[48-v.len()..].copy_from_slice(&v); o }
fn g1c(p:&ArkG1)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;96]; u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y)); hexs(bls12_381::G1Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn g2c(p:&ArkG2)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;192]; u[0..48].copy_from_slice(&fq_be(&x.c1)); u[48..96].copy_from_slice(&fq_be(&x.c0)); u[96..144].copy_from_slice(&fq_be(&y.c1)); u[144..192].copy_from_slice(&fq_be(&y.c0)); hexs(bls12_381::G2Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn hexs(b:impl AsRef<[u8]>)->String{ b.as_ref().iter().map(|x| format!("{:02x}",x)).collect() }
fn fr_dec(x:&Fr)->String{ x.into_bigint().to_string() }

struct RelayMeta { target_block: String, tx: String, amount: String, recipient: String, chain_root: String, seal: String, commitment: String }

// Build the value-bound circuit + its 3 public inputs + redeemer metadata from a witness (wpath) and the
// captured receipt body (bpath). Used by the warm server (serve); mirrors the cold path in main().
fn build_relay(wpath:&str, bpath:&str) -> (RelayBind, Vec<Fr>, RelayMeta) {
    let v:Value=serde_json::from_reader(std::fs::File::open(wpath).unwrap()).unwrap();
    let lj:Value=serde_json::from_reader(std::fs::File::open(bpath).unwrap()).unwrap();
    let hs=v["headers"].as_array().unwrap();
    let (raw,nonce)=raw_of(&hs[3]);
    let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
    assert_eq!(hexs(&bh), hs[3]["hash"].as_str().unwrap().trim_start_matches("0x"), "block hash mismatch");
    let cb=&v["cbmt"]; let mut node=u64::from_str_radix(cb["indices"][0].as_str().unwrap().trim_start_matches("0x"),16).unwrap();
    let mut cbmt_path=Vec::new(); for l in cb["lemmas"].as_array().unwrap() { cbmt_path.push((hx32(l.as_str().unwrap()), node%2==1, true)); node=(node-1)/2; }
    const MAX_CBMT_DEPTH: usize = 16;   // fixed CBMT depth -> circuit/vk invariant to the block's tx count
    assert!(cbmt_path.len() <= MAX_CBMT_DEPTH, "CBMT proof depth {} exceeds MAX_CBMT_DEPTH {}", cbmt_path.len(), MAX_CBMT_DEPTH);
    while cbmt_path.len() < MAX_CBMT_DEPTH { cbmt_path.push(([0u8;32], false, false)); }
    let cbmt_leaf=hx32(v["tx_hash"].as_str().unwrap()); let wit=hx32(cb["witnesses_root"].as_str().unwrap());
    let leaves:Vec<[u8;120]>=(0..4).map(|i| mkleaf(&hs[i], hx32(hs[i]["hash"].as_str().unwrap()))).collect();
    let n01=ckb_mmr::merge(&leaves[0],&leaves[1]); let n23=ckb_mmr::merge(&leaves[2],&leaves[3]); let root=ckb_mmr::merge(&n01,&n23);
    let chain_root=ckb_mmr::mmr_hash(&root); let mpath=vec![(leaves[2],false,n23),(n01,false,root)];
    let seal=cbmt_leaf;
    let body=hx(lj["body_hex"].as_str().unwrap());
    let bridge_code=hx32(lj["bridge_code_hash"].as_str().unwrap());
    let off=&lj["offsets"]; let type_off=off["type_code"].as_u64().unwrap() as usize;
    let amount_off=off["amount"].as_u64().unwrap() as usize; let recip_off=off["recipient"].as_u64().unwrap() as usize;
    assert_eq!(hexs(&ckbhash(&body)), hexs(&seal), "captured body does not hash to the proven tx");
    let amt=&body[amount_off..amount_off+16]; let rcp=&body[recip_off..recip_off+28];
    let mut ns=amt.to_vec(); ns.extend_from_slice(rcp); let mut cc=ns.clone(); cc.extend_from_slice(&seal); let commitment=b2b(&cc);
    let inputs=vec![Fr::from_le_bytes_mod_order(&chain_root), Fr::from_le_bytes_mod_order(&seal), Fr::from_le_bytes_mod_order(&commitment)];
    let meta=RelayMeta{
        target_block: hs[3]["number"].as_str().unwrap().to_string(), tx: v["tx_hash"].as_str().unwrap().to_string(),
        amount: u128::from_le_bytes(amt.try_into().unwrap()).to_string(), recipient: format!("0x{}",hexs(rcp)),
        chain_root: format!("0x{}",hexs(&chain_root)), seal: format!("0x{}",hexs(&seal)), commitment: format!("0x{}",hexs(&commitment)) };
    let circ=RelayBind{raw,nonce,cbmt_leaf,cbmt_path,wit,leaf0:leaves[3],mpath,chain_root,seal,body,bridge_code,type_off,amount_off,recip_off};
    (circ, inputs, meta)
}

// The value-bound leap redeemer JSON - IDENTICAL shape to the cold path below (cardano_mint_bound.py /
// emit_mint_redeemer.py consume amount/recipient/seal/proof/public_inputs_dec).
fn emit_relay(vk:&VerifyingKey<Bls12_381>, proof:&Proof<Bls12_381>, inputs:&[Fr], m:&RelayMeta) -> String {
    let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    serde_json::to_string_pretty(&serde_json::json!({
      "note":"value-bound CKB->Cardano leap redeemer (cardano_bound.ak); commitment derived in-circuit from the receipt amount/recipient",
      "target_block": m.target_block, "tx": m.tx, "amount": m.amount, "recipient": m.recipient,
      "chain_root": m.chain_root, "seal": m.seal, "commitment": m.commitment,
      "vk":{"alpha_g1":g1c(&vk.alpha_g1),"beta_g2":g2c(&vk.beta_g2),"gamma_g2":g2c(&vk.gamma_g2),"delta_g2":g2c(&vk.delta_g2),"ic":ic},
      "proof":{"a":g1c(&proof.a),"b":g2c(&proof.b),"c":g1c(&proof.c)},
      "public_inputs_dec": inputs.iter().map(fr_dec).collect::<Vec<_>>()
    })).unwrap()
}

// CHIRAL_SERVE=<unix socket>: load the (~740MB) ceremony pk ONCE and prove many forward-mint requests, so a
// tester's lock no longer reloads the key (~4 min) each time. Request (one JSON line): {wit,bridge,out}; the
// redeemer is written to `out`. The forward-leg warm prover (mirrors leap_bound_windowed's serve).
fn serve(sock:&str){
    let pk_path=std::env::var("CEREMONY_PK").expect("CHIRAL_SERVE needs CEREMONY_PK (the ceremony proving key)");
    ckb_consensus_circuit::setup_mpc::serve_warm(sock, &pk_path, move |req, pk, vk| {
        let wit=req["wit"].as_str().ok_or("missing wit")?;
        let bridge=req["bridge"].as_str().ok_or("missing bridge")?;
        let out=req["out"].as_str().ok_or("missing out")?;
        let (circ, inputs, meta)=build_relay(wit, bridge);
        let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let proof=Groth16::<Bls12_381>::prove(pk, circ.clone(), &mut rng).map_err(|e| format!("{e:?}"))?;
        if !Groth16::<Bls12_381>::verify(vk, &inputs, &proof).map_err(|e| format!("{e:?}"))? { return Err("warm proof did not verify under ceremony vk".into()); }
        std::fs::write(out, emit_relay(vk, &proof, &inputs, &meta)).map_err(|e| e.to_string())?;
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
    let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
    assert_eq!(hexs(&bh), hs[3]["hash"].as_str().unwrap().trim_start_matches("0x"), "block hash mismatch");
    // CBMT path
    let cb=&v["cbmt"]; let mut node=u64::from_str_radix(cb["indices"][0].as_str().unwrap().trim_start_matches("0x"),16).unwrap();
    let mut cbmt_path=Vec::new(); for l in cb["lemmas"].as_array().unwrap() { cbmt_path.push((hx32(l.as_str().unwrap()), node%2==1, true)); node=(node-1)/2; }
    // FIXED-DEPTH: pad the CBMT proof to a constant MAX so the circuit (and thus the vk) is invariant to how
    // many txs share the lock's block. Padding levels are inactive no-ops (see merkle_gadget::merkle_root_fixed).
    const MAX_CBMT_DEPTH: usize = 16;   // covers up to 2^16 txs/block; real CKB blocks are far smaller
    assert!(cbmt_path.len() <= MAX_CBMT_DEPTH, "CBMT proof depth {} exceeds MAX_CBMT_DEPTH {}", cbmt_path.len(), MAX_CBMT_DEPTH);
    while cbmt_path.len() < MAX_CBMT_DEPTH { cbmt_path.push(([0u8;32], false, false)); }
    let cbmt_leaf=hx32(v["tx_hash"].as_str().unwrap()); let wit=hx32(cb["witnesses_root"].as_str().unwrap());
    // checkpoint MMR over T-3..T
    let leaves:Vec<[u8;120]>=(0..4).map(|i| mkleaf(&hs[i], hx32(hs[i]["hash"].as_str().unwrap()))).collect();
    let n01=ckb_mmr::merge(&leaves[0],&leaves[1]); let n23=ckb_mmr::merge(&leaves[2],&leaves[3]); let root=ckb_mmr::merge(&n01,&n23);
    let chain_root=ckb_mmr::mmr_hash(&root); let mpath=vec![(leaves[2],false,n23),(n01,false,root)];
    let seal=cbmt_leaf;
    // the captured receipt body + the offsets (computed + verified on the real tx by bridge_deploy_lock.mjs)
    let body=hx(lj["body_hex"].as_str().unwrap());
    let bridge_code=hx32(lj["bridge_code_hash"].as_str().unwrap());
    let off=&lj["offsets"]; let type_off=off["type_code"].as_u64().unwrap() as usize;
    let amount_off=off["amount"].as_u64().unwrap() as usize; let recip_off=off["recipient"].as_u64().unwrap() as usize;
    assert_eq!(hexs(&ckbhash(&body)), hexs(&seal), "captured body does not hash to the proven tx");
    let mk=||RelayBind{raw,nonce,cbmt_leaf,cbmt_path:cbmt_path.clone(),wit,leaf0:leaves[3],mpath:mpath.clone(),chain_root,seal,body:body.clone(),bridge_code,type_off,amount_off,recip_off};
    let cs=ConstraintSystem::<Fr>::new_ref();
    mk().generate_constraints(cs.clone()).unwrap();
    eprintln!("relay_bind: is_satisfied={} constraints={}", cs.is_satisfied().unwrap(), cs.num_constraints());
    assert!(cs.is_satisfied().unwrap(), "value-bound live circuit not satisfied");
    let amt=&body[amount_off..amount_off+16]; let rcp=&body[recip_off..recip_off+28];
    let mut ns=amt.to_vec(); ns.extend_from_slice(rcp); let mut cc=ns.clone(); cc.extend_from_slice(&seal); let commitment=b2b(&cc);
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    // E1: the vk is a COMPILE-TIME parameter of the deployed zk_chiral_mint policy, so a deterministic
    // seed_from_u64(7) setup makes the policy's vk forgeable (toxic waste publicly recoverable). Prefer a
    // ceremony key: CEREMONY_OUT runs the MPC trusted setup once; CEREMONY_PK loads it; else the seeded
    // dev/test fallback (which still prints a redeemer for local sanity but MUST NOT back a live policy).
    let (pk,vk) = if let Ok(dir)=std::env::var("CEREMONY_OUT") {
        eprintln!("relay_bind: running MPC trusted-setup ceremony over the value-bound circuit -> {dir} ...");
        let (pk,transcript)=ckb_consensus_circuit::setup_mpc::run_ceremony(mk(), 3, 3, "relay_bind");
        ckb_consensus_circuit::setup_mpc::save_pk(&pk, &format!("{dir}/relay_bind_pk.bin"));
        let _ = std::fs::write(format!("{dir}/relay_bind_transcript.json"), serde_json::to_string_pretty(&transcript).unwrap());
        let vk=pk.vk.clone(); (pk,vk)
    } else if let Ok(out)=std::env::var("CHIRAL_SECURE_SETUP") {
        // E1-FIX: arkworks-native trusted setup, seeded from OS entropy (read once from /dev/urandom, then
        // dropped) - a SECURE single-party setup. The custom MPC assembly (setup_mpc::derive_pk) currently
        // yields an INCONSISTENT proving key (proofs fail their own vk; see relay_bind dry-run); this
        // proven-correct generator replaces it for the testnet pilot. Non-forgeable: the toxic waste is
        // discarded, NOT a public seed like the dev fallback below. Saves the pk so the server loads it via
        // CEREMONY_PK unchanged, and emits a redeemer so the policy is baked from this vk.
        use std::io::Read;
        let mut seed=[0u8;32]; std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed).unwrap();
        let mut secure=ark_std::rand::rngs::StdRng::from_seed(seed);
        eprintln!("relay_bind: SECURE single-party setup (OS entropy, discarded) -> {out}");
        let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(mk(),&mut secure).unwrap();
        ckb_consensus_circuit::setup_mpc::save_pk(&pk,&out);
        (pk,vk)
    } else if let Ok(p)=std::env::var("CEREMONY_PK") {
        eprintln!("relay_bind: loading ceremony key from {p}"); let pk=ckb_consensus_circuit::setup_mpc::load_pk(&p); let vk=pk.vk.clone(); (pk,vk)
    } else {
        eprintln!("relay_bind: Groth16 (SEEDED test) setup+prove on LIVE value-bound data - dev only, forgeable vk...");
        Groth16::<Bls12_381>::circuit_specific_setup(mk(),&mut rng).unwrap()
    };
    let proof=Groth16::<Bls12_381>::prove(&pk,mk(),&mut rng).unwrap();
    let inputs=vec![Fr::from_le_bytes_mod_order(&chain_root),Fr::from_le_bytes_mod_order(&seal),Fr::from_le_bytes_mod_order(&commitment)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap();
    eprintln!("relay_bind: arkworks verify = {ok} (LIVE VALUE-BOUND leap for block {}, amount {} recipient {})",
        hs[3]["number"].as_str().unwrap(), u128::from_le_bytes(amt.try_into().unwrap()), hexs(rcp));
    assert!(ok);
    let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    let redeemer=serde_json::json!({
      "note":"value-bound CKB->Cardano leap redeemer (cardano_bound.ak); commitment derived in-circuit from the receipt amount/recipient",
      "target_block": hs[3]["number"], "tx": v["tx_hash"], "amount": u128::from_le_bytes(amt.try_into().unwrap()).to_string(), "recipient": format!("0x{}",hexs(rcp)),
      "chain_root": format!("0x{}",hexs(&chain_root)), "seal": format!("0x{}",hexs(&seal)), "commitment": format!("0x{}",hexs(&commitment)),
      "vk":{"alpha_g1":g1c(&vk.alpha_g1),"beta_g2":g2c(&vk.beta_g2),"gamma_g2":g2c(&vk.gamma_g2),"delta_g2":g2c(&vk.delta_g2),"ic":ic},
      "proof":{"a":g1c(&proof.a),"b":g2c(&proof.b),"c":g1c(&proof.c)},
      "public_inputs_dec": inputs.iter().map(fr_dec).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&redeemer).unwrap());
}
