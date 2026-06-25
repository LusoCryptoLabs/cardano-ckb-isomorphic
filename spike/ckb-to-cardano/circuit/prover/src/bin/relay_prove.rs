//! Relayer prove stage: read the LIVE witness (relayer.py) and produce the leap Groth16 proof + the
//! broadcast-ready Cardano redeemer. Derives RawHeader bytes, the CBMT path (from get_transaction_proof
//! lemmas), and the checkpoint MMR (over the 4 fetched headers) entirely from live data. Proves
//! R1 PoW + R2 MMR-membership + R3 tx-inclusion + R4 seal/commitment on the CURRENT Pudge chain state.
use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr; use ark_ff::{PrimeField, BigInteger};
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK; use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder; use num_bigint::BigUint; use serde_json::Value;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget, ckb_mmr, mmr_gadget};

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
// SEC D1: standard blake2b-256 (zero personalization) for the bridge COMMITMENT - matches the Cardano-side
// `builtin.blake2b_256`. ckbhash (personalized) stays for PoW/MMR/block-hash which mirror CKB consensus.
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

struct RelayLeap { raw:[u8;192], nonce:[u8;16], cbmt_leaf:[u8;32], cbmt_path:Vec<([u8;32],bool)>, wit:[u8;32],
    leaf0:[u8;120], mpath:Vec<([u8;120],bool,[u8;120])>, chain_root:[u8;32], seal:[u8;32], commitment:[u8;32] }
fn b2fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{ let mut a=FpVar::<F>::zero(); let mut c=F::one(); for byte in b { for bit in byte.to_bits_le()? { a+=FpVar::from(bit)*c; c.double_in_place(); } } Ok(a) }
impl ConstraintSynthesizer<Fr> for RelayLeap {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let raw=w(&self.raw,&cs)?; let nonce=w(&self.nonce,&cs)?;
        // R1 PoW
        let ph=blake2b256(&raw,b"ckb-default-hash")?; let mut ei=ph.clone(); ei.extend(nonce.clone());
        let eag=eaglesong_gadget::eaglesong(&ei)?; let pow=blake2b256(&eag,b"ckb-default-hash")?;
        let target=merkle_gadget::compact_to_target(&raw[4..8])?;
        merkle_gadget::enforce_leq_be(&pow,&target)?;
        // R3 tx inclusion -> transactions_root (raw[64..96])
        let leaf=w(&self.cbmt_leaf,&cs)?; let wit=w(&self.wit,&cs)?;
        let mut path=Vec::new(); for (s,d) in &self.cbmt_path { path.push((w(s,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?)); }
        let troot=merkle_gadget::tx_root_from_proof(&leaf,&path,&wit)?;
        for i in 0..32 { troot[i].enforce_equal(&raw[64+i])?; }
        // R2 MMR membership; leaf0.children_hash == block hash = ckbhash(raw||nonce)
        let mut hin=raw.clone(); hin.extend(nonce.clone()); let bh=blake2b256(&hin,b"ckb-default-hash")?;
        let leaf0=w(&self.leaf0,&cs)?; for i in 0..32 { leaf0[i].enforce_equal(&bh[i])?; }
        let mut mpath=Vec::new(); for (sib,d,par) in &self.mpath { mpath.push((w(sib,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?, w(par,&cs)?)); }
        let cr=w(&self.chain_root,&cs)?;
        mmr_gadget::enforce_membership(&cs,&leaf0,&mpath,&cr)?;
        // R4 commitment + public inputs (chain_root, seal, commitment)
        let seal=w(&self.seal,&cs)?;
        // SEC D2: bind the seal to the block-included transaction - `seal` must equal `leaf`, the tx hash
        // proven (R3 CBMT) under THIS header's transactions_root on a PoW-valid (R1), MMR-anchored (R2)
        // header. The seal is no longer a free witness; it is a transaction that actually occurred on chain.
        for i in 0..32 { seal[i].enforce_equal(&leaf[i])?; }
        let pi_cr=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.chain_root)))?;
        let pi_seal=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.seal)))?;
        let pi_comm=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.commitment)))?;
        b2fp(&cr)?.enforce_equal(&pi_cr)?; b2fp(&seal)?.enforce_equal(&pi_seal)?;
        let comm=w(&self.commitment,&cs)?; b2fp(&comm)?.enforce_equal(&pi_comm)?;
        Ok(())
    }
}
fn fq_be(x:&Fq)->[u8;48]{ let mut o=[0u8;48]; let v=x.into_bigint().to_bytes_be(); o[48-v.len()..].copy_from_slice(&v); o }
fn g1c(p:&ArkG1)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;96]; u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y)); hexs(bls12_381::G1Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn g2c(p:&ArkG2)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;192]; u[0..48].copy_from_slice(&fq_be(&x.c1)); u[48..96].copy_from_slice(&fq_be(&x.c0)); u[96..144].copy_from_slice(&fq_be(&y.c1)); u[144..192].copy_from_slice(&fq_be(&y.c0)); hexs(bls12_381::G2Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn hexs(b:impl AsRef<[u8]>)->String{ b.as_ref().iter().map(|x| format!("{:02x}",x)).collect() }
fn fr_dec(x:&Fr)->String{ x.into_bigint().to_string() }

fn main(){
    let path=std::env::args().nth(1).unwrap_or("/tmp/witness.json".into());
    let v:Value=serde_json::from_reader(std::fs::File::open(&path).unwrap()).unwrap();
    let hs=v["headers"].as_array().unwrap();
    let (raw,nonce)=raw_of(&hs[3]);
    // sanity: recompute block hash from live header
    let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
    assert_eq!(hexs(&bh), hs[3]["hash"].as_str().unwrap().trim_start_matches("0x"), "block hash mismatch");
    eprintln!("relay: target block {} hash {} recomputed OK", hs[3]["number"].as_str().unwrap(), &hexs(&bh)[..16]);
    // CBMT path from lemmas/indices
    let cb=&v["cbmt"]; let mut node=u64::from_str_radix(cb["indices"][0].as_str().unwrap().trim_start_matches("0x"),16).unwrap();
    let lemmas=cb["lemmas"].as_array().unwrap();
    let mut cbmt_path=Vec::new(); for l in lemmas { cbmt_path.push((hx32(l.as_str().unwrap()), node%2==1)); node=(node-1)/2; }
    let cbmt_leaf=hx32(v["tx_hash"].as_str().unwrap()); let wit=hx32(cb["witnesses_root"].as_str().unwrap());
    // checkpoint MMR over the 4 fetched headers (T-3..T); membership of leaf 3 (=T)
    let leaves:Vec<[u8;120]>=(0..4).map(|i| mkleaf(&hs[i], hx32(hs[i]["hash"].as_str().unwrap()))).collect();
    let n01=ckb_mmr::merge(&leaves[0],&leaves[1]); let n23=ckb_mmr::merge(&leaves[2],&leaves[3]); let root=ckb_mmr::merge(&n01,&n23);
    let chain_root=ckb_mmr::mmr_hash(&root);
    let mpath=vec![(leaves[2],false,n23),(n01,false,root)];
    // SEC D2: the seal IS the block-included leap tx (= the CBMT leaf = the proven tx_hash), not a free
    // witness. The circuit enforces seal == cbmt_leaf, so the seal the relayer can present is exactly a
    // transaction proven to sit in the confirmed CKB chain.
    let seal=cbmt_leaf;
    // SEC D1: standard blake2b-256 commitment - matches cardano_bound.ak `builtin.blake2b_256`.
    let new_state=b"ckb-anchored:leap".to_vec(); let commitment={let mut c=new_state.clone(); c.extend_from_slice(&seal); b2b(&c)};
    let circ=RelayLeap{raw,nonce,cbmt_leaf,cbmt_path,wit,leaf0:leaves[3],mpath,chain_root,seal,commitment};
    let cs=ConstraintSystem::<Fr>::new_ref(); 
    // quick satisfiability check before the heavy setup
    {let c2=RelayLeap{raw,nonce,cbmt_leaf,cbmt_path:circ.cbmt_path.clone(),wit,leaf0:leaves[3],mpath:circ.mpath.clone(),chain_root,seal,commitment};
     c2.generate_constraints(cs.clone()).unwrap(); eprintln!("relay: circuit is_satisfied={} constraints={}", cs.is_satisfied().unwrap(), cs.num_constraints()); assert!(cs.is_satisfied().unwrap()); }
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    eprintln!("relay: Groth16 setup+prove on LIVE data...");
    let setup=RelayLeap{raw,nonce,cbmt_leaf,cbmt_path:circ.cbmt_path.clone(),wit,leaf0:leaves[3],mpath:circ.mpath.clone(),chain_root,seal,commitment};
    let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(setup,&mut rng).unwrap();
    let proof=Groth16::<Bls12_381>::prove(&pk,circ,&mut rng).unwrap();
    let inputs=vec![Fr::from_le_bytes_mod_order(&chain_root),Fr::from_le_bytes_mod_order(&seal),Fr::from_le_bytes_mod_order(&commitment)];
    assert!(Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap());
    eprintln!("relay: arkworks verify = true (LIVE leap proof for block {})", hs[3]["number"].as_str().unwrap());
    let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    let redeemer=serde_json::json!({
      "note":"broadcast-ready Cardano redeemer for cardano_bound.ak spend (CKB->Cardano leap)",
      "target_block": hs[3]["number"], "chain_root": format!("0x{}",hexs(&chain_root)),
      "seal": format!("0x{}",hexs(&seal)), "commitment": format!("0x{}",hexs(&commitment)),
      "vk":{"alpha_g1":g1c(&vk.alpha_g1),"beta_g2":g2c(&vk.beta_g2),"gamma_g2":g2c(&vk.gamma_g2),"delta_g2":g2c(&vk.delta_g2),"ic":ic},
      "proof":{"a":g1c(&proof.a),"b":g2c(&proof.b),"c":g1c(&proof.c)},
      "public_inputs_dec": inputs.iter().map(fr_dec).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&redeemer).unwrap());
}
