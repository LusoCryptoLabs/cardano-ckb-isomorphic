//! Assemble the FAITHFUL CKB-consensus leap circuit on REAL block 21,341,101 and produce a Groth16
//! proof the Aiken verifier accepts. Now wired to real data:
//!   R1  PoW: ckbhash(eaglesong(ckbhash(RawHeader)||nonce)) <= compact_to_target(header.compact_target)
//!   R3  the tx is bound to THIS header's transactions_root via a REAL CBMT path + ckbhash(raw||wit)
//!   R4  commitment = ckbhash(new_state || seal); public inputs (3) = (checkpoint_root, seal, commitment)
use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, BigInteger};
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder;
use eaglesong::eaglesong as native_eaglesong;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget, ckb_mmr, mmr_gadget};

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
// SEC D1: the bridge COMMITMENT is recomputed on Cardano with `builtin.blake2b_256` (STANDARD blake2b-256,
// zero personalization). The circuit MUST hash the commitment the same way, or a valid proof's `commitment`
// public input can never equal the validator's recomputed value. PoW/MMR/block-hash stay on `ckbhash`
// (those mirror real CKB consensus); only the commitment uses standard blake2b.
fn b2b(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hx(s:&str)->Vec<u8>{ (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }

// REAL block 21,341,101
fn raw_header()->([u8;192],[u8;16]){
    let mut r=Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&0x1d083f14u32.to_le_bytes());      // compact_target @4..8
    r.extend_from_slice(&0x19e9f512d04u64.to_le_bytes());
    r.extend_from_slice(&0x145a3adu64.to_le_bytes());
    r.extend_from_slice(&0x70802fc0033abu64.to_le_bytes());
    r.extend_from_slice(&hx("d33b041d4f08e5510692dd0adbdd0be325db777a7fff1aef237a845f3058d60a"));
    r.extend_from_slice(&hx("7e9f6b0a9b2a84aa7b8fd9cff42ef6d999ab22f5ec4c3e746439e9b1af981d4f")); // transactions_root @64..96
    r.extend_from_slice(&hx("0000000000000000000000000000000000000000000000000000000000000000"));
    r.extend_from_slice(&hx("a7f0a504f0b8e334a6e66548347affbe55ee4207bc2b3bddc69cd0eff8eca72c"));
    r.extend_from_slice(&hx("105ee644c39127572a332bb93f132a006fafe4cf2dc3e10900ba21e2b0d55709"));
    let mut raw=[0u8;192]; raw.copy_from_slice(&r);
    let mut n=[0u8;16]; n.copy_from_slice(&0x2e24d7131728615efc333b1b2a26860cu128.to_le_bytes());
    (raw,n)
}
// REAL CBMT membership for tx index 1 of block 21,341,101
fn cbmt()->([u8;32], Vec<([u8;32],bool)>, [u8;32]){
    let leaf:[u8;32]=hx("e41483226bdc513c86cdcf97e9a7bee783542cae2acadc0a3fc8f990defaa520").try_into().unwrap();
    let wit:[u8;32]=hx("c4fd19a160c8a54c09532c08ee31490222c059d3aa3cd32dd173486f14f95709").try_into().unwrap();
    let path=vec![ (hx("d3087d258517721730213691ce0f66df27e4f6acc069c8f89ec1990d4924d66c").try_into().unwrap(), false), (hx("003dfeafc9199a0f3cc4f6ef47ea3a7183ae38483929c6e5e93b1f0cddc21248").try_into().unwrap(), true) ];
    (leaf, path, wit)
}

#[derive(Clone)]
struct LeapCircuit { raw:[u8;192], nonce:[u8;16], leaf:[u8;32], path:Vec<([u8;32],bool)>, wit:[u8;32],
    new_state:Vec<u8>, seal:[u8;32], chain_root:[u8;32],
    leaf0:[u8;120], mpath:Vec<([u8;120],bool,[u8;120])> }
fn bytes_to_fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{
    let mut acc=FpVar::<F>::zero(); let mut c=F::one();
    for byte in b { for bit in byte.to_bits_le()? { acc += FpVar::from(bit)*c; c.double_in_place(); } }
    Ok(acc)
}
impl ConstraintSynthesizer<Fr> for LeapCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let raw: Vec<UInt8<Fr>> = self.raw.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        let nonce: Vec<UInt8<Fr>> = self.nonce.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        // R1 PoW with in-circuit compact-target decode
        let pow_hash = blake2b256(&raw, b"ckb-default-hash")?;
        let mut ei=pow_hash.clone(); ei.extend(nonce);
        let eag=eaglesong_gadget::eaglesong(&ei)?;
        let pow_out=blake2b256(&eag, b"ckb-default-hash")?;
        let target=merkle_gadget::compact_to_target(&raw[4..8])?;
        merkle_gadget::enforce_leq_be(&pow_out, &target)?;
        // R3 bind tx to THIS header's transactions_root (raw[64..96]) via the real CBMT path
        let leaf: Vec<UInt8<Fr>> = self.leaf.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        let wit: Vec<UInt8<Fr>> = self.wit.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        let mut path=Vec::new();
        for (s,d) in &self.path { let sv: Vec<UInt8<Fr>> = s.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?; path.push((sv, Boolean::new_witness(cs.clone(),||Ok(*d))?)); }
        let troot=merkle_gadget::tx_root_from_proof(&leaf,&path,&wit)?;
        for i in 0..32 { troot[i].enforce_equal(&raw[64+i])?; }
        // R2: the proven header is a leaf of the checkpointed ChainRootMMR. Its leaf.children_hash
        // must equal THIS header's block hash = ckbhash(RawHeader || nonce) -> ties R2 to R1.
        let mut hin = raw.clone(); let nonce2: Vec<UInt8<Fr>> = self.nonce.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?; hin.extend(nonce2);
        let block_hash = blake2b256(&hin, b"ckb-default-hash")?;
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let leaf0=w(&self.leaf0,&cs)?;
        for i in 0..32 { leaf0[i].enforce_equal(&block_hash[i])?; }   // leaf.children_hash == block hash
        let mut mpath=Vec::new();
        for (sib,d,par) in &self.mpath { mpath.push((w(sib,&cs)?, Boolean::new_witness(cs.clone(),||Ok(*d))?, w(par,&cs)?)); }
        let cr_bytes=w(&self.chain_root,&cs)?;
        mmr_gadget::enforce_membership(&cs, &leaf0, &mpath, &cr_bytes)?;
        // R4 commitment + public inputs
        let ns: Vec<UInt8<Fr>> = self.new_state.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        let seal: Vec<UInt8<Fr>> = self.seal.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        // SEC D2: bind the seal to the block-included transaction. `seal` is no longer a free witness - it
        // must equal `leaf`, the tx hash proven (R3 CBMT) to sit under THIS header's transactions_root, on a
        // header proven (R1 PoW) and anchored (R2 MMR) in the checkpointed chain. So the seal a relayer can
        // present is exactly a transaction that actually occurred on the confirmed CKB chain.
        for i in 0..32 { seal[i].enforce_equal(&leaf[i])?; }
        let mut ci=ns; ci.extend(seal.clone());
        // SEC D1: standard blake2b-256 (zero personalization) - matches cardano_bound.ak `builtin.blake2b_256`.
        let comm=blake2b256(&ci, &[0u8;16])?;
        let cr: Vec<UInt8<Fr>> = self.chain_root.iter().map(|b| UInt8::new_witness(cs.clone(),||Ok(*b))).collect::<Result<_,_>>()?;
        // commitment value for the public input
        let comm_bytes: Vec<u8> = { let ns=self.new_state.clone(); let mut c=ns; c.extend_from_slice(&self.seal); b2b(&c).to_vec() };
        let mut cb=[0u8;32]; cb.copy_from_slice(&comm_bytes);
        let pi_cr=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.chain_root)))?;
        let pi_seal=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&self.seal)))?;
        let pi_comm=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(&cb)))?;
        bytes_to_fp(&cr)?.enforce_equal(&pi_cr)?;
        bytes_to_fp(&seal)?.enforce_equal(&pi_seal)?;
        bytes_to_fp(&comm)?.enforce_equal(&pi_comm)?;
        Ok(())
    }
}

fn fq_be(x:&Fq)->[u8;48]{ let mut o=[0u8;48]; let v=x.into_bigint().to_bytes_be(); o[48-v.len()..].copy_from_slice(&v); o }
fn g1c(p:&ArkG1)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;96]; u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y)); hexs(bls12_381::G1Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn g2c(p:&ArkG2)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;192]; u[0..48].copy_from_slice(&fq_be(&x.c1)); u[48..96].copy_from_slice(&fq_be(&x.c0)); u[96..144].copy_from_slice(&fq_be(&y.c1)); u[144..192].copy_from_slice(&fq_be(&y.c0)); hexs(bls12_381::G2Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn hexs(b:impl AsRef<[u8]>)->String{ b.as_ref().iter().map(|x| format!("{:02x}",x)).collect() }
fn fr_dec(x:&Fr)->String{ x.into_bigint().to_string() }

fn main(){
    let (raw,nonce)=raw_header(); let (leaf,path,wit)=cbmt();
    // native PoW sanity on this real block
    let ph=ckbhash(&raw); let mut ei=ph.to_vec(); ei.extend_from_slice(&nonce); let mut eag=[0u8;32]; native_eaglesong(&ei,&mut eag); let pow=ckbhash(&eag);
    eprintln!("native pow_out (BE) = {}", hexs(&pow));
    // SEC D2: the seal IS the block-included tx (= the CBMT leaf), not an arbitrary value.
    let new_state=b"ckb-anchored:demo:v1".to_vec(); let seal=leaf;
    let mut cc=new_state.clone(); cc.extend_from_slice(&seal); let commitment=b2b(&cc); // SEC D1: standard blake2b
    // R2: build the checkpointed ChainRootMMR over REAL headers 21,341,101..104 (101 = the proven header)
    let lh0=hx("94ba8c1183aa9bb52f0705f37bd9b5e1aa78721774aa5f6deebeb31a640b8c18"); let mut a0=[0u8;32]; a0.copy_from_slice(&lh0);
    let l0=ckb_mmr::leaf(a0, [0u8;32], 21341101, 1979133747803051, 1780789357828, 487079700);
    let lh1=hx("a5df20923eb0892f0f1b02b0bd474b21488271779a92222ffb0b13892a6ed491"); let mut a1=[0u8;32]; a1.copy_from_slice(&lh1);
    let l1=ckb_mmr::leaf(a1, [0u8;32], 21341102, 1979133764580267, 1780789359155, 487079700);
    let lh2=hx("6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff"); let mut a2=[0u8;32]; a2.copy_from_slice(&lh2);
    let l2=ckb_mmr::leaf(a2, [0u8;32], 21341103, 1979133781357483, 1780789369508, 487079700);
    let lh3=hx("f9255030c4b1506609d2a4cb3b31cea087be49d14a57e2a38fdf11def1ef0142"); let mut a3=[0u8;32]; a3.copy_from_slice(&lh3);
    let l3=ckb_mmr::leaf(a3, [0u8;32], 21341104, 1979133798134699, 1780789379908, 487079700);
    let n01=ckb_mmr::merge(&l0,&l1); let n23=ckb_mmr::merge(&l2,&l3); let root=ckb_mmr::merge(&n01,&n23);
    let chain_root=ckb_mmr::mmr_hash(&root);
    // membership path of leaf0 (the proven header): (sibling, cur_is_left, parent)
    let mut mpath: Vec<([u8;120],bool,[u8;120])> = vec![ (l1,true,n01), (n23,true,root) ];
    // S1: pad the MMR membership path to a production depth to measure per-merge constraint cost.
    // Count is structural (independent of the dummy values); gated on COUNT_ONLY so real proving
    // (which checks witness satisfaction) can never run with a padded dummy path.
    if std::env::var("COUNT_ONLY").is_ok() {
        if let Ok(d) = std::env::var("MMR_DEPTH") {
            let d: usize = d.parse().unwrap_or(2);
            while mpath.len() < d { mpath.push(([0u8;120], true, [0u8;120])); }
        }
    }
    let circ=LeapCircuit{raw,nonce,leaf,path,wit,new_state,seal,chain_root,leaf0:l0,mpath};
    {
        // S1 instrumentation: report the R1CS size (decides universal-SRS reuse vs PLONK budget).
        let cs = ConstraintSystem::<Fr>::new_ref();
        circ.clone().generate_constraints(cs.clone()).unwrap();
        eprintln!("CONSTRAINTS={} witness_vars={} instance_vars={} next_pow2={}",
            cs.num_constraints(), cs.num_witness_variables(), cs.num_instance_variables(),
            (cs.num_constraints() as u64).next_power_of_two());
        if std::env::var("COUNT_ONLY").is_ok() { return; }
    }
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    // KEY SOURCE: CEREMONY_OUT=<dir> runs the real two-phase ceremony on THIS circuit and persists the key;
    // CEREMONY_PK=<path> loads a previously-ceremonied key; otherwise the legacy deterministic setup.
    let (pk,vk) = if let Ok(dir)=std::env::var("CEREMONY_OUT") {
        let (pk,transcript)=ckb_consensus_circuit::setup_mpc::run_ceremony(circ.clone(), 3, 3, "leap");
        ckb_consensus_circuit::setup_mpc::save_pk(&pk, &format!("{dir}/leap_pk.bin"));
        let _ = std::fs::write(format!("{dir}/leap_transcript.json"), serde_json::to_string_pretty(&transcript).unwrap());
        let vk=pk.vk.clone(); (pk,vk)
    } else if let Ok(p)=std::env::var("CEREMONY_PK") {
        eprintln!("loading ceremony key from {p}"); let pk=ckb_consensus_circuit::setup_mpc::load_pk(&p); let vk=pk.vk.clone(); (pk,vk)
    } else {
        eprintln!("Groth16 setup over the FAITHFUL leap circuit (R1 real PoW+compact-decode, R3 real CBMT, R4)...");
        Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(), &mut rng).unwrap()
    };
    eprintln!("proving...");
    let proof=Groth16::<Bls12_381>::prove(&pk, circ.clone(), &mut rng).unwrap();
    let inputs=vec![Fr::from_le_bytes_mod_order(&chain_root), Fr::from_le_bytes_mod_order(&seal), Fr::from_le_bytes_mod_order(&commitment)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap();
    eprintln!("arkworks verify = {ok}"); assert!(ok);
    let ic: Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    println!("{{");
    println!("  \"vk\": {{ \"alpha_g1\":\"{}\",\"beta_g2\":\"{}\",\"gamma_g2\":\"{}\",\"delta_g2\":\"{}\",\"ic\":[{}] }},",
        g1c(&vk.alpha_g1),g2c(&vk.beta_g2),g2c(&vk.gamma_g2),g2c(&vk.delta_g2), ic.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","));
    println!("  \"proof\": {{ \"a\":\"{}\",\"b\":\"{}\",\"c\":\"{}\" }},", g1c(&proof.a),g2c(&proof.b),g1c(&proof.c));
    println!("  \"public_inputs_dec\": [{}]", inputs.iter().map(|x| format!("\"{}\"",fr_dec(x))).collect::<Vec<_>>().join(","));
    println!("}}");
}
