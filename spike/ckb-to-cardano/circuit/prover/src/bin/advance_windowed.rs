//! Advance-side window accumulator (see ../../RESTRUCTURE.md): the ring-buffer Merkle UPDATE that
//! AdvanceCKBCert performs each block. It proves old_window_root -> new_window_root by replacing the
//! leaf at slot = (tip_height mod W) with the new header hash, touching only that slot's root path
//! (~2·log2(W) merges, not a full W-leaf rebuild). Soundness: the circuit VERIFIES the old root from
//! (old_leaf, siblings) before recomputing the new one, so the prover cannot forge the siblings.
//!
//!   COUNT_ONLY=1 [WINDOW_DEPTH=6] cargo run --release --bin advance_windowed
//!   cargo run --release --bin advance_windowed         # setup+prove+verify
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{PrimeField, One};
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder;
use ckb_consensus_circuit::merkle_gadget;

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }

// Off-circuit binary window-Merkle: root + (sibling, leaf_is_left) path for `idx`. Merge=ckbhash(l||r).
fn root_path(leaves:&[[u8;32]], idx:usize)->([u8;32], Vec<([u8;32],bool)>){
    let mut level:Vec<[u8;32]>=leaves.to_vec(); let mut i=idx; let mut path=Vec::new();
    while level.len()>1 {
        let leaf_is_left=i%2==0;
        let sib= if leaf_is_left { level[i+1] } else { level[i-1] };
        path.push((sib, leaf_is_left));
        let mut next=Vec::new(); let mut j=0;
        while j<level.len(){ let mut c=level[j].to_vec(); c.extend_from_slice(&level[j+1]); next.push(ckbhash(&c)); j+=2; }
        level=next; i/=2;
    }
    (level[0], path)
}

#[derive(Clone)]
struct WindowUpdate {
    depth:usize, slot:u64,
    old_leaf:[u8;32], new_leaf:[u8;32], siblings:Vec<[u8;32]>,
    old_root:[u8;32], new_root:[u8;32],
}
fn b2fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{ let mut a=FpVar::<F>::zero(); let mut c=F::one(); for byte in b { for bit in byte.to_bits_le()? { a+=FpVar::from(bit)*c; c.double_in_place(); } } Ok(a) }
impl ConstraintSynthesizer<Fr> for WindowUpdate {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let old_leaf=w(&self.old_leaf,&cs)?;
        let new_leaf=w(&self.new_leaf,&cs)?;
        // slot bits (witness) -> path directions; bind their value to the `slot` public input so the
        // update is tied to (tip_height mod W), not an arbitrary position.
        let mut slot_acc=FpVar::<Fr>::zero(); let mut coeff=Fr::one();
        let mut path_old=Vec::new(); let mut path_new=Vec::new();
        for k in 0..self.depth {
            let bit=Boolean::new_witness(cs.clone(), || Ok((self.slot>>k)&1==1))?;
            slot_acc += FpVar::from(bit.clone())*coeff; coeff = coeff + coeff;
            let sib=w(&self.siblings[k],&cs)?;
            // leaf_is_left = (bit==0) = !bit
            path_old.push((sib.clone(), bit.not()));
            path_new.push((sib, bit.not()));
        }
        // 1) VERIFY the old window root from (old_leaf, siblings) - prevents forged siblings.
        let or=merkle_gadget::merkle_root(&old_leaf, &path_old)?;
        let old_root_pi=FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&self.old_root)))?;
        b2fp(&or)?.enforce_equal(&old_root_pi)?;
        // 2) COMPUTE the new window root from (new_leaf, same siblings).
        let nr=merkle_gadget::merkle_root(&new_leaf, &path_new)?;
        let new_root_pi=FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&self.new_root)))?;
        b2fp(&nr)?.enforce_equal(&new_root_pi)?;
        // 3) bind the inserted header hash and the slot as public inputs.
        let new_leaf_pi=FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&self.new_leaf)))?;
        b2fp(&new_leaf)?.enforce_equal(&new_leaf_pi)?;
        let slot_pi=FpVar::new_input(cs.clone(), || Ok(Fr::from(self.slot)))?;
        slot_acc.enforce_equal(&slot_pi)?;
        Ok(())
    }
}

fn main(){
    let depth: usize = std::env::var("WINDOW_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let wsize=1usize<<depth;
    let slot: u64 = 21341104u64 % (wsize as u64);     // tip_height mod W
    // build the current window, then update slot with the new header hash
    let mut leaves=vec![[0u8;32]; wsize];
    for k in 0..wsize { leaves[k]=ckbhash(&(k as u64 + 1).to_le_bytes()); }
    let idx=slot as usize;
    let old_leaf=leaves[idx];
    let new_leaf=ckbhash(&21341104u64.to_le_bytes());  // hash standing in for the new header
    let (old_root, path)=root_path(&leaves, idx);
    let siblings:Vec<[u8;32]>=path.iter().map(|(s,_)|*s).collect();
    let mut nl=leaves.clone(); nl[idx]=new_leaf;
    let (new_root,_)=root_path(&nl, idx);
    let circ=WindowUpdate{depth, slot, old_leaf, new_leaf, siblings, old_root, new_root};
    {
        let cs=ConstraintSystem::<Fr>::new_ref();
        circ.clone().generate_constraints(cs.clone()).unwrap();
        eprintln!("WINDOW_DEPTH={} slot={} CONSTRAINTS={} witness_vars={} next_pow2={}",
            depth, slot, cs.num_constraints(), cs.num_witness_variables(), (cs.num_constraints() as u64).next_power_of_two());
        if std::env::var("COUNT_ONLY").is_ok() { return; }
    }
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    eprintln!("Groth16 setup over the WINDOW-UPDATE circuit...");
    let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(), &mut rng).unwrap();
    let proof=Groth16::<Bls12_381>::prove(&pk, circ.clone(), &mut rng).unwrap();
    let inputs=vec![
        Fr::from_le_bytes_mod_order(&old_root), Fr::from_le_bytes_mod_order(&new_root),
        Fr::from_le_bytes_mod_order(&new_leaf), Fr::from(slot),
    ];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap();
    eprintln!("arkworks verify = {ok}"); assert!(ok, "window-update proof must verify");
    // negative: a tampered new_root must be rejected by the verifier
    let mut bad=inputs.clone(); bad[1]+=Fr::from(1u64);
    let bad_ok=Groth16::<Bls12_381>::verify(&vk,&bad,&proof).unwrap();
    assert!(!bad_ok, "tampered new_root must be rejected");
    println!("WINDOW_UPDATE_OK depth={} verify={} tamper_rejected={}", depth, ok, !bad_ok);
}
