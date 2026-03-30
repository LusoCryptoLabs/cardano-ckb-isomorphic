//! AdvanceCKBCert circuit with PROVEN MMR-append: REAL header 21,341,104 is appended to the old
//! ChainRootMMR (leaves 21,341,101..103) — new_root is now COMPUTED in-circuit (not witnessed) as a
//! full-carry MMR append, and each merge sums total_difficulty (add256), so the new root's embedded
//! cumulative work is proven. R1 PoW + parent-link + difficulty_verify tie the appended leaf to reality.
use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, BigInteger};
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder;
use num_bigint::BigUint;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget, difficulty_gadget, ckb_mmr, mmr_gadget};

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hx(s:&str)->Vec<u8>{ (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn hx32(s:&str)->[u8;32]{ hx(s).try_into().unwrap() }
fn target_from_compact(c:u32)->[u8;32]{ let e=(c>>24)as usize; let m=c&0x007fffff; let mut t=[0u8;32]; let mb=m.to_be_bytes(); for k in 0..3 { let p=32-e+k; if p<32 {t[p]=mb[1+k];} } t }
fn native_difficulty(c:u32)->[u8;32]{ let target=BigUint::from_bytes_be(&target_from_compact(c)); let max=(BigUint::from(1u8)<<256usize)-BigUint::from(1u8); let d=&max/&target; let mut o=[0u8;32]; let db=d.to_bytes_be(); o[32-db.len()..].copy_from_slice(&db); o }
fn drev(mut be:[u8;32])->[u8;32]{ be.reverse(); be }  // BE difficulty -> LE for the digest field

fn raw104()->([u8;192],[u8;16]){
    let mut r=Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&487079700u32.to_le_bytes());
    r.extend_from_slice(&1780789379908u64.to_le_bytes());
    r.extend_from_slice(&21341104u64.to_le_bytes());
    r.extend_from_slice(&1979133798134699u64.to_le_bytes());
    r.extend_from_slice(&hx("6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff"));       // == tip 21,341,103
    r.extend_from_slice(&hx("10f2e7ecea7598f807bd59cc8f4a088eda955b68d66e8c69d5404cf36878734c"));
    r.extend_from_slice(&hx("0b0894848570dc9d837b3a99c69860c9112f6b3bffc7a3322609575bea9ec73c"));
    r.extend_from_slice(&hx("d65c507211e9f0b5de4ba187c484a43b526710406b03128ec489e55e80c7fd30"));
    r.extend_from_slice(&hx("bef24d4b00922757a866aac43f132a00c0cee11243c3e1090091e524b5d55709"));
    let mut raw=[0u8;192]; raw.copy_from_slice(&r);
    let mut n=[0u8;16]; n.copy_from_slice(&77054535269512247200822733458160144498u128.to_le_bytes());
    (raw,n)
}

#[derive(Clone)]
struct AdvanceCircuit { raw:[u8;192], nonce:[u8;16], old_tip:[u8;32], diff_be:[u8;32],
    p_high:[u8;120], p_low:[u8;120],
    old_root:[u8;32], new_root:[u8;32], old_total:[u8;32], new_total:[u8;32] }
fn b2fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{ let mut a=FpVar::<F>::zero(); let mut c=F::one(); for byte in b { for bit in byte.to_bits_le()? { a+=FpVar::from(bit)*c; c.double_in_place(); } } Ok(a) }
impl ConstraintSynthesizer<Fr> for AdvanceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let raw=w(&self.raw,&cs)?; let nonce=w(&self.nonce,&cs)?;
        // R1 PoW(h104)
        let ph=blake2b256(&raw, b"ckb-default-hash")?; let mut ei=ph.clone(); ei.extend(nonce.clone());
        let eag=eaglesong_gadget::eaglesong(&ei)?; let pow=blake2b256(&eag, b"ckb-default-hash")?;
        let target=merkle_gadget::compact_to_target(&raw[4..8])?;
        merkle_gadget::enforce_leq_be(&pow,&target)?;
        // parent-link: raw.parent_hash (32..64) == old tip (21,341,103)
        let old_tip=w(&self.old_tip,&cs)?; for i in 0..32 { raw[32+i].enforce_equal(&old_tip[i])?; }
        // difficulty: verify diff == floor((2^256-1)/target); leaf total_difficulty (LE) = reverse(diff)
        let diff_be=w(&self.diff_be,&cs)?;
        difficulty_gadget::difficulty_verify(&cs,&target,&diff_be)?;
        let mut diff_le=diff_be.clone(); diff_le.reverse();
        // block hash = ckbhash(RawHeader || nonce)
        let mut hin=raw.clone(); hin.extend(nonce.clone());
        let block_hash=blake2b256(&hin, b"ckb-default-hash")?;
        // build leaf_new digest (120B) entirely in-circuit from R1 outputs + raw fields
        let mut leaf=Vec::with_capacity(120);
        leaf.extend(block_hash);                 // children_hash
        leaf.extend(diff_le);                    // total_difficulty (LE), proven
        leaf.extend_from_slice(&raw[16..24]); leaf.extend_from_slice(&raw[16..24]); // number
        leaf.extend_from_slice(&raw[24..32]); leaf.extend_from_slice(&raw[24..32]); // epoch
        leaf.extend_from_slice(&raw[8..16]);  leaf.extend_from_slice(&raw[8..16]);  // timestamp
        leaf.extend_from_slice(&raw[4..8]);   leaf.extend_from_slice(&raw[4..8]);   // compact_target
        // old MMR peaks (witnessed; proven in prior advances): p_high=merge(L101,L102), p_low=L103
        let p_high=w(&self.p_high,&cs)?; let p_low=w(&self.p_low,&cs)?;
        // bag(old) = merge(p_high, p_low); old_root = mmr_hash(bag)
        let bag=mmr_gadget::merge_digest(&cs,&p_high,&p_low)?;
        let old_root_g=mmr_gadget::root_hash(&bag)?;
        let old_root=w(&self.old_root,&cs)?; for i in 0..32 { old_root_g[i].enforce_equal(&old_root[i])?; }
        // APPEND leaf (full carry, leaf_count=3=0b11): n_low=merge(p_low,leaf); n_top=merge(p_high,n_low)
        let n_low=mmr_gadget::merge_digest(&cs,&p_low,&leaf)?;
        let n_top=mmr_gadget::merge_digest(&cs,&p_high,&n_low)?;
        let new_root_g=mmr_gadget::root_hash(&n_top)?;
        let new_root=w(&self.new_root,&cs)?; for i in 0..32 { new_root_g[i].enforce_equal(&new_root[i])?; }
        // proven cumulative work: old_total == bag.total_difficulty (BE), new_total == n_top.total_difficulty (BE)
        let old_total=w(&self.old_total,&cs)?; let new_total=w(&self.new_total,&cs)?;
        let mut bag_be: Vec<UInt8<Fr>> = bag[32..64].to_vec(); bag_be.reverse();
        let mut top_be: Vec<UInt8<Fr>> = n_top[32..64].to_vec(); top_be.reverse();
        for i in 0..32 { bag_be[i].enforce_equal(&old_total[i])?; top_be[i].enforce_equal(&new_total[i])?; }
        // public inputs (4) bind (old_root, old_total, new_root, new_total) -> advance_ckbcert.ak
        let pis=[(&old_root,&self.old_root),(&old_total,&self.old_total),(&new_root,&self.new_root),(&new_total,&self.new_total)];
        for (bytes,val) in pis { let pi=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(val)))?; b2fp(bytes)?.enforce_equal(&pi)?; }
        Ok(())
    }
}
fn fq_be(x:&Fq)->[u8;48]{ let mut o=[0u8;48]; let v=x.into_bigint().to_bytes_be(); o[48-v.len()..].copy_from_slice(&v); o }
fn g1c(p:&ArkG1)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;96]; u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y)); hexs(bls12_381::G1Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn g2c(p:&ArkG2)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;192]; u[0..48].copy_from_slice(&fq_be(&x.c1)); u[48..96].copy_from_slice(&fq_be(&x.c0)); u[96..144].copy_from_slice(&fq_be(&y.c1)); u[144..192].copy_from_slice(&fq_be(&y.c0)); hexs(bls12_381::G2Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn hexs(b:impl AsRef<[u8]>)->String{ b.as_ref().iter().map(|x| format!("{:02x}",x)).collect() }
fn fr_dec(x:&Fr)->String{ x.into_bigint().to_string() }
fn main(){
    let (raw,nonce)=raw104(); let old_tip=hx32("6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff");
    let compact=487079700u32; let diff_be=native_difficulty(compact);
    // native old MMR (leaves 101,102,103) + append 104
    let l101=ckb_mmr::leaf(hx32("94ba8c1183aa9bb52f0705f37bd9b5e1aa78721774aa5f6deebeb31a640b8c18"), drev(native_difficulty(487079700)), 21341101, 1979133747803051, 1780789357828, 487079700);
    let l102=ckb_mmr::leaf(hx32("a5df20923eb0892f0f1b02b0bd474b21488271779a92222ffb0b13892a6ed491"), drev(native_difficulty(487079700)), 21341102, 1979133764580267, 1780789359155, 487079700);
    let l103=ckb_mmr::leaf(hx32("6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff"), drev(native_difficulty(487079700)), 21341103, 1979133781357483, 1780789369508, 487079700);
    let p_high=ckb_mmr::merge(&l101,&l102); let p_low=l103;
    let bag=ckb_mmr::merge(&p_high,&p_low); let old_root=ckb_mmr::mmr_hash(&bag);
    let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
    let leaf=ckb_mmr::leaf(bh, drev(diff_be), 21341104, 1979133798134699, 1780789379908, compact);
    let n_low=ckb_mmr::merge(&p_low,&leaf); let n_top=ckb_mmr::merge(&p_high,&n_low); let new_root=ckb_mmr::mmr_hash(&n_top);
    let mut old_total=[0u8;32]; old_total.copy_from_slice(&bag[32..64]); old_total.reverse();
    let mut new_total=[0u8;32]; new_total.copy_from_slice(&n_top[32..64]); new_total.reverse();
    let circ=AdvanceCircuit{raw,nonce,old_tip,diff_be,p_high,p_low,old_root,new_root,old_total,new_total};
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    eprintln!("AdvanceCKBCert+MMR-append: Groth16 setup (PoW + difficulty_verify + PROVEN append)...");
    let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(),&mut rng).unwrap();
    eprintln!("proving..."); let proof=Groth16::<Bls12_381>::prove(&pk,circ.clone(),&mut rng).unwrap();
    let inputs=vec![Fr::from_le_bytes_mod_order(&old_root),Fr::from_le_bytes_mod_order(&old_total),Fr::from_le_bytes_mod_order(&new_root),Fr::from_le_bytes_mod_order(&new_total)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap(); eprintln!("arkworks verify = {ok}"); assert!(ok);
    eprintln!("old_root={} new_root={}", hexs(&old_root), hexs(&new_root));
    let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    println!("{{ \"vk\": {{ \"alpha_g1\":\"{}\",\"beta_g2\":\"{}\",\"gamma_g2\":\"{}\",\"delta_g2\":\"{}\",\"ic\":[{}] }}, \"proof\": {{ \"a\":\"{}\",\"b\":\"{}\",\"c\":\"{}\" }}, \"public_inputs_dec\": [{}] }}",
        g1c(&vk.alpha_g1),g2c(&vk.beta_g2),g2c(&vk.gamma_g2),g2c(&vk.delta_g2), ic.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
        g1c(&proof.a),g2c(&proof.b),g1c(&proof.c), inputs.iter().map(|x| format!("\"{}\"",fr_dec(x))).collect::<Vec<_>>().join(","));
}
