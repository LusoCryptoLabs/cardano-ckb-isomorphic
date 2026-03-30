//! Batch AdvanceCKBCert: append N=2 REAL headers (21,341,106..107) to the ChainRootMMR in ONE proof,
//! using the VARIABLE-CARRY append (general leaf_count). Each header: R1 PoW + parent-link + difficulty
//! _verify; the root is bagged once before/after; cumulative work proven. Generalizes the advance to any
//! chain position and amortizes N headers per checkpoint advance.
use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr; use ark_ff::{PrimeField, BigInteger};
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK; use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder; use num_bigint::BigUint;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget, difficulty_gadget, ckb_mmr, mmr_gadget};
fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hx(s:&str)->Vec<u8>{ (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn hx32(s:&str)->[u8;32]{ hx(s).try_into().unwrap() }
fn tfc(c:u32)->[u8;32]{ let e=(c>>24)as usize; let m=c&0x007fffff; let mut t=[0u8;32]; let mb=m.to_be_bytes(); for k in 0..3 { let p=32-e+k; if p<32 {t[p]=mb[1+k];} } t }
fn ndiff(c:u32)->[u8;32]{ let tg=BigUint::from_bytes_be(&tfc(c)); let mx=(BigUint::from(1u8)<<256usize)-BigUint::from(1u8); let d=&mx/&tg; let mut o=[0u8;32]; let db=d.to_bytes_be(); o[32-db.len()..].copy_from_slice(&db); o }
fn drev(mut b:[u8;32])->[u8;32]{ b.reverse(); b }
fn raw_of(compact:u32, ts:u64, number:u64, epoch:u64, parent:&str, txr:&str, prop:&str, extra:&str, dao:&str, nonce:u128)->([u8;192],[u8;16]){
    let mut r=Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes()); r.extend_from_slice(&compact.to_le_bytes());
    r.extend_from_slice(&ts.to_le_bytes()); r.extend_from_slice(&number.to_le_bytes()); r.extend_from_slice(&epoch.to_le_bytes());
    r.extend_from_slice(&hx(parent)); r.extend_from_slice(&hx(txr)); r.extend_from_slice(&hx(prop)); r.extend_from_slice(&hx(extra)); r.extend_from_slice(&hx(dao));
    let mut raw=[0u8;192]; raw.copy_from_slice(&r); let mut n=[0u8;16]; n.copy_from_slice(&nonce.to_le_bytes()); (raw,n)
}
const HMAX:usize=3;
#[derive(Clone)]
struct BatchCircuit { hdrs:Vec<([u8;192],[u8;16])>, diffs:Vec<[u8;32]>, old_tip:[u8;32],
    old_pres:Vec<bool>, old_peak:Vec<[u8;120]>, old_root:[u8;32], new_root:[u8;32], old_total:[u8;32], new_total:[u8;32] }
fn b2fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{ let mut a=FpVar::<F>::zero(); let mut c=F::one(); for byte in b { for bit in byte.to_bits_le()? { a+=FpVar::from(bit)*c; c.double_in_place(); } } Ok(a) }
impl ConstraintSynthesizer<Fr> for BatchCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        // old MMR peaks
        let mut pres=Vec::new(); let mut peak=Vec::new();
        for h in 0..HMAX { pres.push(Boolean::new_witness(cs.clone(),||Ok(self.old_pres[h]))?); peak.push(w(&self.old_peak[h],&cs)?); }
        let obag=mmr_gadget::bag_var(&cs,&pres,&peak)?; let or_g=mmr_gadget::root_hash(&obag)?;
        let old_root=w(&self.old_root,&cs)?; for i in 0..32 { or_g[i].enforce_equal(&old_root[i])?; }
        // process N headers
        let mut tip=w(&self.old_tip,&cs)?;
        for k in 0..self.hdrs.len() {
            let raw=w(&self.hdrs[k].0,&cs)?; let nonce=w(&self.hdrs[k].1,&cs)?;
            let ph=blake2b256(&raw,b"ckb-default-hash")?; let mut ei=ph.clone(); ei.extend(nonce.clone());
            let eag=eaglesong_gadget::eaglesong(&ei)?; let pow=blake2b256(&eag,b"ckb-default-hash")?;
            let target=merkle_gadget::compact_to_target(&raw[4..8])?;
            merkle_gadget::enforce_leq_be(&pow,&target)?;
            for i in 0..32 { raw[32+i].enforce_equal(&tip[i])?; }     // parent-link to running tip
            let diff_be=w(&self.diffs[k],&cs)?; difficulty_gadget::difficulty_verify(&cs,&target,&diff_be)?;
            let mut diff_le=diff_be.clone(); diff_le.reverse();
            let mut hin=raw.clone(); hin.extend(nonce.clone()); let bh=blake2b256(&hin,b"ckb-default-hash")?;
            let mut leaf=Vec::with_capacity(120); leaf.extend(bh.clone()); leaf.extend(diff_le);
            leaf.extend_from_slice(&raw[16..24]); leaf.extend_from_slice(&raw[16..24]);
            leaf.extend_from_slice(&raw[24..32]); leaf.extend_from_slice(&raw[24..32]);
            leaf.extend_from_slice(&raw[8..16]); leaf.extend_from_slice(&raw[8..16]);
            leaf.extend_from_slice(&raw[4..8]); leaf.extend_from_slice(&raw[4..8]);
            let (np,npk)=mmr_gadget::append_var(&cs,&pres,&peak,&leaf)?; pres=np; peak=npk;
            tip=bh;   // next header chains to this block hash
        }
        let nbag=mmr_gadget::bag_var(&cs,&pres,&peak)?; let nr_g=mmr_gadget::root_hash(&nbag)?;
        let new_root=w(&self.new_root,&cs)?; for i in 0..32 { nr_g[i].enforce_equal(&new_root[i])?; }
        let old_total=w(&self.old_total,&cs)?; let new_total=w(&self.new_total,&cs)?;
        let mut ob: Vec<UInt8<Fr>> = obag[32..64].to_vec(); ob.reverse();
        let mut nb: Vec<UInt8<Fr>> = nbag[32..64].to_vec(); nb.reverse();
        for i in 0..32 { ob[i].enforce_equal(&old_total[i])?; nb[i].enforce_equal(&new_total[i])?; }
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
fn mkleaf(hash_hex:&str,compact:u32,number:u64,epoch:u64,ts:u64)->[u8;120]{ ckb_mmr::leaf(hx32(hash_hex), drev(ndiff(compact)), number, epoch, ts, compact) }
fn main(){
    // old MMR over leaves 101..105 (leaf_count=5)
    let oldhdrs:[(&str,u32,u64,u64,u64);5]=[("94ba8c1183aa9bb52f0705f37bd9b5e1aa78721774aa5f6deebeb31a640b8c18", 487079700u32, 21341101u64, 1979133747803051u64, 1780789357828u64),("a5df20923eb0892f0f1b02b0bd474b21488271779a92222ffb0b13892a6ed491", 487079700u32, 21341102u64, 1979133764580267u64, 1780789359155u64),("6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff", 487079700u32, 21341103u64, 1979133781357483u64, 1780789369508u64),("f9255030c4b1506609d2a4cb3b31cea087be49d14a57e2a38fdf11def1ef0142", 487079700u32, 21341104u64, 1979133798134699u64, 1780789379908u64),("16fe6f664c1a62e5b0459d1d24a16ea505f8d8cfd009ecbbddff048b57328640", 487079700u32, 21341105u64, 1979133814911915u64, 1780789380420u64)];
    let oldleaves:Vec<[u8;120]>=oldhdrs.iter().map(|(h,c,n,e,t)| mkleaf(h,*c,*n,*e,*t)).collect();
    let old=ckb_mmr::build(&oldleaves);
    let old_root=ckb_mmr::mmr_hash(&ckb_mmr::bag(&old).unwrap());
    let mut old_pres=vec![]; let mut old_peak=vec![]; let zero=[0u8;120];
    for h in 0..HMAX { old_pres.push(old.get(h).map(|o| o.is_some()).unwrap_or(false)); old_peak.push(old.get(h).and_then(|o| *o).unwrap_or(zero)); }
    let mut ob=[0u8;32]; ob.copy_from_slice(&ckb_mmr::bag(&old).unwrap()[32..64]); ob.reverse();
    let h106=raw_of(487079700, 1780789386545, 21341106, 1979133831689131,
        "16fe6f664c1a62e5b0459d1d24a16ea505f8d8cfd009ecbbddff048b57328640","d3fbcd5171328cc2840186379d18f81d4d117892831ed9865cbfefe9ef5e6e3a","0000000000000000000000000000000000000000000000000000000000000000","fe78a153b8cbb41ce3009da6d55fca8261fe27f13955447c13df5b2051dcb2f0","32ab3dfa28922757f98854cc3f132a00a48e8a3f51c3e10900cb12fcb7d55709", 27269099965621937691040959662541129252);
    let h107=raw_of(487079700, 1780789394075, 21341107, 1979133848466347,
        "a137ba2172c45abb4cfa8eed49b2ebe305c7b2e99c90e5138b8efe7ac3e1b94b","ce7db8f15ac5015a55e4b561e3a86ae13eb77e4eb06b10ee7570751cb204321e","f07783d6225729f95c10b91e37c7eba63f1fc0ad683d20dc9bd890aa443ba458","702e8c503d996cb1bb8d5f44a6ef6e711b8521462b071138730abc1bbbbf8ac2","6c87b5513d922757219a29d03f132a00b1eede5558c3e1090068a967b9d55709", 132080498609638446071409259037520630211);
    let hdrs=vec![h106,h107];
    let diffs=vec![ndiff(487079700), ndiff(487079700)];
    // native append to compute new_root + new_total
    let mut peaks=old.clone();
    for k in 0..2 { let (raw,nonce)=hdrs[k]; let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
        let cmp=u32::from_le_bytes(raw[4..8].try_into().unwrap()); let num=u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let ep=u64::from_le_bytes(raw[24..32].try_into().unwrap()); let ts=u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let leaf=ckb_mmr::leaf(bh, drev(ndiff(cmp)), num, ep, ts, cmp); ckb_mmr::append(&mut peaks, leaf); }
    let new_root=ckb_mmr::mmr_hash(&ckb_mmr::bag(&peaks).unwrap());
    let mut nb=[0u8;32]; nb.copy_from_slice(&ckb_mmr::bag(&peaks).unwrap()[32..64]); nb.reverse();
    let old_tip=hx32("16fe6f664c1a62e5b0459d1d24a16ea505f8d8cfd009ecbbddff048b57328640");
    let circ=BatchCircuit{hdrs,diffs,old_tip,old_pres,old_peak,old_root,new_root,old_total:ob,new_total:nb};
    // structural check first
    let cs=ConstraintSystem::<Fr>::new_ref(); circ.clone().generate_constraints(cs.clone()).unwrap();
    eprintln!("batch circuit: is_satisfied={} constraints={}", cs.is_satisfied().unwrap(), cs.num_constraints());
    assert!(cs.is_satisfied().unwrap());
    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    eprintln!("Groth16 setup (batch N=2)..."); let (pk,vk)=Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(),&mut rng).unwrap();
    eprintln!("proving..."); let proof=Groth16::<Bls12_381>::prove(&pk,circ.clone(),&mut rng).unwrap();
    let inputs=vec![Fr::from_le_bytes_mod_order(&old_root),Fr::from_le_bytes_mod_order(&ob),Fr::from_le_bytes_mod_order(&new_root),Fr::from_le_bytes_mod_order(&nb)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap(); eprintln!("arkworks verify = {ok}"); assert!(ok);
    let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    println!("{{ \"vk\": {{ \"alpha_g1\":\"{}\",\"beta_g2\":\"{}\",\"gamma_g2\":\"{}\",\"delta_g2\":\"{}\",\"ic\":[{}] }}, \"proof\": {{ \"a\":\"{}\",\"b\":\"{}\",\"c\":\"{}\" }}, \"public_inputs_dec\": [{}] }}",
        g1c(&vk.alpha_g1),g2c(&vk.beta_g2),g2c(&vk.gamma_g2),g2c(&vk.delta_g2), ic.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
        g1c(&proof.a),g2c(&proof.b),g1c(&proof.c), inputs.iter().map(|x| format!("\"{}\"",fr_dec(x))).collect::<Vec<_>>().join(","));
}
