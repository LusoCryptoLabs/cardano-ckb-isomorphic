//! advance_live - the PARAMETERIZED production AdvanceCKBCert prover (header-chain follower model).
//!
//! Same 7-public-input transition the on-chain advance_ckbcert.ak binds
//!   (old_root, old_total_difficulty, new_root, new_total_difficulty, old_window_root, new_window_root, new_tip_height)
//! but GENERAL over chain position and provable in the leap's 2^21 SRS tier.
//!
//! DESIGN (see RESTRUCTURE.md): the per-leap circuit already moved membership to the rolling WINDOW, so the
//! checkpoint's chain_root no longer needs to be CKB's deep ChainRootMMR (which costs 2^22-2^23 to append in
//! a SNARK). Here chain_root COMMITS THE CURRENT TIP (chain_root == tip block hash). Each advance proves:
//!   * R1: the new header has real Eaglesong PoW (<= target), and
//!   * PARENT-LINK: new.parent_hash == the checkpoint's chain_root (= prior tip hash) -> the chain is linked
//!     block-by-block from the pinned genesis anchor (no free-floating header), and
//!   * DIFFICULTY: new_total_difficulty == old_total_difficulty + difficulty(new) (real work added; the
//!     validator's strict `new_total > old_total` is the Nakamoto heaviest-chain rule), and
//!   * WINDOW: the new header's block hash is inserted at ring slot height mod W (old window root verified
//!     from siblings, then recomputed) -> the per-leap binds membership against new_window_root, and
//!   * TIP: new_tip_height is authenticated (the header's own height field).
//!
//! The circuit STRUCTURE is identical every advance => ONE vk serves all advances (what AdvanceCKBCert bakes).
//! The WINDOW holds REAL recent CKB header hashes (relayer-supplied, shared with the per-leap's window).
//! Honest scope (testnet): chain_root tracks the tip of a PoW+work-validated header chain anchored at a chosen
//! genesis header; it is NOT CKB's on-chain ChainRootMMR root (deep historical membership / MMR cross-anchor
//! are out of scope - the window is the membership the bridge uses).
//!
//!   COUNT_ONLY=1 cargo run --release --bin advance_live                       # constraint count (tier check)
//!   cargo run --release --bin advance_live                                    # regression: header 21,341,104
//!   CHIRAL_ADVANCE_STATE=state.json CHIRAL_ADVANCE_STEP=step.json PROVE=1 \
//!     cargo run --release --bin advance_live > advance_live_redeemer.json     # prove + emit redeemer + new state
use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, BigInteger};
use ark_groth16::Groth16;
use ark_r1cs_std::{uint8::UInt8, boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use blake2b_rs::Blake2bBuilder;
use num_bigint::BigUint;
use serde_json::Value;
use ckb_consensus_circuit::{eaglesong_gadget, blake2b_gadget::blake2b256, merkle_gadget, difficulty_gadget};

fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }
fn hx(s:&str)->Vec<u8>{ let s=s.trim_start_matches("0x"); (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn hx32(s:&str)->[u8;32]{ hx(s).try_into().unwrap() }
fn tfc(c:u32)->[u8;32]{ let e=(c>>24)as usize; let m=c&0x007fffff; let mut t=[0u8;32]; let mb=m.to_be_bytes(); for k in 0..3 { let p=32-e+k; if p<32 {t[p]=mb[1+k];} } t }
fn ndiff(c:u32)->[u8;32]{ let tg=BigUint::from_bytes_be(&tfc(c)); let mx=(BigUint::from(1u8)<<256usize)-BigUint::from(1u8); let d=&mx/&tg; let mut o=[0u8;32]; let db=d.to_bytes_be(); o[32-db.len()..].copy_from_slice(&db); o }
fn add_be(a:&[u8;32], b:&[u8;32])->[u8;32]{ let s=BigUint::from_bytes_be(a)+BigUint::from_bytes_be(b); let sb=s.to_bytes_be(); let mut o=[0u8;32]; o[32-sb.len()..].copy_from_slice(&sb); o }

// off-circuit binary window-Merkle: root + (sibling, leaf_is_left) path for idx; merge=ckbhash(l||r)
fn window_root_path(leaves:&[[u8;32]], idx:usize)->([u8;32], Vec<([u8;32],bool)>){
    let mut level:Vec<[u8;32]>=leaves.to_vec(); let mut i=idx; let mut path=Vec::new();
    while level.len()>1 {
        let lil=i%2==0; let sib= if lil { level[i+1] } else { level[i-1] }; path.push((sib,lil));
        let mut nx=Vec::new(); let mut j=0; while j<level.len(){ let mut c=level[j].to_vec(); c.extend_from_slice(&level[j+1]); nx.push(ckbhash(&c)); j+=2; } level=nx; i/=2;
    }
    (level[0], path)
}

// 192-byte RawHeader + 16-byte nonce from explicit fields.
fn raw_of(compact:u32, ts:u64, number:u64, epoch:u64, parent:&str, txr:&str, prop:&str, extra:&str, dao:&str, nonce:u128)->([u8;192],[u8;16]){
    let mut r=Vec::new();
    r.extend_from_slice(&0u32.to_le_bytes()); r.extend_from_slice(&compact.to_le_bytes());
    r.extend_from_slice(&ts.to_le_bytes()); r.extend_from_slice(&number.to_le_bytes()); r.extend_from_slice(&epoch.to_le_bytes());
    r.extend_from_slice(&hx(parent)); r.extend_from_slice(&hx(txr)); r.extend_from_slice(&hx(prop)); r.extend_from_slice(&hx(extra)); r.extend_from_slice(&hx(dao));
    let mut raw=[0u8;192]; raw.copy_from_slice(&r); let mut n=[0u8;16]; n.copy_from_slice(&nonce.to_le_bytes()); (raw,n)
}
// 192-byte RawHeader + 16-byte nonce from a relayer header JSON (same field names as relayer.py).
fn raw_of_json(h:&Value)->([u8;192],[u8;16]){
    let u=|k:&str| u128::from_str_radix(h[k].as_str().unwrap().trim_start_matches("0x"),16).unwrap();
    raw_of(u("compact_target") as u32, u("timestamp") as u64, u("number") as u64, u("epoch") as u64,
        h["parent_hash"].as_str().unwrap(), h["transactions_root"].as_str().unwrap(),
        h["proposals_hash"].as_str().unwrap(), h["extra_hash"].as_str().unwrap(), h["dao"].as_str().unwrap(),
        u("nonce"))
}

#[derive(Clone)]
struct AdvanceLive {
    raw:[u8;192], nonce:[u8;16], diff_be:[u8;32],
    old_root:[u8;32], new_root:[u8;32], old_total:[u8;32], new_total:[u8;32],   // chain_root == tip hash; totals BE
    old_wroot:[u8;32], new_wroot:[u8;32], old_slot_leaf:[u8;32], w_siblings:Vec<[u8;32]>,
}
fn b2fp<F:PrimeField>(b:&[UInt8<F>])->Result<FpVar<F>,SynthesisError>{ let mut a=FpVar::<F>::zero(); let mut c=F::one(); for byte in b { for bit in byte.to_bits_le()? { a+=FpVar::from(bit)*c; c.double_in_place(); } } Ok(a) }
impl ConstraintSynthesizer<Fr> for AdvanceLive {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w=|b:&[u8],cs:&ConstraintSystemRef<Fr>| -> Result<Vec<UInt8<Fr>>,SynthesisError> { b.iter().map(|x| UInt8::new_witness(cs.clone(),||Ok(*x))).collect() };
        let raw=w(&self.raw,&cs)?; let nonce=w(&self.nonce,&cs)?;
        // R1 PoW(new header)
        let ph=blake2b256(&raw, b"ckb-default-hash")?; let mut ei=ph.clone(); ei.extend(nonce.clone());
        let eag=eaglesong_gadget::eaglesong(&ei)?; let pow=blake2b256(&eag, b"ckb-default-hash")?;
        let target=merkle_gadget::compact_to_target(&raw[4..8])?;
        merkle_gadget::enforce_leq_be(&pow,&target)?;
        // CHAIN_ROOT = TIP HASH. parent-link: raw.parent_hash (32..64) == checkpoint chain_root (= prior tip).
        let old_root=w(&self.old_root,&cs)?; for i in 0..32 { raw[32+i].enforce_equal(&old_root[i])?; }
        // difficulty: verify diff == floor((2^256-1)/target); accumulate work (LE add).
        let diff_be=w(&self.diff_be,&cs)?;
        difficulty_gadget::difficulty_verify(&cs,&target,&diff_be)?;
        let mut diff_le=diff_be.clone(); diff_le.reverse();
        // block hash = ckbhash(RawHeader || nonce); this is the NEW chain_root (new tip) AND the window leaf.
        let mut hin=raw.clone(); hin.extend(nonce.clone());
        let block_hash=blake2b256(&hin, b"ckb-default-hash")?;
        let new_root=w(&self.new_root,&cs)?; for i in 0..32 { block_hash[i].enforce_equal(&new_root[i])?; }
        // cumulative work: new_total (BE) == old_total (BE) + diff. Add in LE, then compare BE bytes.
        let old_total=w(&self.old_total,&cs)?; let new_total=w(&self.new_total,&cs)?;
        let mut old_le: Vec<UInt8<Fr>> = old_total.clone(); old_le.reverse();
        let (sum_le,_carry)=difficulty_gadget::add256(&cs,&old_le,&diff_le)?;
        let mut sum_be: Vec<UInt8<Fr>> = sum_le.clone(); sum_be.reverse();
        for i in 0..32 { sum_be[i].enforce_equal(&new_total[i])?; }
        // ---- WINDOW RING-BUFFER UPDATE: insert this header's block_hash at slot = height mod W ----
        let mut height_bits: Vec<Boolean<Fr>> = Vec::new();
        for i in 16..24 { for b in raw[i].to_bits_le()? { height_bits.push(b); } }
        let mut wpath=Vec::new();
        for (k, sib) in self.w_siblings.iter().enumerate() { wpath.push((w(sib,&cs)?, height_bits[k].clone().not())); }
        let old_slot_leaf=w(&self.old_slot_leaf,&cs)?;
        let owr=merkle_gadget::merkle_root(&old_slot_leaf, &wpath)?;
        let old_wroot=w(&self.old_wroot,&cs)?; for i in 0..32 { owr[i].enforce_equal(&old_wroot[i])?; }
        let nwr=merkle_gadget::merkle_root(&block_hash, &wpath)?;
        let new_wroot=w(&self.new_wroot,&cs)?; for i in 0..32 { nwr[i].enforce_equal(&new_wroot[i])?; }
        // ---- 7 public inputs binding (old_root, old_total, new_root, new_total, old_wroot, new_wroot) ----
        let pis=[(&old_root,&self.old_root),(&old_total,&self.old_total),(&new_root,&self.new_root),(&new_total,&self.new_total),(&old_wroot,&self.old_wroot),(&new_wroot,&self.new_wroot)];
        for (bytes,val) in pis { let pi=FpVar::new_input(cs.clone(),||Ok(Fr::from_le_bytes_mod_order(val)))?; b2fp(bytes)?.enforce_equal(&pi)?; }
        // 7th PI: authenticate new tip_height (= this header's height, raw[16..24])
        let mut hfp = FpVar::<Fr>::zero(); let mut hc = Fr::from(1u64);
        for b in &height_bits { hfp += FpVar::from(b.clone())*hc; hc = hc + hc; }
        let new_tip = u64::from_le_bytes(self.raw[16..24].try_into().unwrap());
        let pi_tip = FpVar::new_input(cs.clone(),||Ok(Fr::from(new_tip)))?;
        hfp.enforce_equal(&pi_tip)?;
        Ok(())
    }
}

fn fq_be(x:&Fq)->[u8;48]{ let mut o=[0u8;48]; let v=x.into_bigint().to_bytes_be(); o[48-v.len()..].copy_from_slice(&v); o }
fn g1c(p:&ArkG1)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;96]; u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y)); hexs(bls12_381::G1Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn g2c(p:&ArkG2)->String{ let (x,y)=p.xy().unwrap(); let mut u=[0u8;192]; u[0..48].copy_from_slice(&fq_be(&x.c1)); u[48..96].copy_from_slice(&fq_be(&x.c0)); u[96..144].copy_from_slice(&fq_be(&y.c1)); u[144..192].copy_from_slice(&fq_be(&y.c0)); hexs(bls12_381::G2Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed()) }
fn hexs(b:impl AsRef<[u8]>)->String{ b.as_ref().iter().map(|x| format!("{:02x}",x)).collect() }
fn fr_dec(x:&Fr)->String{ x.into_bigint().to_string() }

// CHIRAL_SERVE=<unix socket>: WARM advance prover - load the ceremony pk ONCE and prove many advance steps so
// the χCKB light-client advance never reloads the ~426MB key per block. Request (one JSON line):
//   {state:<checkpoint-state.json>, step:<step.json with header>, depth?:6, out:<redeemer path>}.
// Writes the SAME {vk,proof,public_inputs_dec,new_state} JSON the cold path prints, to `out`. The cold path
// (env CHIRAL_ADVANCE_STATE/STEP -> stdout) is UNTOUCHED below; this only adds a warm mode. catch_unwind in
// serve_warm keeps one bad request from crashing the resident service; the in-process verify guards drift.
#[cfg(unix)]
fn serve(sock:&str){
    let depth0: usize = std::env::var("WINDOW_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let pk_path=std::env::var("CEREMONY_PK").expect("CHIRAL_SERVE needs CEREMONY_PK (the advance ceremony key)");
    ckb_consensus_circuit::setup_mpc::serve_warm(sock, &pk_path, move |req, pk, vk| {
        let sp=req["state"].as_str().ok_or("missing state")?;
        let tp=req["step"].as_str().ok_or("missing step")?;
        let out=req["out"].as_str().ok_or("missing out")?;
        let depth=req["depth"].as_u64().map(|x| x as usize).unwrap_or(depth0);
        let wsize=1usize<<depth;
        let st:Value=serde_json::from_reader(std::fs::File::open(sp).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let step:Value=serde_json::from_reader(std::fs::File::open(tp).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let old_root=hx32(st["chain_root"].as_str().ok_or("state.chain_root")?);
        let old_total=hx32(st["total_difficulty"].as_str().ok_or("state.total_difficulty")?);
        let wleaves:Vec<[u8;32]>=st["window_leaves"].as_array().ok_or("state.window_leaves")?.iter().map(|x| hx32(x.as_str().unwrap())).collect();
        if wleaves.len()!=wsize { return Err("window_leaves != W".into()); }
        let (raw,nonce)=raw_of_json(&step["header"]);
        if raw[32..64]!=old_root[..] { return Err("step header parent_hash != state chain_root (not the tip's child)".into()); }
        let compact=u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let diff_be=ndiff(compact);
        let height=u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let slot=(height % wsize as u64) as usize;
        let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
        if let Some(rep)=step["block_hash"].as_str() { if hexs(&bh)!=rep.trim_start_matches("0x") { return Err("computed block hash != relayer-reported block_hash".into()); } }
        let new_total=add_be(&old_total,&diff_be);
        let old_slot_leaf=wleaves[slot];
        let (old_wroot,wp)=window_root_path(&wleaves,slot);
        let w_siblings:Vec<[u8;32]>=wp.iter().map(|(s,_)|*s).collect();
        let mut nl=wleaves.clone(); nl[slot]=bh;
        let (new_wroot,_)=window_root_path(&nl,slot);
        let circ=AdvanceLive{raw,nonce,diff_be,old_root,new_root:bh,old_total,new_total,old_wroot,new_wroot,old_slot_leaf,w_siblings};
        let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let proof=Groth16::<Bls12_381>::prove(pk,circ.clone(),&mut rng).map_err(|e| format!("{e:?}"))?;
        let inputs=vec![Fr::from_le_bytes_mod_order(&circ.old_root),Fr::from_le_bytes_mod_order(&circ.old_total),
                        Fr::from_le_bytes_mod_order(&circ.new_root),Fr::from_le_bytes_mod_order(&circ.new_total),
                        Fr::from_le_bytes_mod_order(&circ.old_wroot),Fr::from_le_bytes_mod_order(&circ.new_wroot),
                        Fr::from(height)];
        if !Groth16::<Bls12_381>::verify(vk,&inputs,&proof).map_err(|e| format!("{e:?}"))? { return Err("warm advance proof did not verify under ceremony vk".into()); }
        let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
        let red=format!("{{ \"vk\": {{ \"alpha_g1\":\"{}\",\"beta_g2\":\"{}\",\"gamma_g2\":\"{}\",\"delta_g2\":\"{}\",\"ic\":[{}] }}, \"proof\": {{ \"a\":\"{}\",\"b\":\"{}\",\"c\":\"{}\" }}, \"public_inputs_dec\": [{}], \"new_state\": {{ \"chain_root\":\"{}\",\"total_difficulty\":\"{}\",\"window_root\":\"{}\",\"tip_height\":{} }} }}",
            g1c(&vk.alpha_g1),g2c(&vk.beta_g2),g2c(&vk.gamma_g2),g2c(&vk.delta_g2), ic.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
            g1c(&proof.a),g2c(&proof.b),g1c(&proof.c), inputs.iter().map(|x| format!("\"{}\"",fr_dec(x))).collect::<Vec<_>>().join(","),
            hexs(&bh), hexs(&circ.new_total), hexs(&circ.new_wroot), height);
        std::fs::write(out, &red).map_err(|e| e.to_string())?;
        Ok(out.to_string())
    });
}

fn main(){
    #[cfg(unix)]
    if let Ok(sock)=std::env::var("CHIRAL_SERVE") { serve(&sock); return; }
    let depth: usize = std::env::var("WINDOW_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let wsize=1usize<<depth;

    // -------- assemble the circuit instance + the resulting new checkpoint state --------
    let (circ, tip_height, new_tip_hash): (AdvanceLive, u64, [u8;32]) =
    if let (Ok(sp),Ok(tp))=(std::env::var("CHIRAL_ADVANCE_STATE"),std::env::var("CHIRAL_ADVANCE_STEP")) {
        let st:Value=serde_json::from_reader(std::fs::File::open(&sp).unwrap()).unwrap();
        let step:Value=serde_json::from_reader(std::fs::File::open(&tp).unwrap()).unwrap();
        let old_root=hx32(st["chain_root"].as_str().unwrap());            // == current tip hash
        let old_total=hx32(st["total_difficulty"].as_str().unwrap());     // BE
        let wleaves:Vec<[u8;32]>=st["window_leaves"].as_array().unwrap().iter().map(|x| hx32(x.as_str().unwrap())).collect();
        assert_eq!(wleaves.len(), wsize, "window_leaves != W");
        let (raw,nonce)=raw_of_json(&step["header"]);
        // sanity: the new header must be the direct child of the checkpoint tip
        assert_eq!(&raw[32..64], &old_root[..], "step header parent_hash != state chain_root (not the tip's child)");
        let compact=u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let diff_be=ndiff(compact);
        let height=u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let slot=(height % wsize as u64) as usize;
        let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
        // cross-assert the recomputed block hash against the relayer-reported RPC hash (mirror
        // leap_bound_windowed.rs): both sides MUST derive chain_root from the same field bytes, or the
        // on-chain checkpoint (circuit's value) would diverge from the relayer's bookkeeping.
        if let Some(rep)=step["block_hash"].as_str() {
            assert_eq!(hexs(&bh), rep.trim_start_matches("0x"), "computed block hash != relayer-reported block_hash");
        }
        let new_total=add_be(&old_total,&diff_be);
        let old_slot_leaf=wleaves[slot];
        let (old_wroot,wp)=window_root_path(&wleaves,slot);
        let w_siblings:Vec<[u8;32]>=wp.iter().map(|(s,_)|*s).collect();
        let mut nl=wleaves.clone(); nl[slot]=bh;
        let (new_wroot,_)=window_root_path(&nl,slot);
        (AdvanceLive{raw,nonce,diff_be,old_root,new_root:bh,old_total,new_total,old_wroot,new_wroot,old_slot_leaf,w_siblings}, height, bh)
    } else {
        // REGRESSION: advance to header 21,341,104 from a genesis anchored at its parent (21,341,103), total 0.
        let old_root=hx32("6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff"); // tip 21,341,103 hash
        let old_total=[0u8;32];
        let (raw,nonce)=raw_of(487079700,1780789379908,21341104,1979133798134699,
            "6e98d756be2cab8557f61f138fd67a0b23a1dc7024f17c26e360801eaac003ff",
            "10f2e7ecea7598f807bd59cc8f4a088eda955b68d66e8c69d5404cf36878734c",
            "0b0894848570dc9d837b3a99c69860c9112f6b3bffc7a3322609575bea9ec73c",
            "d65c507211e9f0b5de4ba187c484a43b526710406b03128ec489e55e80c7fd30",
            "bef24d4b00922757a866aac43f132a00c0cee11243c3e1090091e524b5d55709",
            77054535269512247200822733458160144498);
        let compact=487079700u32; let diff_be=ndiff(compact);
        let bh=ckbhash(&[raw.as_slice(),nonce.as_slice()].concat());
        let new_total=add_be(&old_total,&diff_be);
        let height=21341104u64; let slot=(height % wsize as u64) as usize;
        let mut wl=vec![[0u8;32];wsize]; for k in 0..wsize { wl[k]=ckbhash(&((k as u64)+1).to_le_bytes()); }
        let old_slot_leaf=wl[slot];
        let (old_wroot,wp)=window_root_path(&wl,slot);
        let w_siblings:Vec<[u8;32]>=wp.iter().map(|(s,_)|*s).collect();
        let mut nl=wl.clone(); nl[slot]=bh;
        let (new_wroot,_)=window_root_path(&nl,slot);
        (AdvanceLive{raw,nonce,diff_be,old_root,new_root:bh,old_total,new_total,old_wroot,new_wroot,old_slot_leaf,w_siblings}, height, bh)
    };

    // structural check + count
    {
        let cs=ConstraintSystem::<Fr>::new_ref();
        circ.clone().generate_constraints(cs.clone()).unwrap();
        let sat=cs.is_satisfied().unwrap();
        eprintln!("ADVANCE_LIVE depth={depth} CONSTRAINTS={} next_pow2={} is_satisfied={sat}",
            cs.num_constraints(), (cs.num_constraints() as u64).next_power_of_two());
        assert!(sat, "advance_live circuit must be satisfiable");
        if std::env::var("COUNT_ONLY").is_ok() { return; }
    }
    if std::env::var("PROVE").is_err() { eprintln!("(set PROVE=1 for full Groth16 setup/prove/redeemer)"); return; }

    let mut rng=ark_std::rand::rngs::StdRng::seed_from_u64(7);
    let (pk,vk) = if let Ok(dir)=std::env::var("CEREMONY_OUT") {
        let (pk,transcript)=ckb_consensus_circuit::setup_mpc::run_ceremony(circ.clone(), 3, 3, "advance_live");
        ckb_consensus_circuit::setup_mpc::save_pk(&pk, &format!("{dir}/advance_live_pk.bin"));
        let _ = std::fs::write(format!("{dir}/advance_live_transcript.json"), serde_json::to_string_pretty(&transcript).unwrap());
        let vk=pk.vk.clone(); (pk,vk)
    } else if let Ok(p)=std::env::var("CEREMONY_PK") {
        eprintln!("loading ceremony key from {p}"); let pk=ckb_consensus_circuit::setup_mpc::load_pk(&p); let vk=pk.vk.clone(); (pk,vk)
    } else {
        eprintln!("advance_live: Groth16 (test) setup..."); Groth16::<Bls12_381>::circuit_specific_setup(circ.clone(),&mut rng).unwrap()
    };
    eprintln!("proving..."); let proof=Groth16::<Bls12_381>::prove(&pk,circ.clone(),&mut rng).unwrap();
    let inputs=vec![Fr::from_le_bytes_mod_order(&circ.old_root),Fr::from_le_bytes_mod_order(&circ.old_total),
                    Fr::from_le_bytes_mod_order(&circ.new_root),Fr::from_le_bytes_mod_order(&circ.new_total),
                    Fr::from_le_bytes_mod_order(&circ.old_wroot),Fr::from_le_bytes_mod_order(&circ.new_wroot),
                    Fr::from(tip_height)];
    let ok=Groth16::<Bls12_381>::verify(&vk,&inputs,&proof).unwrap(); eprintln!("arkworks verify = {ok}"); assert!(ok);
    eprintln!("old_root={} new_root={} new_total={} tip={}", hexs(&circ.old_root), hexs(&circ.new_root), hexs(&circ.new_total), tip_height);
    // emit the redeemer AND the resulting checkpoint state (chain_root=new tip hash, total, window_root, tip)
    let ic:Vec<String>=vk.gamma_abc_g1.iter().map(g1c).collect();
    println!("{{ \"vk\": {{ \"alpha_g1\":\"{}\",\"beta_g2\":\"{}\",\"gamma_g2\":\"{}\",\"delta_g2\":\"{}\",\"ic\":[{}] }}, \"proof\": {{ \"a\":\"{}\",\"b\":\"{}\",\"c\":\"{}\" }}, \"public_inputs_dec\": [{}], \"new_state\": {{ \"chain_root\":\"{}\",\"total_difficulty\":\"{}\",\"window_root\":\"{}\",\"tip_height\":{} }} }}",
        g1c(&vk.alpha_g1),g2c(&vk.beta_g2),g2c(&vk.gamma_g2),g2c(&vk.delta_g2), ic.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
        g1c(&proof.a),g2c(&proof.b),g1c(&proof.c), inputs.iter().map(|x| format!("\"{}\"",fr_dec(x))).collect::<Vec<_>>().join(","),
        hexs(&new_tip_hash), hexs(&circ.new_total), hexs(&circ.new_wroot), tip_height);
}
