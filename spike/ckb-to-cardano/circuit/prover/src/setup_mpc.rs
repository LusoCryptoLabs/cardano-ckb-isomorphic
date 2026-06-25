//! REAL two-phase Groth16 trusted-setup ceremony (BLS12-381), run on the ACTUAL production circuits.
//!
//! Replaces the deterministic `circuit_specific_setup(seed_from_u64(..))` (whose toxic waste is fully
//! recoverable) with a multi-contributor ceremony whose toxic waste {tau, alpha, beta, delta} is
//! unrecoverable unless EVERY contributor colludes - so >=1 honest contributor (who destroys their
//! secret) => secure.
//!
//!   Phase-1 (Powers of Tau): contributors re-randomize (tau, alpha, beta). Output (in the exponent,
//!     secrets unknown): {tau^i G1}_{0..2n-2}, {tau^i G2}_{0..n-1}, {alpha tau^i G1}, {beta tau^i G1},
//!     beta G2. Each contribution is publicly verifiable: a Schnorr PoK of the secret increment +
//!     batched pairing checks that the whole accumulator is a consistent PoT.
//!   Derive key (gamma=1, public; sound): evaluate the circuit's QAP "in the exponent" using a group
//!     iFFT (arkworks' own FFT over G1/G2 points) to get the Lagrange-basis points {L_j(tau) G}, then
//!     assemble EXACTLY the elements ark-groth16's generate_parameters_with_qap would, with delta=1.
//!   Phase-2 (per-circuit): contributors re-randomize delta (delta *= s in G1/G2; h_query,l_query *=
//!     s^-1) with a Schnorr PoK - the same transform as the original ceremony.rs, now on the REAL pk.
//!
//! The result is validated by a hard cryptographic oracle: a proof produced under the ceremony key must
//! verify under arkworks Groth16::verify AND under the on-chain Aiken verifier. A wrong derivation
//! cannot produce verifying proofs.
//!
//! What a sandbox CANNOT provide: contributor INDEPENDENCE (>=1 honest human on an airgapped machine).
//! Here each secret is drawn fresh from the OS CSPRNG and dropped; the machinery is built so real
//! external contributors slot in unchanged, and every contribution is recorded verifiably in the
//! transcript. That residual (independence) is a social property, flagged honestly in the transcript.

use ark_bls12_381::{Bls12_381, Fr, Fq, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use blake2b_rs::Blake2bBuilder;
use rayon::prelude::*;

// ----------------------------------------------------------------------------------------------------
// OS-entropy RNG: each contributor's secret comes from /dev/urandom and is dropped after use.
// ----------------------------------------------------------------------------------------------------
pub fn os_rng() -> ark_std::rand::rngs::StdRng {
    use ark_std::rand::SeedableRng;
    use std::io::Read;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed).unwrap();
    ark_std::rand::rngs::StdRng::from_seed(seed)
}

fn b2b32(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).build();
    for c in chunks { h.update(c); }
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}

fn g1_bytes(p: &G1Affine) -> Vec<u8> { let mut v = Vec::new(); p.serialize_uncompressed(&mut v).unwrap(); v }

// ----------------------------------------------------------------------------------------------------
// Schnorr proof-of-knowledge of a scalar s s.t. new_point = s * base   (Fiat-Shamir, rogue-resistant).
// Identical pattern to ceremony.rs. Verifies: z*base == K + c*new_point, c = H(base, new_point, K).
// ----------------------------------------------------------------------------------------------------
#[derive(Clone)]
pub struct Pok { pub k_g1: G1Affine, pub z: Fr }

fn fs_challenge(base: &G1Affine, new_point: &G1Affine, k_g1: &G1Affine) -> Fr {
    let o = b2b32(&[&g1_bytes(base), &g1_bytes(new_point), &g1_bytes(k_g1)]);
    Fr::from_le_bytes_mod_order(&o)
}

fn schnorr_prove<R: Rng>(base: G1Affine, new_point: G1Affine, s: Fr, rng: &mut R) -> Pok {
    let k = Fr::rand(rng);
    let k_g1 = (base.into_group() * k).into_affine();
    let c = fs_challenge(&base, &new_point, &k_g1);
    Pok { k_g1, z: k + c * s }
}

fn schnorr_verify(base: G1Affine, new_point: G1Affine, pok: &Pok) -> bool {
    let c = fs_challenge(&base, &new_point, &pok.k_g1);
    let lhs = (base.into_group() * pok.z).into_affine();
    let rhs = (pok.k_g1.into_group() + new_point.into_group() * c).into_affine();
    lhs == rhs
}

// ----------------------------------------------------------------------------------------------------
// Phase-1 accumulator (Powers of Tau, with alpha/beta). Stored affine.
// degrees: tau_g1 = 0..=2n-2 (2n-1 pts), tau_g2 = 0..=n-1, alpha_tau_g1/beta_tau_g1 = 0..=n-1.
// ----------------------------------------------------------------------------------------------------
#[derive(Clone)]
pub struct Phase1 {
    pub tau_g1: Vec<G1Affine>,
    pub tau_g2: Vec<G2Affine>,
    pub alpha_tau_g1: Vec<G1Affine>,
    pub beta_tau_g1: Vec<G1Affine>,
    pub beta_g2: G2Affine,
}

#[derive(Clone)]
pub struct Phase1Pok { pub tau: Pok, pub alpha: Pok, pub beta: Pok }

impl Phase1 {
    /// Canonical initial accumulator: tau=alpha=beta=1, so every power is the generator.
    pub fn initial(n: usize) -> Self {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        Phase1 {
            tau_g1: vec![g1; 2 * n - 1],
            tau_g2: vec![g2; n],
            alpha_tau_g1: vec![g1; n],
            beta_tau_g1: vec![g1; n],
            beta_g2: g2,
        }
    }

    /// Apply a contributor's secret (tau_s, alpha_s, beta_s); return a Schnorr PoK of each increment.
    /// The secrets must be dropped by the caller after this returns.
    pub fn contribute<R: Rng>(&mut self, tau_s: Fr, alpha_s: Fr, beta_s: Fr, rng: &mut R) -> Phase1Pok {
        let tau_base = self.tau_g1[1];
        let alpha_base = self.alpha_tau_g1[0];
        let beta_base = self.beta_tau_g1[0];

        // powers of tau_s up to 2n-2
        let max = self.tau_g1.len();
        let mut taup = Vec::with_capacity(max);
        let mut acc = Fr::one();
        for _ in 0..max { taup.push(acc); acc *= tau_s; }

        let n = self.tau_g2.len();
        // tau_g1[i] *= tau_s^i
        self.tau_g1.par_iter_mut().enumerate().for_each(|(i, p)| { *p = (p.into_group() * taup[i]).into_affine(); });
        // tau_g2[i] *= tau_s^i
        self.tau_g2.par_iter_mut().enumerate().for_each(|(i, p)| { *p = (p.into_group() * taup[i]).into_affine(); });
        // alpha_tau_g1[i] *= alpha_s * tau_s^i ; beta_tau_g1[i] *= beta_s * tau_s^i
        self.alpha_tau_g1[..n].par_iter_mut().enumerate().for_each(|(i, p)| { *p = (p.into_group() * (alpha_s * taup[i])).into_affine(); });
        self.beta_tau_g1[..n].par_iter_mut().enumerate().for_each(|(i, p)| { *p = (p.into_group() * (beta_s * taup[i])).into_affine(); });
        self.beta_g2 = (self.beta_g2.into_group() * beta_s).into_affine();

        Phase1Pok {
            tau: schnorr_prove(tau_base, self.tau_g1[1], tau_s, rng),
            alpha: schnorr_prove(alpha_base, self.alpha_tau_g1[0], alpha_s, rng),
            beta: schnorr_prove(beta_base, self.beta_tau_g1[0], beta_s, rng),
        }
    }

    /// Verify a contribution's PoKs against the saved pre-contribution bases.
    pub fn verify_pok(bases: (G1Affine, G1Affine, G1Affine), new: &Phase1, pok: &Phase1Pok) -> bool {
        schnorr_verify(bases.0, new.tau_g1[1], &pok.tau)
            && schnorr_verify(bases.1, new.alpha_tau_g1[0], &pok.alpha)
            && schnorr_verify(bases.2, new.beta_tau_g1[0], &pok.beta)
    }

    /// Batched, publicly-verifiable check that this accumulator is a CONSISTENT Powers-of-Tau (no
    /// secret needed). Uses random linear combinations so each ladder costs O(1) pairings, not O(n).
    pub fn verify_wellformed(&self) -> bool {
        let g1 = self.tau_g1[0];
        let g2 = self.tau_g2[0];
        let p = |a: G1Affine, b: G2Affine| Bls12_381::pairing(a, b);
        // (0) degree-0 elements are the generators
        if g1 != G1Affine::generator() || g2 != G2Affine::generator() { return false; }
        // (1) couple the G1 and G2 tau ladders: e(tau G1, G2) == e(G1, tau G2)
        if p(self.tau_g1[1], g2) != p(g1, self.tau_g2[1]) { return false; }
        // (2) tau_g1 is geometric with ratio tau (batched): e(S{i} rho_i tau_g1[i+1], G2) == e(S rho_i tau_g1[i], tau_g2[1])
        {
            let l = self.tau_g1.len() - 1;
            let rho = rho_vec(l);
            let a = msm_g1(&self.tau_g1[1..], &rho);
            let b = msm_g1(&self.tau_g1[..l], &rho);
            if p(a, g2) != p(b, self.tau_g2[1]) { return false; }
        }
        // (3) tau_g2 is geometric (batched): e(G1, S rho_i tau_g2[i+1]) == e(tau_g1[1], S rho_i tau_g2[i])
        {
            let l = self.tau_g2.len() - 1;
            let rho = rho_vec(l);
            let a = msm_g2(&self.tau_g2[1..], &rho);
            let b = msm_g2(&self.tau_g2[..l], &rho);
            if p(g1, a) != p(self.tau_g1[1], b) { return false; }
        }
        // (4) alpha ladder ties to tau ladder: e(S rho_i alpha_tau_g1[i], G2) == e(alpha G1, S rho_i tau_g2[i])
        {
            let n = self.alpha_tau_g1.len();
            let rho = rho_vec(n);
            let a = msm_g1(&self.alpha_tau_g1, &rho);
            let b = msm_g2(&self.tau_g2[..n], &rho);
            if p(a, g2) != p(self.alpha_tau_g1[0], b) { return false; }
        }
        // (5) beta ladder ties to tau ladder
        {
            let n = self.beta_tau_g1.len();
            let rho = rho_vec(n);
            let a = msm_g1(&self.beta_tau_g1, &rho);
            let b = msm_g2(&self.tau_g2[..n], &rho);
            if p(a, g2) != p(self.beta_tau_g1[0], b) { return false; }
        }
        // (6) beta_g2 consistent with beta G1: e(beta G1, G2) == e(G1, beta G2)
        if p(self.beta_tau_g1[0], g2) != p(g1, self.beta_g2) { return false; }
        true
    }
}

// deterministic random scalars for batched checks (Fiat-Shamir style, no secret)
fn rho_vec(len: usize) -> Vec<Fr> {
    (0..len).map(|i| {
        let o = b2b32(&[b"chiral-pot-rho", &(i as u64).to_le_bytes()]);
        Fr::from_le_bytes_mod_order(&o)
    }).collect()
}
fn msm_g1(bases: &[G1Affine], scalars: &[Fr]) -> G1Affine { G1Projective::msm(bases, scalars).unwrap().into_affine() }
fn msm_g2(bases: &[G2Affine], scalars: &[Fr]) -> G2Affine { G2Projective::msm(bases, scalars).unwrap().into_affine() }

// ----------------------------------------------------------------------------------------------------
// QAP "in the exponent": evaluate the circuit's Lagrange basis at the secret tau via a group iFFT, then
// assemble exactly the ProvingKey ark-groth16 would build (gamma=1, delta=1).
// ----------------------------------------------------------------------------------------------------
fn add_scaled_g1(acc: &mut G1Projective, base: G1Projective, coeff: &Fr, one: &Fr, neg_one: &Fr) {
    if coeff == one { *acc += base; }
    else if coeff == neg_one { *acc -= base; }
    else { *acc += base * coeff; }
}
fn add_scaled_g2(acc: &mut G2Projective, base: G2Projective, coeff: &Fr, one: &Fr, neg_one: &Fr) {
    if coeff == one { *acc += base; }
    else if coeff == neg_one { *acc -= base; }
    else { *acc += base * coeff; }
}

/// The R1CS shape needed to size phase-1 (domain n) before building the accumulator.
pub fn circuit_domain<C: ConstraintSynthesizer<Fr>>(circ: C) -> usize {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circ.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let domain_size = cs.num_constraints() + cs.num_instance_variables();
    GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap().size()
}

/// Derive the initial Groth16 ProvingKey (gamma=1, delta=1) from a Phase-1 accumulator, in the exponent.
/// Mirrors ark_groth16::generator + LibsnarkReduction::instance_map_with_evaluation exactly.
pub fn derive_pk<C: ConstraintSynthesizer<Fr>>(circ: C, p1: &Phase1) -> ProvingKey<Bls12_381> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circ.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    let num_constraints = cs.num_constraints();
    let num_instance = cs.num_instance_variables();
    let num_witness = cs.num_witness_variables();
    let qap_num_variables = (num_instance - 1) + num_witness;
    let domain_size = num_constraints + num_instance;
    let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap();
    let n = domain.size();
    assert!(p1.tau_g1.len() >= 2 * n - 1, "phase-1 too small for this circuit");

    // Lagrange basis in the exponent: iFFT of the first n powers (identity: iFFT([tau^i G]) = [L_i(tau) G]).
    let ifft_g1 = |src: &[G1Affine]| -> Vec<G1Projective> {
        let mut v: Vec<G1Projective> = src[..n].iter().map(|a| a.into_group()).collect();
        domain.ifft_in_place(&mut v); v
    };
    let lag_g1 = ifft_g1(&p1.tau_g1);
    let alpha_lag = ifft_g1(&p1.alpha_tau_g1);
    let beta_lag = ifft_g1(&p1.beta_tau_g1);
    let lag_g2 = {
        let mut v: Vec<G2Projective> = p1.tau_g2[..n].iter().map(|a| a.into_group()).collect();
        domain.ifft_in_place(&mut v); v
    };

    let one = Fr::one(); let neg_one = -one;
    let m1 = qap_num_variables + 1;
    let mut a_query = vec![G1Projective::zero(); m1];
    let mut b_g1 = vec![G1Projective::zero(); m1];
    let mut b_g2 = vec![G2Projective::zero(); m1];
    // numerator = beta*u_i(tau) + alpha*v_i(tau) + w_i(tau)  (in the exponent, G1)
    let mut num = vec![G1Projective::zero(); m1];

    // public-input "pinning": a[idx] gets L_{num_constraints+idx}(tau); it flows into numerator via beta*a.
    for idx in 0..num_instance {
        let pin = num_constraints + idx;
        a_query[idx] += lag_g1[pin];
        num[idx] += beta_lag[pin];
    }
    // constraint contributions
    for i in 0..num_constraints {
        let li1 = lag_g1[i]; let li2 = lag_g2[i]; let a_li = alpha_lag[i]; let b_li = beta_lag[i];
        for (coeff, idx) in &matrices.a[i] {
            add_scaled_g1(&mut a_query[*idx], li1, coeff, &one, &neg_one); // u_i term
            add_scaled_g1(&mut num[*idx], b_li, coeff, &one, &neg_one);    // beta*u_i term
        }
        for (coeff, idx) in &matrices.b[i] {
            add_scaled_g1(&mut b_g1[*idx], li1, coeff, &one, &neg_one);    // v_i term (G1)
            add_scaled_g2(&mut b_g2[*idx], li2, coeff, &one, &neg_one);    // v_i term (G2)
            add_scaled_g1(&mut num[*idx], a_li, coeff, &one, &neg_one);    // alpha*v_i term
        }
        for (coeff, idx) in &matrices.c[i] {
            add_scaled_g1(&mut num[*idx], li1, coeff, &one, &neg_one);     // w_i term
        }
    }

    // gamma=1 -> gamma_abc = numerator[public]; delta=1 -> l = numerator[private], h_query unscaled.
    let gamma_abc_g1: Vec<G1Affine> = G1Projective::normalize_batch(&num[..num_instance]);
    let l_query: Vec<G1Affine> = G1Projective::normalize_batch(&num[num_instance..]);
    // h_query[i] = zt * tau^i (delta=1), zt = tau^n - 1  =>  tau^{n+i} - tau^i,  i in 0..n-1
    let h_query: Vec<G1Affine> = {
        let hp: Vec<G1Projective> = (0..(n - 1))
            .into_par_iter()
            .map(|i| p1.tau_g1[n + i].into_group() - p1.tau_g1[i].into_group())
            .collect();
        G1Projective::normalize_batch(&hp)
    };

    let a_query = G1Projective::normalize_batch(&a_query);
    let b_g1_query = G1Projective::normalize_batch(&b_g1);
    let b_g2_query = G2Projective::normalize_batch(&b_g2);

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let vk = VerifyingKey::<Bls12_381> {
        alpha_g1: p1.alpha_tau_g1[0], // alpha G1
        beta_g2: p1.beta_g2,          // beta G2
        gamma_g2: g2,                 // gamma = 1
        delta_g2: g2,                 // delta = 1 (initial; phase-2 randomizes)
        gamma_abc_g1,
    };
    ProvingKey::<Bls12_381> {
        vk,
        beta_g1: p1.beta_tau_g1[0],   // beta G1
        delta_g1: g1,                 // delta = 1
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    }
}

// ----------------------------------------------------------------------------------------------------
// Phase-2: per-circuit delta re-randomization (same transform as ceremony.rs, now on the real pk).
// ----------------------------------------------------------------------------------------------------
pub fn contribute_phase2<R: Rng>(pk: &mut ProvingKey<Bls12_381>, s: Fr, rng: &mut R) -> Pok {
    let old_g1 = pk.delta_g1;
    let si = s.inverse().unwrap();
    pk.vk.delta_g2 = (pk.vk.delta_g2.into_group() * s).into_affine();
    pk.delta_g1 = (pk.delta_g1.into_group() * s).into_affine();
    pk.h_query.par_iter_mut().for_each(|h| *h = (h.into_group() * si).into_affine());
    pk.l_query.par_iter_mut().for_each(|l| *l = (l.into_group() * si).into_affine());
    schnorr_prove(old_g1, pk.delta_g1, s, rng)
}
pub fn verify_phase2(old_delta_g1: G1Affine, new_delta_g1: G1Affine, pok: &Pok) -> bool {
    schnorr_verify(old_delta_g1, new_delta_g1, pok)
}

// ----------------------------------------------------------------------------------------------------
// Orchestration + persistence.
// ----------------------------------------------------------------------------------------------------
pub fn save_pk(pk: &ProvingKey<Bls12_381>, path: &str) {
    // Serialize FIRST (cheap, in-memory) so the expensive ceremony result is captured before any I/O.
    let mut buf = Vec::new();
    pk.serialize_compressed(&mut buf).unwrap();
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Never panic on a write error - fall back to a guaranteed-writable location so a 40-min ceremony
    // is never lost to a path mistake.
    match std::fs::write(path, &buf) {
        Ok(_) => eprintln!("[ceremony] saved proving key -> {path} ({} bytes)", buf.len()),
        Err(e) => {
            let name = std::path::Path::new(path).file_name().unwrap().to_string_lossy().to_string();
            for fb in [format!("/root/{name}"), format!("/tmp/{name}")] {
                if std::fs::write(&fb, &buf).is_ok() {
                    eprintln!("[ceremony] WARN: write to {path} failed ({e}); saved fallback -> {fb}");
                    return;
                }
            }
            eprintln!("[ceremony] ERROR: could not persist proving key anywhere: {e}");
        }
    }
}
pub fn load_pk(path: &str) -> ProvingKey<Bls12_381> {
    // The ceremony proving key is OUR OWN output (trusted), so the validity checks the *checked*
    // deserializers run - per-point subgroup membership (a scalar-mul over millions of points) and, for the
    // compressed form, y-recovery by sqrt - are the bulk of the ~391s cold load and are wasted work here.
    let uc = format!("{path}.uc");
    if std::path::Path::new(&uc).exists() {
        // Fastest: an uncompressed, unchecked sidecar loads in seconds (no decompression, no subgroup check).
        let buf = std::fs::read(&uc).unwrap();
        return ProvingKey::<Bls12_381>::deserialize_uncompressed_unchecked(&buf[..]).unwrap();
    }
    // Default: load the existing compressed key UNCHECKED - same file on disk, skips only the subgroup check.
    let buf = std::fs::read(path).unwrap();
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed_unchecked(&buf[..]).unwrap();
    // One-off: CHIRAL_BAKE_UC=1 writes the uncompressed sidecar (~2x disk) so every later load takes the fast
    // path above. Run once on the VPS after transferring the keys; subsequent warm-prover restarts load in seconds.
    if std::env::var("CHIRAL_BAKE_UC").is_ok() && !std::path::Path::new(&uc).exists() {
        let mut b = Vec::new();
        if pk.serialize_uncompressed(&mut b).is_ok() {
            match std::fs::write(&uc, &b) {
                Ok(_) => eprintln!("[load_pk] baked uncompressed sidecar -> {uc} ({} bytes)", b.len()),
                Err(e) => eprintln!("[load_pk] WARN: could not write {uc}: {e}"),
            }
        }
    }
    pk
}

/// Generic WARM prover: load the ceremony proving key ONCE, then serve many prove requests over a unix
/// socket so a leg never reloads the (~480MB) key per request. `handle` does the circuit-specific work -
/// assemble its instance from the request JSON, prove under `pk`, write the redeemer - and returns the path
/// it wrote (echoed to the caller). ping/shutdown are handled here; each request runs under catch_unwind so a
/// single malformed request can't crash the resident service. This is the loop first validated for the
/// return leg (leap_bound_windowed), lifted here so the forward + advance legs reuse it verbatim.
#[cfg(unix)]
pub fn serve_warm<F>(sock: &str, pk_path: &str, handle: F)
where
    F: Fn(&serde_json::Value, &ProvingKey<Bls12_381>, &VerifyingKey<Bls12_381>) -> Result<String, String>,
{
    use std::io::{BufRead, BufReader, Write};
    eprintln!("[warm] loading ceremony key {pk_path} (once)...");
    let t0 = std::time::Instant::now();
    let pk = load_pk(pk_path);
    let vk = pk.vk.clone();
    eprintln!("[warm] pk loaded in {:.1}s; serving on {sock}", t0.elapsed().as_secs_f64());
    let _ = std::fs::remove_file(sock);
    let listener = std::os::unix::net::UnixListener::bind(sock).expect("bind unix socket");
    for conn in listener.incoming() {
        let mut s = match conn { Ok(s) => s, Err(_) => continue };
        let mut line = String::new();
        if BufReader::new(&s).read_line(&mut line).is_err() { continue; }
        if line.trim() == "ping" { let _ = s.write_all(b"{\"ok\":true,\"ready\":true}\n"); continue; }
        if line.trim() == "shutdown" { let _ = s.write_all(b"{\"ok\":true,\"bye\":true}\n"); break; }
        let tp = std::time::Instant::now();
        // catch_unwind: a bad request (missing file / malformed inputs -> .unwrap() panic) must return an error
        // to THAT caller, never crash the resident service (which holds the ~6.6-min pk load).
        let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<String, String> {
            let req: serde_json::Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
            handle(&req, &pk, &vk)
        })).unwrap_or_else(|_| Err("prover panicked on this request (missing file / malformed inputs?)".into()));
        let reply = match &resp {
            Ok(o) => format!("{{\"ok\":true,\"out\":{},\"prove_secs\":{:.1}}}", serde_json::to_string(o).unwrap(), tp.elapsed().as_secs_f64()),
            Err(e) => format!("{{\"error\":{}}}", serde_json::to_string(e).unwrap()),
        };
        let _ = s.write_all(reply.as_bytes()); let _ = s.write_all(b"\n");
        eprintln!("[warm] served in {:.1}s: {reply}", tp.elapsed().as_secs_f64());
    }
}

// ---- redeemer JSON (compressed-hex vk+proof+public inputs) - same format the Aiken tests/relayer expect.
fn fq_be(x: &Fq) -> [u8; 48] { let mut o = [0u8; 48]; let v = x.into_bigint().to_bytes_be(); o[48 - v.len()..].copy_from_slice(&v); o }
fn hexs(b: impl AsRef<[u8]>) -> String { b.as_ref().iter().map(|x| format!("{:02x}", x)).collect() }
fn g1c(p: &G1Affine) -> String {
    let (x, y) = p.xy().unwrap(); let mut u = [0u8; 96];
    u[..48].copy_from_slice(&fq_be(&x)); u[48..].copy_from_slice(&fq_be(&y));
    hexs(bls12_381::G1Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed())
}
fn g2c(p: &G2Affine) -> String {
    let (x, y) = p.xy().unwrap(); let mut u = [0u8; 192];
    u[0..48].copy_from_slice(&fq_be(&x.c1)); u[48..96].copy_from_slice(&fq_be(&x.c0));
    u[96..144].copy_from_slice(&fq_be(&y.c1)); u[144..192].copy_from_slice(&fq_be(&y.c0));
    hexs(bls12_381::G2Affine::from_uncompressed_unchecked(&u).unwrap().to_compressed())
}
fn fr_dec(x: &Fr) -> String { x.into_bigint().to_string() }

/// Build the {vk, proof, public_inputs_dec} redeemer JSON for a proof under a (ceremony) key.
pub fn emit_redeemer(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>, inputs: &[Fr]) -> serde_json::Value {
    let ic: Vec<String> = vk.gamma_abc_g1.iter().map(g1c).collect();
    serde_json::json!({
        "vk": { "alpha_g1": g1c(&vk.alpha_g1), "beta_g2": g2c(&vk.beta_g2), "gamma_g2": g2c(&vk.gamma_g2), "delta_g2": g2c(&vk.delta_g2), "ic": ic },
        "proof": { "a": g1c(&proof.a), "b": g2c(&proof.b), "c": g1c(&proof.c) },
        "public_inputs_dec": inputs.iter().map(fr_dec).collect::<Vec<_>>(),
    })
}

fn vk_hash(vk: &VerifyingKey<Bls12_381>) -> String {
    let mut buf = Vec::new(); vk.serialize_compressed(&mut buf).unwrap();
    let o = b2b32(&[&buf]);
    o.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Run the full ceremony on `circ`: n1 Phase-1 contributors + n2 Phase-2 contributors, all verified.
/// Returns the ceremony ProvingKey and a JSON transcript. The circuit used for keygen must be the SAME
/// shape used for proving.
pub fn run_ceremony<C: Clone + ConstraintSynthesizer<Fr>>(
    circ: C, n1: usize, n2: usize, label: &str,
) -> (ProvingKey<Bls12_381>, serde_json::Value) {
    let n = circuit_domain(circ.clone());
    eprintln!("[ceremony:{label}] domain n = {n} (2^{})", (n as f64).log2() as u32);
    let mut os = os_rng();
    let mut p1 = Phase1::initial(n);
    let mut t_phase1 = Vec::new();

    eprintln!("[ceremony:{label}] phase-1 Powers-of-Tau: {n1} contributors");
    for i in 0..n1 {
        let bases = (p1.tau_g1[1], p1.alpha_tau_g1[0], p1.beta_tau_g1[0]);
        let (tau_s, alpha_s, beta_s) = (Fr::rand(&mut os), Fr::rand(&mut os), Fr::rand(&mut os));
        let pok = p1.contribute(tau_s, alpha_s, beta_s, &mut os); // secrets dropped at end of scope
        let pok_ok = Phase1::verify_pok(bases, &p1, &pok);
        let wf_ok = p1.verify_wellformed();
        let mut forged = pok.clone(); forged.tau.z += Fr::one();
        let forged_rejected = !Phase1::verify_pok(bases, &p1, &forged);
        eprintln!("  p1 contributor {}: pok={} wellformed={} forged_rejected={}", i + 1, pok_ok, wf_ok, forged_rejected);
        assert!(pok_ok && wf_ok && forged_rejected, "phase-1 contribution {} failed", i + 1);
        t_phase1.push(serde_json::json!({"contributor": i+1, "pok_verified": pok_ok, "accumulator_wellformed": wf_ok, "forged_pok_rejected": forged_rejected}));
    }

    eprintln!("[ceremony:{label}] deriving circuit proving key from PoT (gamma=1, delta=1)...");
    let mut pk = derive_pk(circ.clone(), &p1);

    eprintln!("[ceremony:{label}] phase-2 delta ceremony: {n2} contributors");
    let mut t_phase2 = Vec::new();
    for i in 0..n2 {
        let old = pk.delta_g1;
        let s = Fr::rand(&mut os);
        let pok = contribute_phase2(&mut pk, s, &mut os); // secret dropped
        let ok = verify_phase2(old, pk.delta_g1, &pok);
        let mut forged = pok.clone(); forged.z += Fr::one();
        let forged_rejected = !verify_phase2(old, pk.delta_g1, &forged);
        eprintln!("  p2 contributor {}: pok={} forged_rejected={}", i + 1, ok, forged_rejected);
        assert!(ok && forged_rejected, "phase-2 contribution {} failed", i + 1);
        t_phase2.push(serde_json::json!({"contributor": i+1, "pok_verified": ok, "forged_pok_rejected": forged_rejected}));
    }

    let transcript = serde_json::json!({
        "circuit": label,
        "domain": n,
        "phase1_powers_of_tau": {"contributors": n1, "rounds": t_phase1},
        "phase2_delta": {"contributors": n2, "rounds": t_phase2},
        "vk_blake2b": vk_hash(&pk.vk),
        "note": "Real two-phase Groth16 ceremony on the production circuit. Toxic waste {tau,alpha,beta,delta} \
                 is a product of all contributors' OS-entropy secrets, each dropped. gamma=1 (public, sound). \
                 SANDBOX CAVEAT: contributor INDEPENDENCE is simulated (same machine); the machinery + \
                 verifiable transcript let real external contributors slot in unchanged.",
    });
    (pk, transcript)
}
