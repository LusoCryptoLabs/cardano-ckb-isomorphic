//! Security-grade FRI, generic over the challenge field: the same hash-only low-degree test as the base
//! spike, but folding over an EXTENSION FIELD (F_p² or F_p⁴) with proof-of-work grinding, so it can target
//! real (conjectured) post-quantum soundness instead of the demo's ~40 bits.
//!
//! Why an extension field: a fold challenge β drawn from the base field F_p (Goldilocks, ~2⁶⁴) caps the
//! commit-phase soundness at ≈ n/|F| ≈ 2²³/2⁶⁴ = 2⁻⁴¹ classical / ≈2⁻²⁰ under Grover - broken by a quantum
//! prover. F_p² (≈2¹²⁸) lifts that to ≈2⁻¹⁰⁵ classical / ≈2⁻⁵² quantum; F_p⁴ (≈2²⁵⁶) to ≈2⁻²³³/≈2⁻¹¹⁶, a
//! clean ≥100-bit *quantum* margin. See SECURITY.md. Hash-only + field arithmetic ⇒ post-quantum.
//!
//! The FRI control flow below is field-generic (trait `Fx`); F_p² and F_p⁴ share the exact same proven logic.
extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use blake2b_ref::Blake2bBuilder;
use crate::{add, sub, mul, inv, pow, GEN, root_of_unity, eval_on_coset, Transcript, leading_zero_bits};

// =====================================================================================================
// byte cursor (shared by de)
// =====================================================================================================
pub struct Cur<'a> { b: &'a [u8], p: usize }
impl<'a> Cur<'a> {
    fn u32(&mut self) -> u32 { let v = u32::from_le_bytes(self.b[self.p..self.p+4].try_into().unwrap()); self.p += 4; v }
    fn u64(&mut self) -> u64 { let v = u64::from_le_bytes(self.b[self.p..self.p+8].try_into().unwrap()); self.p += 8; v }
    fn h32(&mut self) -> [u8; 32] { let mut o = [0u8; 32]; o.copy_from_slice(&self.b[self.p..self.p+32]); self.p += 32; o }
    /// borrow `k` bytes from the buffer without copying (zero-copy path reads)
    fn take(&mut self, k: usize) -> &'a [u8] { let s = &self.b[self.p..self.p + k]; self.p += k; s }
}

// =====================================================================================================
// Fx - the abstract challenge field the FRI folds over
// =====================================================================================================
pub trait Fx: Copy + PartialEq {
    fn zero() -> Self;
    fn from_base(x: u64) -> Self;
    fn fadd(self, o: Self) -> Self;
    fn fsub(self, o: Self) -> Self;
    fn fmul(self, o: Self) -> Self;
    fn finv(self) -> Self;
    fn scale(self, s: u64) -> Self;              // base · self
    fn write(self, o: &mut Vec<u8>);             // little-endian limbs (serialization + leaf hashing)
    fn read(c: &mut Cur) -> Self;
    fn challenge(tr: &mut Transcript) -> Self;   // sample from the transcript
}

// =====================================================================================================
// F_p² = F_p[X]/(X² − 7)  (7 is a non-residue, as in Plonky2)
// =====================================================================================================
pub const W: u64 = 7;
pub type F2 = (u64, u64);
#[inline(always)] pub fn e_add(a: F2, b: F2) -> F2 { (add(a.0, b.0), add(a.1, b.1)) }
#[inline(always)] pub fn e_sub(a: F2, b: F2) -> F2 { (sub(a.0, b.0), sub(a.1, b.1)) }
#[inline(always)] pub fn e_mul(a: F2, b: F2) -> F2 {
    (add(mul(a.0, b.0), mul(W, mul(a.1, b.1))), add(mul(a.0, b.1), mul(a.1, b.0)))
}
#[inline(always)] pub fn e_scale(s: u64, a: F2) -> F2 { (mul(s, a.0), mul(s, a.1)) }
#[inline(always)] pub fn e_inv(a: F2) -> F2 {
    let n = inv(sub(mul(a.0, a.0), mul(W, mul(a.1, a.1))));
    (mul(a.0, n), mul(sub(0, a.1), n))
}
/// Exponentiation in F_p² (used to certify 7 / V are non-residues).
pub fn e_pow(mut a: F2, mut e: u128) -> F2 {
    let mut r = (1u64, 0u64);
    while e > 0 { if e & 1 == 1 { r = e_mul(r, a); } a = e_mul(a, a); e >>= 1; }
    r
}
impl Fx for F2 {
    #[inline(always)] fn zero() -> Self { (0, 0) }
    #[inline(always)] fn from_base(x: u64) -> Self { (x, 0) }
    #[inline(always)] fn fadd(self, o: Self) -> Self { e_add(self, o) }
    #[inline(always)] fn fsub(self, o: Self) -> Self { e_sub(self, o) }
    #[inline(always)] fn fmul(self, o: Self) -> Self { e_mul(self, o) }
    #[inline(always)] fn finv(self) -> Self { e_inv(self) }
    #[inline(always)] fn scale(self, s: u64) -> Self { e_scale(s, self) }
    fn write(self, o: &mut Vec<u8>) { o.extend_from_slice(&self.0.to_le_bytes()); o.extend_from_slice(&self.1.to_le_bytes()); }
    fn read(c: &mut Cur) -> Self { (c.u64(), c.u64()) }
    fn challenge(tr: &mut Transcript) -> Self { (tr.challenge_field(), tr.challenge_field()) }
}

// =====================================================================================================
// F_p⁴ = F_p²[Y]/(Y² − V), tower over F_p², V a non-residue in F_p²  (element a + b·Y, a,b ∈ F_p²)
// =====================================================================================================
pub const V: F2 = (0, 1); // V = X (a square root of 7); certified a non-residue in F_p² by the host test
pub type F4 = (F2, F2);
#[inline(always)] fn q_add(a: F4, b: F4) -> F4 { (e_add(a.0, b.0), e_add(a.1, b.1)) }
#[inline(always)] fn q_sub(a: F4, b: F4) -> F4 { (e_sub(a.0, b.0), e_sub(a.1, b.1)) }
#[inline(always)] fn q_mul(a: F4, b: F4) -> F4 {
    // (a0+a1Y)(b0+b1Y) = (a0b0 + V·a1b1) + (a0b1 + a1b0)Y
    (e_add(e_mul(a.0, b.0), e_mul(V, e_mul(a.1, b.1))), e_add(e_mul(a.0, b.1), e_mul(a.1, b.0)))
}
#[inline(always)] fn q_inv(a: F4) -> F4 {
    // norm to F_p²: N = a0² − V·a1²; inv = (a0·N⁻¹, −a1·N⁻¹)
    let n = e_inv(e_sub(e_mul(a.0, a.0), e_mul(V, e_mul(a.1, a.1))));
    (e_mul(a.0, n), e_mul(e_sub((0, 0), a.1), n))
}
impl Fx for F4 {
    #[inline(always)] fn zero() -> Self { ((0, 0), (0, 0)) }
    #[inline(always)] fn from_base(x: u64) -> Self { ((x, 0), (0, 0)) }
    #[inline(always)] fn fadd(self, o: Self) -> Self { q_add(self, o) }
    #[inline(always)] fn fsub(self, o: Self) -> Self { q_sub(self, o) }
    #[inline(always)] fn fmul(self, o: Self) -> Self { q_mul(self, o) }
    #[inline(always)] fn finv(self) -> Self { q_inv(self) }
    #[inline(always)] fn scale(self, s: u64) -> Self { (e_scale(s, self.0), e_scale(s, self.1)) }
    fn write(self, o: &mut Vec<u8>) { self.0.write(o); self.1.write(o); }
    fn read(c: &mut Cur) -> Self { (<F2 as Fx>::read(c), <F2 as Fx>::read(c)) }
    fn challenge(tr: &mut Transcript) -> Self { (<F2 as Fx>::challenge(tr), <F2 as Fx>::challenge(tr)) }
}

// =====================================================================================================
// Merkle over Fx leaves
// =====================================================================================================
fn leaf<T: Fx>(v: T) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(64);
    v.write(&mut bytes);
    let mut h = Blake2bBuilder::new(32).build();
    h.update(&bytes);
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}
fn node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).build();
    h.update(a); h.update(b);
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}
struct XMerkle { nodes: Vec<[u8; 32]>, n: usize }
impl XMerkle {
    fn build<T: Fx>(vals: &[T]) -> XMerkle {
        let n = vals.len();
        let mut nodes = vec![[0u8; 32]; 2 * n];
        for i in 0..n { nodes[n + i] = leaf(vals[i]); }
        for i in (1..n).rev() { nodes[i] = node(&nodes[2 * i], &nodes[2 * i + 1]); }
        XMerkle { nodes, n }
    }
    fn root(&self) -> [u8; 32] { self.nodes[1] }
    fn path(&self, idx: usize) -> Vec<[u8; 32]> {
        let mut p = Vec::new();
        let mut i = self.n + idx;
        while i > 1 { p.push(self.nodes[i ^ 1]); i >>= 1; }
        p
    }
}
fn verify_path<T: Fx>(root: &[u8; 32], n: usize, mut idx: usize, val: T, path: &[[u8; 32]]) -> bool {
    let mut h = leaf(val);
    for sib in path {
        h = if idx & 1 == 0 { node(&h, sib) } else { node(sib, &h) };
        idx >>= 1;
    }
    n.is_power_of_two() && &h == root
}

// =====================================================================================================
// proof structure (generic)
// =====================================================================================================
pub struct EQueryLayer<T> { pub v_lo: T, pub v_hi: T, pub path_lo: Vec<[u8; 32]>, pub path_hi: Vec<[u8; 32]> }
pub struct EQuery<T> { pub layers: Vec<EQueryLayer<T>> }
pub struct EProofG<T> {
    pub log_n: u32, pub n_folds: u32, pub num_queries: u32, pub pow_bits: u32, pub pow_nonce: u64,
    pub roots: Vec<[u8; 32]>, pub final_coeffs: Vec<T>, pub queries: Vec<EQuery<T>>,
}

pub fn ser<T: Fx>(p: &EProofG<T>) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&p.log_n.to_le_bytes());
    o.extend_from_slice(&p.n_folds.to_le_bytes());
    o.extend_from_slice(&p.num_queries.to_le_bytes());
    o.extend_from_slice(&p.pow_bits.to_le_bytes());
    o.extend_from_slice(&p.pow_nonce.to_le_bytes());
    o.extend_from_slice(&(p.roots.len() as u32).to_le_bytes());
    for r in &p.roots { o.extend_from_slice(r); }
    o.extend_from_slice(&(p.final_coeffs.len() as u32).to_le_bytes());
    for c in &p.final_coeffs { c.write(&mut o); }
    o.extend_from_slice(&(p.queries.len() as u32).to_le_bytes());
    for q in &p.queries {
        o.extend_from_slice(&(q.layers.len() as u32).to_le_bytes());
        for l in &q.layers {
            l.v_lo.write(&mut o); l.v_hi.write(&mut o);
            o.extend_from_slice(&(l.path_lo.len() as u32).to_le_bytes());
            for h in &l.path_lo { o.extend_from_slice(h); }
            for h in &l.path_hi { o.extend_from_slice(h); }
        }
    }
    o
}
pub fn de<T: Fx>(b: &[u8]) -> Option<EProofG<T>> {
    if b.len() < 24 { return None; }
    let mut c = Cur { b, p: 0 };
    let log_n = c.u32(); let n_folds = c.u32(); let num_queries = c.u32(); let pow_bits = c.u32();
    let pow_nonce = c.u64();
    let nr = c.u32() as usize; let mut roots = Vec::with_capacity(nr);
    for _ in 0..nr { roots.push(c.h32()); }
    let nc = c.u32() as usize; let mut final_coeffs = Vec::with_capacity(nc);
    for _ in 0..nc { final_coeffs.push(T::read(&mut c)); }
    let nq = c.u32() as usize; let mut queries = Vec::with_capacity(nq);
    for _ in 0..nq {
        let nl = c.u32() as usize; let mut layers = Vec::with_capacity(nl);
        for _ in 0..nl {
            let v_lo = T::read(&mut c); let v_hi = T::read(&mut c);
            let pl = c.u32() as usize;
            let mut path_lo = Vec::with_capacity(pl); for _ in 0..pl { path_lo.push(c.h32()); }
            let mut path_hi = Vec::with_capacity(pl); for _ in 0..pl { path_hi.push(c.h32()); }
            layers.push(EQueryLayer { v_lo, v_hi, path_lo, path_hi });
        }
        queries.push(EQuery { layers });
    }
    Some(EProofG { log_n, n_folds, num_queries, pow_bits, pow_nonce, roots, final_coeffs, queries })
}

fn put_final<T: Fx>(tr: &mut Transcript, c: T) { let mut b = Vec::new(); c.write(&mut b); tr.observe(&b); }

// naive O(m²) interpolation of Fx evaluations on the base coset (only the tiny final layer)
fn interpolate_final<T: Fx>(ev: &[T], shift: u64, omega: u64) -> Vec<T> {
    let m = ev.len();
    let inv_omega = inv(omega); let inv_m = inv(m as u64); let inv_shift = inv(shift);
    let mut out = vec![T::zero(); m];
    for i in 0..m {
        let mut acc = T::zero();
        let mut w = 1u64; let step = pow(inv_omega, i as u64);
        for j in 0..m { acc = acc.fadd(ev[j].scale(w)); w = mul(w, step); }
        out[i] = acc.scale(inv_m).scale(pow(inv_shift, i as u64));
    }
    out
}
fn horner<T: Fx>(coeffs: &[T], x: u64) -> T {
    let mut acc = T::zero();
    for &c in coeffs.iter().rev() { acc = acc.scale(x).fadd(c); }
    acc
}

// =====================================================================================================
// generic prove / verify
// =====================================================================================================
pub fn prove<T: Fx>(log_n: u32, n_folds: u32, coeffs: &[u64], pow_bits: u32, num_queries: usize) -> EProofG<T> {
    prove_seeded::<T>(&[], log_n, n_folds, coeffs, pow_bits, num_queries)
}

/// Like `prove`, but the Fiat–Shamir transcript is first seeded with `seed` (a public statement). The
/// resulting proof is cryptographically BOUND to that statement: a verifier seeding the same `seed` accepts;
/// any other statement derives different challenges/positions and rejects. This is how a checkpoint proof is
/// tied to the exact (epoch, chain_root, total_difficulty) it attests.
pub fn prove_seeded<T: Fx>(seed: &[u8], log_n: u32, n_folds: u32, coeffs: &[u64], pow_bits: u32, num_queries: usize) -> EProofG<T> {
    let mut tr = Transcript::new();
    if !seed.is_empty() { tr.observe(seed); }
    prove_fri::<T>(&mut tr, log_n, n_folds, coeffs, pow_bits, num_queries).0
}

/// The extension-field FRI prover threaded on a caller-supplied transcript (already seeded as the caller
/// wishes), returning the proof and the query positions. A STARK shares its transcript with this so its
/// composition polynomial is FRI-tested with the same quantum-secure params (F_p⁴ challenges + grinding).
pub fn prove_fri<T: Fx>(tr: &mut Transcript, log_n: u32, n_folds: u32, coeffs: &[u64], pow_bits: u32, num_queries: usize) -> (EProofG<T>, Vec<usize>) {
    let n = 1usize << log_n;
    let omega0 = root_of_unity(log_n);
    let inv2 = inv(2);

    let mut ev: Vec<T> = eval_on_coset(coeffs, GEN, omega0, n).into_iter().map(T::from_base).collect();
    let mut trees: Vec<XMerkle> = Vec::new();
    let mut codewords: Vec<Vec<T>> = Vec::new();
    let mut roots: Vec<[u8; 32]> = Vec::new();
    let mut shift_l = GEN; let mut omega_l = omega0;

    let mut betas: Vec<T> = Vec::new();
    for _l in 0..(n_folds as usize) {
        let t = XMerkle::build(&ev);
        let r = t.root();
        roots.push(r); trees.push(t); codewords.push(ev.clone());
        tr.observe(&r);
        let beta = T::challenge(tr); betas.push(beta);
        let m = ev.len(); let half = m >> 1;
        let mut nev = vec![T::zero(); half];
        let mut x = shift_l;
        for i in 0..half {
            let e0 = ev[i]; let e1 = ev[i + half];
            let even = e0.fadd(e1).scale(inv2);
            let odd = e0.fsub(e1).scale(inv(add(x, x)));
            nev[i] = even.fadd(beta.fmul(odd));
            x = mul(x, omega_l);
        }
        ev = nev;
        shift_l = mul(shift_l, shift_l);
        omega_l = mul(omega_l, omega_l);
    }
    let final_size = ev.len();
    let full = interpolate_final(&ev, shift_l, omega_l);
    let final_coeffs: Vec<T> = full[0..final_size / 2].to_vec();
    for c in &final_coeffs { put_final(tr, *c); }

    let mut pow_nonce = 0u64;
    if pow_bits > 0 {
        while leading_zero_bits(&tr.grind(pow_nonce)) < pow_bits { pow_nonce += 1; }
    }
    tr.observe(&pow_nonce.to_le_bytes());

    let mut positions = Vec::with_capacity(num_queries);
    for _ in 0..num_queries { positions.push(tr.challenge_index(n)); }
    let mut queries = Vec::with_capacity(num_queries);
    for &p0 in &positions {
        let mut cur_pos = p0;
        let mut layers = Vec::with_capacity(n_folds as usize);
        for l in 0..(n_folds as usize) {
            let m = n >> l; let half = m >> 1;
            let lo = cur_pos % half; let hi = lo + half;
            layers.push(EQueryLayer {
                v_lo: codewords[l][lo], v_hi: codewords[l][hi],
                path_lo: trees[l].path(lo), path_hi: trees[l].path(hi),
            });
            cur_pos = lo;
        }
        queries.push(EQuery { layers });
    }
    (EProofG { log_n, n_folds, num_queries: num_queries as u32, pow_bits, pow_nonce, roots, final_coeffs, queries }, positions)
}

pub fn verify<T: Fx>(p: &EProofG<T>) -> bool {
    let mut tr = Transcript::new();
    verify_fri::<T>(&mut tr, p).is_some()
}

/// The extension-field FRI verifier threaded on a caller-supplied transcript (already seeded). Returns
/// `Some(positions)` iff the proof is a valid low-degree proof - the STARK then re-derives its composition at
/// those positions from the layer-0 openings (`p.queries[*].layers[0]`).
pub fn verify_fri<T: Fx>(tr: &mut Transcript, p: &EProofG<T>) -> Option<Vec<usize>> {
    let log_n = p.log_n;
    let n = 1usize << log_n;
    let n_folds = p.n_folds as usize;
    let nq = p.num_queries as usize;
    if p.roots.len() != n_folds || p.queries.len() != nq { return None; }

    let mut betas: Vec<T> = Vec::with_capacity(n_folds);
    for l in 0..n_folds { tr.observe(&p.roots[l]); betas.push(T::challenge(tr)); }
    for c in &p.final_coeffs { put_final(tr, *c); }

    if p.pow_bits > 0 && leading_zero_bits(&tr.grind(p.pow_nonce)) < p.pow_bits { return None; }
    tr.observe(&p.pow_nonce.to_le_bytes());

    let mut positions = Vec::with_capacity(nq);
    for _ in 0..nq { positions.push(tr.challenge_index(n)); }

    let omega0 = root_of_unity(log_n);
    for (qi, q) in p.queries.iter().enumerate() {
        if q.layers.len() != n_folds { return None; }
        let mut cur_pos = positions[qi];
        let mut prev: Option<(T, T, u64, T)> = None;
        let mut shift_l = GEN; let mut omega_l = omega0;
        for l in 0..n_folds {
            let m = n >> l; let half = m >> 1;
            let lo = cur_pos % half; let hi = lo + half;
            let ql = &q.layers[l];
            if !verify_path(&p.roots[l], m, lo, ql.v_lo, &ql.path_lo) { return None; }
            if !verify_path(&p.roots[l], m, hi, ql.v_hi, &ql.path_hi) { return None; }
            let v_cur = if cur_pos < half { ql.v_lo } else { ql.v_hi };
            if let Some((plo, phi, px, pbeta)) = prev {
                // inversion-free fold check: 2·x·v_cur == x·(e0+e1) + β·(e0−e1)
                let lhs = v_cur.scale(add(px, px));
                let rhs = plo.fadd(phi).scale(px).fadd(pbeta.fmul(plo.fsub(phi)));
                if lhs != rhs { return None; }
            }
            let x = mul(shift_l, pow(omega_l, lo as u64));
            prev = Some((ql.v_lo, ql.v_hi, x, betas[l]));
            cur_pos = lo;
            shift_l = mul(shift_l, shift_l);
            omega_l = mul(omega_l, omega_l);
        }
        let x_final = mul(shift_l, pow(omega_l, cur_pos as u64));
        let v_final = horner(&p.final_coeffs, x_final);
        let (plo, phi, px, pbeta) = prev.unwrap();
        let lhs = v_final.scale(add(px, px));
        let rhs = plo.fadd(phi).scale(px).fadd(pbeta.fmul(plo.fsub(phi)));
        if lhs != rhs { return None; }
    }
    Some(positions)
}

// =====================================================================================================
// concrete instantiations: F_p² (ext) and F_p⁴ (quartic). Stable names for host/ckbvm.
// =====================================================================================================
pub type EProof = EProofG<F2>;
pub fn prove_ext(log_n: u32, n_folds: u32, coeffs: &[u64], pow_bits: u32, num_queries: usize) -> EProof {
    prove::<F2>(log_n, n_folds, coeffs, pow_bits, num_queries)
}
pub fn verify_ext(p: &EProof) -> bool { verify::<F2>(p) }
pub fn ser_ext(p: &EProof) -> Vec<u8> { ser::<F2>(p) }
pub fn de_ext(b: &[u8]) -> Option<EProof> { de::<F2>(b) }

pub type QProof = EProofG<F4>;
pub fn prove_q(log_n: u32, n_folds: u32, coeffs: &[u64], pow_bits: u32, num_queries: usize) -> QProof {
    prove::<F4>(log_n, n_folds, coeffs, pow_bits, num_queries)
}
pub fn verify_q(p: &QProof) -> bool { verify::<F4>(p) }
pub fn ser_q(p: &QProof) -> Vec<u8> { ser::<F4>(p) }
pub fn de_q(b: &[u8]) -> Option<QProof> { de::<F4>(b) }

// =====================================================================================================
// ZERO-COPY verify: verify straight from the serialized byte buffer, reading Merkle paths as slices into
// the buffer instead of copying them into owned Vecs. Paths are ~95% of the proof, so this cuts peak memory
// from ~2× (buffer + deserialized structure) to ~1× the proof size - what lets the production-domain proof
// fit CKB-VM's 4 MB. Same transcript/soundness as `verify`; only the memory profile differs.
// =====================================================================================================
fn verify_path_bytes<T: Fx>(root: &[u8; 32], n: usize, mut idx: usize, val: T, path: &[u8]) -> bool {
    if !n.is_power_of_two() || path.len() % 32 != 0 { return false; }
    let mut h = leaf(val);
    let mut i = 0;
    while i < path.len() {
        let sib: &[u8; 32] = path[i..i + 32].try_into().unwrap();
        h = if idx & 1 == 0 { node(&h, sib) } else { node(sib, &h) };
        idx >>= 1; i += 32;
    }
    &h == root
}

pub fn verify_zc<T: Fx>(b: &[u8]) -> bool { verify_zc_seeded::<T>(&[], b) }

/// Zero-copy verify, with the transcript first seeded by `seed` (the public statement the proof is bound to).
pub fn verify_zc_seeded<T: Fx>(seed: &[u8], b: &[u8]) -> bool {
    if b.len() < 24 { return false; }
    let mut c = Cur { b, p: 0 };
    let log_n = c.u32(); let n_folds = c.u32() as usize; let num_queries = c.u32() as usize;
    let pow_bits = c.u32(); let pow_nonce = c.u64();
    let n = 1usize << log_n;
    let nr = c.u32() as usize; if nr != n_folds { return false; }
    let mut roots = Vec::with_capacity(n_folds);          // tiny: n_folds × 32 B
    for _ in 0..n_folds { roots.push(c.h32()); }
    let ncoef = c.u32() as usize;
    let mut final_coeffs = Vec::with_capacity(ncoef);     // tiny: final layer
    for _ in 0..ncoef { final_coeffs.push(T::read(&mut c)); }

    // transcript (identical to `verify`, but seeded with the statement first)
    let mut tr = Transcript::new();
    if !seed.is_empty() { tr.observe(seed); }
    let mut betas: Vec<T> = Vec::with_capacity(n_folds);
    for l in 0..n_folds { tr.observe(&roots[l]); betas.push(T::challenge(&mut tr)); }
    for cf in &final_coeffs { put_final(&mut tr, *cf); }
    if pow_bits > 0 && leading_zero_bits(&tr.grind(pow_nonce)) < pow_bits { return false; }
    tr.observe(&pow_nonce.to_le_bytes());
    let mut positions = Vec::with_capacity(num_queries);
    for _ in 0..num_queries { positions.push(tr.challenge_index(n)); }

    let nq = c.u32() as usize; if nq != num_queries { return false; }
    let omega0 = root_of_unity(log_n);
    for qi in 0..num_queries {
        let nl = c.u32() as usize; if nl != n_folds { return false; }
        let mut cur_pos = positions[qi];
        let mut prev: Option<(T, T, u64, T)> = None;
        let mut shift_l = GEN; let mut omega_l = omega0;
        for l in 0..n_folds {
            let m = n >> l; let half = m >> 1;
            let lo = cur_pos % half; let hi = lo + half;
            let v_lo = T::read(&mut c); let v_hi = T::read(&mut c);
            let pl = c.u32() as usize;
            let path_lo = c.take(pl * 32);                // borrowed - no copy
            let path_hi = c.take(pl * 32);
            if !verify_path_bytes(&roots[l], m, lo, v_lo, path_lo) { return false; }
            if !verify_path_bytes(&roots[l], m, hi, v_hi, path_hi) { return false; }
            let v_cur = if cur_pos < half { v_lo } else { v_hi };
            if let Some((plo, phi, px, pbeta)) = prev {
                let lhs = v_cur.scale(add(px, px));
                let rhs = plo.fadd(phi).scale(px).fadd(pbeta.fmul(plo.fsub(phi)));
                if lhs != rhs { return false; }
            }
            let x = mul(shift_l, pow(omega_l, lo as u64));
            prev = Some((v_lo, v_hi, x, betas[l]));
            cur_pos = lo;
            shift_l = mul(shift_l, shift_l);
            omega_l = mul(omega_l, omega_l);
        }
        let x_final = mul(shift_l, pow(omega_l, cur_pos as u64));
        let v_final = horner(&final_coeffs, x_final);
        let (plo, phi, px, pbeta) = prev.unwrap();
        let lhs = v_final.scale(add(px, px));
        let rhs = plo.fadd(phi).scale(px).fadd(pbeta.fmul(plo.fsub(phi)));
        if lhs != rhs { return false; }
    }
    true
}
pub fn verify_q_zc(b: &[u8]) -> bool { verify_zc::<F4>(b) }
pub fn verify_ext_zc(b: &[u8]) -> bool { verify_zc::<F2>(b) }

// statement-bound (checkpoint) variants: the proof is tied to `seed` (the checkpoint it attests)
pub fn prove_q_seeded(seed: &[u8], log_n: u32, n_folds: u32, coeffs: &[u64], pow_bits: u32, num_queries: usize) -> QProof {
    prove_seeded::<F4>(seed, log_n, n_folds, coeffs, pow_bits, num_queries)
}
pub fn verify_q_zc_seeded(seed: &[u8], b: &[u8]) -> bool { verify_zc_seeded::<F4>(seed, b) }
