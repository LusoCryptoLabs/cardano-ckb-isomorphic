//! fri-core - a minimal but REAL FRI low-degree-test, shared by the host prover and the CKB-VM verifier.
//! Hash-only (blake2b Merkle + Fiat–Shamir), no pairings, no trusted setup ⇒ a post-quantum *verifier*.
//! The verifier is inversion-free (the fold consistency is checked by cross-multiplication), so its cost is
//! Merkle hashing + a little Goldilocks arithmetic - exactly the primitives measured in spike/pq-fri-ckbvm.
//!
//! Field: Goldilocks p = 2^64 - 2^32 + 1. Domain at layer l: a coset  shift_l · ⟨ω_l⟩  with shift_l = 7^(2^l),
//! ω_l = ω_0^(2^l), |⟨ω_l⟩| = n/2^l. The pair (i, i+half) are x and −x; squaring sends both to index i of the
//! next (squared) domain. FRI folds blowup-rate-1/2 codewords down to a low-degree final polynomial sent in
//! the clear (so the degree bound is enforced by construction - no separate degree test needed).
#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use blake2b_ref::Blake2bBuilder;

pub mod ext;
pub mod consensus;

pub const P: u64 = 0xFFFF_FFFF_0000_0001;
const EPS: u64 = 0xFFFF_FFFF; // 2^32 - 1 = 2^64 mod p
pub const GEN: u64 = 7; // multiplicative generator / coset shift

// ---------------- Goldilocks field ----------------
#[inline(always)]
pub fn add(a: u64, b: u64) -> u64 {
    let (s, c) = a.overflowing_add(b);
    let (s, c2) = s.overflowing_sub(P);
    if c ^ c2 { s.wrapping_add(P) } else { s }
}
#[inline(always)]
pub fn sub(a: u64, b: u64) -> u64 {
    let (d, borrow) = a.overflowing_sub(b);
    if borrow { d.wrapping_add(P) } else { d }
}
#[inline(always)]
fn reduce128(x: u128) -> u64 {
    // 2^64 ≡ 2^32 - 1 (mod p). Standard plonky2-style reduction.
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & EPS;
    let t0 = sub(lo, hi_hi);
    let t1 = hi_lo.wrapping_mul(EPS);
    add(t0, t1)
}
#[inline(always)]
pub fn mul(a: u64, b: u64) -> u64 {
    reduce128((a as u128) * (b as u128))
}
pub fn pow(mut a: u64, mut e: u64) -> u64 {
    let mut r = 1u64;
    while e > 0 {
        if e & 1 == 1 { r = mul(r, a); }
        a = mul(a, a);
        e >>= 1;
    }
    r
}
pub fn inv(a: u64) -> u64 { pow(a, P - 2) }

/// primitive 2^k-th root of unity (k ≤ 32).
pub fn root_of_unity(k: u32) -> u64 {
    // ω_max = 7^((p-1)/2^32) has order 2^32; square (32-k) times for order 2^k.
    let mut w = pow(GEN, (P - 1) >> 32);
    for _ in 0..(32 - k) { w = mul(w, w); }
    w
}

// ---------------- blake2b helpers ----------------
fn h2(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).build();
    h.update(a); h.update(b);
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}
fn leaf_hash(v: u64) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).build();
    h.update(&v.to_le_bytes());
    let mut o = [0u8; 32]; h.finalize(&mut o); o
}

// ---------------- Merkle tree (host: build; both: verify path) ----------------
pub struct Merkle { pub nodes: Vec<[u8; 32]>, pub n: usize } // nodes: layout [leaves..][..root], n=leaves
impl Merkle {
    pub fn build(vals: &[u64]) -> Merkle {
        let n = vals.len();
        let mut nodes = vec![[0u8; 32]; 2 * n];
        for i in 0..n { nodes[n + i] = leaf_hash(vals[i]); }
        for i in (1..n).rev() { nodes[i] = h2(&nodes[2 * i], &nodes[2 * i + 1]); }
        Merkle { nodes, n }
    }
    pub fn root(&self) -> [u8; 32] { self.nodes[1] }
    /// authentication path for leaf `idx` (bottom→top), len = log2(n).
    pub fn path(&self, idx: usize) -> Vec<[u8; 32]> {
        let mut p = Vec::new();
        let mut i = self.n + idx;
        while i > 1 { p.push(self.nodes[i ^ 1]); i >>= 1; }
        p
    }
}
/// verify that `val` sits at leaf `idx` of a tree of `n` leaves with the given path & root.
pub fn verify_path(root: &[u8; 32], n: usize, mut idx: usize, val: u64, path: &[[u8; 32]]) -> bool {
    let mut h = leaf_hash(val);
    for sib in path {
        h = if idx & 1 == 0 { h2(&h, sib) } else { h2(sib, &h) };
        idx >>= 1;
    }
    n.is_power_of_two() && &h == root
}

// ---------------- Fiat–Shamir transcript ----------------
pub struct Transcript { state: [u8; 32] }
impl Transcript {
    pub fn new() -> Transcript { Transcript { state: [0u8; 32] } }
    pub fn observe(&mut self, bytes: &[u8]) {
        let mut h = Blake2bBuilder::new(32).build();
        h.update(&self.state); h.update(bytes);
        h.finalize(&mut self.state);
    }
    fn squeeze(&mut self) -> [u8; 32] {
        let mut h = Blake2bBuilder::new(32).build();
        h.update(&self.state); h.update(b"squeeze");
        let mut o = [0u8; 32]; h.finalize(&mut o);
        self.state = o; o
    }
    pub fn challenge_field(&mut self) -> u64 {
        let o = self.squeeze();
        let mut b = [0u8; 8]; b.copy_from_slice(&o[0..8]);
        reduce128(u64::from_le_bytes(b) as u128)
    }
    pub fn challenge_index(&mut self, m: usize) -> usize {
        let o = self.squeeze();
        let mut b = [0u8; 8]; b.copy_from_slice(&o[0..8]);
        (u64::from_le_bytes(b) % (m as u64)) as usize
    }
    /// A challenge in the quadratic extension field F_p²: two independent base-field squeezes. Using
    /// extension-field fold challenges is what lifts FRI's commit-phase soundness past the base-field cap.
    pub fn challenge_ext(&mut self) -> (u64, u64) { (self.challenge_field(), self.challenge_field()) }
    /// Non-mutating proof-of-work grind: H(state ‖ "grind" ‖ nonce). The prover searches `nonce` until this
    /// has ≥ `pow_bits` leading zero bits, then folds the nonce in via `observe`; the verifier re-checks it.
    /// Grinding raises the cost of the grind-the-transcript attack (incl. its Grover speedup) on FS soundness.
    pub fn grind(&self, nonce: u64) -> [u8; 32] {
        let mut h = Blake2bBuilder::new(32).build();
        h.update(&self.state); h.update(b"grind"); h.update(&nonce.to_le_bytes());
        let mut o = [0u8; 32]; h.finalize(&mut o); o
    }
}

/// Number of leading zero bits of a 32-byte hash (big-endian bit order), for proof-of-work grinding.
pub fn leading_zero_bits(b: &[u8; 32]) -> u32 {
    let mut n = 0u32;
    for &byte in b.iter() {
        if byte == 0 { n += 8; } else { n += byte.leading_zeros(); break; }
    }
    n
}

// ---------------- Proof structure + (de)serialization ----------------
pub struct QueryLayer { pub v_lo: u64, pub v_hi: u64, pub path_lo: Vec<[u8; 32]>, pub path_hi: Vec<[u8; 32]> }
pub struct Query { pub layers: Vec<QueryLayer> }
pub struct Proof {
    pub log_n: u32,
    pub n_folds: u32,
    pub roots: Vec<[u8; 32]>,     // Merkle roots of layers 0..n_folds
    pub final_coeffs: Vec<u64>,   // the low-degree final polynomial
    pub queries: Vec<Query>,      // one per query position
}

// little-endian byte (de)serializer shared by prover & verifier
pub fn ser(p: &Proof) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&p.log_n.to_le_bytes());
    o.extend_from_slice(&p.n_folds.to_le_bytes());
    o.extend_from_slice(&(p.roots.len() as u32).to_le_bytes());
    for r in &p.roots { o.extend_from_slice(r); }
    o.extend_from_slice(&(p.final_coeffs.len() as u32).to_le_bytes());
    for c in &p.final_coeffs { o.extend_from_slice(&c.to_le_bytes()); }
    o.extend_from_slice(&(p.queries.len() as u32).to_le_bytes());
    for q in &p.queries {
        o.extend_from_slice(&(q.layers.len() as u32).to_le_bytes());
        for l in &q.layers {
            o.extend_from_slice(&l.v_lo.to_le_bytes());
            o.extend_from_slice(&l.v_hi.to_le_bytes());
            o.extend_from_slice(&(l.path_lo.len() as u32).to_le_bytes());
            for h in &l.path_lo { o.extend_from_slice(h); }
            for h in &l.path_hi { o.extend_from_slice(h); }
        }
    }
    o
}
struct Cur<'a> { b: &'a [u8], p: usize }
impl<'a> Cur<'a> {
    fn u32(&mut self) -> u32 { let v = u32::from_le_bytes(self.b[self.p..self.p+4].try_into().unwrap()); self.p += 4; v }
    fn u64(&mut self) -> u64 { let v = u64::from_le_bytes(self.b[self.p..self.p+8].try_into().unwrap()); self.p += 8; v }
    fn h32(&mut self) -> [u8; 32] { let mut o = [0u8; 32]; o.copy_from_slice(&self.b[self.p..self.p+32]); self.p += 32; o }
}
pub fn de(b: &[u8]) -> Option<Proof> {
    if b.len() < 8 { return None; }
    let mut c = Cur { b, p: 0 };
    let log_n = c.u32(); let n_folds = c.u32();
    let nr = c.u32() as usize; let mut roots = Vec::with_capacity(nr);
    for _ in 0..nr { roots.push(c.h32()); }
    let nc = c.u32() as usize; let mut final_coeffs = Vec::with_capacity(nc);
    for _ in 0..nc { final_coeffs.push(c.u64()); }
    let nq = c.u32() as usize; let mut queries = Vec::with_capacity(nq);
    for _ in 0..nq {
        let nl = c.u32() as usize; let mut layers = Vec::with_capacity(nl);
        for _ in 0..nl {
            let v_lo = c.u64(); let v_hi = c.u64();
            let pl = c.u32() as usize;
            let mut path_lo = Vec::with_capacity(pl); for _ in 0..pl { path_lo.push(c.h32()); }
            let mut path_hi = Vec::with_capacity(pl); for _ in 0..pl { path_hi.push(c.h32()); }
            layers.push(QueryLayer { v_lo, v_hi, path_lo, path_hi });
        }
        queries.push(Query { layers });
    }
    Some(Proof { log_n, n_folds, roots, final_coeffs, queries })
}

// ---------------- Verifier (the CKB-VM hot path) ----------------
/// Horner evaluation of `coeffs` (low→high) at x.
fn horner(coeffs: &[u64], x: u64) -> u64 {
    let mut acc = 0u64;
    for &c in coeffs.iter().rev() { acc = add(mul(acc, x), c); }
    acc
}
pub const NUM_QUERIES: usize = 40;

// ---------------- Prover (host side; uses inversions freely) ----------------
/// In-place radix-2 Cooley–Tukey NTT (decimation-in-time): a[j] ← Σ_i a_i·ω^{ij}, with ω a primitive
/// n-th root of unity (n a power of two). Goldilocks has 2-adicity 32, so this is exact for n ≤ 2^32.
/// O(n log n) - this is what lets the prover scale past the demo's 2^13 to the production domain.
fn ntt(a: &mut [u64], omega: u64) {
    let n = a.len();
    // bit-reversal permutation
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 { j ^= bit; bit >>= 1; }
        j |= bit;
        if i < j { a.swap(i, j); }
    }
    let mut len = 2usize;
    while len <= n {
        let wlen = pow(omega, (n / len) as u64);   // primitive len-th root
        let mut i = 0usize;
        while i < n {
            let mut w = 1u64;
            for k in 0..(len >> 1) {
                let u = a[i + k];
                let v = mul(a[i + k + (len >> 1)], w);
                a[i + k] = add(u, v);
                a[i + k + (len >> 1)] = sub(u, v);
                w = mul(w, wlen);
            }
            i += len;
        }
        len <<= 1;
    }
}

pub(crate) fn eval_on_coset(coeffs: &[u64], shift: u64, omega: u64, n: usize) -> Vec<u64> {
    // ev[j] = P(shift·ω^j) = Σ_i (c_i·shift^i)·ω^{ij}: scale coeffs by shift^i, then a single forward NTT.
    let mut a = vec![0u64; n];
    let mut s = 1u64;
    for (i, &c) in coeffs.iter().enumerate() {
        a[i] = mul(c, s);
        s = mul(s, shift);
    }
    ntt(&mut a, omega);
    a
}
pub(crate) fn interpolate_coset(ev: &[u64], shift: u64, omega: u64) -> Vec<u64> {
    // e_j = Σ_i c_i·shift^i·ω^{ij}.  d_i = (1/m)Σ_j e_j ω^{-ij};  c_i = d_i·(shift^{-1})^i.
    let m = ev.len();
    let inv_omega = inv(omega);
    let inv_m = inv(m as u64);
    let inv_shift = inv(shift);
    let mut c = vec![0u64; m];
    for i in 0..m {
        let mut acc = 0u64;
        let mut w = 1u64;                 // ω^{-i·j}, j=0..
        let step = pow(inv_omega, i as u64);
        for j in 0..m { acc = add(acc, mul(ev[j], w)); w = mul(w, step); }
        let d_i = mul(acc, inv_m);
        c[i] = mul(d_i, pow(inv_shift, i as u64));
    }
    c
}
/// Build a FRI proof that `coeffs` (len = n/2, i.e. degree < n/2, rate 1/2) is low-degree.
/// Uses a fresh transcript (the standalone low-degree-test entry point).
pub fn prove(log_n: u32, n_folds: u32, coeffs: &[u64]) -> Proof {
    let mut tr = Transcript::new();
    prove_inner(&mut tr, log_n, n_folds, coeffs).0
}

/// FRI prover threaded on a caller-supplied transcript, returning the proof and the query positions it drew.
/// The STARK reuses this: it pre-seeds `tr` with the trace commitment + constraint challenges so the FRI
/// query positions (and thus the whole proof) are bound to the trace, and so the layer-0 openings can be
/// cross-checked against the trace by the caller.
pub fn prove_inner(tr: &mut Transcript, log_n: u32, n_folds: u32, coeffs: &[u64]) -> (Proof, Vec<usize>) {
    let n = 1usize << log_n;
    let omega0 = root_of_unity(log_n);
    let inv2 = inv(2);

    // layer 0 codeword on the coset
    let mut ev = eval_on_coset(coeffs, GEN, omega0, n);
    let mut trees: Vec<Merkle> = Vec::new();
    let mut codewords: Vec<Vec<u64>> = Vec::new();
    let mut roots: Vec<[u8; 32]> = Vec::new();
    let mut shift_l = GEN; let mut omega_l = omega0;

    let mut betas: Vec<u64> = Vec::new();
    for _l in 0..(n_folds as usize) {
        let t = Merkle::build(&ev);
        let r = t.root();
        roots.push(r); trees.push(t); codewords.push(ev.clone());
        tr.observe(&r);
        let beta = tr.challenge_field(); betas.push(beta);
        // fold ev (size m) → next (size m/2)
        let m = ev.len(); let half = m >> 1;
        let mut nev = vec![0u64; half];
        let mut x = shift_l;
        for i in 0..half {
            let e0 = ev[i]; let e1 = ev[i + half];
            let even = mul(add(e0, e1), inv2);
            let odd = mul(sub(e0, e1), inv(add(x, x)));
            nev[i] = add(even, mul(beta, odd));
            x = mul(x, omega_l);
        }
        ev = nev;
        shift_l = mul(shift_l, shift_l);
        omega_l = mul(omega_l, omega_l);
    }
    // final layer `ev` (size = n >> n_folds) is low-degree: interpolate, keep the low half.
    let final_size = ev.len();
    let full = interpolate_coset(&ev, shift_l, omega_l);
    let keep = final_size / 2;
    // honest prover: full[keep..] are all zero (the folded poly is low-degree). We keep only the low half;
    // a high-degree (dishonest) input leaves nonzero high coeffs that are dropped here, which the verifier's
    // final-fold check then catches - that is exactly the LDT soundness the adversarial F5 case exercises.
    let final_coeffs: Vec<u64> = full[0..keep].to_vec();
    for c in &final_coeffs { tr.observe(&c.to_le_bytes()); }

    // queries
    let mut positions = Vec::with_capacity(NUM_QUERIES);
    for _ in 0..NUM_QUERIES { positions.push(tr.challenge_index(n)); }
    let mut queries = Vec::with_capacity(NUM_QUERIES);
    for &p0 in &positions {
        let mut cur_pos = p0;
        let mut layers = Vec::with_capacity(n_folds as usize);
        for l in 0..(n_folds as usize) {
            let m = n >> l; let half = m >> 1;
            let lo = cur_pos % half; let hi = lo + half;
            layers.push(QueryLayer {
                v_lo: codewords[l][lo],
                v_hi: codewords[l][hi],
                path_lo: trees[l].path(lo),
                path_hi: trees[l].path(hi),
            });
            cur_pos = lo;
        }
        queries.push(Query { layers });
    }
    (Proof { log_n, n_folds, roots, final_coeffs, queries }, positions)
}

/// Returns true iff `proof` is a valid FRI low-degree proof. Pure hashing + Goldilocks arithmetic.
pub fn verify(proof: &Proof) -> bool {
    let mut tr = Transcript::new();
    verify_inner(&mut tr, proof).is_some()
}

/// FRI verifier threaded on a caller-supplied transcript. Returns `Some(positions)` (the layer-0 query
/// positions) iff the proof is a valid low-degree proof, else `None`. The STARK uses the returned positions
/// (and the layer-0 openings in `proof.queries[*].layers[0]`) to bind the composition codeword to the trace.
pub fn verify_inner(tr: &mut Transcript, proof: &Proof) -> Option<Vec<usize>> {
    let log_n = proof.log_n;
    let n = 1usize << log_n;
    let n_folds = proof.n_folds as usize;
    if proof.roots.len() != n_folds { return None; }
    if proof.queries.len() != NUM_QUERIES { return None; }

    // re-derive transcript: observe each layer root, squeeze a fold challenge β_l, finally observe the
    // final polynomial; then squeeze the query positions. Must match the prover EXACTLY.
    let mut betas = Vec::with_capacity(n_folds);
    for l in 0..n_folds {
        tr.observe(&proof.roots[l]);
        betas.push(tr.challenge_field());
    }
    for c in &proof.final_coeffs { tr.observe(&c.to_le_bytes()); }
    let mut positions = Vec::with_capacity(NUM_QUERIES);
    for _ in 0..NUM_QUERIES { positions.push(tr.challenge_index(n)); }

    let omega0 = root_of_unity(log_n);
    for (qi, q) in proof.queries.iter().enumerate() {
        if q.layers.len() != n_folds { return None; }
        let mut cur_pos = positions[qi];
        // (e_lo, e_hi, x, beta) carried from the previous layer for the deferred fold check
        let mut prev: Option<(u64, u64, u64, u64)> = None;
        let mut shift_l = GEN;          // 7^(2^l)
        let mut omega_l = omega0;       // ω_0^(2^l)
        for l in 0..n_folds {
            let m = n >> l; let half = m >> 1;
            let lo = cur_pos % half; let hi = lo + half;
            let ql = &q.layers[l];
            if !verify_path(&proof.roots[l], m, lo, ql.v_lo, &ql.path_lo) { return None; }
            if !verify_path(&proof.roots[l], m, hi, ql.v_hi, &ql.path_hi) { return None; }
            // value committed at cur_pos in this layer:
            let v_cur = if cur_pos < half { ql.v_lo } else { ql.v_hi };
            if let Some((plo, phi, px, pbeta)) = prev {
                // inversion-free fold check: 2·px·v_cur == px·(plo+phi) + pbeta·(plo−phi)
                let lhs = mul(add(px, px), v_cur);
                let rhs = add(mul(px, add(plo, phi)), mul(pbeta, sub(plo, phi)));
                if lhs != rhs { return None; }
            }
            let x = mul(shift_l, pow(omega_l, lo as u64));
            prev = Some((ql.v_lo, ql.v_hi, x, betas[l]));
            cur_pos = lo;
            shift_l = mul(shift_l, shift_l);
            omega_l = mul(omega_l, omega_l);
        }
        // final layer: value from the low-degree polynomial, evaluated at the final domain point.
        let x_final = mul(shift_l, pow(omega_l, cur_pos as u64));
        let v_final = horner(&proof.final_coeffs, x_final);
        let (plo, phi, px, pbeta) = prev.unwrap();
        let lhs = mul(add(px, px), v_final);
        let rhs = add(mul(px, add(plo, phi)), mul(pbeta, sub(plo, phi)));
        if lhs != rhs { return None; }
    }
    Some(positions)
}

// ================================================================================================
// A real (minimal) STARK on top of the FRI engine - Stark101-style.
//
// Statement (public): starting from a(0)=a0, the recurrence  a(i+1) = a(i)^2 + c  over Goldilocks
// produces a(nt-1) = out, for a power-of-two trace length nt. The prover interpolates the trace into a
// polynomial f over the trace group H=⟨g⟩ (|H|=nt), low-degree-extends it onto the disjoint coset domain
// D = 7·⟨ω⟩ (|D|=N=blowup·nt), and proves three constraint quotients are polynomials (i.e. the constraints
// hold) by showing their random linear combination - the composition polynomial CP - is low-degree on D:
//
//   boundary(seed):  (f(x) - a0)        / (x - 1)              must be a polynomial
//   boundary(result):(f(x) - out)       / (x - g^{nt-1})       must be a polynomial
//   transition:      (f(g·x) - f(x)^2 - c) / ((x^{nt}-1)/(x - g^{nt-1}))   must be a polynomial
//
//   CP(x) = α0·Qbound + α1·Qresult + α2·Qtrans      (α drawn from the trace commitment via Fiat–Shamir)
//
// The verifier (the CKB-VM hot path): runs the FRI low-degree test on CP (so CP really is low-degree ⇒ the
// quotients are polynomials ⇒ the constraints hold), and at each FRI query point re-derives CP from the
// opened trace values and checks it equals the FRI-committed CP value - binding the trace to CP. Tampering
// any trace cell makes a quotient non-polynomial ⇒ CP high-degree ⇒ FRI rejects; committing an unrelated
// low-degree CP ⇒ the per-query composition check rejects. Hash-only + Goldilocks ⇒ post-quantum.

/// CP(x) = α0·(f(x)-a0)/(x-1) + α1·(f(x)-out)/(x-g_last) + α2·(f(g·x)-f(x)²-c)·(x-g_last)/(x^{nt}-1).
/// Used identically by prover (over all of D) and verifier (at the query points) so they cannot drift.
fn composition_at(x: u64, fx: u64, fgx: u64, a0: u64, c: u64, out: u64,
                  g_last: u64, nt: usize, alpha: &[u64; 3]) -> u64 {
    let qb = mul(sub(fx, a0), inv(sub(x, 1)));
    let qr = mul(sub(fx, out), inv(sub(x, g_last)));
    let zt_inv = mul(sub(x, g_last), inv(sub(pow(x, nt as u64), 1))); // 1 / ((x^{nt}-1)/(x-g_last))
    let qt = mul(sub(sub(fgx, mul(fx, fx)), c), zt_inv);
    add(add(mul(alpha[0], qb), mul(alpha[1], qr)), mul(alpha[2], qt))
}

pub struct TraceOpen { pub f: u64, pub path: Vec<[u8; 32]> }
pub struct StarkQuery { pub lo: TraceOpen, pub lo_s: TraceOpen, pub hi: TraceOpen, pub hi_s: TraceOpen }
pub struct StarkProof {
    pub log_t: u32, pub log_n: u32,        // trace length nt=2^log_t, eval domain N=2^log_n
    pub a0: u64, pub c: u64, pub out: u64,  // the public statement
    pub root_f: [u8; 32],                  // commitment to the low-degree-extended trace on D
    pub fri: Proof,                        // FRI proof that the composition polynomial CP is low-degree
    pub trace_q: Vec<StarkQuery>,          // trace openings at the FRI query points (parallel to fri.queries)
}

fn stark_transcript(tr: &mut Transcript, log_t: u32, log_n: u32, a0: u64, c: u64, out: u64, root_f: &[u8; 32]) {
    tr.observe(&log_t.to_le_bytes()); tr.observe(&log_n.to_le_bytes());
    tr.observe(&a0.to_le_bytes()); tr.observe(&c.to_le_bytes()); tr.observe(&out.to_le_bytes());
    tr.observe(root_f);
}

/// Prove that `a(i+1)=a(i)^2+c` from `a(0)=a0` reaches `out` after nt-1 steps. Returns the proof and `out`.
pub fn stark_prove(log_t: u32, log_n: u32, a0: u64, c: u64) -> (StarkProof, u64) {
    let nt = 1usize << log_t;
    let mut trace = vec![0u64; nt];
    trace[0] = a0;
    for i in 1..nt { trace[i] = add(mul(trace[i - 1], trace[i - 1]), c); }
    let out = trace[nt - 1];
    (stark_prove_trace(log_t, log_n, a0, c, out, &trace), out)
}

/// Prove an *explicit* trace satisfies the statement (a0,c,out). With an honest trace the constraints hold
/// and CP is low-degree; with a trace that violates the recurrence (or a wrong `out`), the corresponding
/// quotient is not a polynomial ⇒ CP is high-degree ⇒ the verifier's FRI test rejects. (Used by the
/// adversarial battery to forge a genuinely invalid computation.)
pub fn stark_prove_trace(log_t: u32, log_n: u32, a0: u64, c: u64, out: u64, trace: &[u64]) -> StarkProof {
    let nt = 1usize << log_t;
    let n = 1usize << log_n;
    let blowup = n / nt;
    let g = root_of_unity(log_t);          // generates the trace group H
    let omega = root_of_unity(log_n);      // generates the eval-domain group; D = 7·⟨ω⟩
    let g_last = inv(g);                   // g^{nt-1}

    let f_coeffs = interpolate_coset(trace, 1, g);         // f over H
    let fd = eval_on_coset(&f_coeffs, GEN, omega, n);      // f on D (the LDE)
    let tree_f = Merkle::build(&fd);
    let root_f = tree_f.root();

    // bind statement + trace commitment, draw the constraint-combination challenges
    let mut tr = Transcript::new();
    stark_transcript(&mut tr, log_t, log_n, a0, c, out, &root_f);
    let alpha = [tr.challenge_field(), tr.challenge_field(), tr.challenge_field()];

    // composition codeword on D, then FRI-prove it is low-degree (sharing the transcript ⇒ query positions
    // are bound to the trace, and FRI's layer-0 root is exactly the CP commitment)
    let mut cp = vec![0u64; n];
    let mut x = GEN;
    for j in 0..n {
        cp[j] = composition_at(x, fd[j], fd[(j + blowup) % n], a0, c, out, g_last, nt, &alpha);
        x = mul(x, omega);
    }
    let cp_coeffs = interpolate_coset(&cp, GEN, omega);
    let n_folds = log_n - 4;
    let (fri, positions) = prove_inner(&mut tr, log_n, n_folds, &cp_coeffs);

    // open the trace at each query point lo and hi=lo+N/2, plus their g·x shifts (index +blowup)
    let half = n >> 1;
    let topen = |idx: usize| TraceOpen { f: fd[idx], path: tree_f.path(idx) };
    let mut trace_q = Vec::with_capacity(positions.len());
    for &p0 in &positions {
        let lo = p0 % half; let hi = lo + half;
        trace_q.push(StarkQuery {
            lo: topen(lo), lo_s: topen((lo + blowup) % n),
            hi: topen(hi), hi_s: topen((hi + blowup) % n),
        });
    }
    StarkProof { log_t, log_n, a0, c, out, root_f, fri, trace_q }
}

/// Verify a STARK proof. Pure blake2b + Goldilocks ⇒ this is the post-quantum CKB-VM hot path.
pub fn stark_verify(p: &StarkProof) -> bool {
    let nt = 1usize << p.log_t;
    let n = 1usize << p.log_n;
    if p.fri.log_n != p.log_n { return false; }
    if p.fri.queries.len() != NUM_QUERIES || p.trace_q.len() != NUM_QUERIES { return false; }
    let blowup = n / nt;
    let g = root_of_unity(p.log_t);
    let omega = root_of_unity(p.log_n);
    let g_last = inv(g);

    let mut tr = Transcript::new();
    stark_transcript(&mut tr, p.log_t, p.log_n, p.a0, p.c, p.out, &p.root_f);
    let alpha = [tr.challenge_field(), tr.challenge_field(), tr.challenge_field()];

    // FRI low-degree test on CP (continues the shared transcript) ⇒ positions + "CP is low-degree"
    let positions = match verify_inner(&mut tr, &p.fri) { Some(ps) => ps, None => return false };

    let half = n >> 1;
    for (qi, &p0) in positions.iter().enumerate() {
        let lo = p0 % half; let hi = lo + half;
        let q = &p.trace_q[qi];
        // trace openings must be consistent with the committed LDE
        if !verify_path(&p.root_f, n, lo, q.lo.f, &q.lo.path) { return false; }
        if !verify_path(&p.root_f, n, (lo + blowup) % n, q.lo_s.f, &q.lo_s.path) { return false; }
        if !verify_path(&p.root_f, n, hi, q.hi.f, &q.hi.path) { return false; }
        if !verify_path(&p.root_f, n, (hi + blowup) % n, q.hi_s.f, &q.hi_s.path) { return false; }
        // composition re-derived from the trace must equal the FRI-committed CP value at lo and hi
        let cp_lo = p.fri.queries[qi].layers[0].v_lo;
        let cp_hi = p.fri.queries[qi].layers[0].v_hi;
        let x_lo = mul(GEN, pow(omega, lo as u64));
        let x_hi = mul(GEN, pow(omega, hi as u64));
        if composition_at(x_lo, q.lo.f, q.lo_s.f, p.a0, p.c, p.out, g_last, nt, &alpha) != cp_lo { return false; }
        if composition_at(x_hi, q.hi.f, q.hi_s.f, p.a0, p.c, p.out, g_last, nt, &alpha) != cp_hi { return false; }
    }
    true
}

// ---- StarkProof (de)serialization (reuses the FRI Proof codec for the embedded sub-proof) ----
fn ser_open(o: &mut Vec<u8>, t: &TraceOpen) {
    o.extend_from_slice(&t.f.to_le_bytes());
    o.extend_from_slice(&(t.path.len() as u32).to_le_bytes());
    for h in &t.path { o.extend_from_slice(h); }
}
pub fn ser_stark(p: &StarkProof) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&p.log_t.to_le_bytes());
    o.extend_from_slice(&p.log_n.to_le_bytes());
    o.extend_from_slice(&p.a0.to_le_bytes());
    o.extend_from_slice(&p.c.to_le_bytes());
    o.extend_from_slice(&p.out.to_le_bytes());
    o.extend_from_slice(&p.root_f);
    let fri = ser(&p.fri);
    o.extend_from_slice(&(fri.len() as u32).to_le_bytes());
    o.extend_from_slice(&fri);
    o.extend_from_slice(&(p.trace_q.len() as u32).to_le_bytes());
    for q in &p.trace_q { ser_open(&mut o, &q.lo); ser_open(&mut o, &q.lo_s); ser_open(&mut o, &q.hi); ser_open(&mut o, &q.hi_s); }
    o
}
impl<'a> Cur<'a> {
    fn open(&mut self) -> TraceOpen {
        let f = self.u64();
        let pl = self.u32() as usize;
        let mut path = Vec::with_capacity(pl);
        for _ in 0..pl { path.push(self.h32()); }
        TraceOpen { f, path }
    }
}
pub fn de_stark(b: &[u8]) -> Option<StarkProof> {
    if b.len() < 44 { return None; }
    let mut c = Cur { b, p: 0 };
    let log_t = c.u32(); let log_n = c.u32();
    let a0 = c.u64(); let cst = c.u64(); let out = c.u64();
    let root_f = c.h32();
    let flen = c.u32() as usize;
    let fri = de(&b[c.p..c.p + flen])?; c.p += flen;
    let nq = c.u32() as usize;
    let mut trace_q = Vec::with_capacity(nq);
    for _ in 0..nq {
        trace_q.push(StarkQuery { lo: c.open(), lo_s: c.open(), hi: c.open(), hi_s: c.open() });
    }
    Some(StarkProof { log_t, log_n, a0, c: cst, out, root_f, fri, trace_q })
}
