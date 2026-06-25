//! A real two-column STARK AIR for the bridge's CONSENSUS quantity: cumulative difficulty (the heaviest-chain
//! metric). It proves the actual `total_difficulty` transition a checkpoint advance asserts -
//!
//!   acc(0) = total_old ;  acc(i+1) = acc(i) + work(i) ;  acc(nt-1) = total_new
//!
//! - over a trace of `nt` blocks with two columns `acc` (running cumulative work) and `work` (per-block work).
//! Unlike the placeholder low-degree test, the proof attests the genuine difficulty accumulation: tamper
//! `total_new`, the accumulation, or any work, and a constraint quotient stops being a polynomial ⇒ the
//! composition polynomial is high-degree ⇒ FRI rejects. Hash-only (blake2b) + Goldilocks ⇒ post-quantum.
//!
//! Scope (see INTEGRATION.md): an AIR can faithfully encode this *arithmetic* of consensus. Per-block work
//! *validity* (Eaglesong PoW meeting target, parent linkage, MMR chain_root) is hashing, which is the zkVM's
//! job - proved for real in `spike/sp1-ckb` (SP1 header-chain). This AIR is the difficulty-accounting layer
//! that composes with it. It binds to a checkpoint via the seeded transcript (`*_seeded`), exactly like the
//! quartic FRI gate; combining this AIR with the quartic-extension FRI yields the full quantum-secure,
//! real-statement, checkpoint-bound gate.
extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use crate::{add, sub, mul, inv, pow, GEN, root_of_unity, eval_on_coset, interpolate_coset,
            Merkle, verify_path, Transcript, Proof, prove_inner, verify_inner, NUM_QUERIES};

/// CP(x) = α0·(acc−total_old)/(x−1) + α1·(acc−total_new)/(x−g_last)
///       + α2·(acc(gx) − acc(x) − work(x))·(x−g_last)/(x^{nt}−1).  Used identically by prover and verifier.
fn comp(x: u64, ax: u64, agx: u64, wx: u64, told: u64, tnew: u64, g_last: u64, nt: usize, a: &[u64; 3]) -> u64 {
    let qb = mul(sub(ax, told), inv(sub(x, 1)));
    let qr = mul(sub(ax, tnew), inv(sub(x, g_last)));
    let zt_inv = mul(sub(x, g_last), inv(sub(pow(x, nt as u64), 1)));
    let qt = mul(sub(sub(agx, ax), wx), zt_inv);
    add(add(mul(a[0], qb), mul(a[1], qr)), mul(a[2], qt))
}

pub struct Open { pub v: u64, pub path: Vec<[u8; 32]> }
pub struct CumQuery {
    pub a_lo: Open, pub a_lo_s: Open, pub a_hi: Open, pub a_hi_s: Open, // acc at lo, lo+bw, hi, hi+bw
    pub w_lo: Open, pub w_hi: Open,                                      // work at lo, hi
}
pub struct CumProof {
    pub log_t: u32, pub log_n: u32,
    pub total_old: u64, pub total_new: u64,
    pub root_a: [u8; 32], pub root_w: [u8; 32],
    pub fri: Proof,
    pub queries: Vec<CumQuery>,
}

fn transcript(tr: &mut Transcript, seed: &[u8], log_t: u32, log_n: u32, told: u64, tnew: u64,
              root_a: &[u8; 32], root_w: &[u8; 32]) {
    if !seed.is_empty() { tr.observe(seed); }
    tr.observe(&log_t.to_le_bytes()); tr.observe(&log_n.to_le_bytes());
    tr.observe(&told.to_le_bytes()); tr.observe(&tnew.to_le_bytes());
    tr.observe(root_a); tr.observe(root_w);
}

/// Prove cumulative difficulty `total_old → total_new` over `works` (nt−1 per-block works). Returns the proof
/// (whose public statement is `total_old`, `total_new`). `seed` binds the proof to a checkpoint (empty = none).
pub fn prove_cum_seeded(seed: &[u8], log_t: u32, log_n: u32, total_old: u64, works: &[u64]) -> CumProof {
    let nt = 1usize << log_t;
    let mut a = vec![0u64; nt];
    let mut w = vec![0u64; nt];
    a[0] = total_old;
    for i in 0..nt - 1 { w[i] = works[i]; a[i + 1] = add(a[i], works[i]); }
    // w[nt-1] is only referenced by the (excluded) last-row transition; leave 0.
    prove_cum_trace_seeded(seed, log_t, log_n, total_old, a[nt - 1], &a, &w)
}

/// Prove explicit (acc, work) traces satisfy the statement. With honest traces the constraints hold and the
/// composition is low-degree; tampering makes a quotient non-polynomial ⇒ high-degree CP ⇒ verifier rejects.
pub fn prove_cum_trace_seeded(seed: &[u8], log_t: u32, log_n: u32, total_old: u64, total_new: u64,
                              a_trace: &[u64], w_trace: &[u64]) -> CumProof {
    let nt = 1usize << log_t;
    let n = 1usize << log_n;
    let blowup = n / nt;
    let g = root_of_unity(log_t);
    let omega = root_of_unity(log_n);
    let g_last = inv(g);

    let fa = eval_on_coset(&interpolate_coset(a_trace, 1, g), GEN, omega, n);
    let fw = eval_on_coset(&interpolate_coset(w_trace, 1, g), GEN, omega, n);
    let tree_a = Merkle::build(&fa); let root_a = tree_a.root();
    let tree_w = Merkle::build(&fw); let root_w = tree_w.root();

    let mut tr = Transcript::new();
    transcript(&mut tr, seed, log_t, log_n, total_old, total_new, &root_a, &root_w);
    let alpha = [tr.challenge_field(), tr.challenge_field(), tr.challenge_field()];

    let mut cp = vec![0u64; n];
    let mut x = GEN;
    for j in 0..n {
        cp[j] = comp(x, fa[j], fa[(j + blowup) % n], fw[j], total_old, total_new, g_last, nt, &alpha);
        x = mul(x, omega);
    }
    let n_folds = log_n - 4;
    let (fri, positions) = prove_inner(&mut tr, log_n, n_folds, &interpolate_coset(&cp, GEN, omega));

    let half = n >> 1;
    let oa = |i: usize| Open { v: fa[i], path: tree_a.path(i) };
    let ow = |i: usize| Open { v: fw[i], path: tree_w.path(i) };
    let mut queries = Vec::with_capacity(positions.len());
    for &p0 in &positions {
        let lo = p0 % half; let hi = lo + half;
        queries.push(CumQuery {
            a_lo: oa(lo), a_lo_s: oa((lo + blowup) % n), a_hi: oa(hi), a_hi_s: oa((hi + blowup) % n),
            w_lo: ow(lo), w_hi: ow(hi),
        });
    }
    CumProof { log_t, log_n, total_old, total_new, root_a, root_w, fri, queries }
}

pub fn prove_cum(log_t: u32, log_n: u32, total_old: u64, works: &[u64]) -> CumProof {
    prove_cum_seeded(&[], log_t, log_n, total_old, works)
}

pub fn verify_cum(p: &CumProof) -> bool { verify_cum_seeded(&[], p) }

/// Verify the cumulative-difficulty STARK, with the transcript optionally seeded by `seed` (the checkpoint).
pub fn verify_cum_seeded(seed: &[u8], p: &CumProof) -> bool {
    let nt = 1usize << p.log_t;
    let n = 1usize << p.log_n;
    if p.fri.log_n != p.log_n { return false; }
    if p.fri.queries.len() != NUM_QUERIES || p.queries.len() != NUM_QUERIES { return false; }
    let blowup = n / nt;
    let g = root_of_unity(p.log_t);
    let omega = root_of_unity(p.log_n);
    let g_last = inv(g);

    let mut tr = Transcript::new();
    transcript(&mut tr, seed, p.log_t, p.log_n, p.total_old, p.total_new, &p.root_a, &p.root_w);
    let alpha = [tr.challenge_field(), tr.challenge_field(), tr.challenge_field()];

    let positions = match verify_inner(&mut tr, &p.fri) { Some(ps) => ps, None => return false };
    let half = n >> 1;
    for (qi, &p0) in positions.iter().enumerate() {
        let lo = p0 % half; let hi = lo + half;
        let q = &p.queries[qi];
        // acc openings vs root_a, work openings vs root_w
        if !verify_path(&p.root_a, n, lo, q.a_lo.v, &q.a_lo.path) { return false; }
        if !verify_path(&p.root_a, n, (lo + blowup) % n, q.a_lo_s.v, &q.a_lo_s.path) { return false; }
        if !verify_path(&p.root_a, n, hi, q.a_hi.v, &q.a_hi.path) { return false; }
        if !verify_path(&p.root_a, n, (hi + blowup) % n, q.a_hi_s.v, &q.a_hi_s.path) { return false; }
        if !verify_path(&p.root_w, n, lo, q.w_lo.v, &q.w_lo.path) { return false; }
        if !verify_path(&p.root_w, n, hi, q.w_hi.v, &q.w_hi.path) { return false; }
        // recompute the composition from the opened trace values; must equal the FRI-committed CP value
        let x_lo = mul(GEN, pow(omega, lo as u64));
        let x_hi = mul(GEN, pow(omega, hi as u64));
        let cp_lo = p.fri.queries[qi].layers[0].v_lo;
        let cp_hi = p.fri.queries[qi].layers[0].v_hi;
        if comp(x_lo, q.a_lo.v, q.a_lo_s.v, q.w_lo.v, p.total_old, p.total_new, g_last, nt, &alpha) != cp_lo { return false; }
        if comp(x_hi, q.a_hi.v, q.a_hi_s.v, q.w_hi.v, p.total_old, p.total_new, g_last, nt, &alpha) != cp_hi { return false; }
    }
    true
}

// ---- serialization ----
fn put_open(o: &mut Vec<u8>, op: &Open) {
    o.extend_from_slice(&op.v.to_le_bytes());
    o.extend_from_slice(&(op.path.len() as u32).to_le_bytes());
    for h in &op.path { o.extend_from_slice(h); }
}
pub fn ser_cum(p: &CumProof) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&p.log_t.to_le_bytes()); o.extend_from_slice(&p.log_n.to_le_bytes());
    o.extend_from_slice(&p.total_old.to_le_bytes()); o.extend_from_slice(&p.total_new.to_le_bytes());
    o.extend_from_slice(&p.root_a); o.extend_from_slice(&p.root_w);
    let fri = crate::ser(&p.fri);
    o.extend_from_slice(&(fri.len() as u32).to_le_bytes()); o.extend_from_slice(&fri);
    o.extend_from_slice(&(p.queries.len() as u32).to_le_bytes());
    for q in &p.queries {
        put_open(&mut o, &q.a_lo); put_open(&mut o, &q.a_lo_s); put_open(&mut o, &q.a_hi);
        put_open(&mut o, &q.a_hi_s); put_open(&mut o, &q.w_lo); put_open(&mut o, &q.w_hi);
    }
    o
}
struct Cur<'a> { b: &'a [u8], p: usize }
impl<'a> Cur<'a> {
    fn u32(&mut self) -> u32 { let v = u32::from_le_bytes(self.b[self.p..self.p+4].try_into().unwrap()); self.p += 4; v }
    fn u64(&mut self) -> u64 { let v = u64::from_le_bytes(self.b[self.p..self.p+8].try_into().unwrap()); self.p += 8; v }
    fn h32(&mut self) -> [u8; 32] { let mut o = [0u8; 32]; o.copy_from_slice(&self.b[self.p..self.p+32]); self.p += 32; o }
    fn open(&mut self) -> Open {
        let v = self.u64(); let pl = self.u32() as usize;
        let mut path = Vec::with_capacity(pl); for _ in 0..pl { path.push(self.h32()); }
        Open { v, path }
    }
}
// =====================================================================================================
// COMPOSED gate: the cumulative-difficulty AIR with its composition polynomial FRI-tested over the QUARTIC
// extension F_p⁴ (grinding + secure queries) - quantum-secure params AND the real consensus statement, both.
// The trace (acc, work) stays base-field; only the FRI on CP runs over F_p⁴ (CP is embedded as (CP,0), so the
// layer-0 openings are (CP[i], 0): the verifier checks the base part equals the recomputed composition and the
// extension part is zero). The STARK shares its transcript with ext::prove_fri/verify_fri::<F4>.
// =====================================================================================================
use crate::ext::{self, F4, prove_fri, verify_fri};

pub struct CumProofQ {
    pub log_t: u32, pub log_n: u32, pub total_old: u64, pub total_new: u64,
    pub root_a: [u8; 32], pub root_w: [u8; 32],
    pub fri: ext::QProof,            // F_p⁴ FRI on the composition polynomial
    pub queries: Vec<CumQuery>,      // base-field trace openings (parallel to fri.queries)
}

pub fn prove_cum_q_seeded(seed: &[u8], log_t: u32, log_n: u32, total_old: u64, works: &[u64],
                          pow_bits: u32, num_queries: usize) -> CumProofQ {
    let nt = 1usize << log_t;
    let n = 1usize << log_n;
    let blowup = n / nt;
    let g = root_of_unity(log_t); let omega = root_of_unity(log_n); let g_last = inv(g);

    let mut a = vec![0u64; nt]; let mut w = vec![0u64; nt];
    a[0] = total_old;
    for i in 0..nt - 1 { w[i] = works[i]; a[i + 1] = add(a[i], works[i]); }
    let total_new = a[nt - 1];

    let fa = eval_on_coset(&interpolate_coset(&a, 1, g), GEN, omega, n);
    let fw = eval_on_coset(&interpolate_coset(&w, 1, g), GEN, omega, n);
    let tree_a = Merkle::build(&fa); let root_a = tree_a.root();
    let tree_w = Merkle::build(&fw); let root_w = tree_w.root();

    let mut tr = Transcript::new();
    transcript(&mut tr, seed, log_t, log_n, total_old, total_new, &root_a, &root_w);
    let alpha = [tr.challenge_field(), tr.challenge_field(), tr.challenge_field()];

    let mut cp = vec![0u64; n];
    let mut x = GEN;
    for j in 0..n {
        cp[j] = comp(x, fa[j], fa[(j + blowup) % n], fw[j], total_old, total_new, g_last, nt, &alpha);
        x = mul(x, omega);
    }
    let n_folds = log_n - 4;
    let (fri, positions) = prove_fri::<F4>(&mut tr, log_n, n_folds, &interpolate_coset(&cp, GEN, omega), pow_bits, num_queries);

    let half = n >> 1;
    let oa = |i: usize| Open { v: fa[i], path: tree_a.path(i) };
    let ow = |i: usize| Open { v: fw[i], path: tree_w.path(i) };
    let mut queries = Vec::with_capacity(positions.len());
    for &p0 in &positions {
        let lo = p0 % half; let hi = lo + half;
        queries.push(CumQuery {
            a_lo: oa(lo), a_lo_s: oa((lo + blowup) % n), a_hi: oa(hi), a_hi_s: oa((hi + blowup) % n),
            w_lo: ow(lo), w_hi: ow(hi),
        });
    }
    CumProofQ { log_t, log_n, total_old, total_new, root_a, root_w, fri, queries }
}

pub fn verify_cum_q_seeded(seed: &[u8], p: &CumProofQ) -> bool {
    let nt = 1usize << p.log_t;
    let n = 1usize << p.log_n;
    if p.fri.log_n != p.log_n { return false; }
    let nq = p.fri.num_queries as usize;
    if p.queries.len() != nq || p.fri.queries.len() != nq { return false; }
    let blowup = n / nt;
    let g = root_of_unity(p.log_t); let omega = root_of_unity(p.log_n); let g_last = inv(g);

    let mut tr = Transcript::new();
    transcript(&mut tr, seed, p.log_t, p.log_n, p.total_old, p.total_new, &p.root_a, &p.root_w);
    let alpha = [tr.challenge_field(), tr.challenge_field(), tr.challenge_field()];

    let positions = match verify_fri::<F4>(&mut tr, &p.fri) { Some(ps) => ps, None => return false };
    let half = n >> 1;
    for (qi, &p0) in positions.iter().enumerate() {
        let lo = p0 % half; let hi = lo + half;
        let q = &p.queries[qi];
        if !verify_path(&p.root_a, n, lo, q.a_lo.v, &q.a_lo.path) { return false; }
        if !verify_path(&p.root_a, n, (lo + blowup) % n, q.a_lo_s.v, &q.a_lo_s.path) { return false; }
        if !verify_path(&p.root_a, n, hi, q.a_hi.v, &q.a_hi.path) { return false; }
        if !verify_path(&p.root_a, n, (hi + blowup) % n, q.a_hi_s.v, &q.a_hi_s.path) { return false; }
        if !verify_path(&p.root_w, n, lo, q.w_lo.v, &q.w_lo.path) { return false; }
        if !verify_path(&p.root_w, n, hi, q.w_hi.v, &q.w_hi.path) { return false; }
        let x_lo = mul(GEN, pow(omega, lo as u64));
        let x_hi = mul(GEN, pow(omega, hi as u64));
        // layer-0 CP values are F_p⁴ = (CP, 0): base part must equal the recomputed composition, ext part 0
        let cp_lo = p.fri.queries[qi].layers[0].v_lo;
        let cp_hi = p.fri.queries[qi].layers[0].v_hi;
        if cp_lo.1 != (0, 0) || cp_hi.1 != (0, 0) { return false; }
        if comp(x_lo, q.a_lo.v, q.a_lo_s.v, q.w_lo.v, p.total_old, p.total_new, g_last, nt, &alpha) != cp_lo.0 .0 { return false; }
        if comp(x_hi, q.a_hi.v, q.a_hi_s.v, q.w_hi.v, p.total_old, p.total_new, g_last, nt, &alpha) != cp_hi.0 .0 { return false; }
    }
    true
}

// CumProofQ (de)serialization (reuses ext::ser/de for the F_p⁴ sub-proof)
pub fn ser_cum_q(p: &CumProofQ) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&p.log_t.to_le_bytes()); o.extend_from_slice(&p.log_n.to_le_bytes());
    o.extend_from_slice(&p.total_old.to_le_bytes()); o.extend_from_slice(&p.total_new.to_le_bytes());
    o.extend_from_slice(&p.root_a); o.extend_from_slice(&p.root_w);
    let fri = ext::ser::<F4>(&p.fri);
    o.extend_from_slice(&(fri.len() as u32).to_le_bytes()); o.extend_from_slice(&fri);
    o.extend_from_slice(&(p.queries.len() as u32).to_le_bytes());
    for q in &p.queries {
        put_open(&mut o, &q.a_lo); put_open(&mut o, &q.a_lo_s); put_open(&mut o, &q.a_hi);
        put_open(&mut o, &q.a_hi_s); put_open(&mut o, &q.w_lo); put_open(&mut o, &q.w_hi);
    }
    o
}
pub fn de_cum_q(b: &[u8]) -> Option<CumProofQ> {
    if b.len() < 84 { return None; }
    let mut c = Cur { b, p: 0 };
    let log_t = c.u32(); let log_n = c.u32();
    let total_old = c.u64(); let total_new = c.u64();
    let root_a = c.h32(); let root_w = c.h32();
    let flen = c.u32() as usize;
    let fri = ext::de::<F4>(&b[c.p..c.p + flen])?; c.p += flen;
    let nq = c.u32() as usize;
    let mut queries = Vec::with_capacity(nq);
    for _ in 0..nq {
        queries.push(CumQuery {
            a_lo: c.open(), a_lo_s: c.open(), a_hi: c.open(), a_hi_s: c.open(),
            w_lo: c.open(), w_hi: c.open(),
        });
    }
    Some(CumProofQ { log_t, log_n, total_old, total_new, root_a, root_w, fri, queries })
}

pub fn de_cum(b: &[u8]) -> Option<CumProof> {
    if b.len() < 84 { return None; }
    let mut c = Cur { b, p: 0 };
    let log_t = c.u32(); let log_n = c.u32();
    let total_old = c.u64(); let total_new = c.u64();
    let root_a = c.h32(); let root_w = c.h32();
    let flen = c.u32() as usize;
    let fri = crate::de(&b[c.p..c.p + flen])?; c.p += flen;
    let nq = c.u32() as usize;
    let mut queries = Vec::with_capacity(nq);
    for _ in 0..nq {
        queries.push(CumQuery {
            a_lo: c.open(), a_lo_s: c.open(), a_hi: c.open(), a_hi_s: c.open(),
            w_lo: c.open(), w_hi: c.open(),
        });
    }
    Some(CumProof { log_t, log_n, total_old, total_new, root_a, root_w, fri, queries })
}
