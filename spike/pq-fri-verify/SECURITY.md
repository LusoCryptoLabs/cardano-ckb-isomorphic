# Post-quantum soundness: from a 40-query demo to security-grade parameters

The base spike (`core::{prove,verify}`, 40 queries, base-field fold challenges) demonstrates the *machinery*
of a hash-only, setup-free verifier — but its *parameters* are demo-grade (~40-bit soundness, and a
catastrophic base-field cap, below). `core::ext` (`prove_ext`/`verify_ext`) adds the two mechanisms needed for
real, conjectured post-quantum security, and we measure their cost in CKB-VM:

1. **Extension-field fold challenges** (β ∈ F_p², |F| ≈ 2¹²⁸) — removes the base-field commit-phase cap.
2. **Proof-of-work grinding** (`pow_bits`) — raises the cost of grinding-the-transcript attacks (incl. Grover).
3. **More queries** (96 vs 40) — raises query-phase soundness.

This is hash-only (blake2b) + Goldilocks/F_p² arithmetic — no pairings, no trusted setup. Its security rests
only on the hash (random-oracle / QROM) and FRI proximity, none of which Shor breaks; that is what "post-
quantum" means here, in the same conjectural sense as NIST PQC and production STARKs (ethSTARK, Plonky2/3,
RISC0, SP1).

## The three soundness components (conjectured, ethSTARK-style)

Rate ρ = ½ (blowup 2). Field F_p, p = 2⁶⁴−2³²+1; extension F_p² = F_p[X]/(X²−7) (7 is a non-residue — the
verifier `assert`s `7^((p−1)/2) = −1`). Domain size n. Digest = blake2b-256.

| component | error (classical, conjectured) | at our params (n=2¹³, Q=96, pow=20) | production (n=2²³) |
|---|---|---|---|
| **query phase** | ρ^Q = 2^−Q | 2^−96 | 2^−96 |
| **grinding** | 2^−pow | 2^−20 | 2^−20 |
| **commit phase** (FRI folding, proximity gaps) | ≈ n / \|F_challenge\| | 2¹³/2¹²⁸ = **2^−115** | 2²³/2¹²⁸ = **2^−105** |
| hash collision | 2^−128 | 2^−128 | 2^−128 |

Total classical soundness ≈ **2^−115** (query+grind = 2^−116; commit = 2^−115) — i.e. **~115-bit conjectured
classical soundness**, vs the demo's ~40 bits.

### Why the extension field is not optional

With **base-field** challenges (β ∈ F_p, |F| ≈ 2⁶⁴) the commit-phase error is n/2⁶⁴: **2^−51** here, **2^−41**
at production n=2²³. A cheating prover grinds the commitment to land β in the bad set; classically ~2⁴¹ work,
and **under Grover ~2²⁰·⁵ — trivially broken by a quantum adversary.** Drawing β from F_p² lifts this to
2^−105…2^−115 (≈2^−52 even under a full Grover square-root), removing the cap. This is the qualitative fix; the
`ext` module's `E3` test (perturbing only the *extension limb* of the final polynomial → rejected) confirms
the F_p² arithmetic is load-bearing.

## Quantum accounting (honest) — and the quartic F_p⁴ configuration

- **Hashes:** blake2b-256 gives quantum preimage 2¹²⁸ (Grover) and collision ≥ 2⁸⁵ (BHT, QRAM-heavy) to 2¹²⁸
  (realistic) — at or above a 100-bit target.
- **Commit phase:** with F_p², ~2^−105 classical ⇒ ≳ 2^−52 under a full Grover speedup at n=2²³ — strong, but
  short of a 100-bit *quantum* floor. **F_p⁴ (≈2²⁵⁶) fixes this: ~2^−233 classical / ~2^−116 quantum.** We
  implemented this (`core::ext::F4`, a degree-2 tower F_p²[Y]/(Y²−V), V certified a non-residue) — see the
  measured quartic row below.
- **Query + grinding:** classically Q + pow (100 + 24 = 124 bits in the quartic config). Grover square-roots
  the *grinding-the-transcript* search; under the conservative full-Grover reading a uniform 100-bit *quantum*
  floor on this component wants ~Q≈180 + pow≈48 (≈2× bits) — a linear cost dial (below). Under the standard
  view (query repetition is not a simple unstructured search) 100 queries already give a wide margin.

**Bottom line:** F_p⁴ + 100 queries + 24-bit PoW gives **~124-bit conjectured classical** soundness with a
**≥100-bit *quantum* commit-phase margin** and ≥100-bit hash margin; the only conservative caveat is the
query-phase quantum factor, which is a pure ~2× query dial. Exact QROM bounds for Fiat–Shamir STARKs are
conjectural across the whole field; we target the same level as production systems (ethSTARK/Plonky3/SP1).

## Measured cost in CKB-VM (ckb-debugger, `--mode full`, riscv64imac)

`ext_verify` embeds a real `prove_ext` proof (n=2¹³, 9 folds, **96 queries, F_p², 20-bit PoW**):

| configuration | result | cycles | proof size | host battery |
|---|---|---|---|---|
| 40-query base demo (reference) | accept | 46.8 M | 215 KB | 7/7 |
| **F_p² , 96 q, 20-bit PoW** (`ext_verify`) | accept (0) | **112.7 M** | 529 KB | 6/6 |
| F_p² tampered | reject (20) | 3.6 M | — | |
| **F_p⁴ , 144 q, 24-bit PoW** (`quartic_verify`, ≥100-bit quantum margin) | accept (0) | **171.3 M** | 836 KB | 6/6 |
| F_p⁴ tampered | reject (20) | 4.2 M | — | |

**The quantum-margin upgrade is nearly free on-chain.** Going from F_p² to the quartic F_p⁴ configuration —
the one that gives a clean ≥100-bit *quantum* commit-phase margin — costs only **+6 M cycles (112.7 → 119.1 M,
≈3.4 % of a ~3.5×10⁹-cycle CKB block)**, because Merkle hashing dominates the verify and the path count is
set by the query count (≈100), not the extension degree; the heavier F_p⁴ field arithmetic is a small share.
Both host batteries are **6/6** (valid accepted; tampered leaf / tampered root / tampered top-limb final poly
/ wrong PoW nonce / high-degree codeword all rejected). The `quartic` Q3 case perturbs the *top* F_p⁴ limb and
is rejected, confirming the full quartic arithmetic is load-bearing.

## Scaling to the production domain (measured + extrapolated)

All the rows above are at the demo domain n=2¹³. The real CKB-consensus LDE domain is ~2²². Cost is dominated
by Merkle hashing, which scales with `queries × Σ(layer path depths)` — i.e. ~linearly in log n. Measured for
the quartic config (100 q, 24-bit PoW):

| domain n | quartic verify (owned) | quartic verify (zero-copy) | proof size | heap |
|---|---|---|---|---|
| 2¹³ (demo) | 119.1 M | 116.2 M | 581 KB | 64 KB (zc) / 2 MB (owned) |
| 2¹⁸ | 229.3 M | — | 1.13 MB | 2 MB (owned) |
| **2²² (production LDE)** | *(>4 MB — does not fit, owned)* | **333.1 M** | 1.68 MB | **64 KB (zc) — fits** |

So a **security-grade, quantum-margin verifier at the real production circuit size costs ~333 M cycles
(~9.5 % of a CKB block) and fits CKB-VM's 4 MB** — with the proof (~1.7 MB) as the larger practical cost (it
is witness data on-chain). Measured 333 M matches the linear extrapolation (~342 M), confirming the model.

### The on-chain memory wall — surfaced, then solved (zero-copy)

CKB-VM has **4 MB total memory** (code + rodata + heap + stack). The *owned* verifier (`verify`/`de`) needs a
heap well above ckb-std's 516 KB default — n=2¹⁸ already required **2 MB** for the deserialized proof — and
with the proof both embedded (rodata) *and* deserialized (heap) it **hits the 4 MB wall around n ≈ 2²⁰–2²²**,
i.e. right at production scale.

**Solved by `verify_zc` (`core::ext`):** verify straight from the proof byte-buffer, reading Merkle paths as
*slices into the buffer* instead of copying them into owned `Vec`s. Paths are ~95 % of the proof, so peak
memory drops from ~2× to ~1× the proof size: the production 1.68 MB proof verifies in a **64 KB heap**, fitting
4 MB with large margin (measured above). The owned and zero-copy verifiers are cross-checked to agree
(`quartic` host battery), and zero-copy is even slightly cheaper (no deserialization copy: 116.2 M vs 119.1 M
at 2¹³). On-chain the proof comes from a transaction witness; `verify_zc` consumes that witness buffer
directly with no second copy.

- **Proof size** grows linearly with queries and log n (581 KB → 1.68 MB at production); on-chain that is
  witness data — the dominant practical cost of higher security, separate from cycles.

## The real on-chain shape — a CKB script with the proof as a transaction witness

The measurements above embed the proof in the binary. The actual deployment shape is a CKB **lock/type script**
that loads the proof from the **transaction witness** per-transaction. `quartic_witness` (`ckbvm`) does exactly
this — `load_witness(0, GroupInput)` → `verify_q_zc` — and `scripts/gen_tx.py` builds a ckb-debugger mock
transaction (the 37 KB script as a cell-dep, the proof as `witnesses[0]`). Run end-to-end:

```
python3 scripts/gen_tx.py bin/quartic_witness.bin fixtures/quartic_proof.bin > tx.json
ckb-debugger --tx-file tx.json --cell-index 0 --cell-type input --script-group-type lock
```

| case (proof supplied via witness) | result | cycles |
|---|---|---|
| valid, n=2¹³ | accept (0) | 116.5 M |
| tampered, n=2¹³ | reject (20) | 0.72 M |
| **valid, n=2²² (production)** | **accept (0)** | **333.7 M** |

So the complete deployment shape is validated: a real CKB script, the post-quantum proof carried as
witness data, loaded by syscall in a transaction context, verified zero-copy — at production domain size,
fitting CKB-VM's 4 MB, valid accepted / tampered rejected. Witness-load cost is negligible (116.5 M vs 116.2 M
embedded; 333.7 M vs 333.1 M). The production transaction is ~3.4 MB (the 1.68 MB proof dominates the witness).

## What this does and does not establish

**Does:** the post-quantum verifier mechanisms that take it from demo-grade to security-grade —
extension-field challenges (up to **F_p⁴, giving a ≥100-bit *quantum* commit-phase margin**), proof-of-work
grinding, and secure query counts — are implemented, adversarially tested (6/6 each for F_p² and F_p⁴),
**measured in CKB-VM at production domain size (333 M cycles, ~9.5 % of a block)**, and run **as a real CKB
lock script with the proof carried in a transaction witness** under a mock transaction. The base-field
quantum cap is removed; the only soundness residual is a conservative query-phase quantum factor, a pure ~2×
query dial (linear, in-budget).

**Does not:** constitute an audit or a proof of QROM soundness (no STARK has the latter unconditionally); the
on-chain shape is demonstrated under ckb-debugger's mock transaction, not deployed/audited on a live network;
and none of this makes the whole *bridge* quantum-proof — that additionally needs the verifier wired into the
actual checkpoint script, the live Groth16/BLS leg replaced, an audit, and (for true end-to-end safety) the
anchored chains' own signatures/consensus to be post-quantum (Cardano's Ed25519 is not). See
`docs/PQ_STRATEGY.md`.
