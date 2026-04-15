# Post-quantum strategy for the Chiral binding protocol

> Where PQ is *achievable*, where it is *blocked*, and the one move that buys PQ + trusted-setup-removal at
> once. Written to avoid the central trap: a PQ **proof** is not the same as PQ **security**.

## 0. The trap: PQ proof ≠ PQ security

A FRI/STARK proof system is post-quantum (it is hash-based — no pairings, no discrete log). But a proof only
inherits the security of **what it proves**. STARK-Mithril (the `sp1/m2all` prototype) wraps Mithril's BLS
check in a FRI proof: the *verification* becomes hash-only, but the *statement* is still "these BLS
signatures are valid." A quantum adversary forges the BLS signatures (Shor), then honestly STARK-proves the
forged verification. The hash wrapper is PQ; the security is still BLS.

**Rule:** a bridge can never be more post-quantum than the consensus/attestation crypto it bridges. So the
question is never "can we STARK it" — it is "which cryptographic link is the weakest, and do we control it."

## 1. Every cryptographic link, classified

| # | link | primitive | PQ? | who controls |
|---|---|---|---|---|
| L1 | binding: single-use seal + commitment `blake2b(state‖seal)` | hash | ✅ PQ | bridge |
| L2 | **forward source**: CKB **Eaglesong PoW** + header-MMR | hash | ✅ PQ-friendly (Grover = only quadratic) | CKB consensus |
| L3 | forward proof of CKB consensus (R1–R4 + advance) | Groth16 / BLS12-381 | ❌ Shor | **bridge** |
| L4 | forward on-chain verify (Cardano) | BLS12-381 pairing builtin | ❌ Shor | Cardano budget |
| L5 | **reverse source**: Cardano **Praos** (VRF/KES/Ed25519) | EC | ❌ Shor | **external** |
| L6 | reverse oracle: **Mithril** aggregate cert | BLS12-381 STM | ❌ Shor | external (Mithril) |
| L7 | reverse on-chain verify (CKB-VM): `cert-verify` | BLS pairings in-VM | ❌ Shor | bridge |
| L8 | reverse proof option: STARK-Mithril (`sp1/m2all`) | FRI (hash) over an L6 statement | ⚠️ PQ verify, **not** PQ security | bridge |

Note L1 (the binding itself) is **already PQ** — blake2b + single-use seals. The PQ problem is entirely in
the **oracles** (L3–L8), not the construction.

## 2. The two legs split cleanly

**Reverse (Cardano→CKB) is PQ-blocked at the source.** L5 (Praos) and L6 (Mithril) are BLS/Ed25519 and
**external** — the bridge cannot replace Cardano's own consensus crypto. STARK-Mithril (L8) upgrades L7 from
"BLS pairings in-VM" to "hash-only FRI verify" — a real *verification* improvement (and a cost/PQ-readiness
win) — but the *security* stays pinned to L6's BLS. **Verdict: reverse-leg PQ security is impossible until
Cardano/Mithril themselves ship PQ.** Mark it so; do not chase it.

**Forward (CKB→Cardano) is the PQ-meaningful leg.** Its source L2 (Eaglesong PoW) is already the most
PQ-friendly consensus there is, and L1 is hash-based. The only non-PQ links are **L3 (the proof) and L4 (the
on-chain verify) — both controlled by the bridge or by Cardano's budget.** So this is the leg where aiming at
PQ actually moves security, not just verification.

## 3. The move: a transparent FRI proof of CKB consensus

Replace L3 (Groth16) with a **transparent FRI/STARK** proof of the Eaglesong-PoW consensus circuit. This is
the rare change that hits two goals at once:

1. **Trusted-setup removal** — FRI is transparent (no SRS, no toxic waste). This *is* the `#4` setup-removal
   goal (see `PLONK_SETUP_REMOVAL.md`); PQ and setup-removal are the **same move** here.
2. **PQ soundness of the consensus proof** — hash-based, so L3 becomes Shor-resistant. Combined with L1 (PQ
   binding) and L2 (PQ source), the entire **off-chain** half of the forward leg is post-quantum.

And it **reuses the SP1 prototype**: `sp1/m2all` already proves hash+BLS relations in a FRI STARK; pointing
SP1 at the CKB-consensus circuit (Eaglesong + MMR + CBMT inclusion — all hash-based, already gadget-built in
`circuit/`) is the natural next guest program.

## 4. The residual: L4 (Cardano on-chain verify)

The one link the move does **not** fix is L4. Plutus can verify a *pairing* (BLS builtin) in budget but
**cannot** verify FRI directly: no Poseidon2 builtin, blake2b is too expensive at FRI's volume (10⁴–10⁵
hashes), and small-field arithmetic is emulated in bignums. Any on-chain wrap that fits Plutus today is
pairing-based (Groth16/PLONK over BLS) — and therefore **not PQ**. So:

- **Honest maximum today:** everything the bridge controls is PQ (L1, L3 off-chain); the **last mile (L4) is
  a named, isolated residual.** It retires the day Cardano ships a hash-proof-friendly primitive (a Poseidon
  builtin, a cheaper hash, or a native STARK verifier). This is "PQ-ready with one documented last mile" —
  defensible, not PQ theater.
- If a wrap is used for L4 (SP1→Groth16/PLONK), prefer it because the wrap circuit is **fixed and
  application-independent** → its setup is one public ceremony, reused forever (no per-circuit toxic waste).
  Snag: SP1's wrap is BN254; Cardano has only BLS12-381 builtins → needs a **BLS12-381 wrap** (one-time,
  app-independent). See `PLONK_SETUP_REMOVAL.md §3`.

## 5. Where a PQ verifier *can* run in budget: CKB-VM

CKB-VM is RISC-V with a multi-billion-cycle budget — FRI's hashes + small-field arithmetic are native ops, no
pairing builtin required. So **CKB-VM can host a hash-only (PQ) verifier**, where Plutus cannot. Two payoffs:

- It lets the reverse leg (L7) drop in-VM BLS pairings for a FRI verify (PQ *verification*; security still L6).
- It is the natural home of any future PoW→CKB PQ bridge (a PQ source verified PQ-ly end-to-end).

The keystone measurement (`spike/pq-fri-ckbvm/`) establishes the on-chain-in-CKB-VM cost of a FRI verify from
measured primitives — the PQ analogue of the "Groth16 fits Plutus at 22.7%" keystone that de-risked the
forward leg originally. **Realized:** `spike/pq-fri-verify/` is a real hash-only, setup-free (post-quantum)
verifier that **runs in CKB-VM** — and now goes beyond a low-degree test to a full **STARK** that verifies an
actual computation:
- **FRI low-degree test:** valid accepted at **46.8 M measured cycles** (n=2¹³, 40 queries), tampered rejected.
- **STARK (boundary + transition constraints → composition poly → FRI):** a real computation verified at
  **46.5 M cycles** — the *same cost class* as the LDT (the AIR layer adds field arithmetic, not a new cost
  class; hashing dominates), invalid computations rejected. ≈1.3 % of a CKB block at this size.
- **Security-grade params (`core::ext` + `SECURITY.md`):** the demo's 40 queries / base-field challenges are
  not security-grade. The verifier now adds **extension-field fold challenges** (removes the base-field
  commit-phase quantum cap), **proof-of-work grinding**, and **secure query counts** — implemented generically
  over the field for both **F_p²** (96 q, ~115-bit classical) and **F_p⁴** (100 q + 24-bit PoW, a clean
  **≥100-bit *quantum* commit-phase margin**), each adversarially tested 6/6. Measured in CKB-VM: F_p²
  **112.7 M** / F_p⁴ **119.1 M cycles (~3.4 % of a block)** — the quantum-margin upgrade is **+6 M cycles,
  nearly free**, since Merkle hashing dominates. A **zero-copy verifier** (`verify_zc`,
  reads Merkle paths as slices into the proof buffer instead of copying) then **fits the real production
  domain n=2²² in CKB-VM's 4 MB and verifies in 333 M cycles (~9.5 % of a block)** — measured, not
  extrapolated. Finally, it runs **as a real CKB lock script with the proof carried in a transaction witness**
  (`quartic_witness` + `scripts/gen_tx.py`, under a ckb-debugger mock tx): valid accepted / tampered rejected,
  production n=2²² accepted at 333.7 M cycles — the full on-chain deployment shape. The only soundness residual
  is a conservative query-phase quantum factor (a ~2× query dial). See `SECURITY.md`.
- **Integrated as the checkpoint acceptance rule (`INTEGRATION.md`):** `checkpoint_main.rs` is a CKB **type
  script** on the checkpoint cell (same 48-byte `epoch‖chain_root‖total_difficulty` state as `advance-cert`)
  that **replaces the BLS Mithril cert with a checkpoint-bound post-quantum proof.** The proof is tied to the
  exact new state by seeding the Fiat–Shamir transcript with it (`prove_q_seeded`/`verify_q_zc_seeded`).
  Demonstrated under a ckb-debugger advance transaction: accepts only when the new checkpoint is strictly
  heavier (`out_total > in_total`), epoch-monotone, and carries a valid bound proof; rejects a lighter chain
  (22), a non-monotone epoch (21), and a tampered datum (20, the binding catches it). The PQ verifier is now
  the acceptance gate, end to end.
- **The proof attests the REAL transition (`core::consensus` + `checkpoint_consensus`):** a two-column STARK
  AIR proves the genuine cumulative-difficulty transition `acc(i+1)=acc(i)+work(i)`, `acc(0)=total_old`,
  `acc(nt-1)=total_new` — the heaviest-chain quantity itself, not a placeholder. The upgraded checkpoint gate
  verifies it **and** requires `proof.total_old==in_total && proof.total_new==out_total`, so the checkpoint
  advances only when a STARK proves the new total_difficulty is the correct cumulative sum from the old one,
  bound to this checkpoint. Demonstrated end-to-end (52.9 M cycles): valid accepted; totals mismatch (23),
  tampered datum (20), lighter chain (22) rejected. Per-block **PoW validity + chain_root MMR** are hashing,
  hence the zkVM's job — proved for real in `sp1-ckb`; this AIR is the difficulty-accounting layer that
  composes with it. See `INTEGRATION.md`.
- **Composed: quantum-secure AND real-statement, one gate (`checkpoint_consensus_q`):** the difficulty AIR's
  composition polynomial is FRI-tested over the **quartic F_p⁴** (grinding + 100 queries) — the FRI engine is
  shared (`ext::prove_fri`/`verify_fri`), only field/params differ. A single 625 KB proof carries the
  ≥100-bit-quantum-margin security *and* the genuine `total_difficulty`-transition statement; the checkpoint
  script enforces both (totals-match + binding + heaviest-chain + epoch). Demonstrated end-to-end at 133.6 M
  cycles (valid accepted; totals mismatch 23 / tampered datum 20 / lighter 22 rejected). Every mechanism in
  the spike, composed into the actual checkpoint acceptance rule.
- **Cardano leg — measured infeasible by the same approach (`PLUTUS_PQ_COST.md`):** Plutus has no general VM
  and accelerates only BLS12-381 (the non-PQ primitive). Benchmarked (v3): a blake2b Merkle-node hash ≈964 K
  cpu-steps / 2,916 mem; a Goldilocks mul ≈951 K / 3,107 — so only ~4,800 hashes fit one tx's 14 M memory cap,
  while the weakest demo FRI verifier needs ~7,200 (≈1.9× over), a quantum-secure one ~5×, production ~14×.
  **The hash-STARK verifier does not fit a Plutus tx**; closing the Cardano side needs PQ-friendly builtins or
  PQ signatures at the Cardano protocol level, above the bridge. **So the CKB leg's verifier is post-quantum
  and demonstrated; the Cardano leg's cannot be by the same approach today — neither leg is end-to-end
  quantum-resistant** (each also roots in the chains' classical Ed25519/secp256k1/BLS signatures).
- **Prover runs on commodity hardware:** the FRI/STARK prover (now NTT-based, O(n log n)) proves at the
  production **2²³** domain in **~16 s / 1.2 GB** on a 15 GB box — the "≥32 GB" caveat was the SP1 Groth16
  *wrap* (the non-PQ outer SNARK we don't want), not the PQ core-STARK prover.

**Production prover, realized:** `spike/sp1-ckb/` generates a real **SP1 v6 core-STARK proof of a
CKB-consensus kernel** (PoW header-chain: parent linkage + proof-of-work + cumulative difficulty → tip +
`total_work`) and **verifies it**, end-to-end on this 15 GB / 4-core box — 32 blocks in 57 s / 10 GB,
256 blocks (1.5 M cycles) in 95 s / 13 GB, **no Groth16 wrap** (hash-based ⇒ post-quantum). An invalid chain
is unprovable (the verifier rejects the non-zero exit). This retires the "≥32 GB-gated" caveat: that figure
was the non-PQ Groth16 wrapping, not the PQ core proof.

So **both halves now run on commodity hardware**: a post-quantum verifier in CKB-VM (`pq-fri-verify`), and a
production prover of CKB-relevant statements (`sp1-ckb`).

**On-chain SP1 verification — costed and measured (`spike/sp1-verify-cost/`).** The last integration is
verifying an SP1 *compressed* proof on-chain (the PQ STARK, not the non-PQ Groth16 wrap). SP1 is over
KoalaBear+Poseidon2 while `pq-fri-verify` is Goldilocks+blake2b, so this needs SP1's verifier in CKB-VM.
Rather than do the full port, we measured the two deciding quantities directly:
- **Per-permutation cost:** Poseidon2-KoalaBear = **26,157 CKB-VM cycles**, ≈4× a blake2b compress (faithful
  port, ckb-debugger).
- **Permutations per verify:** instrumenting SP1's *actual* permutation (a `[patch.crates-io]` copy of
  `p3-poseidon2` with a counter) shows an SP1 core-proof verify performs **86,291 Poseidon2 permutations**,
  essentially constant per shard (86,844 at 256 blocks).

So a native SP1 verify in CKB-VM is **≈2.3 G cycles — roughly a whole CKB block, ~30–50× our own
Goldilocks+blake2b STARK verifier (47 M).** (The *compressed* proof's exact count couldn't be measured — the
recursion prover OOMs at >15 GB here — but its verify is the same kind/order, ~0.3–2.6 G cycles.) This
**corrects an earlier optimistic ~10⁸ model by an order of magnitude.** Takeaway: the post-quantum on-chain
path is decisively the **in-house Goldilocks+blake2b stack** (`pq-fri-verify`); SP1 is for *proving*
off-chain, re-proven into the lighter on-chain system if one pipeline is wanted. No research risk remains on
the forward leg — only this now-measured engineering choice.

## 6. Build order

1. **(done)** classify links (this doc) + genesis pins on both legs (`TESTNET_LOG §I.1/§K`). L1 is PQ.
2. **keystone (this session):** measure a FRI verify's cost in CKB-VM from real primitives → confirm a PQ
   verifier fits CKB-VM's budget (and compare to the current BLS `cert-verify`).
3. **forward PQ off-chain:** SP1 guest = the CKB-consensus circuit; prove as a FRI STARK (needs a ≥32 GB or
   network prover — the box here is 15 GB). Removes the trusted setup *and* makes L3 PQ.
4. **L4 last mile:** either keep an explicit pairing wrap (documented residual) or pursue a BLS12-381
   app-independent wrap; retire entirely if/when Cardano gains a hash-proof primitive.
5. **reverse leg:** mark PQ-blocked (L5/L6 external); optionally adopt STARK-Mithril for PQ *verification* +
   constant-size proofs when a prover box is available.

## 7. One-line posture

> The binding is PQ; the forward source (CKB PoW) is PQ; making the forward proof a transparent FRI makes the
> off-chain forward leg PQ **and** setup-free in one move. The sole residual is Cardano's on-chain pairing
> verify (budget-forced), isolated and documented. The reverse leg is PQ-blocked by Cardano's own crypto and
> is marked, not chased.
