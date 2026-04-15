# Post-quantum bridge — complete state of the endeavour

This is the single map of the post-quantum work: what was built, what was measured, and — honestly — what is
done, what is blocked by resources, and what is not ours to close. For the design rationale see
`PQ_STRATEGY.md`; for the soundness analysis `spike/pq-fri-verify/SECURITY.md`; for the on-chain integration
`spike/pq-fri-verify/INTEGRATION.md`; for the Cardano-side verdict `spike/ckb-to-cardano/groth16/PLUTUS_PQ_COST.md`.

## Thesis

The bridge's classical security rests on pairings (Groth16/BLS) and the chains' signatures — all broken by
Shor. The post-quantum replacement is a **hash-only, transparent STARK/FRI** verifier. We set out to find
whether such a verifier is *feasible, secure-grade, and deployable* on-chain. **On the CKB side: yes,
demonstrated end-to-end. On the Cardano side: measured infeasible by the same approach. Neither leg is
end-to-end quantum-resistant**, because each also roots in the chains' classical signatures.

## What was built and measured (all in `spike/`)

| spike | what it establishes | headline measurement |
|---|---|---|
| `pq-fri-ckbvm` | cost *model* of a FRI verify in CKB-VM (the keystone) | blake2b ≈ 5.8 K cyc/hash |
| `pq-fri-verify` core | real FRI LDT → full STARK → **cumulative-difficulty AIR**, in CKB-VM | FRI 46.8 M; STARK 46.5 M; AIR 52.8 M cyc |
| `pq-fri-verify` ext | **security-grade**: F_p² → **F_p⁴** challenges, grinding, secure queries | F_p⁴ 144 q: **171.3 M cyc**, ≥100-bit quantum commit margin |
| `pq-fri-verify` zero-copy | production domain fits CKB-VM's 4 MB | n=2²²: **333 M cyc**, 64 KB heap |
| `pq-fri-verify` checkpoint | the verifier **as the checkpoint acceptance rule**, proof in a tx witness | advance accept 116–134 M; lighter/epoch/tamper rejected |
| `pq-fri-verify` consensus + `_q` | proof attests the **real total_difficulty transition**, composed with F_p⁴ | composed gate **133.6 M cyc** |
| `sp1-ckb` | a real **SP1 STARK of a CKB header-chain**, generated + verified on a 15 GB box | 256 blocks: prove 95 s / 13 GB, verify ✓ |
| `sp1-verify-cost` | cost of verifying an SP1 proof natively in CKB-VM | Poseidon2 26.2 K cyc; 86 K perms ⇒ ~2.3 G cyc |
| `ckb-to-cardano/groth16` PLUTUS_PQ_COST | the Cardano leg can't host a hash-STARK | blake2b 964 K cpu / 2.9 K mem ⇒ ~2–14× over a Plutus tx |

Everything is adversarially tested and runs under ckb-debugger / aiken / the SP1 SDK.

## The gaps, by level

### Level 1 — buildable here (the remaining engineering)
- **SP1 ↔ AIR prover pipeline / recursion.** `sp1-ckb` proves PoW+linkage; `consensus` proves the difficulty
  *sum*; binding them cheaply on-chain is **recursion** (prove, in a cheap STARK, that you verified the inner
  proof). **Designed + the enabling primitive built and measured** (`spike/pq-recursion`): a recursion needs a
  field-friendly hash, so **Poseidon2-Goldilocks** is implemented and measured at **18,420 cyc/perm** in
  CKB-VM (~2.8× blake2b — the price of arithmetizability). Cost model: recursion turns SP1's ~2.3 G native
  verify into a **~300 M constant-size outer-STARK verify (~7–8× cheaper)**. *Remaining:* the recursion AIR
  itself (a general multi-column/degree AIR framework + Poseidon2-and-FRI-verifier-as-constraints) — i.e. an
  `sp1-recursion`-class engineering build, no research risk. See `spike/pq-recursion/RECURSION.md`.
- **Faithful CKB-consensus circuit — done.** `sp1-ckb` uses **real Eaglesong** PoW (CKB's upstream crate),
  CKB's **compact-target** difficulty, **U256** cumulative work, and a real **Merkle Mountain Range**
  `chain_root` (the light-client commitment) — a real-Eaglesong consensus proof generated + verified here
  (16 blocks, 109 s / 11.9 GB). The proof's public outputs are **wired into the checkpoint** as the advance
  statement (`sp1-ckb` → `checkpoint`); on-chain that advance is gated by verifying the SP1 proof (native
  ~2.3 G, or recursion ~300 M).
- **Soundness tightening.** Querying tightened to 144 (171.3 M cyc). A uniform 100-bit *quantum* floor would
  push queries/grinding further; exact bounds are conjectural (below).

### Level 2 — blocked by resources / process (not research)
- **A real production proof.** SP1's compressed/recursion prover **OOM-killed at >15 GB** here; needs ≥32–64 GB.
- **Audit + formal verification.** Nothing here is audited; QROM/Fiat–Shamir STARK soundness is **conjectural
  across the entire field** (no STARK has unconditional quantum soundness) — we target the same level as
  production systems (ethSTARK / Plonky3 / SP1).
- **Live deployment.** All demonstrations are ckb-debugger mock transactions: no testnet/mainnet, genesis
  one-shot/thread-token lifecycle, fee/capacity economics, or the ~1.7 MB-proof data cost. Retiring the live
  BLS leg (migration, dual-run) is unstarted.

### Level 3 — NOT ours to close (protocol-level)
- **The Cardano leg.** A hash-**STARK** verifier is infeasible in Plutus (no general VM; BLS-only
  acceleration; ~2–14× over the per-tx budget). **But a PQ Cardano leg *is* developable under the
  certificate model:** a hash-based **signature** (WOTS+/XMSS) verifies in a Plutus tx — measured
  (`PQ_CARDANO.md`) at ~28 % cpu / ~66 % mem of budget. So both legs can be post-quantum under the
  committee/certificate trust model (BLS → hash-based cert). What stays protocol-level: the *trustless*
  Cardano leg (hash-STARK needs tx-chaining or **PQ-friendly Plutus builtins**), and large multi-signer
  quorums (need aggregation / tx-splitting).
- **The anchor signatures.** Cardano **Ed25519/KES** + the Mithril **BLS** cert and CKB **secp256k1** locks
  are all classical. End-to-end PQ requires **Cardano and CKB themselves to adopt PQ signatures** — protocol
  decisions above the bridge. (CKB's Eaglesong PoW consensus is already hash-based.)

## What "complete" means — the verdict

| target | status |
|---|---|
| De-risk the PQ verifier (the spike's goal) | **done** — feasible, secure-grade, production-scale, integrated, attests the real transition |
| Production PQ verifier on the CKB side | needs: faithful circuit, SP1↔AIR pipeline (or accept 2.3 G), big-box proof, audit, deployment (L1–L2) |
| **Both legs / end-to-end quantum-resistant bridge** | **not achievable by this project** — gated on Cardano protocol PQ + both chains' PQ signatures (L3) |

**Bottom line.** The hard *cryptographic* question — *can a post-quantum, on-chain, checkpoint-gating
verifier exist and fit?* — is answered **yes** and demonstrated end-to-end on CKB. The path to a *fully*
quantum-resistant bridge is no longer a research question; it is **engineering + audit + deployment on the CKB
side, and protocol-level adoption (PQ builtins / PQ signatures) on the Cardano side and in both chains' own
consensus** — the last of which no bridge can deliver alone. This document is the honest finish line: not "the
bridge is quantum-proof," but "the post-quantum verifier is proven feasible and built, and every remaining gap
is named, measured, and correctly attributed."
