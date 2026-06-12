# Cardano <-> CKB Isomorphic Bridge: Design-Conformance Verdict

Date: 2026-06-12. Checkpoint: `5d1d80d` (the pre-multichain Cardano-CKB core). Method: a multi-agent
verification run (23 agents) that (1) executed every build/test battery, (2) checked the implementation against
each load-bearing design invariant, (3) adversarially re-verified every failure or concern to separate real
defects from flakes/misreads/by-design behavior, and (4) synthesized this verdict. Toolchain: aiken v1.1.21,
cargo 1.96, ckb-debugger, python3 (WSL ChiralSP1); node (Windows). Everything here is testnet, no value at risk.

## 1. Verdict

**PASS-WITH-CAVEATS.** The bridge works as designed: every core security invariant of the isomorphic bridge is
enforced in source and confirmed by adversarial re-verification. Replay-once (genesis-pinned singleton nullifier
registries on both chains, insert-at-most-once SMT), value conservation + recipient binding (amount/recipient
sliced from the proven CKB receipt and bound in-circuit, never a free witness, with `minted_total==amount &&
minted_to_recipient==amount`), and the seal<->bound-cell bijection + owner-signature ownership all hold soundly.
All test batteries pass (after the harness fix below). The only adversarially-CONFIRMED real issue is a known
deploy gap: the live CKB Mithril verifier predates the STM-quorum pin, so on-chain `k`/`total` are still
witness-supplied today. It is testnet-only, and the fix is build-ready but deploy-deferred behind a professional
audit. Hence PASS on design conformance, with the deploy gap as the one outstanding caveat.

## 2. Test batteries

| Component | Ran | Passed | Counts |
|---|---|---|---|
| aiken: `cardano/binding` | yes | PASS | 5/5 (binding_lock transfer/unbind + seal one-shot, 4 negatives reject) |
| aiken: `groth16` leg (on-chain verifier suite) | yes | PASS | 123/123, 0 failed |
| cert-verify adversarial (Mithril STM in CKB-VM) | yes | PASS | 28/28 (Battery A 11, B 8, C 4, D 5) |
| cert-verify STM-pinned source compiles (both modes) | yes | PASS | deploy + advance riscv builds clean |
| Mithril verifier differential (live certs vs `mithril-stm`) | yes | PASS | 11/11 |
| ckb-testtool: burn-gated-unlock + v2 round-trip | yes | PASS | 15/15 (+ xada 9/9, xada_burn 7/7) |
| ZK leap circuits compile (arkworks) | yes | PASS | 9 bins, 0 errors |
| relayer off-chain parse + transcode self-check | yes | PASS | 4/4 py_compile clean |
| ckb-testtool: dex-integration leap-mint guard | yes (after fix) | PASS | 16/16 |
| ckb-testtool: relay-escrow (permissionless + timeout) | yes (after fix) | PASS | 6/6 |

The guard and relay-escrow suites originally reported FAIL only because the test harness did not cross-compile
the RISC-V contract binary before `cargo test`, so they panicked at the `fs::read(BIN).expect("build ... first")`
precondition in 0.00s before any CKB-VM logic ran. This was a harness/orchestration gap, not a contract defect,
confirmed by an auditor who built the binary and reran each suite green (16/16, 6/6). It is now fixed: each
integration crate has a `build.rs` that cross-compiles its contract first, so `cargo test` is green from a clean
tree.

## 3. Design invariants

| Property | Holds | Enforced by | Note |
|---|---|---|---|
| Replay-once on both chains | yes | CKB `burn_nullifier_registry.rs` (256-bit SMT, type-id genesis pin, non-membership-then-insert) + consumers `burn_gated_unlock_v2.rs` / `bound_asset_v2.rs`; Cardano `seal_set.ak` / `seal_nullifier.ak` + `seal_thread.ak` genesis pin; `leap_mint_guard.seal_consumed` | Sound both sides. Cardano SMT depth 256->128 (Conway mem fit) is a liveness edge only (~2^64 grind), never a double-spend. Disjoint 1-byte leg tags 0x01/0x02/0x03. |
| Value conservation + recipient binding (no unbacked mint / inflation) | yes | Circuit `leap_bound_windowed.rs:110-131` (in-circuit derive + `enforce_equal` to pi_comm); `bridge_lock_v1.rs:30-69` (capacity==amount); `cardano_bound.ak:140-156`; `leap_mint_guard.ak:108-137`; `leap_guard.ak:16-24`; `g16/verifier.ak` (real pairing) | No value field is a free witness at any hop. Recipient match is Script-credential-only (fail-closed, blocks VKey mint). |
| One seal <-> one bound cell (bijection + ownership + committed state) | partial (by design) | `seal_nft.ak:12-15` (one-shot); `binding_lock.ak:49-98` (owner-signature gate, seal continuity); `bound_asset_v2.rs` (cell names its seal txid, singleton, S5 lock pinned to certified recipient) | Ownership + committed-state legs hold soundly. Commitment is STATE-ONLY `b2b256(out_state)` not `blake2b256(S'||OP')`; seal INDEX not pinned at creation. Deliberate + documented (folding OP' is circular/non-constructible, `RECIPIENT_COMMITMENT.md`); self-griefing liveness only, no theft/duplication/ownership-bypass. |
| Mithril STM finality, quorum (k,total,m) PINNED + reorg K-floor k_min=12 | partial (deploy gap) | Source `cert-verify/src/main.rs:32-33,91,...`; K-floor `cardano_bound.ak:63,78,148`, `ada_escrow.ak:68,85,139`, `chiral_policy.ak:16,46` | K-floor k_min=12 is LIVE + enforced on the Cardano leg. STM-quorum pin correct in source but NOT live on the deployed CKB verifiers, see issue below. |
| 5 shipped audit fixes present in (rolled-back) source, by content | yes | `cert-verify/main.rs` (singleton guard codes 40-45); k_min const in 3 .ak files; on-chain leg tags `xada_mint.rs:294` / `bound_asset_v2.rs:251`; `escrow_lock.py:84` placeholder-vk guard | All 5 present + content-verified (commit hashes in the older notes are stale after a history rewrite; the code is there). Off-chain leg tag reads env `CHIRAL_NULL_TAG` (default empty) to match currently-deployed pre-fix contracts; safety-monotone. |

## 4. Confirmed issue (one)

**STM-quorum pin is not live on the CKB Mithril leg.** The `cert-verify` source correctly pins `STM_K=1944` /
`STM_M=16948` and rejects any witness-declared `ct.k != STM_K` (`main.rs:91`), but the DEPLOYED verifiers
predate the pin (deploy commits are ancestors of pin commit `86ed321`; the live `cv_advance` `0xe877a802...` and
`cv_deploy_v2` `0x75b288f3...` take `k`/`total` as witness-supplied). Impact: a single compromised SPO key could
craft a witness with `k=1` and sub-quorum stake and pass cert verification on the live CKB leg. The fix is
build-ready and validated off-chain (compiles clean in both modes); the redeploy is a deliberate, audit-gated
destructive cascade (new `cv_*` hashes -> re-genesis the AVK chain -> re-bake the LCKP hash into `bound_asset_v2`
-> re-genesis the seal). This is the project's own HIGH finding #3 (`SECURITY_FIXES.md`). Testnet-only.

The Cardano-leg companion K-floor `k_min=12` IS live and enforced today.

## 5. Not verifiable offline (completeness)

- **No on-chain / live-fixture re-execution.** Everything here is source review, unit/property suites, and
  compile checks. Issue #1's deploy gap is established from git ancestry, decoded type hashes, and deploy records
  (`BRIDGE_STATUS.md`, `SECURITY_FIXES.md`), not by probing live cells. Live behaviors (the live χCKB mint leap
  tx `07a8023d`, the policy cell, the round-trip toggle) are cited from project records, not re-run.
- **`validate_transcode.py` byte-for-byte witness equivalence not run** (needs live fixtures); only `py_compile`
  parse-clean was confirmed.
- **Deploy-gated + ceremony items out of scope by design:** the STM-pin redeploy cascade, advancing the Mithril
  ceremony / raising K, real MPC trusted setup, `PINNED_GENESIS` vs the true Mithril genesis cert, BLS
  hash-to-curve domain separation, and the upgrade-key/governor lockdown are all deferred to a professional
  cryptographic audit and cannot be settled offline. Consistent with the project's mainnet-gating posture for an
  unaudited, testnet-only system with no value at risk.
