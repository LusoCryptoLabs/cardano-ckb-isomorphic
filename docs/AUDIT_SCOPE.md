# Chiral — audit-readiness scope

For an independent third-party audit (the #1 external production gate). Read with `DESIGN.md`,
`BINDING_SPEC.md`, `SECURITY_AUDIT.md` (internal findings, already remediated), `THREAT_MODEL`,
`CHIRAL_READINESS.md`, and `PRODUCTION_PLAN.md`. **Internal review shares the authors' blind spots; this
package exists to make an external review fast and complete, not to substitute for it.**

## 1. What the system is (one paragraph)
Two asymmetric isomorphic-binding legs. **Cardano→CKB:** ownership = a Cardano seal UTxO; state = a CKB
cell; CKB verifies a **Mithril (BLS-STM) certificate in CKB-VM** + tx-membership. **CKB→Cardano:**
ownership = a CKB seal cell; state = a Cardano UTxO; Cardano verifies a **Groth16 proof of CKB consensus
in Plutus**. Trust per direction = one oracle (stake-threshold signature / SNARK soundness + setup) +
each chain's own consensus. No committee, no custodian in the safety path.

## 2. Trust assumptions to validate (the load-bearing list)
1. **Mithril honest-stake-majority** (reverse-leg oracle) — and that the in-VM verify faithfully
   implements mithril-stm (message construction, AVK/Merkle, stake lottery, quorum, BLS aggregate).
2. **Groth16 soundness + trusted setup** (forward-leg oracle) — setup is today a *demo* (see §6);
   soundness of the circuit is the crux (see §3.A).
3. **CKB PoW honest-majority** + the in-circuit consensus rules (Eaglesong, compact-target, MMR, CBMT).
4. **Cardano consensus** (seal ownership / double-spend) — inherited.
5. **Genesis checkpoints** (first Mithril VK on CKB; first CKB chain-root on Cardano) — one-time social.
6. **Relayer = liveness only** (cannot forge; can stall) — verify across both legs.

## 3. Scope by specialty + priority

### A. ZK circuit soundness — CRITICAL, specialist (the hardest, least-fakeable item)
Completeness is tested; **soundness (no proof for a false statement) is not establishable by testing** —
needs formal review / extensive fuzzing.
- Circuit + gadgets: `spike/ckb-to-cardano/circuit/prover/src/` — `eaglesong_gadget.rs`,
  `blake2b_gadget.rs`, `merkle_gadget.rs` (compact-target, leq), `ckb_mmr.rs` + `mmr_gadget.rs`,
  `difficulty_gadget.rs`, and the `LeapCircuit` / advance / batch / finalize circuits in `src/bin/`.
- Public-input encoding must match the validator (`lib/g16/verifier.ak`, `cardano_bound.ak`): the
  LE/BE convention, blake2b personalization (commitment uses *standard* blake2b; PoW/MMR use `ckbhash`)
  — historically a Critical (D1). Verify `seal == cbmt_leaf` binding (D2).
- **Note for auditors:** production circuit is ~2²³ (`circuit/CIRCUIT_SIZING.md`); a restructure to ~2²¹
  is proposed (`circuit/RESTRUCTURE.md`) and, if adopted, **re-scopes R2** — audit the chosen version.

### B. Pairing / BLS + Mithril in CKB-VM — CRITICAL, specialist
- Mithril verify in-VM: `spike/light-client-cell/` (`light_client_advance.rs`, `cert-verify`,
  `txset-cert`, `advance-cert`), `spike/cross-chain/cross_chain_tx_proof.rs`, `spike/mithril-verify/`.
- The Groth16 verifier in Plutus over BLS12-381 builtins: `lib/g16/verifier.ak`.
- Pure-Rust `bls12_381` usage in-VM (no precompile) — constant-timeness is not a CKB concern, but
  correctness of point decode / subgroup handling is.

### C. Hand-rolled parsers — CRITICAL (where the Criticals historically lived)
- **Conway CBOR** (in-VM, no library): `spike/phase1/bound_asset_unified.rs` (LIVE),
  `spike/bound-asset/*.rs`, `spike/burn-gated-unlock/src/` + `conway-mint/`, `spike/phase1/a3_decoder/`.
  Tag-258 input sets, tag-24 inline datums, value/mint maps — OOB / parser-confusion / canonicalization.
- **CKB molecule / MMR**: `circuit/prover/src/ckb_mmr.rs`, `circuit/ckb_consensus/`.
- **Relayer transcoder** (off-chain but trust-relevant): `relayer/transcode.py` — must reproduce the
  on-chain-accepted witness byte-for-byte (`validate_transcode.py`); confirm no path lets a malformed
  witness pass the script.

### D. On-chain scripts & validators — HIGH
- **CKB (Rust):** `phase1/bound_asset_unified.rs` (LIVE BoundAsset: genesis/transition/finalize),
  `light-client-cell/*` (checkpoint authentication — A1 was a Critical: type-hash match required),
  `burn-gated-unlock/{burn_gated_unlock_v2, burn_nullifier_registry}` (C1 burn-replay SMT nullifier),
  `relay-escrow/` (permissionless relay + timeout refund), `primitives/ckb/{mldsa,smt_replay}.rs`.
- **Cardano (Aiken):** `validators/{advance_ckbcert, cardano_bound, chiral_policy, ckbcert_thread,
  leap_mint_guard, seal_nullifier, seal_thread, zk_chiral_mint, zk_leap_lock}.ak`,
  `lib/g16/{verifier, ckbcert, seal_set}.ak`, `lib/leap_guard.ak`, and `cardano/binding/*.ak`
  (`seal_nft`, `binding_lock`). B1 was a Critical: mint `vk` must be a compile-time param, not redeemer.

### E. Setup ceremony — HIGH (see §6) · F. Relayer/ops liveness — MEDIUM (safety-non-critical)

## 4. Known residuals (do not re-find; audit the fix/decision)
- **D5** — in-circuit DAA / epoch-schedule conformance not enforced (economic security holds).
- **D2-A** — per-outpoint membership: decision to adopt (`PRODUCTION_PLAN.md` S2); audit the gadget if built.
- **Restructure (R2)** — `circuit/RESTRUCTURE.md`, pending sign-off; changes how chain membership is proven.
- Forward-leg redeploy + seal-nullifier genesis wiring completion.

## 5. Already-closed Criticals (context — internal, shares blind spots; re-verify, don't assume)
C1 burn-replay (SMT nullifier) · A1 checkpoint authentication (type-hash match) · B1 mint vk as
compile-time param · D1 public-input encoding (LE/BE + blake2b personalization) · D2 seal==cbmt_leaf ·
A7 STM lottery unique strictly-increasing indices. Full detail + tests in `SECURITY_AUDIT.md`.

## 6. Trusted setup — the demo vs the requirement
`circuit/prover/src/bin/ceremony.rs` implements a **mechanically-real** Groth16 phase-2 (verifiable
re-randomization + Schnorr PoK of the secret + rogue-rejection), but it runs **single-process on a toy
circuit** (`y=x³+x+5`) with Phase-1/PoT stubbed; the code itself states the production run on the real
proving key is external. **Audit the *mechanism* here; the real multi-party (or universal-SRS) run on the
frozen production circuit is a separate, external deliverable** (`PRODUCTION_PLAN.md` D-2: targeting a
universal-SRS PLONK; note no public BLS12-381 SRS exists at the production degree — see CIRCUIT_SIZING.md).

## 7. Out of scope for a v1 safety audit
Post-quantum research (`spike/pq-fri-*`, `pq-recursion`, `sp1-*`, the SP1 STARK-Mithril and its CKB-VM
Groth16-wrap verifier `sp1/m2all/groth16-ckbvm/` — an optional v2, ~3.81 G cycles, not on the live path),
benchmarks (`*-bench`, `*-cost`), and the DEX/UI layer (`dex-integration`) except where it touches mint
conservation.

## 8. Reproduce / build
- Circuit gadget tests + proof: `circuit/prover` (`cargo run --release --bin gadget_tests` / `leap_prove`);
  constraint sizing: `COUNT_ONLY=1 [MMR_DEPTH=N] cargo run --release --bin leap_prove`.
- Aiken: `groth16/` (`aiken check`).
- Mithril in-VM + BoundAsset: `spike/light-client-cell/`, `spike/phase1/` (ckb-testtool).
- Live tx-by-tx record: `docs/LIVE_STATUS.md`, `docs/TESTNET_LOG.md`.

> Freeze `BINDING_SPEC` + `THREAT_MODEL` + the circuit version before the engagement — auditors need a
> stable target, and circuit findings force a re-setup, so audit the circuit FIRST, fix, re-freeze, then setup.
