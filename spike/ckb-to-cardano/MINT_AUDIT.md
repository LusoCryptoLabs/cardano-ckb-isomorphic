# CKB→Cardano Token-Mint — Security Audit

**Date:** 2026-06-10 · **Scope:** the production D6 minting chain (`leap_mint_guard` + `cardano_bound`
+ `leap_guard`/`ckbcert` libs + `seal_nullifier`/`seal_thread` + `leap_ratelimit*` + `chiral_policy*`)
and the leap circuit (`circuit/prover/src/bin/leap_windowed.rs`).
**Method:** two adversarial workflows (56 agents total). 10 attack-dimension finders + a 2-dimension
re-run after socket failures; **every** finding independently refuted by two diverse lenses
(control-flow trace + concrete whole-tx construction, both default-to-refuted). Only findings that
survived both lenses are reported as real.

> **One-line verdict:** the on-chain authorization, replay-protection, and singleton machinery is
> **sound**. There is **one critical** defect — the leap *proof does not bind the asset's value or
> recipient* — which makes the Groth16 leg unsafe to carry value until the circuit is fixed. The leg
> was never used with real value (the historical preview demo minted→burned 100k in a closed loop).

---

## 🔴 CRITICAL — the leap proof binds nothing about value or recipient

**IDs:** INFL-1, VERIF-1, DATUM-2 · confirmed critical by every lens · root cause is singular.

`circuit/prover/src/bin/leap_windowed.rs:102` witnesses `new_state` (= `amount(16 LE) ‖ recipient(28)`)
as a **free witness**. Its only use in the constraint system is forming
`commitment = blake2b256(new_state ‖ seal)` (`:105-106`). The only value bound to CKB is `seal`,
constrained to equal a CBMT leaf = a **block-included transaction hash** (`:104`). The circuit proves
*"a tx with this hash was mined in a confirmed CKB block"* — it **never decodes that tx to read the
locked output capacity**. Nothing ties `new_state`'s amount/recipient bytes to any real locked value.

On-chain, `cardano_bound.ak:142,146` faithfully relays this: it forces `state == new_state` and pins
`commitment(new_state, seal)` into the public inputs — but that is merely **self-consistent**, not
bound to reality. `leap_mint_guard.ak:132-134` then reads `amount`/`recipient` from those bytes and
mints accordingly. The on-chain check `amount == committed` is real but validates an
**unconstrained** value.

**Exploit (both lenses walked the full tx):** relayer performs one minimal real lock (1 CKB), builds a
proof with `new_state = LE16(1_000_000_000) ‖ attacker_credential`. The proof verifies; `cardano_bound`
and `leap_mint_guard` accept; **1e9 unbacked χCKB are minted to the attacker** against a 1-CKB lock.
The recipient is attacker-chosen by the same gap (RECIP-1, high). Consistent with the codebase's own
note in `relayer/cardano_mint.py` ("amount-binding is a production step").

**Fix (circuit work):** inside the circuit, decode the seal-tx outputs and constrain
`new_state.amount` to the locked capacity and `new_state.recipient` to a value committed by the CKB
lock — or derive amount/recipient as public inputs from the verified tx body. The on-chain guards are
already correct; they only need a sound value to check.

---

## 🟠 HIGH

**RATELIMIT-1 — the SEC-D6 aggregate cap ships disabled and is not governable.** The cap is a
**compile-time** parameter to `leap_ratelimit` (`d6_deploy.py:33` `CAP=0`) and `max_amount=0`
(`d6_deploy.py:109`), both meaning "disabled," with **no on-chain way to enable** the aggregate cap
after deploy. The reorg defense built in D6_REORG.md is therefore **off** in the production
derivation. *Fix:* source the cap from the governance `PolicyState` (like K) so it is a governable
on-chain value, and ship a non-zero genesis cap.

---

## 🟡 MEDIUM

- **GOV-1 — the sane-K band allows K=0.** `chiral_policy_thread.ak:39-42` accepts
  `min_confirmations ∈ [0,32]`; a single governor key can set **K=0** and re-open depth-0 reorg theft.
  *Fix:* raise the floor (e.g. `K ≥ 6`) in `is_sane_genesis` and in `chiral_policy`'s `sane_caps`.
- **RLT-1 — rate-limiter genesis is not address-pinned and `rate_ticked` is address-blind.** A
  misplaced/decoy genesis limiter cell silently voids the aggregate cap. *Fix:* pin the thread token to
  the `leap_ratelimit` script hash at genesis and have `rate_ticked` require it. (Moot while CAP=0, but
  fix together with RATELIMIT-1.)
- **INFL-3 — minted amount has no upper bound** with both caps disabled at genesis (subsumed by
  CRITICAL + RATELIMIT-1).

## ⚪ LOW / INFO (hardening — none exploitable today)

- **read_policy missing script-hash pin** (authz-1 / RLT-2, low): `leap_mint_guard.read_policy`
  (`:41`) locates the governance cell by NFT only, while `cardano_bound.read_k` also pins
  `Script(h) == policy_script`. Not exploitable — the policy NFT is a one-shot singleton and `read_k`
  fails-closed in the same tx — but the cap/pause source should self-validate. *Fix:* add the same
  `&& Script(h) == policy_script` pin to `read_policy`.
- **bs.state length unchecked** (INFL-2 / authz-3, low/info): `slice_bytearray` silently clamps, so a
  short state reads as amount 0 / truncated recipient. *Fix:* `expect length_of_bytearray(bs.state) >= 44`.
- **LeapOutBurn reads a decoy bound output** (DATUM-1 / authz-2 / DM-2 / BURN-1, low/info): the burn
  path matches a first-match, unvalidated `bound_out` with no exactly-one / no spend binding. Benign —
  the CKB-side unlock is authoritative — but unguarded.
- **seal_consumed first-match by script hash only** (DM-1, low): safe because every input at the
  `seal_nullifier` script forces `seal_nullifier.spend` (SMT non-membership + thread token +
  exactly-one) to run independently.
- **Legacy `zk_chiral_mint.ak` has no nullifier** (DM-3, info): it would double-mint freely. It is
  compiled into `plutus.json` but **not** wired into the `d6_deploy.py` chain. *Action:* never deploy
  it as the FT policy; consider removing it to avoid foot-guns.

**Contested:** RECIP-2 (stake credential ignored on the recipient — one lens low, one refuted).
**Refuted:** VERIF-2 (finalize_vk placeholder collapsing domain separation — both lenses refuted);
RECIP-3 (dup of INFL-2).

---

## ✅ Soundly defended (positive results — do not regress)

- **No-mint-without-leap.** The mint is bound to an **actual `cardano_bound` SPEND** (`expect [bound_in]`,
  exactly one, `leap_mint_guard.ak:115-124`), so the Groth16 `verify` necessarily runs. Decoy outputs and
  reference-input decoys cannot authorize a mint; a `Finalize` spend cannot ride along
  (Transition requires one continuing output, Finalize requires none — mutually exclusive).
- **Replay / double-mint impossible (per seal).** `seal_consumed` requires the leap's `ckb_seal` to be
  **inserted into the global `seal_nullifier` SMT registry in the same tx**; the registry is a true
  singleton (`seal_thread` genesis pin + `mints_one_thread`), so SMT non-membership rejects any second
  insert. One seal → one mint, ever.
- **No multi-name inflation** (`only_one_name`); **burn path cannot mint** (`authorize_burn` requires a
  negative net mint); `mints_one_thread` has no 0/2 off-by-one.

---

## Strategic note

This critical defect lives in the **Groth16-of-CKB-consensus leg** (the χCKB minting / D6 path). A
separate design brief classifies that leg as out-of-scope "symmetric re-homing" and proposes a
Mithril-only **ownership-toggle leap** (state pinned to CKB) as the real near-term leap — which
structurally avoids this entire bug class (no wrapped amount is minted from a witness). The audit
therefore **supports parking the Groth16 leg**: it is not value-ready, and the productive path does not
depend on it. See `docs/` (LEAP design brief) and `D6_REORG.md`.
