# Re-audit: AUTHZ (no-mint-without-leap) + DOUBLEMINT (replay) — CKB→Cardano χCKB leg

The original 42-agent adversarial audit (2026-06-10) confirmed INFL-1/VERIF-1 (the value-binding gap, now
FIXED — see [VALUE_BINDING_FIX.md](VALUE_BINDING_FIX.md)) but its `authz` and `doublemint` finders **died on
socket errors** — those two dimensions were left **UNAUDITED**. This is the manual re-audit. Method: an
adversarial code-level trace of the on-chain validators, with each property pinned to a regression test.

**Verdict: both dimensions are SOUND.** No new soundness gap found. The defenses are layered and each rests on
a genesis-pinned trust root that is itself enforced + tested.

---

## 1. AUTHZ — the wrapped FT cannot be minted without a verified leap

**Claim:** every χCKB mint is gated by a fresh Groth16-verified CKB lock for the exact (amount, recipient).

Trace (`leap_mint_guard.ak` `mint`/`LeapInMint`):
1. `expect [bound_in] = filter(inputs, h == bound_script_hash)` — a mint requires **spending exactly one
   `cardano_bound` UTxO** (not merely referencing/creating one). `leap_mint_guard.ak:115`.
2. Spending it triggers `cardano_bound.spend`, whose **every** branch verifies a SNARK:
   - `Transition → verify(vk, proof, public_inputs)` (`cardano_bound.ak:139`)
   - `Finalize → verify(finalize_vk, proof, public_inputs)` (`cardano_bound.ak:150`)
   - `else(_) { fail }` (`cardano_bound.ak:157`) — **no admin/withdraw/bypass path.**
3. The proof binds `commitment(new_state, st.ckb_seal)` against the **canonical, genesis-pinned** checkpoint
   `window_root` (read via the thread-NFT reference input, not the redeemer — `canonical_cp`,
   `cardano_bound.ak:82`) and the **governance-pinned** confirmation depth `K`
   (`read_k`, NFT- + script-hash-pinned, `cardano_bound.ak:62`). `inputs_bind_w`, `cardano_bound.ak:52`.
4. `cardano_bound.continuing` forces **exactly one** continuing output whose `(ckb_seal, state)` equals
   `(st.ckb_seal, new_state)` (`cardano_bound.ak:93`, SEC N1). `leap_mint_guard` reads the leap fact
   `(amount, recipient)` from **that same** output and mints `minted_total == fact.amount`, all to
   `fact.recipient`, one FT name only (`authorize_mint` + `only_one_name`, `leap_mint_guard.ak:144`).
5. The operational policy (pause/caps) is read from the **one-shot-NFT-pinned**, fail-closed governor cell
   (`read_policy`, `leap_mint_guard.ak:39`, SEC MF-4) and enforced (`enforce_policy`).

**Adversarial pokes (all closed):**
- *Forge a bound UTxO without a proof.* Creating an output at the `cardano_bound` address triggers no
  validator — but **spending** it (required to mint) runs `cardano_bound.spend`, which needs a proof binding a
  real CKB lock. A fake bound UTxO is unspendable-to-mint. ✓
- *Inflate the mint above the locked value.* `authorize_mint` requires `minted_total == fact.amount` and the
  proof binds `commitment(new_state, seal)`; `new_state` is now **derived in-circuit** from the
  `bridge_lock_v1` receipt body (amount == capacity, enforced by the CKB type script) — not a free witness.
  Two independent layers (on-chain commitment + in-circuit derivation). ✓ (`leap_bound_windowed.rs`)
- *Substitute an attacker policy cell* (open caps / unpaused). Needs the one-shot policy NFT (genesis-minted,
  governor-held, unforgeable); `read_policy` is exactly-one + fail-closed. ✓
- *Skip the registry / rate-limiter.* `seal_consumed` + `rate_ticked` are both required; absent inputs →
  graceful `False`. ✓ (test `leapin_rejects_without_nullifier`)

**Pinned by:** `leapin_rejects_without_nullifier`, `leapin_accepts_when_seal_consumed_and_ticked`,
`leapin_rejects_when_rate_underreported`, `bind_k_mismatch_rejected`, `bind_tip_mismatch_rejected`,
`read_k_returns_governance_k`, and `bound_windowed_leap_verifies` (the live combined proof the verifier
accepts).

---

## 2. DOUBLEMINT — one CKB seal authorizes at most one mint, ever

**Claim:** a single CKB lock (one `ckb_seal`) can drive ≤1 χCKB mint across **all** transactions, regardless of
how the bound UTxO is transitioned.

Trace:
1. Every `LeapInMint` requires `seal_consumed(self, nullifier_hash, bs.ckb_seal)` — the leap's seal must be
   **inserted into the global seal-nullifier registry** with `Insert.key == bs.ckb_seal`
   (`leap_mint_guard.ak:53,144`).
2. `seal_nullifier.spend` forces `seal_set.inserts(old_root, new_root, key, sibs)` — a **non-membership** proof
   under the old root → membership under the new root, 32-byte key, full 256-depth siblings, singleton pinned
   by the thread token, exactly-one continuing output (`seal_nullifier.ak:19`). ⇒ a seal can be inserted **at
   most once, ever**.
3. The registry is **genesis-pinned** by `seal_thread` (`seal_thread.ak:17`): the thread token mints only if a
   unique `genesis_ref` is consumed (one-shot), exactly one token is minted, and it lands on a registry output
   whose datum is the **empty-tree root**. No pre-loaded root, no second lineage.

**Why repeated transitions don't help the thief:** a `cardano_bound` UTxO preserves `ckb_seal` across every
`Transition` (`cardano_bound.ak:142`). The first mint inserts seal `S`; any later mint re-transitioning the
same UTxO must insert `S` again → non-membership fails. Transitions without a mint need no insert, but they
cannot create supply. So total mints for `S` ≤ 1.

**Adversarial pokes (all closed):**
- *Two leaps in one mint tx.* `expect [bound_in]` (exactly one) + one FT name. ✓
- *Finalize-mint as a second mint.* `Finalize` requires **no** continuing output (`cardano_bound.ak:151`), so
  `leap_mint_guard`'s `expect [bound_out]` finds zero → reject. Finalize cannot mint. ✓
- *Stand up a parallel registry to re-insert a consumed seal.* The insert must satisfy `seal_consumed`, which
  matches the **canonical** `nullifier_hash`; a second `seal_nullifier` instance parameterized with a different
  thread policy has a **different script hash** (so `seal_consumed` can't find it), and a second lineage under
  the same script needs the **canonical** thread token — but a different `genesis_ref` yields a **different
  policy id** so `has_thread(canonical)` fails. Closed both ways. ✓
- *Replay at the registry directly.* Re-inserting a present key folds to the wrong root → reject. ✓ (test
  `replay_rejected_at_registry`)

**Pinned by:** `replay_rejected_at_registry`, `missing_thread_token_rejected`, `genesis_mint_ok`,
`genesis_without_unique_ref_rejected`, `genesis_nonempty_root_rejected`, `seal_consumed_rejects_wrong_key`,
and the live SMT soundness checks (`registry_smt.rs`: `general_smt_matches_live_anchor`,
`registry_accepts_two_sequential_inserts`, `registry_rejects_replay`).

---

## 3. Residual dependencies (already established; restated for completeness)

- **Trust root — window_root:** authz step 3 trusts the canonical checkpoint. That checkpoint lineage is
  genesis-pinned (`ckbcert_thread`) and advanced under the heaviest-chain + genesis-pin rules (L3). The
  combined prover (`leap_bound_windowed`) proves window membership against **stand-in window leaves in the
  DEMO**; production maintains the real window root via `AdvanceCKBCert`. This is the one fidelity gap, already
  documented in [VALUE_BINDING_FIX.md](VALUE_BINDING_FIX.md) §7.
- **Trust root — SMT soundness:** the `seal_set` sparse-Merkle gadget is validated against a live anchor by
  `registry_smt.rs` + the `g16/seal_set` Aiken tests.
- **Caps:** the SEC-D6 reorg caps are now **enabled** in the deploy derivation (`d6_deploy.py`); see the
  RATELIMIT-1 fix. Aggregate cap is compile-time/immutable; per-leap caps are governable.

## 4. Result

`authz` and `doublemint` — the two dimensions the original audit could not reach — are **verified sound** by
adversarial trace, each property locked by a regression test (full Aiken suite: 208 tests, 0 failures). No code
change was required for soundness; the re-audit's artifacts are this document + the per-leap-cap tests added
alongside the cap-enablement.
