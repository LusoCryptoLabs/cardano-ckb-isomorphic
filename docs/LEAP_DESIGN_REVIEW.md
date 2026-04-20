# Chiral "Real Leap" Brief — Adversarial Design Review

**Date:** 2026-06-10 · **Subject:** the Mithril-only ownership-toggle leap design brief (state pinned to
CKB; ownership toggles `CardanoBound{seal,commitment}` ↔ `CkbOwned{lock}`).
**Method:** 79-agent adversarial workflow — 7 attack dimensions targeting the safety invariants I1–I5,
each grounded against the real reused code (`spike/phase1/bound_asset_unified.rs`,
`cardano/binding/*`, `docs/BINDING_SPEC.md`, `docs/LEAP_FLOWS.md`), every issue refuted by two lenses
(spec-lawyer + implementer-attacker). Liveness-only failures were explicitly downgraded — a *safety*
blocker must produce a both-owned / neither-owned / theft / replay outcome.

> **Verdict: CONDITIONAL GO.** The architecture is sound — the genuinely dangerous cross-chain attacks
> (both-owned window, reorg-after-re-home, seal-survives-leap) were **refuted**, and invariants I1–I5
> are the right invariants. **But the brief's "mostly plumbing, reuse FINALIZE" framing is wrong:** the
> reused machinery does not carry the recipient binding, the mode authentication, the output-lock
> authority, or the cross-leg seal accounting the invariants require. **Four blocker-class design
> additions** are needed before implementation. All are specifiable (concrete fixes below) — this is
> real protocol design, not plumbing.

---

## 🔴 Blockers (must be designed before implementation)

### B1 — Recipient binding has no carrier (I2 is unenforceable as written)
*Confirmed by both lenses across RBIND-1, RBIND-2, ATOM-2(atomicity), ATOM-1(liveness), ATOM-2(init).*

The Cardano→CKB leap is, in the brief's words, a seal-spend that "consumes it, does NOT recreate it" —
i.e. the existing **Unbind** path. But `SealDatum = {owner, commitment}` (`binding_lock.ak:19-22`) has
**no recipient field**, and `commitment = blake2b256(state‖seal)` (`BINDING_SPEC §1`) binds state + seal,
never a CKB lock. The reused FINALIZE branch (`bound_asset_unified.rs:230-239`) reads **no datum** at
all — only "seal consumed" + `seal_at_lock==Some(false)`. So **nothing in the Mithril-certified Cardano
tx names the CKB recipient lock.**

**Attack (stands):** a permissionless relayer observes the certified Unbind, builds the `LEAP_TO_CKB`
CKB tx, and sets the surviving `CkbOwned` cell's lock to **its own key**. The oracle checks pass; nothing
to compare against. **The asset is stolen on arrival.** This is the *same failure class* as the mint
audit's **critical RECIP-1** — recipient binding is a systemic weak point in the cross-chain design.

**Fix:** stop calling it a FINALIZE reuse. Add a dedicated `LeapToCkb` Cardano redeemer that, on seal
consumption (still not recreated), **requires an owner-signed inline datum committing the CKB recipient
lock hash** — e.g. fold it in as `commitment = blake2b256(state ‖ seal ‖ recipient_lock_hash)`. Add a
**new** CKB-side parse path (FINALIZE reads none today) that extracts the committed recipient and
asserts `output.lock_hash == committed_recipient`.

### B2 — Mode is shape-inferred, not an authenticated tag → branch confusion / theft
*Confirmed by both lenses across ATOM-1(init), ATOM-3(atomicity), MODE-3, MODE-4, ATOM-4/5(init).*

The reused dispatcher branches purely on cell presence (`match load_cell_data(0, GroupOutput/GroupInput)`,
`bound_asset_unified.rs:205,213`). Both new leaps have the **{input present, output present}** shape —
**positionally identical to TRANSITION.** Reusing as-is means both leaps run the TRANSITION branch, which
demands a full certified Cardano tx — making `LEAP_TO_CARDANO` (meant to need *no* Mithril proof)
impossible. The moment a tag is added without enforcing tag↔position agreement, an attacker routes a
`CardanoBound` cell (whose lock is `<anyone-can-relay>`, `BINDING_SPEC §1`) through the no-Mithril
`LEAP_TO_CARDANO` arm and **reassigns ownership of a cell they never owned** — theft, I1 broken.

**Fix:** make the authenticated mode tag the **primary dispatch key**. Reject any tx whose
`(input_tag, output_tag, input_present, output_present)` tuple isn't exactly one of the five legal shapes.
`LEAP_TO_CARDANO` must assert `input.tag == CkbOwned`; `LEAP_TO_CKB` must assert `input.tag == CardanoBound`.

### B3 — Confused deputy: the type script never reads the lock (CkbOwned authority/output-lock unpinned)
*Confirmed by both lenses (MODE-1).*

The reused type script has **no `load_cell_lock_hash`** anywhere. Output lock scripts don't execute at
creation in CKB, so **only the type script can pin a `CkbOwned` output's lock.** The brief's "authorized
purely by the input cell's native CKB lock" lives in a script the design never touches. Combined with B1,
this is the mechanism by which the relayer sets the output lock to itself.

**Fix:** store `CkbOwned{lock_hash}` in cell data; in `LEAP_TO_CKB` require
`load_cell_lock_hash(0, GroupOutput) == committed_recipient` (and reject the well-known anyone-can-spend
hash); for `CkbOwned` inputs require `load_cell_lock_hash(0, GroupInput) == committed lock_hash`. *(The
sub-claim that a correctly-locked CkbOwned cell moves without the owner key was refuted — CKB always runs
the input lock; the real defect is output-lock pinning, tightly coupled to B1.)*

### B4 — Seal single-use needs the cross-leg accounting the brief calls "out of scope"
*Confirmed by both lenses (ATOM-1, seal_uniqueness).*

`LEAP_TO_CKB` authorizes purely by the cell-data seal outpoint appearing in the certified tx + A6's
*intra-tx* single-cell guard. There is **no global nullifier.** If two `CardanoBound` cells ever name the
same seal, an attacker spends each in a separate CKB tx, both citing the *same* certified Cardano
seal-spend, and **both produce a surviving `CkbOwned` cell** — two assets from one release. This is exactly
`SECURITY_AUDIT.md` **N-FIN-1**, which the project already had to close on the mint leg with
`seal_nullifier.ak` / `seal_set.ak` / `seal_thread.ak`. The brief's claim that the ownership-toggle "does
not need cross-leg single-use accounting" is **wrong** — it inherits the identical vector.

**Fix:** extend the CKB-side global seal nullifier (SMT + genesis-pinned thread token, insert each consumed
seal once across all history) to the leap branches, **or** enforce seal-outpoint uniqueness at
`CardanoBound` creation (which itself needs the B5 seal↔NFT binding).

---

## 🟠 Majors

- **M1 — `seal_prime` not pinned to the one-shot NFT (I4 unenforced on CKB; permanent-stuck liveness).**
  `seal_prime` is a bare outpoint; the one-shot NFT is identified by `(policy_id from seed, name)`
  (`seal_nft.ak:10-16`). No verified map between them, and `LEAP_TO_CARDANO` runs no oracle, so the CKB
  side can't verify `seal_prime` is controllable / unused / mintable. Worst demonstrated harm is
  **liveness** (cell permanently immovable — there are zero timeout/reclaim primitives), not safety.
  *Fix:* commit the seal **policy-id** (one-shot per seed) and have the Cardano mint validator require the
  minted policy + commitment to match.
- **M2 — Reorg safety is assumed, not enforced.** `LEAP_TO_CKB` pins **no on-chain confirmation depth**;
  I5 leans on the certifier's immutable-file behaviour, unlike the audited Groth16 leg which pins depth K.
  *Fix:* enforce a finality/depth gate on the Mithril import, or explicitly document the trust assumption.
- **M3 — State-unchanged (I3) not enforced by any reused mechanism at the CKB→Cardano flip** (contested;
  one lens minor). *Fix:* explicit `out_state == in_state` check on `LEAP_TO_CARDANO`.

## ⚪ Minors / hardening
No-split single-cell guard (SEC A6) must be **restated** for both new branches (MODE-5); explicit mode tag
collides with the hardcoded 36-byte header / state-at-offset-36 layout and the commitment domain (MODE-3,
ATOM-3 init) — needs a deliberate re-layout; `seal_at_lock`/`seal_commitment` parsers were written for
Genesis/Transfer/Unbind shapes and need generalizing for the new leap tx shapes (ATOM-6).

---

## ✅ Refuted (proven safe — the architecture's hard parts hold)
- **No both-owned window in CKB→Cardano** from the `CardanoBound` cell being movable on CKB before
  `seal_prime` exists — refuted.
- **Cardano reorg of the seal-spend after the CKB re-home, racing a leap-out** — refuted.
- **`seal_at_lock==Some(false)` proving policy-not-specific-seal / seal surviving the leap** — refuted
  (the no-recreation check is sound for this purpose).
- **Relayer front-running by choosing which cert to relay** — refuted (liveness only, cannot forge).
- **Uniqueness enforced at Cardano-mint time being exploitable on CKB** — refuted for the safety horn
  (each cell binds a single Cardano-consensus-unique outpoint; can't double-move *that* cell).

These refutations matter: the **one-owner invariant under reorg/timing — the brief's stated hardest
property — is achievable.** The blockers are all about *under-specified bindings with known fixes*, not a
broken core.

---

## Recommended sequence
1. **Revise the brief** to v2 with B1–B4 + M1–M3 designed in (drop the "reuse FINALIZE" / "mostly plumbing"
   framing; LEAP_TO_CKB is a *new* Cardano redeemer + a *new* CKB parse path; add the mode-tag dispatcher
   and the cross-leg seal nullifier extension).
2. **Then** the implementation plan against `bound_asset_unified.rs` becomes accurate.
3. The recipient-binding blocker (B1) is the **same class** as the mint leg's critical RECIP-1 — design a
   *single* recipient-commitment mechanism reusable by both legs.
