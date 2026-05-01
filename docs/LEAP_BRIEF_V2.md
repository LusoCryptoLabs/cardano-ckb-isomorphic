# LEAP_BRIEF_V2.md — Chiral Ownership-Toggle Leap (v2)

**Status:** Design-complete, codeable. (Repaired across two adversarial-review rounds — F1–F9 + minors; round 2
fixed F9 to a **state-only** commitment (live parity, non-circular) and F3 to a **direct `(txid, idx)`** outpoint
match. All blockers B1–B4 closed; M1/M3 closed; M2 = inherited Mithril assumption; residuals RQ-1…RQ-10.)
**Architecture (fixed):** business state is pinned to CKB; *ownership* toggles between
`CardanoBound{seal, commitment}` and `CkbOwned{lock}`; the only oracle is the Mithril-certified Cardano
tx-set (double-MMR against an authenticated `LCKP` checkpoint).
**Authoritative AS-IS:** the deployed-once unified verifier `spike/phase1/bound_asset_unified.rs`
(code_hash `0x42f74fbc`, 47,248 B), `cardano/binding/validators/binding_lock.ak`,
`cardano/binding/validators/seal_nft.ak`, `spike/burn-gated-unlock/src/bin/burn_nullifier_registry.rs`,
`spike/burn-gated-unlock/src/bin/burn_gated_unlock_v2.rs`,
`spike/ckb-to-cardano/groth16/validators/leap_mint_guard.ak`.

**Reading convention:** `bau:NNN` = `bound_asset_unified.rs:NNN`; `bl:NNN` = `binding_lock.ak:NNN`;
`bnr:NNN` = `burn_nullifier_registry.rs:NNN`; `bgu:NNN` = `burn_gated_unlock_v2.rs:NNN`;
`sn:NNN` = `seal_nft.ak:NNN`; `lmg:NNN` = `leap_mint_guard.ak:NNN`. All refs verified against the live source.

**The keystone primitive** (recipient commitment `RC`) is defined once in **`RECIPIENT_COMMITMENT.md`** and
referenced here, not duplicated. `RC` folds the **SOURCE** (consumed) seal, never the destination seal — see
that doc's §1.0.

---

## 0. The redesign decision (clean re-layout, disjoint deployment)

The PHILOSOPHY mandate is *clean, correct-by-construction*, so v2 **re-lays-out the 36-byte header** (adds a
version byte + an authenticated tag byte) instead of bolting flags onto the existing presence-based dispatch.

The single most consequential AS-IS fact is that the **live commitment is STATE-ONLY**:
`seal_commitment(datum) == b2b256(out_state)` (`bau:212`), confirmed by the live genesis
`commitment == blake2b256(S0)` (`LIVE_STATUS.md:17`). v2 keeps the state commitment **exactly as deployed**
for GENESIS/TRANSITION/FINALIZE and introduces a **separate, additive** recipient commitment `RC` read only by
the two new leap branches (see `RECIPIENT_COMMITMENT.md`).

**Backward-compat is by disjoint deployment, not in-place upgrade.** v2 is a NEW deployment (new code_hash).
Live v1 cells keep referencing the old code_hash `0x42f74fbc` and are never evaluated by the v2 dispatcher; a
version byte (§2, §8) makes any cross-interpretation fail closed. This eliminates the "legacy untagged cell"
ambiguity that a fold-into-state approach would create, and is *why* re-layout beats minimal-diff here.

---

## 1. Per-blocker closure table (HONEST — closed / inherited-assumption / RQ)

| ID | failure | status | exact mechanism + file:line |
|----|---------|--------|-----------------------------|
| **B1** recipient has no carrier / relayer picks recipient | **CLOSED** | `RC` (folding state ‖ **SOURCE** seal ‖ recipient) rides in `SealDatum` field 1 (commitment) + explicit field 2; owner-signed (`bl:35-36`), Mithril-certified; CKB recomputes `RC` over `in_data[2..38]` and pins the on-chain lock. `RECIPIENT_COMMITMENT.md` §1,§4; new `seal_recipient` next to `bau:66`; `bl:19-22,24-27,38-57` |
| **B2** mode is shape-inferred (leap ≡ transition) | **CLOSED** | 1-byte **authenticated tag** at cell-data `[1]` as PRIMARY dispatch key; exhaustive 5-shape whitelist with `_ => 40`. Replaces presence-only dispatch at `bau:205,213,231`; tag read in §2,§3 |
| **B3** type script never reads the cell lock | **CLOSED** | ADD `load_cell_lock_hash` (absent at `bau:10`); pin output lock on leap-in (`return 29`, §4) and input lock on leap-out (`return 31`, §5) to the committed hash |
| **B4** no cross-leg replay nullifier | **CLOSED** | CKB-VM SMT **source-seal-outpoint** nullifier in ONE **genesis-pinned canonical** registry (hardcoded type-id constant, §6.3) gating BOTH leap branches; key derived from the **certified** body, not relayer cell bytes (§6.2, F3). Reuse `bnr` whole-file; consumer ported from `bgu:142-160`; args `bau:182`. The same-tx **cross-type-group** batch is now also closed by the verifier-side one-leap-per-tx guard (`count_instances`, `return 51/52`; **RQ-8 RESOLVED**). |
| **M1** `seal_prime` not pinned to the one-shot NFT | **CLOSED** | leap-out requires `seal_at_lock(..policy..) == Some(true)` (`bau:119-157`); the `seal_nft` mint validator now binds `committed_policy == policy_id` (`sn:10-16`, the inert `_redeemer` is replaced — §5.1, F8); optional `mint_qty==1` (`bgu:85-118`) |
| **M2** Cardano reorg unenforced | **CLOSED (Option A)** | The Mithril cert AUTHENTICATES `latest_block_number`; `cert-verify` now publishes `"LCKP"‖root‖height(8 LE)` (44 B) and advances it **monotonically** (no regression). `bound_asset_v2` binds each leap to a non-zero authenticated finalized height (`return 6`), and `checkpoint_root()` fails closed on conflicting checkpoints (`return 53`, RQ-4). Mithril certifies immutable (finalized) data, so this makes the inherited finality **explicit + on-chain-checked**; a literal depth gate is redundant (§7). Verified in CKB-VM. |
| **M3** state-unchanged not enforced on flip | **CLOSED** | explicit `in_state == out_state` on **both** flip branches: `LEAP_TO_CARDANO` (`return 32`, §5) and `LEAP_TO_CKB` (`return 47`, §4.3) |

---

## 2. v2 cell-data layout + authenticated mode tag

### 2.1 The re-laid-out header

AS-IS header is `seal_txid(32) ‖ seal_idx(u32 LE) ‖ state(36..)` with **no tag** (`bau:6,209,216-217`). v2
prepends `version(1) ‖ tag(1)` and a 32-byte lock slot, shifting the seal/state body by a fixed offset:

```
v2 cell data:
  [0]       version  = 0x02                          (1 byte)
  [1]       tag      ∈ {CARDANO_BOUND, CKB_OWNED}     (1 byte)   ← PRIMARY dispatch key
  [2..34]   seal_txid                                (32 bytes)
  [34..38]  seal_idx (u32 LE)                         (4 bytes)
  [38..70]  recipient_lock_hash / owner_lock_hash     (32 bytes) ← NEW (B3 carrier) — see §2.4
  [70..]    state                                    (variable)
```

- **tag values:** `CARDANO_BOUND = 0x01`, `CKB_OWNED = 0x02`. `0x00` is reserved/illegal (an all-zero blob is
  never a valid tag).
- **minimum valid length: 70 bytes** (was 36). `state = data[70..]` (may be empty).
- `seal_txid = data[2..34]`; `seal_idx = u32::from_le_bytes(data[34..38])` — same widths as AS-IS, shifted +2.

### 2.4 Semantics of the `[38..70]` lock slot (MAJOR F6 — FIXED)

The previous draft left the lock slot's value **unpinned by GENESIS and TRANSITION**, so a genesis or
transition could write *anything* there; then `LEAP_TO_CARDANO` (which reads it as the authoritative owner lock
at §5 step (1)) could not trust it — a silent leap-out DoS / authority-ambiguity. The slot is now given a
**single, pinned semantics for every mode that produces a `CkbOwned` cell**:

> **Invariant LS:** for any output whose `tag == CKB_OWNED`, `out_data[38..70]` MUST equal the cell's **actual
> on-chain lock hash**, and the type script enforces it via `load_cell_lock_hash` at creation time.

This makes the slot *authoritative and unforgeable* on every path that creates a `CkbOwned` cell, so the
leap-out reads it without ambiguity:

- **GENESIS (S1)** and **TRANSITION (S2)** now ADD a pin:
  `if load_cell_lock_hash(0, GroupOutput)? != out_data[38..70] { return 45; }` (the same B3 host call, applied
  to the produced `CkbOwned` cell). This is the *only* new check on the legacy paths and is purely additive —
  it does not touch the state-only commitment.
- **LEAP_TO_CKB (S5)** already pins it (`return 29`, §4), so the surviving cell's slot is authoritative.
- **LEAP_TO_CARDANO (S4)** reads the **input** `CkbOwned` cell's slot as the authoritative owner lock and
  checks the actual input lock equals it (`return 31`, §5). Because invariant LS held when that input cell was
  *created* (by S1/S2/S5), the slot it carries is exactly the lock that must authorize the leap-out — no
  ambiguity, no DoS.
- For a `CardanoBound` cell the slot is **provably unused**: it MUST be zeroed (`return 35` on the producing
  S4 path) and no branch ever reads it for authority while `tag == CARDANO_BOUND` (the asset lives on Cardano;
  authority is `SealDatum.owner`).

So the slot is *either pinned to the real lock (CkbOwned) or provably zero (CardanoBound)* — never an
unconstrained relayer-chosen value. (New codes: `45` genesis/transition lock-slot mismatch.)

---

## 3. The 5-shape tag-first dispatcher (closes B2)

### 3.1 Legal-shape whitelist

Dispatch is a 4-tuple `(in_tag, out_tag, in_present, out_present)` matched against an **exhaustive whitelist**;
anything else → `return 40`. `in_tag`/`out_tag` are read from cell data `[1]` when present; `∅` = absent.

| # | mode | in_present | out_present | in_tag | out_tag | semantics |
|---|------|-----------|-------------|--------|---------|-----------|
| S1 | GENESIS | no | yes | ∅ | `CkbOwned` | bind: mint seal to lock, create owned cell |
| S2 | TRANSITION | yes | yes | `CkbOwned` | `CkbOwned` | advance state, owner stays on CKB |
| S3 | FINALIZE | yes | no | `CkbOwned` | ∅ | leap-out (asset released on Cardano) |
| S4 | LEAP_TO_CARDANO | yes | yes | `CkbOwned` | `CardanoBound` | flip CKB→Cardano (ownership leaves CKB) |
| S5 | LEAP_TO_CKB | yes | yes | `CardanoBound` | `CkbOwned` | flip Cardano→CKB (ownership arrives on CKB) |

Explicitly illegal (fail closed). **Reachability note (MINOR — FIXED):** the `tag_of` reader rejects an absent
tag's *opposite-tag* partner before these arms, so the arms below are the only way those tuples surface; they
are reachable error paths, not dead code:

- `(CardanoBound, CardanoBound)` → `40` (no-op flip — caught by the catch-all `_ => 40`).
- `(CardanoBound, ∅)` → `41` (a `CardanoBound` anchor cannot just vanish; its asset is on Cardano). This arm is
  reached because `(Some(CARDANO_BOUND), None)` is an explicit non-whitelisted tuple routed to `41`, distinct
  from the catch-all, so it carries a specific diagnostic.
- `(∅, CardanoBound)` (genesis landing Cardano-bound) → `42`. Reached via the explicit
  `(None, Some(CARDANO_BOUND))` arm — a genesis must land `CkbOwned`.
- `(CkbOwned, ∅)` is FINALIZE (S3), distinguished from a leap by **out_present** — a leap always recreates a
  cell. A relayer trying to "leap-out into nothing" gets FINALIZE semantics (the `seal_at_lock==Some(false)`
  proof, §8), not theft.

### 3.2 Dispatcher code (replaces the nested `match` at `bau:205/213/231`)

```rust
// A6 single-cell guard PER TYPE GROUP unchanged (bau:186-187): reject a 2nd in/out in this type group.
let out = load_cell_data(0, Source::GroupOutput).ok();   // Option<Vec<u8>>
let inp = load_cell_data(0, Source::GroupInput ).ok();

// tag_of: None if cell absent; Err if present-but-malformed.
//   present => len>=70 else return 7; data[0]==0x02 (version) else return 43; tag=data[1] ∈ {0x01,0x02} else return 44.
let out_tag = match out.as_ref() { Some(d) => Some(tag_of(d)?), None => None };
let in_tag  = match inp.as_ref() { Some(d) => Some(tag_of(d)?), None => None };

match (in_tag, out_tag) {
    (None,                Some(CKB_OWNED))     => genesis(&out.unwrap(), ..),                 // S1
    (Some(CKB_OWNED),     Some(CKB_OWNED))     => transition(&inp.unwrap(), &out.unwrap(),..),// S2
    (Some(CKB_OWNED),     None)                => finalize(&inp.unwrap(), ..),                // S3
    (Some(CKB_OWNED),     Some(CARDANO_BOUND)) => leap_to_cardano(&inp.unwrap(),&out.unwrap(),..), // S4
    (Some(CARDANO_BOUND), Some(CKB_OWNED))     => leap_to_ckb(&inp.unwrap(),&out.unwrap(),..),     // S5
    (Some(CARDANO_BOUND), None)                => 41,   // anchor cannot vanish (specific diagnostic)
    (None,                Some(CARDANO_BOUND)) => 42,   // genesis must land CkbOwned (specific diagnostic)
    _                                          => 40,   // any other illegal shape — fail closed
}
```

The match arms ARE the whitelist; codes 41/42 give specific diagnostics for the two near-miss illegal tuples,
and the catch-all `_ => 40` makes every remaining combination fail closed. B2 is structurally closed:
- `leap_to_ckb` (S5) is reachable **only** when `in_tag == CardanoBound ∧ out_tag == CkbOwned`.
- `leap_to_cardano` (S4) is reachable **only** when `in_tag == CkbOwned ∧ out_tag == CardanoBound`.
- TRANSITION (S2) requires **both** tags `CkbOwned`; a leap flips exactly one tag, so a leap can never be
  relabeled a transition without breaking the Mithril-certified commitment that authenticates the tag.

The **version gate** in `tag_of` (`data[0] != 0x02 → return 43`) plus the disjoint deployment (§8) keep v1 and
v2 cells from ever cross-interpreting.

---

## 4. LEAP_TO_CKB (Cardano→CKB) — closes B1, B3 (and B4 via §6)

The dangerous direction: a permissionless relayer builds the CKB tx, so the surviving `CkbOwned` lock must be
forced to the owner-intended recipient.

### 4.1 New Cardano redeemer `LeapToCkb` (append-only)

`BindingRedeemer` grows from 2 to 3 variants (`bl:24-27`), appended to preserve the existing Constr tags
(`Transfer = Constr 121 []`, `Unbind = Constr 122 []`):

```aiken
pub type BindingRedeemer {
  Transfer                                       // Constr 121 []   (UNCHANGED — live transfer_seal_ours.py)
  Unbind                                         // Constr 122 []   (UNCHANGED — live unbind_seal_ours.py)
  LeapToCkb { recipient_lock_hash: ByteArray }   // Constr 123 [ bstr 32 ]   (NEW)
}
```

`LeapToCkb` carries the owner-chosen 32-byte CKB recipient lock hash **in the redeemer**, so it is part of the
spend the owner signs; the validator forces it into the continuing seal datum.

### 4.2 New SealDatum field + Cardano-side check

`SealDatum` gains `recipient_lock_hash` as **field 2** (append-only); the `binding_lock` `LeapToCkb` branch
requires `cont.recipient_lock_hash == redeemer.recipient_lock_hash` and `length == 32`. Both are defined in
**`RECIPIENT_COMMITMENT.md`** §3.1 and §5 — not duplicated here.

**Seal continuity on leap-in:** `LeapToCkb` **recreates** the seal at the lock (like `Transfer`, not
`Unbind`), so on CKB this is the S5 flip producing a `CkbOwned` cell while the seal NFT remains parked at the
binding lock as the canonical anchor. This yields `seal_at_lock == Some(true)`, distinguishing `LEAP_TO_CKB`
from `FINALIZE`/`Unbind` (`Some(false)`).

### 4.3 CKB parse path for S5

After the shared double-MMR certification (`bau:199-202`) and `parse()` (`bau:203`):

```rust
fn leap_to_ckb(in_data, out_data, tx_body, ins, datum, seal_policy, lock_addr) -> i8 {
    // shape guaranteed by dispatcher: in.tag==CardanoBound, out.tag==CkbOwned (B2)
    if out_data.len() < 70 || in_data.len() < 70 { return 7; }
    let out_state     = &out_data[70..];

    // (a) the surviving CkbOwned cell names the DESTINATION seal THIS certified tx re-parked at the lock.
    let th = b2b256(&[&tx_body]);
    if &out_data[2..34] != &th[..] { return 8; }                           // dest seal = tx hash (mirrors bau:210)

    // (b) the certified Cardano tx CONSUMED this CardanoBound input's SOURCE seal outpoint. Match the SPECIFIC
    //     (txid, idx) in the CERTIFIED body `ins` (F3) — NOT the first txid match: a tx may consume several
    //     outputs of one prior txid, so a txid-only match could false-reject a valid leap.
    let mut src_txid=[0u8;32]; src_txid.copy_from_slice(&in_data[2..34]);
    let src_idx = u32::from_le_bytes([in_data[34],in_data[35],in_data[36],in_data[37]]);
    if ins.iter().find(|(t,i)| t==&src_txid && *i==src_idx).is_none() { return 24; }  // certified tx consumed THIS outpoint
    // (src_txid, src_idx) is now the authenticated certified identity — feeds RC, the consumption proof, and the nullifier.

    // (c) seal IS recreated at the lock (LeapToCkb re-parks it). PROOF required; None fails closed.
    if seal_at_lock(&tx_body, lock_addr, seal_policy) != Some(true) { return 25; }  // reuse bau:119-157

    // (c2) STATE-UNCHANGED across the flip (M3 symmetry, MINOR — FIXED): the certified source state must
    //      equal the destination state. The certified source state is the SealDatum-bound state; here it is
    //      carried as in_data[70..] of the consumed CardanoBound anchor.
    if &in_data[70..] != out_state { return 47; }

    // (d)+(e)+(f)+(g) KEYSTONE recipient binding + output-lock pin — see RECIPIENT_COMMITMENT.md §4.
    //   reads seal_commitment (field1=RC, bau:66) + seal_recipient (field2), recomputes RC over
    //   out_state ‖ SOURCE seal in_data[2..38] ‖ recipient, asserts equality, pins cell-data slot,
    //   and asserts load_cell_lock_hash(0,GroupOutput) == recipient.   returns 26/27/28/29 on failure.

    // (h) B4: nullify the consumed SOURCE seal outpoint exactly once, globally, using the CERTIFIED identity.
    if !seal_nullifier_inserts(&src_txid, src_idx) { return 50; }          // canonical registry pinned (§6.3)
    0
}
```

Theft is impossible: steps (d)–(g) force the surviving `CkbOwned` cell's *actual lock* to be the owner-signed,
Mithril-certified recipient (closing **B1**), and step (g)'s `load_cell_lock_hash` is the first time the type
script ever reads the on-chain lock (absent at `bau:10` — closing **B3**). The seal folded into `RC`, the seal
checked consumed at code 24, the idx pinned at code 46, and the seal nullified at code 50 are **the same
SOURCE-seal identity, taken from the certified body** — they cannot diverge (F1, F3).

---

## 5. LEAP_TO_CARDANO (CKB→Cardano) — closes M1, M3, plus input-lock auth, output-commitment cert (F9)

S4 arm `(CkbOwned, CardanoBound)`: ownership leaves CKB. The dangerous failure is the opposite of B1 — the
relayer must not flip a cell it does not own, and the resulting `CardanoBound` anchor must faithfully name the
Cardano seal AND faithfully commit the carried state.

```rust
fn leap_to_cardano(in_data, out_data, tx_body, ins, datum, seal_policy, lock_addr) -> i8 {
    // shape guaranteed: in.tag==CkbOwned, out.tag==CardanoBound (B2)
    if in_data.len() < 70 || out_data.len() < 70 { return 11; }

    // (1) INPUT-LOCK AUTH (B3, the leap-out half): the CkbOwned input must actually be owned by the
    //     lock it claims. Invariant LS (§2.4) guarantees in_data[38..70] is the real lock the cell was
    //     created under, so satisfying that lock IS the owner authorizing the flip.
    let in_lock = load_cell_lock_hash(0, Source::GroupInput).map_err(|_| 30)?;   // NEW host call
    if in_lock[..] != in_data[38..70] { return 31; }       // actual lock == committed owner-lock slot

    // (2) STATE-UNCHANGED (M3): the business state must not mutate on the flip.
    if &in_data[70..] != &out_data[70..] { return 32; }    // explicit out_state == in_state

    // (3) M1: the certified tx MINTED seal_prime to the binding lock, pinned to the one-shot NFT POLICY.
    if seal_at_lock(&tx_body, lock_addr, seal_policy) != Some(true) { return 33; }   // reuse bau:119-157

    // (4) the new CardanoBound cell names seal_prime: out_seal_txid == tx hash of the mint tx.
    let th = b2b256(&[&tx_body]);
    if &out_data[2..34] != &th[..] { return 34; }

    // (5) well-formed CardanoBound output: lock slot zeroed (asset is no longer CKB-owned). (§2.4)
    if out_data[38..70] != [0u8;32] { return 35; }

    // (6) F9: certify the CardanoBound output commitment over the CARRIED (unchanged) state — STATE-ONLY,
    //     exactly the live shape (bau:212, commitment == blake2b256(state)). seal_prime is bound SEPARATELY by
    //     step (4) (out_seal_txid == th), NOT folded here: out_data[2..34] == th == blake2b256(tx_body) is
    //     unknowable when the owner builds the Cardano mint tx that CARRIES this SealDatum, so folding it would
    //     be the circular fixed-point F1 forbids. State-only is constructible (the owner knows the state) and is
    //     how every live CardanoBound cell commits; the seal is pinned by cell-data + the consumption check.
    if datum.is_empty() { return 48; }
    if seal_commitment(&datum).as_slice() != &b2b256(&[&out_data[70..]])[..] { return 49; }

    // (7) the consumed CkbOwned SOURCE seal is nullified once (B4) — same registry/key as S5 (§6).
    //     Match the SPECIFIC (txid, idx) in the CERTIFIED body `ins` (F3), not the first txid match.
    let mut src_txid=[0u8;32]; src_txid.copy_from_slice(&in_data[2..34]);
    let src_idx = u32::from_le_bytes([in_data[34],in_data[35],in_data[36],in_data[37]]);
    if ins.iter().find(|(t,i)| t==&src_txid && *i==src_idx).is_none() { return 36; }  // certified tx consumed THIS outpoint
    if !seal_nullifier_inserts(&src_txid, src_idx) { return 51; }          // canonical registry pinned (§6.3)
    0
}
```

### 5.1 M1 — `seal_prime` pinned to the one-shot NFT policy-id (MAJOR F8 — FIXED)

AS-IS, `seal_at_lock` already matches the seal **policy** inside the certified body (`val_has_policy`,
`bau:100-118`), and the policy is per-instance from args (`seal_policy = args[0..28]`, `bau:183`). Step (3)
above enforces "the minted policy is present at the lock". The M1 gap is on the *Cardano mint side*: the
one-shot policy is `seal_nft(seed)` whose `policy_id` is the script hash **after `seed` is applied**
(`sn:10-16`), and the **live `seal_nft` redeemer is inert** — `mint(_redeemer: Data, ...)` at `sn:11` ignores
the redeemer entirely, so the previous "pin the redeemer" idea was self-referential. v2 closes M1 by making the
redeemer carry the **committed policy-id** and forcing it to equal the actual `policy_id`:

```aiken
pub type SealMintRedeemer { committed_policy: PolicyId }   // NEW: the leap commits THIS policy (was inert Data)

validator seal_nft(seed: OutputReference) {
  mint(redeemer: SealMintRedeemer, policy_id: PolicyId, self: Transaction) {
    let spends_seed  = list.any(self.inputs, fn(i){ i.output_reference == seed })   // one-shot (sn:12)
    let minted       = self.mint |> tokens(policy_id)
    let exactly_one  = dict.size(minted) == 1 && dict.values(minted) == [1]          // (sn:14-15)
    let pinned       = redeemer.committed_policy == policy_id                        // NEW: not inert
    spends_seed && exactly_one && pinned
  }
  else(_) { fail }
}
```

The pin is **not** self-referential: `committed_policy` is the policy-id the leap machinery commits to *out of
band* (it equals `seal_nft(seed)`'s deterministic script hash), and the validator forces the *actually minted*
`policy_id` to equal it. So "the leap committed policy `P`" + "the tx spends `seed`" + `minted policy == P` pins
`seal_prime` to *the* one-shot NFT, **not a bare outpoint**. Replacing the inert `_redeemer: Data` (`sn:11`) is
the one substantive `seal_nft` change.

> **REGRESSION NOTE (deploy coordination):** editing `seal_nft.ak` changes the validator's compiled code and
> therefore **re-keys all future `policy_id`s** (the policy-id is the script hash). This is **NOT a live
> regression** — the live system uses the immutable v1 seal policy
> `8855af1be1fd48ee096b72e91bee858db51b9ab75e866540c8647674` under the original code (`LIVE_STATUS.md:13`),
> which keeps working unchanged. But every v2 binding instance MUST be parameter-applied and deployed against
> the **new** `seal_nft` code, and the v2 `bound_asset_unified` args `seal_policy` (`bau:183`) MUST carry the
> **new** policy-id. v1 and v2 seal policies are distinct by construction; do not cross-wire them.

**Belt-and-suspenders (optional, recommended):** additionally require the certified body to mint exactly one of
`(seal_policy, seal_name)` using the existing `mint_qty` (`bgu:85-118`):
`if mint_qty(&tx_body, seal_policy, seal_name) != 1 { return 37; }`. This proves *freshness* (a brand-new
one-shot mint) rather than reuse of an existing seal token. (Residual RQ-2.)

### 5.2 M3 — state-unchanged at the flip

Step (2): explicit `in_state == out_state` (`return 32`). The ownership toggle must not be a covert state
edit. AS-IS never enforced this because AS-IS has no flip branch. The symmetric check on the inbound flip is
S5 step (c2) (`return 47`, §4.3).

### 5.3 F9 — the CardanoBound output commitment is certified (STATE-ONLY, live parity)

Step (6): the `CardanoBound` anchor's commitment is certified to equal `blake2b256(out_state)` — **state only**,
byte-identical to the live GENESIS/TRANSITION shape at `bau:212` (`commitment == blake2b256(state)`,
`LIVE_STATUS.md:17`). It does **NOT** fold `seal_prime`: the destination seal txid is `th = blake2b256(tx_body)`
(`return 34`), and the `SealDatum` carrying the commitment lives *inside* that same `tx_body`, so folding it
would be the exact circular fixed-point `RECIPIENT_COMMITMENT.md` §1.0 forbids (the owner cannot commit to the
hash of the tx that carries the commitment). State-only is **constructible** (the owner knows the carried state
when building the Cardano mint tx). `seal_prime` is bound **separately and sufficiently** by step (4)
(`out_seal_txid == th`, `return 34`) plus, on every later spend, the cell-data seal field + the consumption
check — exactly how every live `CardanoBound` cell binds its seal. Combined with the M3 `in_state == out_state`
check (step 2), the anchor provably binds exactly the state that was on CKB under exactly the freshly-minted
seal — a relayer cannot park a different state, and the honest leap-out is now satisfiable (the earlier
`blake2b256(state‖seal_prime)` form was non-constructible — round-2 fix).

---

## 6. Cross-leg seal-nullifier in CKB-VM (closes B4)

### 6.1 The vulnerability and the chosen mechanism

B4 (`N-FIN-1`): two `CardanoBound` cells naming the same seal outpoint each leaping to a surviving cell = two
assets from one release. AS-IS phase1 has **no global nullifier** — its "seal" is per-lineage UTXO consumption,
not a membership set. **Decision:** reuse the existing, integration-tested CKB-VM SMT registry
`burn_nullifier_registry.rs` as the canonical pattern (do NOT re-port the Aiken SMT). Both leap branches insert
the **consumed SOURCE seal outpoint** as the nullifier key into ONE shared, **genesis-pinned canonical**
registry.

### 6.2 The key (outpoint-keyed, from the CERTIFIED body — BLOCKER F3 FIXED)

```
seal_key = b2b256( src_seal_txid(32) ‖ src_seal_idx(u32 LE) )      // 32-byte SMT key (bnr requires 32, bnr:96)
```

**Both `src_seal_txid` and `src_seal_idx` are taken from the CERTIFIED Cardano body's consumed-input list
`ins`** (parsed at `bau:203`, the same list checked at code 24/36), **not** from relayer-supplied cell bytes.
The previous draft keyed `seal_idx` from `in_data[34..38]` — a relayer could present a cell claiming the right
txid but a *different* idx, mapping one real Cardano seal `(txid, idx)` to many distinct nullifier keys and
replaying the seal once per fabricated idx. v2 pins `src_idx` to the idx the certified tx actually consumed
(S4/S5 step "find in `ins`", and cross-check `src_idx == claimed_idx`, `return 46`), so **a given Cardano seal
has exactly one key**.

On S4 the consumed seal is the `CkbOwned` input's outpoint; on S5 it is the `CardanoBound` input's outpoint.
Both legs insert the **same** outpoint-derived key into the **same** registry, so a given seal is nullified at
most once across all leap history. This is the cross-leg accounting B4 demands. Keying by the *outpoint* (not
the certifying tx) is what makes S4 and S5 share one nullifier domain — the burn leg keys by burn-tx-hash
because a burn *is* a tx; a leap consumes a *seal outpoint*.

### 6.3 Registry script + canonical genesis pin (BLOCKER F2 — FIXED)

Deploy **ONE canonical** instance, **unchanged except for the §6.2 key derivation in the consumer**:
- **cell data** = 32-byte SMT root (`bnr:12`).
- **singleton via CKB type-id**: `args == ckbhash(first input outpoint)` at genesis, `empty_root` start, one
  GroupOutput, no GroupInput (`bnr:67-78`). This is the CKB equivalent of the Aiken one-shot thread mint — the
  **non-negotiable singleton genesis pin** that forbids standing up a parallel empty registry to replay.
- **hashing (byte-exact, must not change):** `h2` = blake2b **personalized `b"ckb-smt-null-set"`** (`bnr:33`);
  `ckbhash` personalized `b"ckb-default-hash"` (`bnr:40`); fold (`bnr:50-60`); non-membership
  `fold(ZERO,key,sib) == old_root` (`bnr:102`, code 12) + insertion `fold(PRESENT,key,sib) == new_root`
  (`bnr:104`, code 13). The leap registry is a CKB-only SMT using the CKB personalization — NOT the Aiken bare
  `blake2b_256`. The two SMTs are deliberately non-interoperable; the leap never re-verifies an Aiken root.

**The canonical registry is hardcoded, not a soft per-instance arg (F2).** In the previous draft the consumer
read `registry_type_hash` from the **type-script args** — a soft, per-instance value, so an attacker could
deploy bound cells whose args point at a **parallel, attacker-controlled empty registry**, and "replay-once"
silently failed. v2 pins the canonical registry as a **hardcoded genesis type-id constant** in `bau`, mirroring
the mint-leg's genesis-pinned seal-thread approach:

```rust
// The ONE canonical leap nullifier registry. Its type hash is the genesis type-id of the singleton deployed
// per bnr:67-78 (args == ckbhash(first input outpoint) at genesis). Hardcoded — NOT read from script args —
// so no bound cell can point the nullifier check at a parallel registry. (Mirrors LCKP_TYPE_HASH at bau:14.)
const LEAP_REGISTRY_TYPE_HASH: [u8;32] = [/* set at v2 deploy from the canonical registry genesis */];
```

Every leap branch references this constant; `seal_nullifier_inserts` rejects any registry whose type-hash
`!= LEAP_REGISTRY_TYPE_HASH`. This is the exact pattern already used for the trusted checkpoint
(`LCKP_TYPE_HASH`, `bau:14`) and the burn registry's own singleton (`bnr:63-78`).

> **MINOR — args length (FIXED):** because `registry_type_hash` is now a hardcoded constant, the v2 type-script
> args stay at the AS-IS `seal_policy(28) ‖ lock_addr(28)`, **min len 56** (`bau:182-184`), NOT the 88 the
> previous draft proposed. Code `30` (args `< 56`) is unchanged. No args growth, one fewer relayer-controlled
> field.

### 6.4 Consumer binding in `bau` (port of `registry_inserts_key`)

The consumer is a direct port of `bgu:142-160`, but keyed on the **hardcoded** registry type hash and the
**certified** `(src_txid, src_idx)`:

```rust
fn seal_nullifier_inserts(src_seal_txid:&[u8], src_seal_idx:u32) -> bool {
    let key = b2b256(&[src_seal_txid, &src_seal_idx.to_le_bytes()]);     // certified identity (F3)
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, Source::Input) {
            Ok(Some(th)) if th == LEAP_REGISTRY_TYPE_HASH => {           // canonical registry only (F2)
                if let Ok(w) = load_witness_args(i, Source::Input) {
                    if let Some(b) = w.input_type().to_opt() {
                        let d = b.raw_data();
                        return d.len() >= 32 && d[0..32] == key[..];     // registry's inserted key == this seal
                    }
                }
                return false;
            }
            Ok(_)  => i += 1,
            Err(_) => return false,    // canonical registry not spent in this tx -> fail closed
        }
    }
}
```

The consumer checks ONLY that the canonical registry is spent in-tx and that its inserted `key == seal`; it
**delegates** SMT soundness to the registry validator (preserving the AS-IS consumer/registry separation).

### 6.5 Closing the same-tx cross-type-group double-leap (MAJOR F7 — FIXED)

The A6 single-cell guard (`bau:186-187`) is **per type group** — it forbids two cells *in the same type group*
but does NOT forbid two cells in **different type groups** (different `args`, hence different type hashes) from
both leaping in one tx while each naming the **same** Cardano source seal. Two such cells would each pass their
own A6 check, each call `seal_nullifier_inserts`, and both could be "satisfied" by a single registry insert of
that one seal key.

v2 closes this by making the registry **account for EVERY leap in the tx, all distinct**:

- The **registry validator** is extended from a single-key insert to a **batch insert**: its witness carries a
  *list* of `(key, siblings)` entries, and it proves each key was absent under the running root and present
  after, threading the root through all of them. It rejects the tx unless the number of distinct keys it
  inserts **equals the number of leap cells** that name a seal in this tx. (Equivalently: deploy the registry
  so its update branch asserts `inserted_keys.len() == leap_consumer_count`, where the count is the registry's
  own tally of in-tx inputs whose type hash is a v2 `bound_asset` code hash spending on a leap branch.)
- Each leap consumer (`seal_nullifier_inserts`) requires **its own** seal key to be among the registry's
  inserted set. Because every inserted key must be **distinct** (the SMT non-membership proof forbids inserting
  the same key twice in one batch — the second non-membership proof fails against the post-first-insert root),
  two cells naming the **same** seal cannot both be accounted for: only one key exists for that seal, so at most
  one consumer's check can be satisfied. The second fails closed.

This makes "two cells, same seal, different type groups, one tx" impossible: the registry inserts that seal's
single key at most once, and the batch-count equality forbids a leap that the registry cannot individually
account for. (Implementation detail / residual integration check: RQ-8.)

### 6.6 Why only leaps insert

TRANSITION advances a `CkbOwned` cell along a lineage; its per-lineage UTXO consumption already gives
uniqueness. The cross-lineage double-spend (two `CardanoBound` cells, same seal) is only possible at the flip,
so the nullifier is required on S4/S5 only — GENESIS/TRANSITION/FINALIZE are untouched (back-compat §8). Plain
Cardano `Transfer` routes to TRANSITION (no nullifier insert), confirmed by the relayer `classify()`
(RQ-3).

---

## 7. Reorg / finality handling for the Mithril import (M2 — IMPLEMENTED, Option A)

> **CORRECTION + STATUS.** An earlier draft claimed M2 was unimplementable because "the LCKP / TxSetCert carry
> no slot source." **That was wrong.** The Mithril cert's signed message AUTHENTICATES the Cardano tip height:
> `latest_block_number` is a signed cert part, committed by `check_m1`'s `Sha256(parts) == signed_message` plus
> the BLS-STM aggregate. The verifier simply **discarded** it. M2 (Option A) is now implemented:

1. **`cert-verify` publishes the authenticated height.** It extracts `latest_block_number` from the signed
   parts and publishes `"LCKP" ‖ tx_root(32) ‖ latest_block_number(8 LE)` — 44 bytes (was 36)
   (`spike/light-client-cell/cert-verify/src/main.rs`). When the checkpoint is ADVANCED (a prior LCKP is spent
   in-group), the new height **must not regress** (monotonic; `return 16`).
2. **`bound_asset_v2` binds the leap to it.** `checkpoint_root()` reads the 44-byte format and returns
   `(root, height)`; a leap requires a non-zero authenticated finalized height (`return 6`). Verified in real
   CKB-VM (the in-VM leap + finalize suites run against 44-byte checkpoints).

### 7.1 Why this is the right-sized gate (Mithril already certifies FINALIZED data)
Mithril CardanoTransactions certifies **immutable-file (finalized) Cardano data** — the certified tx-set is
reorg-safe by construction, and `latest_block_number` is already a finalized height. The leap's reorg safety is
therefore *inherent* in Mithril's finality; Option A makes that finality **explicit and on-chain-checked** (an
authenticated height carried by a monotonic, non-regressing checkpoint) instead of an unstated assumption. A
literal `root_max_slot ≤ tip − K` gate would need a SEPARATE current-tip oracle (a two-checkpoint scheme) and is
largely **redundant** with Mithril's immutable-file finality — deliberately not built (it adds machinery, not
safety).

### 7.2 RQ-4 — RESOLVED (checkpoint singleton + fail-closed on conflict)
The LCKP checkpoint is a **type-id singleton**, so at most one LIVE cell carries `LCKP_TYPE_HASH` and a leap can
only reference the one canonical (latest) snapshot. As **defense-in-depth**, `checkpoint_root()` no longer
returns on the first match: it scans ALL cell-deps and **fails closed (`return 53`)** if two trusted checkpoints
disagree — a smuggled-in stale checkpoint can never make the verifier silently pick the wrong root. Proven in
real CKB-VM (`v2vmtest/tests/v2_hardening.rs::rq4_conflicting_checkpoints_rejected_53`). Combined with the
authenticated, monotonic finalized height (§7), M2 is fully closed.

---

## 8. Backward-compatibility proof

### 8.1 v1 and v2 are disjoint by construction

- Live v1 cells have data `seal_txid(32) ‖ seal_idx(4) ‖ state` with **no leading `0x02`**. The v2 `tag_of`
  rejects any cell whose `data[0] != 0x02` (`return 43`).
- v2 is a **new deployment** (new code_hash). v1 cells keep referencing the immutable old code_hash
  `0x42f74fbc`, so the live lifecycle anchors **execute unchanged on the v1 script**:
  - CKB Pudge: genesis `0x0318d35f` → transition `0x94d0620f` → finalize `0x795f4bb9` (`LIVE_STATUS.md`).
  - Cardano preview: mint `83dd51d2` → Transfer `a98b6636` → Unbind `6c729ea6`.
- No live v1 cell is ever evaluated by the v2 dispatcher, so **no live flow can be confused with a leap**. This
  is the clean correctness argument: v2 is additive, deployed alongside.

> The Cardano-side `seal_nft` edit (§5.1, F8) re-keys **future** policy-ids only. The live v1 seal policy
> `8855af1be1fd48ee096b72e91bee858db51b9ab75e866540c8647674` (`LIVE_STATUS.md:13`) was minted under the
> immutable original `seal_nft` code and is unaffected — see the regression note in §5.1.

### 8.2 Within v2, the three live modes stay unconfusable with the leaps

- **GENESIS (S1)** `(∅, CkbOwned)`: commitment is the **state-only** preimage `blake2b256(out_state)`
  (preserved from `bau:212`) — *not* `RC` — because there is no source-chain recipient at genesis. Now also
  pins the output lock slot (invariant LS, §2.4, `return 45`). Reached only when the input is absent.
- **TRANSITION (S2)** `(CkbOwned, CkbOwned)`: both tags `CkbOwned`, commitment state-only, output lock slot
  pinned (§2.4). A leap flips exactly one tag, so `(CkbOwned, CkbOwned)` can never be a leap.
- **FINALIZE (S3)** `(CkbOwned, ∅)`: out absent; a leap always recreates a cell. Further distinguished by
  `seal_at_lock == Some(false)` (`bau:237`) vs `LEAP_TO_CKB`'s `Some(true)`.

Mode confusion matrix:

| certified Cardano event | seal_at_lock | v2 branch | distinguisher |
|---|---|---|---|
| seal minted at lock, no CKB input | `Some(true)` | GENESIS (S1) | in absent |
| seal recreated at lock, CkbOwned in/out | `Some(true)` | TRANSITION (S2) | both `CkbOwned` |
| seal recreated at lock, CardanoBound→CkbOwned | `Some(true)` | LEAP_TO_CKB (S5) | tag flip + `RC`(source seal)/recipient + nullifier |
| seal minted at lock, CkbOwned→CardanoBound | `Some(true)` | LEAP_TO_CARDANO (S4) | tag flip + state-unchanged + out-commitment + nullifier |
| seal NOT recreated (Unbind) | `Some(false)` | FINALIZE (S3) | out absent |

The two `Some(true)` inbound cases (S2, S5) are separated by the **authenticated tag** (B2): S2 is
`CkbOwned→CkbOwned`, S5 is `CardanoBound→CkbOwned`. Without the tag (AS-IS) they are positionally identical —
that is precisely the confusion the tag-first dispatcher removes.

### 8.3 Cardano-side compat

`SealDatum` field 2 and `BindingRedeemer::LeapToCkb` are **append-only** (§4.1, `RECIPIENT_COMMITMENT.md` §3.1):
existing `Transfer`/`Unbind` Constr tags (121/122) and the 2-field datum are byte-identical; `seal_commitment()`
(`bau:66`) still reads field 1. The live builders need no change for the v1 instance; only v2-opted assets emit
3-field datums and use `LeapToCkb`. `Unbind` releases the seal to a plain UTxO and ignores the recipient field,
so leap-out via FINALIZE still passes `seal_at_lock == Some(false)`. The `seal_nft` redeemer change (§5.1) only
affects **new** v2 seal-policy deployments; v1 seal mints are immutable.

---

## 9. Consolidated error codes

| code | meaning |
|---|---|
| 7 | output (or input on a flip) cell `len < 70` (was `<36`) |
| 30 (args) | type-script args `< 56` (UNCHANGED from AS-IS — registry type hash is hardcoded, not an arg; F2) |
| 40 | illegal shape (not in S1–S5 whitelist) |
| 41 | `CardanoBound` input with no output (anchor cannot vanish) — specific diagnostic |
| 42 | GENESIS with `out.tag == CardanoBound` (must land `CkbOwned`) — specific diagnostic |
| 43 | bad version byte (`data[0] != 0x02`) |
| 44 | bad tag byte (`data[1] ∉ {0x01,0x02}`) |
| 45 | GENESIS/TRANSITION: output lock slot `[38..70]` != actual `load_cell_lock_hash` (invariant LS, F6) |
| 24 | S5: certified tx did not consume the `CardanoBound` SOURCE seal outpoint `(txid, idx)` — direct match (F3) |
| 25 | S5: seal not recreated at lock (`Some(false)`/`None`) |
| 26 | S5: recipient field (datum field 2) not 32 bytes |
| 27 | S5: `RC` mismatch (`commitment != blake2b256(state‖SOURCE seal‖recipient)`) |
| 28 | S5: cell-data lock slot `[38..70]` != committed recipient |
| 29 | S5: actual output lock hash != committed recipient (B3) |
| 46 | retired — the F3 idx cross-check is now intrinsic to codes 24/36 (direct `(txid, idx)` outpoint match) |
| 47 | S5: state changed across inbound flip (`in_state != out_state`, M3 symmetry) |
| 50 | S5: seal nullifier insert missing in canonical registry (B4) |
| 30 (lock) | S4: cannot load GroupInput lock hash |
| 31 | S4: actual input lock != `CkbOwned` committed owner-lock (invariant LS) |
| 32 | S4: state changed on flip (M3) |
| 33 | S4: `seal_prime` not minted to lock (M1) |
| 34 | S4: `CardanoBound` out_seal_txid != mint-tx hash |
| 35 | S4: lock slot not zeroed on `CardanoBound` output (§2.4) |
| 36 | S4: certified tx did not consume the old SOURCE seal outpoint `(txid, idx)` — direct match (F3) |
| 37 | S4: optional — `mint_qty(seal_policy,seal_name) != 1` (M1 freshness) |
| 48 | S4: empty datum on `CardanoBound` output (cannot certify commitment, F9) |
| 49 | S4: `CardanoBound` commitment != `blake2b256(out_state)` — state-only, live parity (F9) |
| 51 | S4: seal nullifier insert missing in canonical registry (B4) |

Note: codes `31`/`32` are **repurposed** in v2 — AS-IS `bau:186-187` used `31`/`32` for the A6 single-cell
guard. Because the v2 dispatcher (§3.2) keeps the A6 guard but reorders the flow, the A6 rejects are renumbered
to a free range (e.g. `38`/`39`) to avoid colliding with the S4 lock/state codes. (MINOR — flagged; pick the
final numbering at implementation time, RQ-9.) Existing AS-IS cert/witness/MMR codes 1–5 and
seal-txid/datum/commitment codes 8/9/10 are reused where semantics are unchanged.

---

## 10. Residual risks / open questions

- **RQ-1 (recipient slot width):** mint-leg recipient is a 28-byte Cardano credential; leap recipient is a
  32-byte CKB lock hash. The shared primitive fixes the slot at 32 bytes, **right-aligned, high bytes zero**
  (`RECIPIENT_COMMITMENT.md` §6.4). Freeze this so the two legs' `RC` preimages never collide.
- **RQ-2 (M1 freshness vs. reuse):** `seal_at_lock == Some(true)` proves policy presence; the `seal_nft` policy
  pin (§5.1, F8) proves it is *the* one-shot NFT. Freshness against re-park is additionally covered by the
  nullifier and the optional `mint_qty == 1` (`return 37`). Decide whether to require the optional check.
- **RQ-3 (Transfer vs. leap routing):** confirm the relayer `classify()` never routes a plain `Transfer` into
  a leap branch (only true tag-flips insert nullifiers); add an integration test that a `Transfer` produces no
  nullifier insert.
- **RQ-4 (M2) — RESOLVED.** The checkpoint now carries an AUTHENTICATED, monotonic finalized height (§7) and
  `checkpoint_root()` **fails closed on conflicting checkpoints** (`return 53`, §7.2), with the LCKP cell a
  type-id singleton. Proven in CKB-VM (`v2_hardening::rq4_conflicting_checkpoints_rejected_53`). A literal depth
  gate stays deliberately unbuilt (redundant with Mithril's immutable-file finality — §7.1).
- **RQ-5 (seal_idx authentication):** the SMT key folds the **certified** `src_idx` from `ins` (`bau:203`), not
  `in_data[34..38]`, and cross-checks them (`return 46`). Confirm `parse()` yields the consumed `(txid, idx)`
  for the specific seal outpoint on both S4 and S5 in integration (F3 closure depends on it).
- **RQ-6 (witness multiplexing):** the leap branches need BOTH the MMR proof (in the bound cell's
  `witness[0].input_type`, `bau:191`) and the registry insert proof (in the **registry cell's** witness, a
  different `Source::Input` index). With the F7 batch registry (§6.5) the registry witness carries a *list* of
  inserts; confirm no witness-index collision in integration.
- **RQ-7 (LeapToCkb vs FINALIZE naming):** `LEAP_TO_CKB` (inbound, Cardano→CKB) re-parks the seal
  (`Some(true)`) and reads the recipient datum; `FINALIZE` (outbound leap-out, CKB→Cardano) releases the seal
  (`Some(false)`) and reads no recipient. Keep them distinct in code and tests.
- **RQ-8 (cross-type-group same-seal batch) — RESOLVED (verifier-side one-leap-per-tx guard).** The single-key
  path was already DONE (canonical `burn_nullifier_registry`, genesis type-id singleton, 256-deep SMT, in-VM
  tested end-to-end in `v2vmtest::s5_leap_with_real_nullifier_registry`). The residual cross-type-group SAME-seal
  vector (two v2 instances genesis'd against one Cardano seal in one tx sharing a single nullifier insert) is now
  closed by `count_instances()`: `bound_asset_v2` rejects any tx carrying **more than one bound-cell of its own
  CODE among inputs (`return 51`) or outputs (`return 52`)** — identifying instances by code_hash spans all
  per-instance type groups, so batching is forbidden at the verifier (the chosen mechanism over a batch-aware
  registry). It runs before the cert, so a batched tx is rejected cheaply. Proven in CKB-VM
  (`v2_hardening::rq8_two_bound_inputs_rejected_51`). Unrelated co-occurring cells are ignored (own-code only),
  so no griefing.
- **RQ-9 (A6 code renumber):** v2 repurposes the cell-layout codes around `31`/`32`; the AS-IS A6 single-cell
  rejects (`bau:186-187`) must be renumbered to a free range. Pick the final mapping at implementation.
- **RQ-10 (mint-leg nullifier scope):** the keystone reuse on the Groth16 mint leg (`RECIPIENT_COMMITMENT.md`
  §6) is the **recipient commitment only**. The mint leg keeps its OWN seal nullifier (`seal_nullifier.ak` +
  `seal_thread` genesis pin), which the mint audit (`MINT_AUDIT.md`) already found sound (genesis-pinned
  singleton); the leap's canonical registry (§6.3) is a *separate* CKB-VM SMT. Confirm at deploy that the two
  nullifier domains stay distinct and neither registry pin is a soft per-instance arg.

---

## 11. Implementer's entry point

Start from `spike/phase1/bound_asset_unified.rs`:
1. add `load_cell_lock_hash` to the `high_level` import at `bau:10`;
2. add the hardcoded `LEAP_REGISTRY_TYPE_HASH` constant (§6.3) next to `LCKP_TYPE_HASH` (`bau:14`); keep args at
   the AS-IS 56 bytes (`bau:182-184`) — the registry type hash is NOT an arg (F2);
3. add `seal_recipient` next to `seal_commitment` (`bau:66`) and `seal_nullifier_inserts` (port `bgu:142-160`,
   keyed on the constant + the CERTIFIED `(src_txid, src_idx)`, F3);
4. replace the dispatcher at `bau:205-240` with the §3.2 tag-first match + `tag_of` (5 whitelist arms + the two
   specific-diagnostic arms 41/42 + catch-all 40);
5. keep GENESIS/TRANSITION/FINALIZE arms (add the invariant-LS lock-slot pin `return 45` to S1/S2, §2.4); add
   `leap_to_ckb` (§4.3) and `leap_to_cardano` (§5, including the F9 output-commitment cert);
6. re-lay cell data per §2.1 for v2-opted assets only (deploy a NEW code_hash; do not touch the live v1 script).

Reuse `burn_nullifier_registry.rs` as the seal-nullifier registry, extended for the F7 batch insert (§6.5);
deploy ONE canonical instance and bake its genesis type-id into `LEAP_REGISTRY_TYPE_HASH`. Cardano: append
`SealDatum.recipient_lock_hash` (field 2) and `BindingRedeemer::LeapToCkb` (Constr 123), add the `binding_lock`
`LeapToCkb` branch (`RECIPIENT_COMMITMENT.md` §5), and replace the inert `seal_nft` redeemer with the
policy-pin (§5.1, F8) — coordinating the new policy-id into the v2 `bound_asset` args. Extend the mint-leg
`BoundState` with a `commitment` field and assert `RC` in `leap_mint_guard` (`RECIPIENT_COMMITMENT.md` §6, F5).
Keystone `RC` (folding the SOURCE seal) is defined in `RECIPIENT_COMMITMENT.md`.
