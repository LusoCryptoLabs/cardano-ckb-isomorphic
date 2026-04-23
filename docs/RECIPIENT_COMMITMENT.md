# RECIPIENT_COMMITMENT.md — the shared recipient-commitment primitive (KEYSTONE)

**Status:** Implemented for the LEAP (Cardano `binding_lock.LeapToCkb` + CKB `bound_asset_v2`). §6 mint-leg
reuse is **SUPERSEDED** by an implementation finding (the mint-leg recipient binding is circuit-dependent, not
closeable by RC — see §6). (Repaired after adversarial review — F1, F3, F5, F8, F9 + minors.)
**Purpose:** Define ONE cryptographic primitive — the *recipient commitment* `RC` — reused verbatim by
two otherwise-independent cross-chain flows:

1. the **ownership-toggle leap** (`LEAP_TO_CKB`, Cardano→CKB), where the surviving CKB cell's lock must be
   the owner-intended recipient and not a relayer's lock (closes **B1**, gives the carrier **B3** needs); and
2. ~~the **Groth16 mint leg**~~ — **SEE §6:** grounding against the real code during implementation showed the
   mint-leg recipient binding (RECIP-1) is a **CIRCUIT** problem, NOT closeable by an on-chain RC. The keystone
   closes B1 on the **leap only** (whose source is owner-signed); the proof-authorized mint leg stays parked.

This document is the single definition of `RC`. `LEAP_BRIEF_V2.md` references it and does not duplicate it.

**Reading convention:** `bau:NNN` = `spike/phase1/bound_asset_unified.rs:NNN`;
`bl:NNN` = `cardano/binding/validators/binding_lock.ak:NNN`;
`sn:NNN` = `cardano/binding/validators/seal_nft.ak:NNN`;
`lmg:NNN` = `spike/ckb-to-cardano/groth16/validators/leap_mint_guard.ak:NNN`.
All line refs are verified against the live source in `C:\Users\telmo\chiral-study`.

---

## 0. The controlling AS-IS fact

The live deployed verifier (`bau`, code_hash `0x42f74fbc`) commits **state only**:

```
seal_commitment(datum) == b2b256(out_state)            // bau:212, out_state = out_data[36..] (bau:209)
```

Neither `seal` nor any recipient is in the live commitment preimage. The spec prose's 3-part preimage is
*aspirational* — the on-chain truth is `blake2b256(state)`, confirmed by the live genesis
(`commitment == blake2b256(S0)`, `LIVE_STATUS.md:17`). `RC` is therefore defined as a **strict superset** of
the live preimage: drop `source_seal` and `recipient_lock_hash` and it degenerates to `blake2b256(state)`. This
lets the same hash function and the same datum carrier serve both the legacy state-only modes
(genesis/transition, unchanged) and the recipient-bound leap, differing only in how the preimage is assembled.

---

## 1. The preimage (canonical — ONE definition, ONE seal: the SOURCE seal)

```
RC = blake2b256( state || source_seal || recipient_lock_hash )
```

Fixed-width concatenation, **no length prefixes**, fed to the same `b2b256` builder as `bau:26`
(`blake2b_ref`, 32-byte digest — the same family that produces Cardano txids and the live state commitment).

| field                 | width            | meaning                                                                                  |
|-----------------------|------------------|------------------------------------------------------------------------------------------|
| `state`               | variable (≥ 0)   | the CKB bound-cell business state — byte-identical to `out_state` on the destination cell |
| `source_seal`         | **36 bytes**     | `seal_txid(32) ‖ seal_idx(u32 LE)` — the **SOURCE seal outpoint being CONSUMED** (see §1.0) |
| `recipient_lock_hash` | **32 bytes**     | the destination identifier: the **CKB lock-script hash** that must own the surviving cell  |

### 1.0 `source_seal` is the seal being CONSUMED, never the destination seal (BLOCKER F1 — FIXED)

**This is the load-bearing correction.** `source_seal` is **always the seal outpoint that the leap CONSUMES**,
not the destination/output seal the leap creates. Concretely on `LEAP_TO_CKB` (Cardano→CKB):

- `source_seal` = the `CardanoBound` **input** cell's seal outpoint = `in_data[2..38]` on CKB
  (`seal_txid = in_data[2..34]`, `seal_idx = in_data[34..38]` LE). This is the seal that the certified Cardano
  spend *consumed*, and the CKB type script independently checks it was consumed (S5 step (b),
  `LEAP_BRIEF_V2.md` §4.3, `return 24` — mirrors the AS-IS transition check at `bau:218`).
- It is **NOT** `out_data[2..38]` (the destination seal the leap re-parks), because the destination seal txid is
  pinned to `th = blake2b256(tx_body)` at `bau:210` (S5 step (a), `return 8`). Folding that into `RC` would be
  **circular** — `RC` lives *inside* the very `SealDatum` carried by `tx_body`, so its preimage cannot contain
  `blake2b256(tx_body)`. It would also be **non-constructible**: the owner signs the Cardano spend *before* the
  CKB-tx-hash exists, so it cannot have committed to it.

The source seal is **known to the owner at Cardano-spend time** (it is the outpoint being spent) and is
**present in the certified tx inputs** (checked at code 24), so `RC` is constructible and verifiable. This
mirrors the mint leg, which already correctly uses the **source** seal `bs.ckb_seal` (`lmg:134`), never an
output-derived value.

> Removed contradiction: the previous draft's §1 said "source seal" but §4 recomputed over `out_data[2..38]`
> (the destination seal). Both §1 and §4 now use `in_data[2..38]` (the source seal) consistently.

### 1.1 Why `source_seal` is in the preimage

Folding the consumed source-seal outpoint into `RC` makes the commitment a **domain separator**: a recipient
commitment minted for the consumption of seal `A` cannot be replayed to release a different seal `B`, because
`RC` would not match. This is exactly the binding the cross-leg nullifier (`LEAP_BRIEF_V2.md` §6) relies on —
one consumed seal outpoint authorizes at most one surviving cell, and `RC` ties the *recipient* of that cell to
*that* consumed seal. The nullifier key (§6 of the brief) and the `RC` `source_seal` field are derived from the
**same** authenticated source-seal identity, so they cannot disagree.

**Hash family is load-bearing.** `RC` uses `blake2b256` (`b2b256`, `bau:26`). Blake2s
(`b2s`, `bau:27`) stays confined to the MMR merge and master leaf (`bau:25,201`). Do not cross them; mixing
the families breaks every existing proof.

### 1.2 The leap's commitment vs. the live state-only commitment (resolved)

The destination CKB cell stores its destination seal in its own data header (`out_data[2..38]`, pinned to the
tx hash) and stores `recipient_lock_hash` in its own data lock slot (`out_data[38..70]`; see
`LEAP_BRIEF_V2.md` §2). On the leap-in path the type script does **not** reuse the state-only check at
`bau:212`; it runs the explicit `RC` recomputation in §4 below, using the **source** seal `in_data[2..38]`. The
two checks are kept separate on purpose:

- **GENESIS / TRANSITION** keep `seal_commitment(datum) == b2b256(out_state)` (`bau:212`) **byte-for-byte
  unchanged** (there is no source-chain recipient to bind at genesis; the binder is the genesis tx itself).
- **LEAP_TO_CKB / the mint leg** use the explicit 3-part `RC` recomputation over the **source** seal.

This avoids `minimal_reuse`'s "fold the recipient into `out_state` and add a reconciliation check" approach,
which created an ambiguity between legacy untagged state and tagged state. Here the preimages are explicit and
the version byte (`LEAP_BRIEF_V2.md` §2) keeps v1 and v2 cells disjoint, so there is no ambiguity to resolve.

---

## 2. Who signs it, on which chain

`RC` is only trustworthy if the **current owner** of the asset authorizes *where it lands*. There is **no new
signature scheme** — each chain reuses its existing spend-authorization:

- **Cardano → CKB (leap-in, and the basis of B1):** the signer is `SealDatum.owner`, the VKH already
  AND-ed into **every** binding-lock spend (`signed = list.has(self.extra_signatories, owner)`, `bl:35-36`).
  The recipient rides inside the seal output's continuing inline datum, so the owner's required signature over
  the spend transitively authorizes the datum it produces, and `tx_hash = blake2b256(T_body)` covers it. The
  owner is spending the **source** seal (the outpoint folded into `RC`), so the owner provably knows it.

- **CKB → Cardano (mint leg):** the signer is whoever authorizes the CKB `cardano_bound` spend; the recipient
  is already inside `bs.state` (`lmg:131-133`) and the source seal is `bs.ckb_seal` (`lmg:134`), both covered by
  the Groth16 leap proof. v2's only change is to make the guard assert the **same** `RC` equality over the
  source seal `bs.ckb_seal` instead of trusting a bare slice (§6).

---

## 3. How `RC` is carried in the Mithril-certified Cardano body

`RC` rides as the **`commitment` field of the continuing `SealDatum`** — the exact channel the live system
already certifies. The CKB side parses output-0's inline datum out of `tx_body` (`bau:53-58`) and
`seal_commitment()` extracts the commitment positionally (`bau:66`). Because `tx_hash` covers inline datums
(`BINDING_SPEC.md:136-138` explicitly forbids aux metadata), `RC` is inside the certified preimage with **no
new carrier mechanism**.

The **recipient itself** (the 32-byte lock hash) is *additionally* carried as a **new explicit `SealDatum`
field, appended LAST** (field index 2). It is redundant-but-authenticated:

- `RC` (field 1) binds the recipient **cryptographically** (it is in the hash preimage).
- the explicit `recipient_lock_hash` (field 2) makes the recipient **parseable** without brute-forcing the
  preimage, so the CKB side can both *recompute* `RC` and *read* the recipient to pin the output lock.

### 3.1 SealDatum wire layout (v2)

AS-IS, `SealDatum` is 2 fields (`bl:19-22`):

```aiken
pub type SealDatum {
  owner: ByteArray,        // field 0 (bl:20)
  commitment: ByteArray,   // field 1 (bl:21) = blake2b256(state || seal) per the live builders
}
```

v2 appends field 2 (append-only):

```aiken
pub type SealDatum {
  owner: ByteArray,               // field 0 — UNCHANGED (bl:20); seal_commitment skips this
  commitment: ByteArray,          // field 1 — UNCHANGED POSITION (bl:21); = RC on a leap, = b2b256(state||seal) on transfer/genesis
  recipient_lock_hash: ByteArray, // field 2 — NEW, appended LAST; 32B on a leap, absent on transfer/genesis/unbind
}
```

CBOR: `Constr 121 [owner, commitment, recipient_lock_hash]`.

**APPEND-ONLY is mandatory.** The CKB positional parser `seal_commitment()` (`bau:66`) reads the **Constr
header, then the array header, then `skip()`s field 0 (owner) and reads field 1 as the commitment**. Inserting
the recipient *before* `commitment` would silently shift the commitment read to the recipient bytes and break
genesis/transition with `return 10`. Appending as field 2 leaves the field-1 read untouched — verified against
`bau:66`. The 2-field datums emitted by the live genesis/transfer builders remain valid: `seal_commitment`
still reads field 1, and field 2 is simply absent.

---

## 4. How the destination decodes + asserts it (CKB side — the leap-in)

On `LEAP_TO_CKB` (`LEAP_BRIEF_V2.md` §4), after the shared double-MMR certification (`bau:199-202`) and
`parse()` (`bau:203`), the CKB type script does:

```rust
// destination CkbOwned output cell data (v2 layout, LEAP_BRIEF_V2.md §2):
//   [0] version=0x02 | [1] tag=CKB_OWNED | [2..34] dest_seal_txid | [34..38] dest_seal_idx(LE)
//   | [38..70] recipient_lock_hash | [70..] state
// SOURCE CardanoBound input cell data (the seal being CONSUMED):
//   [2..34] src_seal_txid | [34..38] src_seal_idx(LE)
let out_state    = &out_data[70..];
let source_seal  = &in_data[2..38];                // src_seal_txid(32) ‖ src_seal_idx(4) — the SOURCE seal (F1)

// 1) recover the owner-signed, Mithril-certified fields from the continuing SealDatum:
let rc_claimed = seal_commitment(&datum);          // field 1 (existing reader, bau:66) = RC
let r_claimed  = seal_recipient(&datum);           // field 2 (NEW reader, §4.1) = recipient_lock_hash
if r_claimed.len() != 32 { return 26; }

// 2) KEYSTONE: recompute RC over the cell's own state, the SOURCE seal it consumes, and the claimed recipient:
let rc_local = b2b256(&[out_state, source_seal, &r_claimed]);
if rc_claimed.as_slice() != &rc_local[..] { return 27; }   // recipient bound to (state, SOURCE seal), owner-signed+certified

// 3) cell-data lock slot must equal the committed recipient:
if &out_data[38..70] != r_claimed.as_slice() { return 28; }

// 4) THE TEETH (B3): the ACTUAL on-chain output lock must equal the committed recipient — NEW host call:
let actual = load_cell_lock_hash(0, Source::GroupOutput).map_err(|_| 29)?;   // absent in AS-IS (bau:10)
if actual[..] != r_claimed[..] { return 29; }              // reject relayer/anyone-can-spend lock
```

Steps 2+3+4 force the surviving `CkbOwned` cell's *actual lock* to be the owner-signed recipient committed
under the Mithril-certified body. A relayer cannot substitute its own lock without breaking
`rc_claimed == rc_local` (which is owner-signed and certified) — closing **B1**. Step 4 is the first time the
type script ever reads the on-chain lock (`load_cell_lock_hash` is absent from the import list at `bau:10`) —
closing **B3**.

Note that `source_seal` (`in_data[2..38]`) is the SAME outpoint the type script independently proves was
consumed by the certified Cardano tx (S5 step (b), `return 24`) **and** the SAME outpoint nullified in the
registry (`LEAP_BRIEF_V2.md` §6). One authenticated source-seal identity feeds `RC`, the consumption check, and
the nullifier — they cannot diverge.

### 4.1 New positional reader `seal_recipient` (CKB)

A mirror of `seal_commitment` (`bau:66`) that reads field 2 instead of field 1:

```rust
fn seal_recipient(d: &[u8]) -> Vec<u8> {
    let (_t,_x,ti) = hdr(d, 0);                       // Constr header
    let (_a,_n,ai) = hdr(d, ti);                      // array header
    let j0 = skip(d, ai);                             // skip field 0 (owner)
    let j1 = skip(d, j0);                             // skip field 1 (commitment)
    let (_c, cl, ca) = hdr(d, j1);                    // field 2 = recipient bytes
    if ca + cl as usize > d.len() { return Vec::new(); }   // bounds-checked, fail closed
    d[ca..ca + cl as usize].to_vec()
}
```

`seal_recipient` is invoked **only on the leap-in path** (a 3-field datum). On 2-field genesis/transfer
datums it is never called, so the append-only field cannot break those paths. `hdr`/`skip` are the existing
helpers at `bau:38,42`.

---

## 5. Cardano-side validator enforcement (the binding lock gains exactly one check)

The lock stays thin (it cannot verify CKB state — the asymmetry invariant, `BINDING_SPEC.md:20-23`) but
gains the recipient enforcement, the only place it can be enforced on Cardano. The new `LeapToCkb` branch is
modeled on the existing `Transfer` branch (`bl:38-57`):

```aiken
LeapToCkb { recipient_lock_hash: r } -> {
  // (same as Transfer) owner-signed, exactly ONE continuing seal output at this lock
  expect Some(own_in) = list.find(self.inputs, fn(i){ i.output_reference == own_ref })
  let own_addr = own_in.output.address
  let conts = list.filter(self.outputs,
                fn(o){ o.address == own_addr && has_seal(o, seal_policy, seal_name) })   // has_seal: bl:29-31
  when conts is {
    [cont] -> when cont.datum is {
      InlineDatum(d) -> {
        expect SealDatum { commitment: new_c, recipient_lock_hash: cont_r, .. }: SealDatum = d
        signed
          && bytearray.length(new_c) == 32     // commitment well-formed — UNCHANGED invariant (bl:51)
          && bytearray.length(cont_r) == 32     // recipient well-formed
          && cont_r == r                        // datum recipient == owner-SIGNED redeemer recipient
      }
      _ -> False
    }
    _ -> False
  }
}
```

What the lock guarantees: the owner authorized this leap; exactly one seal continues at the lock; the
continuing datum carries a well-formed 32-byte commitment **and** the owner-signed recipient. What it does
**not** (and cannot) check: that `commitment == RC(state, source_seal, recipient)` and that the CKB output lock
equals the recipient — those are CKB-only (§4). This preserves directionality (Cardano never verifies CKB). The
existing `length(new_c) == 32` invariant (`bl:51`) is untouched.

---

## 6. The Groth16 mint leg (RECIP-1) — NOT closeable by RC (implementation finding)

> **CORRECTION (found during implementation, 2026-06-10).** The original §6 below claimed RC could be
> "reused verbatim" by the mint leg to close RECIP-1. Grounding it against the real code shows it CANNOT, and
> an on-chain RC field there would be a **redundant no-op**:
>
> - The **leap (S5)** binds the recipient by an OWNER SIGNATURE on its Cardano source — a key signs the
>   `SealDatum` (`binding_lock.ak:35-36`). RC ties the recipient to that signature; the recipient is in
>   owner-signed, Mithril-certified data, not a witness.
> - The **mint leg** source is CKB and its authorization is the GROTH16 PROOF. The recipient lives in
>   `bs.state[16..28]` (`leap_mint_guard.ak:133`), where `bs.state == new_state` (`cardano_bound.ak:142`) and
>   `new_state` is a **FREE WITNESS** in the leap circuit (`MINT_AUDIT.md`, INFL-1/VERIF-1). The existing
>   `commitment(new_state, seal) = blake2b256(new_state ‖ seal)` (`cardano_bound.ak:34,146`) is ALREADY bound
>   into the proof's public inputs, and `new_state` already contains the recipient — so the recipient is
>   already committed. Folding it again into `RC = blake2b256(state ‖ ckb_seal ‖ recipient)` re-hashes bytes
>   already inside `state`; the prover simply sets `new_state` (incl. recipient) and the RC consistently,
>   binding **nothing new**.
>
> **Conclusion:** RECIP-1 on the mint leg is purely a **CIRCUIT** problem, identical in kind to the amount gap
> (INFL-1): the circuit must constrain `new_state`'s recipient (and amount) to the CKB-side beneficiary's
> verified intent — `leap_windowed.rs` must decode the seal-tx, not witness `new_state` freely. No on-chain
> datum change closes it. The keystone RC is therefore specific to **owner-signed-source** flows (the leap).
> **§6.1–6.4 below are SUPERSEDED and were not implemented; the mint leg stays parked** (not value-ready for
> amount OR recipient). RQ-1 (recipient slot-width collision between the two legs) is consequently moot.

### 6.1 (SUPERSEDED — see correction above) The actual mint-leg datum

The previous draft referenced a non-existent `BoundState.commitment` field. The **real** mint-leg datum is
(`lmg:27-31`):

```aiken
pub type BoundState {
  ckb_seal: ByteArray,   // the SOURCE seal (the CKB anchor being consumed) — this is RC's source_seal
  state: ByteArray,      // financial state: amount(16 LE) ‖ recipient_credential(28) (lmg:131-133)
}
```

There is **no `commitment` field on `BoundState`**. Today `leap_mint_guard` reads
`recipient = builtin.slice_bytearray(16, 28, bs.state)` (`lmg:133`) — a bare 28-byte Cardano payment credential
sliced out of `bs.state` with **no owner-binding of that recipient on the source chain** — and tallies
`to_recipient` to it (`lmg:135-141`). The `ckb_seal` (`lmg:134`, used as the `LeapFact.nonce` and the nullifier
key in `seal_consumed`, `lmg:53-75`) is the SOURCE seal, exactly the seal `RC` must commit to.

### 6.2 Carrying `RC` on the mint leg

Because `BoundState` has no commitment field, v2 carries `RC` on the mint leg by **extending the datum with a
`commitment` field** (append-only, mirroring §3.1 on the Cardano binding side). The `cardano_bound` CKB spend
validator (which the Groth16 leap proof authenticates) must emit `commitment = RC(state, ckb_seal, recipient)`
where `recipient` is the **Cardano** destination credential (right-aligned to 32 bytes per §6.4):

```aiken
pub type BoundState {
  ckb_seal: ByteArray,     // field 0 — UNCHANGED — the SOURCE seal
  state: ByteArray,        // field 1 — UNCHANGED — amount(16) ‖ recipient_credential(28)
  commitment: ByteArray,   // field 2 — NEW (append-only) = RC(state, ckb_seal, recipient_slot)
}
```

`leap_mint_guard` then recomputes `RC` over the certified `BoundState` and asserts it equals the carried
`commitment` **before** tallying `to_recipient`. Mechanically identical to §4 steps 1–2, using the SOURCE seal
`bs.ckb_seal`:

```aiken
// in LeapInMint, replacing the BARE slice at lmg:133 with an RC-checked read:
let recipient_slot = right_align32(builtin.slice_bytearray(16, 28, bs.state))   // 28→32, high bytes 0 (§6.4)
let rc_local       = recipient_commitment(bs.state, bs.ckb_seal, recipient_slot) // SOURCE seal = bs.ckb_seal
expect rc_local == bs.commitment                         // bind recipient to (state, SOURCE seal), proof-authenticated
let recipient = builtin.slice_bytearray(16, 28, bs.state)
let fact = LeapFact { amount, recipient, nonce: bs.ckb_seal }
// ... then the existing to_recipient tally (lmg:135-141) is now justified
```

So a single Rust `fn recipient_commitment(state:&[u8], source_seal:&[u8;36], recip:&[u8;32]) -> [u8;32]` and a
single Aiken `fn recipient_commitment(...)` are the only two implementations, shared verbatim across leap and
leg — and **both** take the SOURCE seal (`in_data[2..38]` on the leap, `bs.ckb_seal` on the leg).

> Deploy note: extending `BoundState` re-derives the `cardano_bound` datum schema. Live v1 mint-leg flows
> (if any are deployed) keep their immutable code; v2 mint-leg is a NEW deployment alongside, like the binding
> side (`LEAP_BRIEF_V2.md` §8).

### 6.3 `source_seal` symmetry

The primitive is symmetric: `source_seal` is always the seal being **consumed** on the source chain, and
`recipient_lock_hash` always holds **whichever chain's destination identifier**. On `LEAP_TO_CKB` the source is
the Cardano-side `CardanoBound` seal and the recipient is a CKB lock hash; on the mint leg the source is the CKB
anchor `bs.ckb_seal` and the recipient is a Cardano credential. Neither ever folds a destination-derived seal.

### 6.4 Padding convention (frozen)

The leap recipient is a **32-byte** CKB lock hash; the mint-leg recipient is a **28-byte** Cardano payment
credential. The primitive fixes the slot at **32 bytes** and **right-aligns** the 28-byte case (4 high bytes
zero): `recipient_slot = 0x00000000 ‖ credential(28)`. Implementers MUST freeze this one convention so the two
legs' `RC` preimages can never collide. (Residual question RQ-1 in `LEAP_BRIEF_V2.md` §10.)

---

## 7. Exact byte layouts (reference)

### 7.1 `RC` preimage (the bytes fed to `b2b256`)

```
+-------------------+--------------------+--------------------------+
|  state (variable) | src_seal_txid (32) | src_seal_idx (4, u32 LE) |  recipient_lock_hash (32)
+-------------------+--------------------+--------------------------+--------------------------+
        N bytes              32 bytes              4 bytes                      32 bytes
\_________________________________ blake2b256 over the whole concatenation _______________________/
                                     = RC (32 bytes)
        (src_seal = the CONSUMED source seal: in_data[2..38] on the leap, bs.ckb_seal on the leg — F1)
```

### 7.2 SealDatum CBOR (v2)

```
Constr 121 [ bstr owner, bstr commitment(=RC, 32), bstr recipient_lock_hash(32) ]
            └ field 0 ─┘ └ field 1 (skip 1) ────┘ └ field 2 (skip 2) ──────────┘
            seal_commitment reads field 1 ─────────┘
            seal_recipient  reads field 2 ──────────────────────────────────────┘
```

### 7.3 Destination CkbOwned cell data + SOURCE CardanoBound input (where §4 reads from)

```
DESTINATION (output, CkbOwned):
[0]  version 0x02
[1]  tag     0x02 (CKB_OWNED)
[2..34]   dest_seal_txid (32)       ─┐ pinned to blake2b256(tx_body) at bau:210 — NOT used in RC (would be circular)
[34..38]  dest_seal_idx  (u32 LE)   ─┘
[38..70]  recipient_lock_hash (32) ─── cell-data lock slot (§4 step 3) == load_cell_lock_hash (§4 step 4)
[70..]    state                    ─── out_state used in RC recompute (§4 step 2)

SOURCE (input, CardanoBound) — supplies the seal folded into RC:
[2..34]   src_seal_txid (32)        ─┐ source_seal used in RC recompute (§4 step 2), checked consumed at code 24
[34..38]  src_seal_idx  (u32 LE)    ─┘ and nullified in the registry (§6 of the brief)
```

---

## 8. Error codes introduced by the keystone (CKB leap-in path)

| code | meaning                                                                     |
|------|-----------------------------------------------------------------------------|
| 26   | recipient field (datum field 2) not exactly 32 bytes                        |
| 27   | `RC` mismatch: `commitment != blake2b256(state ‖ source_seal ‖ recipient)`  |
| 28   | cell-data lock slot `[38..70]` != committed recipient                       |
| 29   | actual output lock hash (`load_cell_lock_hash`) != committed recipient (B3) |

(Full v2 code map is in `LEAP_BRIEF_V2.md` §9.)

---

## 9. Security properties

- **Recipient authenticity (B1):** `RC` is in the Mithril-certified `tx_hash` and is authorized by the owner's
  required signature (`bl:35-36`). A relayer cannot change the recipient without invalidating the certified
  commitment.
- **Constructibility (B1, F1):** `RC` folds only fields known at Cardano-spend time — `state`, the **source**
  seal being consumed, and the owner-chosen recipient. It never folds the destination seal (which is
  `blake2b256(tx_body)`), so there is no hash-of-the-tx-that-carries-it circularity.
- **No misdirection (B3):** the surviving cell's *actual* lock is pinned to the committed recipient via the
  new `load_cell_lock_hash` call (§4 step 4) — the relayer building the CKB tx cannot point the cell at itself.
- **Seal domain separation:** because the **source** seal is in the preimage, a recipient commitment for the
  consumption of one seal cannot be reused for another, reinforcing the one-seal→one-outcome guarantee of the
  nullifier. `RC`'s `source_seal`, the code-24 consumption check, and the nullifier key are the same identity.
- **Directionality preserved:** Cardano enforces only owner-auth + recipient well-formedness + presence; the
  semantic `RC`↔state↔lock binding is enforced exclusively on CKB (the only side that verifies Cardano).
- **Backward-compat:** genesis/transition keep the state-only commitment (`bau:212`) unchanged; 2-field datums
  and the field-1 commitment read are untouched (§3.1).
