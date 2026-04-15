> **Where are we? → [`STATUS.md`](./STATUS.md)** is the single source of truth: what's done, proven, and
> blocked, plus the Findings & Decisions log (read it before re-investigating anything).

# DEX integration: a bridged token that is JoyID-visible (CKB) and wallet-visible (Cardano)

Drop-in builders to make a leaped asset a **standard, tradeable, metadata-bearing token** on both chains —
CKB **xUDT** (JoyID/CCC render it) and Cardano **CIP-68** (Eternl/Lace render it). Lifted and adapted from
the live patterns in `tecmeup123/cardano-ckb-bridge` (`ckb-testnet-register-tokeninfo.mjs`, `validators/
wckb_mint.ak`), re-shaped for the Chiral binding protocol's verifier and for **financial-grade** use.

```
token.config.mjs     — one config: name/symbol/decimals + code hashes + bridge owner + JoyID/Cardano params
ckb_leap_token.mjs   — CKB: genesis+token-info (co-minted), per-leap mint to a JoyID lock, leap-out burn
cardano_cip68.mjs    — Cardano: CIP-67 labels, asset names, CIP-68 metadata datum for the (100) reference NFT
guard/               — the on-chain leap-mint guard (CKB script + Cardano validator) + MAPPING_SPEC + tests
ui/                  — React+TS DEX front-end: JoyID (CKB xUDT) + Cardano CIP-30, live caps/pause, leap form
```

## Read this first — what "financial-grade" means here

A token builder is **not** a financial-grade system on its own. The guarantees that protect money are
**on-chain**; these off-chain files only *construct* transactions. Here is exactly where each invariant lives:

| Invariant (why it matters) | Enforced by | Status |
|---|---|---|
| **No inflation** — a mint of `+A` to `R` requires a verified leap of exactly `A` to `R` | **on-chain owner script** (the leap-mint guard, §2) | **you must build + audit** |
| **Replay-once** — each leap event mints at most once | **on-chain** (nonce/seal/checkpoint monotonicity) | **on-chain** (BoundAsset/checkpoint) |
| **Burn-exactness** — leap-out releases exactly what was burned | **on-chain** (burn accounting + the release verifier) | **on-chain** |
| **Decimals correct & immutable** — matches the source asset | config + token-info/CIP-68 datum (immutable after genesis) | ✅ these files |
| **Integer-only amounts** (no float rounding, u128 bound) | builder (`toBaseUnits`, `u128le`) | ✅ these files |
| **Atomic recipient** — minted straight to the user's lock | builder (`recipientLock = JoyID lock`) | ✅ these files |
| **Metadata binds & renders** — JoyID/explorer show name/symbol/decimals | builder (Unique cell co-minted under owner mode at genesis) | ✅ these files |
| **Owner ≠ key** — no privileged mint key | config (`bridgeLockHash` = script) + owner script | ✅ config; ⚠️ verify you didn't set a key |

**Bottom line:** these files make the token *correct and visible*; the **on-chain leap-mint guard (§2) is the
load-bearing financial component** and is the thing that must be implemented against your verifier and audited
before real funds. Don't mistake "renders in JoyID" for "safe to hold value."

## §2 — the on-chain leap-mint guard (the part that must be airtight)

The xUDT `owner` (config `bridgeLockHash`) must be a **script** that authorizes a mint/burn **only** when the
same tx carries a valid leap proof. Concretely, for the Chiral binding protocol, the owner = a type/lock script that:

- **Leap-in (mint):** accepts an `xUDT` net mint of `+A` to lock `R` **iff** the tx also satisfies the
  `BoundAsset` leap-in / transition verification (Mithril cert + commitment) proving that exactly `A` units
  leaped to `R`, and the leap event (seal/commitment/nonce) is consumed **once** (monotone checkpoint /
  spent-seal). Reject any mint not so backed → **no inflation, no replay**.
- **Leap-out (burn):** accepts a net burn of `-A` **iff** it records the burn for the source-chain release of
  exactly `A` (the existing burn-gated-unlock / Groth16-of-burn path), once.
- **No other mint path.** Owner mode must not be reachable by any key-only tx.

This is the same shape as `cardano-ckb-bridge`'s `bridge_lock` owner of wADA, but gated on the **isomorphic
verifier** instead of the committee. Reuse/extend `spike/phase1/bound_asset_unified.rs` as this guard.

## §3 — CKB / JoyID specifics

- Mint the xUDT **to the user's JoyID lock** (`recipientLock`). JoyID is CCC-based, so it reads the **Unique
  token-info cell** for name/symbol/decimals — which `genesisWithTokenInfo()` co-mints in the **same
  owner-mode tx** (the only arrangement explorers/JoyID bind metadata from; do it at genesis).
- **Occupied capacity:** an xUDT cell locks ~`minTokenCellCkb` (≈142–145) CKB as state rent. Surface this in
  your DEX UX — the user needs that CKB to *hold* the token, and gets it back when the cell is consumed. For a
  financial app, show "X token + Y CKB reserved," not a bare token balance.
- Amounts: pass display strings to `toBaseUnits()`; never floats.

## §4 — Cardano / wallet specifics

- Use CIP-68: the **(100) reference NFT** carries `cip68MetadataDatum()` inline; the **(333) FT** is the
  tradeable balance. Wallets resolve (333)→(100) and render it. Mint the reference NFT **once**, in the
  genesis (state-NFT) tx; mint the FT only via the verified-leap `MintWrapped` path (`amount == claim.amount`).
- CIP-26 off-chain registry is a dead end for script policies — don't attempt it.

## §5 — Financial-grade go-live checklist (before any real value)

These files give you ✅ the first five; the rest are **required** and out of scope of a builder:

1. ✅ correct decimals/metadata, integer amounts, JoyID/Cardano visibility, atomic recipient.
2. ✅ owner = enforcing script (verify the config hash is a script, not a key).
3. ✅ token-info bound at genesis under owner mode — **proven in the real VM**: a genesis tx co-mints the
   xUDT and the **real Unique token-info cell** (binary fetched from Pudge) in one owner-mode tx; the Unique
   type-id binding is enforced (a wrong type-id is rejected). See `guard/integration` `genesis_*` tests.
4. ✅ **the on-chain leap-mint guard (§2) — BUILT, both sides** (`guard/`): the conservation logic
   (no-inflation / exact-burn / replay-once) is implemented and **unit-tested 22/22** on CKB
   (`guard/core` `cargo test`) and **19/19** in Cardano `lib/leap_guard.ak` (`aiken check`); the wiring
   compiles — CKB `guard/ckb_script` (riscv64, the xUDT-owner lock) + Cardano `validators/leap_mint_guard.ak`.
5. ✅ **conservation tests**: the adversarial battery (over-mint, under-mint, diverted, replay, zero,
   hidden-burn; under/over-burn, mint-on-burn, replay) passes on both chains.
6. ✅ **bound to the REAL verifier layouts + the REAL xUDT, tested in the real VM** (no mock). The CKB guard
   reads the actual `bound_asset_unified.rs` bound-cell (`seal32‖idx4‖state`, state = `amount16‖recipient32`);
   the Cardano guard reads the actual `cardano_bound.BoundState` datum. The CKB tests run the **actual
   deployed xUDT binary** (fetched from Pudge, `guard/integration/fixtures/xudt_testnet.bin`) as the token's
   type script — owner-mode args = the guard's own script hash (the guard matches xUDT by code-hash + owner,
   so there is no circular dependency) — plus the real Unique cell, all in **ckb-testtool's VM: 16/16**.
   Leap-in mint (accept exact; reject inflation / under-mint / leakage), leap-out burn (accept exact; reject
   under-burn), genesis token-info co-mint (accept; reject wrong type-id), the real xUDT's own rule (reject a
   non-owner supply increase), and the caps/pause battery below.
7. ✅ **operational controls — caps + pause/halt, BUILT both sides.** A per-leap **cap** + **floor** and a
   global / per-direction **pause** live in `leap-guard-core::enforce_policy` (shared logic), read on CKB
   from an admin **policy cell** (cell-dep, args `…‖policy_hash`) and on Cardano from an admin **policy
   reference input** (`chiral_policy.ak`, governor-updatable). Enforced in the **real CKB-VM** (over-cap /
   under-min / global-pause / pause-in reject, pause-out leaves leap-in flowing — part of the 16/16) and in
   Cardano (`enforce_policy` 7/7 + `chiral_policy` 4/4). The policy can only *further restrict* — conservation
   always holds regardless.
8. ✅ **decimals/amount mapping locked** (`guard/MAPPING_SPEC.md`): one integer encoding on the value path —
   `u128` base units, **16-byte LE**, decimals are display-only metadata (immutable after genesis), recipient
   is chain-native width (32 CKB / 28 Cardano). The LE byte order is pinned by cross-chain test vectors so
   `u128::from_le_bytes` (CKB) and `bytearray_to_integer(False,…)` (Cardano) agree; no scaling/rounding step
   exists on the value path.
9. 🟡 **go live on testnet** — *tooling built, execution needs your keys*. The deploy + relayer path is now
   built and validated (`DEPLOY.md`): `ui/scripts/deploy_ckb.mjs` deploys the guard + policy to Pudge and
   prints the config block (offline-validated); `ui/scripts/deploy_cardano.md` is the deterministic
   `aiken blueprint apply` runbook; `relayer/` is the watch→prove→submit skeleton (LeapEvent parsing on the
   real MAPPING_SPEC layout); the UI has the real sign+broadcast plumbing (`ui/src/ckb/submit.ts`). What
   remains is **operational, not code**: run the deploy scripts with funded Pudge/Preview keys, connect the
   Mithril/Groth16 proving backends to the relayer, and wire the live out-points into `config.ts`. The
   verifiers themselves are already deployed + proven on the live testnets.
10. ⚠️ **third-party audit** of the guard + the bridge verifier, and mainnet param review (finality depths,
   fees, capacity, cap sizing) — required before any real value; not something I can produce.

Build status: items 1–8 are ✅ **done and tested**; 9 is 🟡 (the deploy/relayer/submit code is built; what's
left is running it with funded keys + connecting the provers — operational, not code); 10 is an external
audit. The token is **visible, correctly shaped, conservation- + caps/pause-guarded, proven in the real VM,
and has a complete deploy path** — treat as testnet / DEX-listing-prep until 9–10 close before real value.
