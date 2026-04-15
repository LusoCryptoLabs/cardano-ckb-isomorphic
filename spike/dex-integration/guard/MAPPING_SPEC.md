# Amount & decimals mapping — the canonical value contract (no truncation, no float)

This pins **exactly** how a leap's value is represented end to end, so that the CKB script, the Cardano
validator, and the off-chain builder all agree on every byte. It is the artifact the "decimals/amount
mapping review" (README §5 item 8) requires: there is **one** integer encoding on the value path and **no**
conversion that can round or truncate.

## The amount

- **Type:** `u128`, the token's **base units** (an integer). It is the smallest indivisible unit; there are
  no fractional amounts anywhere on-chain.
- **Decimals** are *display metadata only* — they live in the CKB **token-info** cell and the Cardano
  **CIP-68 (100)** datum, and are **immutable after genesis**. The decimals value never participates in any
  on-chain arithmetic; it only tells a wallet where to render the decimal point. `display = base_units /
  10^decimals` is a **UI-only** operation.
- **Serialization:** little-endian, **exactly 16 bytes**. This is the only numeric encoding on the value
  path. Pinned by `leap-guard-core`:
  - `encode_amount_le(1)   == [01,00,…,00]`
  - `encode_amount_le(256) == [00,01,00,…,00]`
  - CKB decodes with `u128::from_le_bytes`; Cardano decodes with `builtin.bytearray_to_integer(False, …)`
    (`False` = little-endian) — verified to agree on the same bytes (`leap_guard.ak` +
    `leap-guard-core` `amount_is_little_endian_canonical`).

## The verified state layout (per chain)

The amount is the first field of the verifier's financial `state`; the recipient follows and is
**chain-native width** (a different identifier type on each chain, so the widths differ — this is the
mapping detail most likely to be gotten wrong):

| Chain   | Source           | `state` bytes                         | Recipient meaning            |
|---------|------------------|---------------------------------------|------------------------------|
| CKB     | bound cell data  | `amount(16 LE) ‖ recipient(32)` = 48  | lock-script **hash** (32)    |
| Cardano | `BoundState`     | `amount(16 LE) ‖ recipient(28)` = 44  | payment **credential** (28)  |

On CKB the full bound-cell data is `seal_txid(32) ‖ seal_idx(4) ‖ state`, so the amount sits at byte offset
36 and the recipient at 52 (what `leap_mint_guard`'s `find_bound` reads). On Cardano the `state` is the
`BoundState.state` field, amount at offset 0, recipient at 16.

## Conservation across the mapping

The mapping is value-preserving because the guard binds the **same `u128`** on both ends:

- **Leap-in (mint):** xUDT (CKB) / FT (Cardano) minted `== amount`, **all** to `recipient`. No inflation,
  no diversion. (`authorize_mint`.)
- **Leap-out (burn):** burned `== amount` that the source release credits. No drain. (`authorize_burn`.)
- Both directions additionally pass the operational **policy** (per-leap cap/floor + pause), which can only
  further restrict — never enlarge — the amount. (`enforce_policy`.)

Because the amount is one `u128` carried verbatim (16 LE bytes) from the verified state into the supply
check, **there is no step that converts between units, scales by decimals, or narrows an integer** on the
value path. Decimals affect only the rendered string.

## Bounds & overflow

- `u128` base units bound the maximum representable supply; the builder (`toBaseUnits`/`u128le`) must reject
  any value `>= 2^128` before constructing a tx (off-chain), and the on-chain decode is a fixed 16-byte read
  (cannot overflow). The CKB summation uses `saturating_add`, so a crafted overflow saturates rather than
  wrapping — and a saturated total can never equal the exact `fact.amount`, so it is rejected by conservation.
- **Caps** (policy `max_amount`) give an additional, governable upper bound far below `u128::MAX` for real
  deployments, sized in base units.

## What a reviewer should check at integration

1. The token's `decimals` in token-info (CKB) **equals** the CIP-68 `(100)` `decimals` (Cardano) **equals**
   the source asset's decimals — set once at genesis, never mutated.
2. The off-chain builder maps a user's display string to base units with integer math only (`toBaseUnits`),
   and the same base-units `u128` is what the verifier's `state` carries — no second scaling on either side.
3. The recipient width matches the chain (32 on CKB, 28 on Cardano); the builder writes the correct
   identifier (lock hash vs. payment credential).
