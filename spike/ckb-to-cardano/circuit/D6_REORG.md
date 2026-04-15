# D6 — CKB-reorg defense (confirmation depth K + aggregate cap + trust-root hardening)

Status: circuit change DONE + validated; Aiken side DONE (101/101 `aiken check`); all review must-fixes
landed (MF-1 one-shot policy NFT + read_k pin/range, MF-2 rate-limiter mint-coupling, MF-3 K-binding tests,
MF-4 read_policy fail-closed, MF-6 rationale); blueprint regenerated. REMAINING: finish the in-flight
re-ceremony on the windowed circuits → redeploy `cardano_bound` (6 params now) + `chiral_policy_thread` +
`leap_ratelimit(_thread)` → external audit. Superseded the chat "maturation lock" sketch (dropped — §6).
Adversarially reviewed twice (`reorg-fix-design` then `reorg-fix-review` workflows); this records the
*corrected* design after both. New files: `validators/{leap_ratelimit,leap_ratelimit_thread,chiral_policy_thread}.ak`,
`lib`-moved `PolicyState`; `merkle_gadget::enforce_geq_bits`.

## 0. The attack
A CKB-native asset is locked (single-use seal cell) on CKB at height `H`. Cardano mints a free wrapped
FT (ckCKB) against a Groth16 proof that `H` is in the checkpointed CKB chain. The attacker — who is their
own permissionless relayer **and** their own permissionless checkpoint-advancer — then reorgs CKB to
erase `H`, keeping the asset on CKB **and** the already-sold ckCKB. Profitable whenever bridged value >
cost of the reorg. CKB PoW is cheap (F2Pool / idle ASICs), so this is real.

Today the leg is wide open: the windowed leap circuit enforces only `tip_height − W < height ≤ tip_height`
(`leap_windowed.rs`), whose upper bound `≤ tip_height` **allows depth 0** (the leap header may be the tip),
and the minted FT is free and never re-checked. Enforced confirmation depth = **0**.

## 1. Honest scope (what is and isn't achievable)
For a CKB-native outflow, **security can never exceed CKB PoW** — a sufficiently funded depth-K reorg is
always possible. The achievable guarantee is:

> *A reorg cannot be **shallow** (depth K enforced on-chain) and cannot **profit** (value-in-flight capped
> below the cost of a depth-K reorg).*

That is the claim that survives the F2Pool objection; "we assume CKB won't reorg" does not.
Liveness against a **majority**-hashrate attacker is **not** protectable (they can race the checkpoint tip
and evict in-flight seals from the window) — but that is **liveness, not theft**: funds stay on CKB and
the leap is re-provable once the attack stops.

## 2. The two knobs
- **K** — minimum confirmation depth, a circuit **public input**, pinned by the validator from the
  governor-signed policy. Enforced in-circuit as `tip_height − height ≥ K`.
- **cap / window** — an **aggregate** rolling value ceiling (not per-leap), tuned so
  `cap < cost-to-reorg-K-blocks` and `window_len ≥ wall-clock of a depth-K reorg`.

K sets the reorg *cost floor*; the cap bounds the *value* below it. **Both are required** — K alone does
not prevent profit (a thief mints free FT at exactly depth K and reorgs), and a per-leap cap alone is
split into N sub-cap leaps inside one window.

## 3. Circuit change (DONE) — `leap_windowed.rs`, `finalize_windowed.rs`
- New **public input #5 = K**. Ordering is fixed: `[window_root, seal, commitment, tip_height, K]`
  (finalize: `commitment` = `fin_commitment`). K appended **last**, raw `Fr::from(k)` (same convention as
  `tip_height`). VK `ic` length 5 → 6; `verifier.ak`'s length-pin auto-requires exactly 5 inputs.
- Enforce **`diff ≥ K`** where `diff = tip_height − height`: keep the existing depth-bit decomposition of
  `diff` (so `diff ∈ [0,W)` — preserves the band top `H+W−1`) **and** range-check K to `depth` bits (so
  `K ∈ [0,W)`), then `merkle_gadget::enforce_geq_bits(diff_bits, k_bits)` (the audited MSB-first compare,
  shared primitive). Band becomes **`[H+K, H+W−1]`**, width `W−K`.
- Cost: ~40 constraints; stays at the **2²¹** domain (leap 1,227,947 / finalize 1,227,265). Validated:
  `is_satisfied` is true **iff `diff ≥ K`** (matrix incl. boundaries); a K=12 proof verifies in arkworks.
- One-time **re-ceremony** required (the new IC entry changes the VK). After that K is retunable by
  governance with **no further ceremony** (it is a public input, not a circuit constant).

### Hard limit: K < W. W=64 is frozen.
`K` is bounded by `W−1 = 63` at the production `W=64`. Worse, K **consumes** the live window: usable band
is `[K, W)`, so the relayer race window is `(W−K)` blocks (~`(W−K)·8s`). Governance must keep
`K + MIN_LIVE_WINDOW ≤ W` (e.g. K ≤ 32, leaving ≥32 blocks ≈ ~4 min). If economic analysis needs K > ~30,
`WINDOW_DEPTH` must be raised **before** the (one) ceremony and frozen there — coordinate with the advance
window sizing.

## 4. K-binding (Aiken) — `cardano_bound.ak`, governance
**K source = the governor-signed policy, NEVER the checkpoint datum.** (The checkpoint is advanced
*permissionlessly*; an attacker-advancer would just write `cp.k = 0`. The policy cell is changeable only
by the governor key in `chiral_policy.ak`.)
- `GuardPolicy` gains `min_confirmations: Int` (and `rolling_cap`, `window_len` for §5). The policy cell's
  datum is `PolicyState { governor, policy }`.
- `cardano_bound` reads K from the policy cell as a **reference input**, located by the policy **identity
  NFT** (and matched to the chiral_policy script hash), decoding `PolicyState` and taking
  `.policy.min_confirmations`. Fails-closed if absent (K must be authoritative).
- `inputs_bind_w` becomes 5-ary: `pi == [field_of(wroot), field_of(seal), field_of(comm), tip, k]` — K
  raw, appended last, **identical** in Transition and Finalize. A negative test pins that a proof with K=A
  but policy K=B is rejected, in **both** branches.
- Governance `sane_caps` enforces `0 ≤ min_confirmations ≤ W − MIN_LIVE_WINDOW` so a fat-fingered/compromised
  governor cannot set a self-bricking K.
- **Bug fixed in passing:** `leap_mint_guard.read_policy` currently decodes a bare `GuardPolicy`, but
  `chiral_policy` writes `PolicyState` — incompatible CBOR (latent only because the live demo referenced no
  policy cell). Both readers are unified onto the NFT-identified `PolicyState`. The policy NFT must be
  one-shot (a forged second NFT carrying `min_confirmations=0` would otherwise downgrade K).

## 5. Aggregate cap (Aiken) — `leap_ratelimit.ak` (new singleton)
A thread-pinned singleton UTxO `RateState { window_start, minted_in_window }` that every `LeapInMint`
spends+recreates (mints are already serialized through the seal-nullifier singleton, so this adds no new
serialization). `leap_mint_guard` cross-checks that the limiter's `Tick.amount` equals the bound leap fact
(and that the spent limiter input **carries the thread token** — not just the script hash, or a decoy
spoofs it).

**Corrected time semantics (the chat sketch was broken here):** the validity-interval **lower** bound is
attacker-chosen, so gating the window reset on it lets a self-relaying thief future-date `lower` to reset
every tx → cap collapses to per-leap. Fix: require **Finite upper bound + bounded width** (`hi − lo ≤
MAX_WIDTH`), use the **lower** bound as a *conservative* `now` for the cap (a smaller now only delays
resets — safe), so a future-dated reset is itself unminable until real wall-clock catches the upper bound.

**Honest cost (state it plainly):** the real throughput ceiling is `cap / window_len` (a deliberate global
liveness chokepoint), **not** "~hundreds/hour". `window_len ≥ wall-clock of a depth-K reorg` and
`cap < cost-to-rent-CKB-majority-for-window_len` are **governance invariants**, documented, asserted at
parameter-set time. v1: one-leap-per-tx (keep `expect [bound_in]`), burns non-crediting.

## 6. Dropped: the optimistic maturation lock
The chat proposed minting into a maturation lock and finalizing after a window D via a re-membership proof.
**Dropped:** a withholding attacker finalizes against a checkpoint that *still* shows the lock and only
*then* reveals the heavier chain, so D adds no safety against the majority adversary it targets — while
adding a whole new validator + pending-token machinery + reversion logic (exactly the complexity reviewer
Phroi warns against). K + cap deliver the same economic guarantee with one constraint + one singleton.

## 7. Trust-root hardening (cheap, no ceremony) — confirmed sound, defense-in-depth
Audit result: the genesis pin and one-mint-per-seal are **airtight** (checkpoint thread NFT is a provable
singleton via `mints_one_thread` + consumed genesis ref + advance preserving exactly one; one-mint-per-seal
via the seal-nullifier's own thread-pin + SMT non-membership). Add as belt-and-suspenders:
- `canonical_cp` / `seal_consumed`: `list.find` → `list.filter` + `expect [x]` (exactly-one).
- `cardano_bound.spend`: `expect length_of_bytearray(st.ckb_seal) == 32`.
- **Load-bearing invariant to preserve + test:** one-mint-per-seal actually rests on the **commitment-hash
  byte-binding** `blake2b(state‖seal)` (not on `field_of(seal)`, which is non-injective: `r` is 255-bit so
  `H` and `H+r` alias). A future refactor must never drop the seal from the commitment.

## 8. User impact
- ckCKB doesn't exist until **K confirmations** (latency; same as an exchange deposit). Default target
  K≈12–24 (~2–4 min at ~8 s/block), W−K ≥ 32 blocks of relayer slack.
- CKB-native **outflows** above the cap settle in tranches / over time (throughput = `cap/window`).
- Cardano→CKB and re-rooted assets (seal on Cardano) are **unaffected** — they inherit Cardano finality.
- Re-rooting is a deployment choice: issue high-value assets with the seal on the strong chain → CKB reorg
  can only scramble recoverable representation, never ownership.
