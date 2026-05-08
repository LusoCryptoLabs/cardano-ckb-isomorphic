# v2 leap deploy — DONE (Pudge + preview)

The v2 ownership-toggle leap is deployed and the end-to-end **genesis succeeded on Pudge** (tx `0x408d9c28…`).
Full status + hashes: `docs/LEAP_V2_GOLIVE.md`. This file is the operator log + how to re-run.

## Deployed (final)
- cv_deploy_v2 code `0xa42e3942`:0 · `CHIRAL_LCKP_TH 0xa055798e911a4f7ed074d5e1ee6273683e9a446c70d3e22adab680d70eea5b74`
- AVK checkpoint advanced 1323→1324 (`0x2519ee3c`); 44-byte checkpoint published via `refresh_checkpoint_v2.mjs`
- registry code `0x2b96f094`:0 + genesis singleton `0x4e159851`:0 · `CHIRAL_REG_TH 0xdc18fd562bca1834536c926ce8c9d94f608318c3a79a43959c0c46a84265a24e`
- bound_asset_v2 code `0xb33fc200`:0 · `V2_BOUND_CODE_HASH 0x4cc7ae86c48944f145dbe3c0f6bd44dda7be623c382e4b31c98feef97c1020b7`
- Cardano v2 binding_lock `addr_test1wprutk2vjvuzgwlsvf956we9ssxqlyfl9jdeywrlv6tsyccz32l5e`, seal mint `08000078…`
- State files: `deployed.json` (cv_*), `chain_state.json` (AVK 1324), `checkpoint_v2.json` (latest 44-byte ckpt),
  `v2_registry.json` (registryCode/registryGenesis/boundCode + CHIRAL_REG_TH).

## Build (production — REQUIRED flags)
The burn-gated-unlock binaries MUST be built atomic-free + stripped or the on-chain CKB-VM rejects them:
```
RUSTFLAGS="-C target-feature=-a,+forced-atomics" CHIRAL_LCKP_TH=0x.. CHIRAL_REG_TH=0x.. \
  cargo build --release --bin bound_asset_v2 --target riscv64imac-unknown-none-elf
riscv64-unknown-elf-strip -o <bin>.stripped <bin>      # ~139k -> ~64k; needed for capacity + symbol hygiene
```
`hex32` strips a `0x`/`0X` prefix, so the env may include it. (Earlier deploy baked a shifted hash because it
didn't — see GOLIVE bug #2.)

## Re-run
- Republish checkpoint: `node refresh_checkpoint_v2.mjs`
- Genesis: `node boundasset_v2.mjs genesis` (refreshes ckpt + aligns proof + creates the CkbOwned cell)
- Debug a failing tx: `node boundasset_v2.mjs genesis --dump` → `genesis_dump.json`, then
  `ckb-debugger --tx-file genesis_dump.json --script-group-type type --cell-type output --cell-index 0`
  (build the verifier with `-C debug-assertions=on` to get `ckb_std::debug!` output; `--bin` overrides the script).
- Fund consolidation (orphaned cells from failed deploys): `node reclaim.mjs --live`.

## The leap TOGGLE — DONE (full round-trip live)
The single living seal round-tripped **CkbOwned →(S4)→ CardanoBound →(S5)→ CkbOwned**, each leg a Mithril
certify-then-prove cycle. The toggle reuses the SAME seal (baked `seal_policy ec8d2c74…`): S4/S5 spend +
re-park it at `binding_lock`, toggling its datum shape — NOT minting a new one-shot policy (wrong policy id
would fail `seal_at_lock`).

- S4 leap-to-cardano: Cardano Transfer `5c60bfb3…` (state-only datum) → CKB `0x838e39f2…` (CkbOwned→CardanoBound)
- S5 leap-to-ckb: Cardano LeapToCkb `f81a66bf…` (RC datum) → CKB `0xb45812da…` (CardanoBound→CkbOwned),
  recipient `0x7a971a3b…`; registry root `5b7ed70c…`→`f5a10236…` (seal nullified)

### Automated: the orchestrator (preferred)
`leap_orchestrator.mjs` drives the whole state machine end-to-end with monitoring — it picks the next leg
from on-chain state, runs the Cardano leg, polls the Mithril cert, runs the CKB leg, and logs to
`leap_log.jsonl`. Pre-flight it checks code-cell liveness (a swept code cell aborts before any spend) and
funding (auto-reclaims orphaned lock-only cells if the largest plain cell is below ~1500 CKB).
```
node leap_orchestrator.mjs status                 # both-chain health snapshot (no tx): state, balances,
                                                  #   registry size, parked-checkpoint count, code-cell liveness
node leap_orchestrator.mjs leg    [recipientHex]  # run the ONE next leg (S4 or S5 per current state)
node leap_orchestrator.mjs toggle [recipientHex]  # full round-trip back to CkbOwned
node leap_orchestrator.mjs run N  [recipientHex]  # N consecutive toggles
  --verify      dump + ckb-debugger each CKB leg (both groups) before the live send
  --no-reclaim  never auto-consolidate (fail instead if funding is low)
```
Operational note surfaced by `status`: each `refresh_checkpoint_v2` parks a ~167 CKB typed checkpoint cell
that is NOT auto-reclaimed (the cv_deploy_v2 type script gates spending); they accumulate slowly. The
witness cell (~1.2k CKB) IS recycled each refresh, so only checkpoints grow. Monitor via `status`.

### Re-run / extend the toggle (manual, low-level)
```
# S4 (CkbOwned -> CardanoBound)
wsl: cd cardano/binding && CHIRAL_PREVIEW_KEY=/mnt/c/Users/<u>/.chiral/preview_relayer.key AIKEN=~/.aiken/bin/aiken \
       python3 leap_to_cardano_ours.py            # Transfer seal, records s4_transfer_tx / s4_seal_index
  (wait ≈5 min for Mithril cert: python produce_witness.py <s4_transfer_tx> -> status "ready")
  node leap_to_cardano_v2.mjs [--dump]            # --dump -> s4_dump.json for ckb-debugger, else live

# S5 (CardanoBound -> CkbOwned) — the dangerous leg
wsl: python3 leap_to_ckb_ours.py [recipient_lock_hash_hex]   # default recipient = our Pudge lock; records s5_*
  (wait ≈5 min for cert: python produce_witness.py <s5_leap_tx> -> "ready")
  node leap_to_ckb_v2.mjs [--dump]                # --dump -> s5_dump.json; verify BOTH groups:
    ckb-debugger --tx-file s5_dump.json --script-group-type type --cell-type input --cell-index 0  # bound
    ckb-debugger --tx-file s5_dump.json --script-group-type type --cell-type input --cell-index 1  # registry SMT
```
Note: the recipient must equal the CKB lock that will own the result (S5 pins the cell's ACTUAL lock to it).
REPEATABLE: `leap_to_ckb_v2.mjs` reads the live registry outpoint from `boundasset_v2_state.json::registry`
(the genesis singleton is consumed after leap 1) and `reg_nullifier_witness.py` is a full sparse-Merkle
client over `registry_state.json` (the tracked nullifier set) — it builds real siblings for inserts into a
NON-EMPTY tree and the builder appends the new key after each S5 confirms. Validated in
`v2vmtest/tests/registry_smt.rs` (2-sequential-insert + replay-reject, anchored to the live root). Files:
`leap_common_v2.mjs` (shared), `leap_to_cardano_v2.mjs`, `leap_to_ckb_v2.mjs`, `reg_nullifier_witness.py`,
`registry_state.json`. Full status + hashes: `docs/LEAP_V2_GOLIVE.md`.
