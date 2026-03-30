# #3 — validate the relayer's FINALIZE witness against the real verifier

Goal: prove the relayer's `proveCardanoToCkb` encoder (`mithril_proof.mjs`) produces witness bytes the
**actual on-chain `bound_asset_unified` verifier** parses and cryptographically verifies — end to end, in
CKB-VM (ckb-debugger), no mock.

## Method (`run.sh`)

1. **`gen/`** builds a self-contained, internally-consistent FINALIZE dataset with the **same crate** the
   verifier uses (`ckb-merkle-mountain-range` 0.6, Blake2s256 merge) and the same hashing
   (`leaf = ascii_hex(blake2b256(tx_body))`, `master_leaf = blake2s256(range_key ‖ sub_root)`): a
   seal-consuming Cardano `tx_body` + a two-level MMR membership proof. We set the checkpoint root = our
   master MMR root, so the dataset is valid by construction (no live Mithril cert needed to prove
   encoder⟷verifier agreement). It prints the witness AND the components.
2. **Cross-check:** `mithril_proof.mjs::encodeFinalizeWitness(components)` is asserted **byte-identical** to
   the Rust-generated witness (320 bytes). → the relayer's JS encoder == the reference encoding.
3. **`assemble.py`** builds a FINALIZE mock-tx: the bound cell as INPUT with NO output (FINALIZE), its
   `witness.input_type` = the encoded witness, and a cell-dep carrying `"LCKP" ‖ cert_root`.
4. **ckb-debugger** runs the verifier over it (`--script-group-type type`).

## Result

Run against the **deployed** verifier binary (`0x42f74fbc…`, extracted live from Pudge): the verifier
consumes **102K cycles** and returns **6**.

Why that validates the encoder: in the verifier's logic, **code 4 = sub-proof verify fail**, **code 5 =
master-proof verify fail** — both *before* any code 6. Returning 6 (not 4/5) means the deployed binary
**parsed the relayer-encoded witness and verified BOTH levels of the MMR proof** against the checkpoint
root, then hit a *post-verification* check. So the **witness encoding + MMR proof format is accepted and
cryptographically verified by the live verifier.** That is the thing #3 set out to prove.

### Negative controls (the check is live, not vacuous)
| input | deployed verifier result |
|---|---|
| valid relayer-encoded witness | **6** (passed sub-proof 4 + master-proof 5; hit post-verification check) |
| checkpoint root corrupted (1 byte) | **5** (master proof correctly rejected) |
| witness corrupted (1 byte in a master item) | **5** (proof correctly rejected) |

So the live verifier genuinely verifies the relayer's proof — a valid witness gets *past* the MMR stage,
any tampering is *caught* at it. The encoder is validated against the deployed verifier; **no encoder change
is needed.**

## Reconciliation of finding #1 — SOLVED (code 6 = pre-FINALIZE deployment)
The deployed verifier `0x42f74fbc…` was built from git commit **`5d0c078`** ("PHASE 1 in-script COMPLETE —
genesis + transition"), per `deployed/pudge/unified-instance.json` (only genesis + transition ran live).
In that version, line 89 is:

```rust
let out_data = match load_cell_data(0, Source::GroupOutput) { Ok(d)=>d, Err(_)=>return 6 };
```

So **code 6 = "no continuing bound cell"**. That version only supported GENESIS/TRANSITION (which always
recreate the bound cell, i.e. have a GroupOutput). A bound cell consumed with **no** output **is** a
leap-out — and the pre-FINALIZE verifier rejects it with 6. The current repo source (commit `dab1e4d`,
"PHASE 3 — leap-out FINALIZE") **replaced that `return 6` with the FINALIZE branch** (codes 20–23).

## Leap-out PROVEN to work in CKB-VM (`vmtest/`)
The deployed binary can't do leap-out (it predates FINALIZE), but the **redeploy candidate** can — and we
prove it. `vmtest/` builds the current FINALIZE-capable verifier and runs the relayer's leap-out witness
through it in **ckb-testtool's real CKB-VM** (which supports the atomics a fresh build emits, unlike
ckb-debugger), on the real FINALIZE tx shape (bound cell consumed, no output, `"LCKP"` checkpoint cell-dep):

| test | result |
|---|---|
| `leap_out_finalize_accepts` | ✅ the FINALIZE verifier **accepts** the relayer-encoded leap-out witness |
| `leap_out_bad_root_rejects` | ✅ a corrupted checkpoint root is **rejected** (the MMR check is live) |

So the leap-out leg works end to end: the relayer's witness encoder + the FINALIZE verifier accept a valid
leap-out and reject tampering, in-VM. Combined with the guard's leap-out burn (proven 16/16 in
`guard/integration`), every component of the CKB→Cardano exit is green in-VM. The only remaining step is the
**operational redeploy** of this verifier to Pudge (`DEPLOY.md` Step 3b).

## Two conclusions (on the deployed binary):
1. **The relayer's witness encoder is fully validated** — the deployed verifier parsed it and verified both
   MMR levels (codes 4/5 are live, per the negative controls); it then rejected at the GroupOutput check
   *exactly as its 5d0c078 source dictates*, because leap-out didn't exist when it was deployed. No mystery,
   no unknown drift, no encoder change.
2. **Leap-out (FINALIZE) is NOT on the deployed verifier.** The FINALIZE-capable source (`dab1e4d`) must be
   **redeployed** to Pudge before the CKB→Cardano leap-out path can run on-chain. The relayer's leap-out
   builder + witness encoder are ready and verifier-format-correct; they're waiting on that redeploy. (The
   deployed verifier fully supports the genesis + transition paths, proven live.)

## Two honest findings (worth acting on before production)

1. **The deployed binary has drifted from the repo source.** `spike/phase1/bound_asset_unified.rs` returns
   only codes 1–5, 7–12, 20–23 — there is **no code 6**. The deployed `0x42f74fbc…` returns 6, so it is a
   **newer/different version**. The relayer's encoder is validated against the deployed binary's *format +
   proof verification*; the residual code 6 is a business-logic check in the deployed version we don't have
   source for. **Reconcile the deployed verifier's source/version** before relying on the leap-out
   business logic (the encoding is fine).
2. **A fresh build emits atomics — and that's fine on the live network.** Building `bound_asset_unified.rs`
   fresh emits ~15 **RISC-V atomic instructions** (opcode `0x2F`, from `bytes` via `molecule`). `ckb-debugger
   0.119` rejects them (`InvalidInstruction`) — but the **live Pudge network supports them**: CKB-VM
   **version 2** (ckb2023, RFC0048/0049) activated at epoch **9690** (chain is now ~**13238**) and includes
   the **A extension** — confirmed via `get_consensus`, and ckb-testtool (ckb-vm 0.24.12 @ v2) **executes**
   the atomics (`vmtest`, 2/2). So the FINALIZE binary is deployable to Pudge as-is; ckb-debugger 0.119 is
   simply a lagging tool whose default ISA omits A. (We validate `vmtest` in ckb-testtool, which faithfully
   uses VM v2, and validate the #3 encoder run against the fetched deployed pre-FINALIZE binary.)

## Reproduce

```
cd gen && cargo run --release --quiet > /tmp/ds.json     # generate dataset
# (cross-check the JS encoder == Rust witness — see run.sh)
# fetch the deployed verifier: extract the ELF cell-dep from a live Pudge leap (replay_live_leap.py)
python3 assemble.py /tmp/ds.json /tmp/deployed_bound_asset.bin > /tmp/finalize_mock.json
ckb-debugger --tx-file /tmp/finalize_mock.json --cell-type input --cell-index 0 --script-group-type type
```

Bottom line: the relayer's witness encoder is **format-validated and MMR-proof-verified by the live
verifier**; the remaining work to a clean exit-0 is reconciling the deployed verifier's (drifted) source —
an artifact/version issue, not an encoder issue.
