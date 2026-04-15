# Testnet deployment runbook (Pudge + Preview)

The path from "verifiers proven on testnet" to "a user can leap on testnet." Each step is **key-safe**:
private keys are supplied at *your* runtime via env vars and are never stored in this repo. Run these on a
machine you control, not a shared/ephemeral box.

What's already on testnet (prior work): the CKB **BoundAsset** verifier (Pudge), the Cardano
**`cardano_bound`** Groth16 verifier (Preview), and the system **xUDT** + **Unique** scripts. What this
runbook deploys is the **new financial layer**: the leap-mint guard, the caps/pause policy, and the
CIP-68 token — then wires the UI and the relayer.

## Prerequisites
- A funded **Pudge** address + its private key (faucet: https://faucet.nervos.org/). Need ~a few thousand CKB
  to cover the two code/state cells' occupied capacity.
- A funded **Preview** address + signing key (faucet: https://docs.cardano.org/cardano-testnets/tools/faucet).
- The deployed **BoundAsset type-script hash** on Pudge (`BOUND_TYPE_HASH`) and the **`cardano_bound`
  script hash** on Preview — outputs of the prior verifier deployment.
- Built artifacts: `guard/ckb_script` compiled to riscv64; `ckb-to-cardano/groth16` built with `aiken build`.

---

## Step 1 — CKB: deploy the guard + policy (`ui/scripts/deploy_ckb.mjs`)

```
cd ui
pnpm install
CKB_DEPLOYER_KEY=0x<privkey> BOUND_TYPE_HASH=0x<boundAsset type hash> \
  node scripts/deploy_ckb.mjs
```

It deploys, as two **type-id** cells (each a unique singleton):
1. the **admin policy cell** (caps/pause) — initially OPEN (not paused, no caps), admin = the deployer lock;
2. the **leap-mint guard** code cell.

Then it derives the guard lock (= the xUDT owner) and prints a ready-to-paste `CKB = { … }` block plus the
cell-deps a leap tx needs (guard code cell, policy cell). **Paste that block into `ui/src/config.ts`.**

Verification done in-repo before you run it: the deploy logic is exercised offline (address + 96-byte guard
args + 32-byte owner hash all derive correctly), and the real guard/xUDT/Unique run together in ckb-testtool
(`guard/integration`, 16/16). What needs your key: the on-chain broadcast (capacity is real).

> Updating caps/pause later: rebuild the policy cell's data (`flags ‖ min16 ‖ max16`) and spend→recreate the
> policy cell with the admin key. flags bit0=global pause, bit1=pause-in, bit2=pause-out.

---

## Step 2 — Cardano: apply params + deploy (see `ui/scripts/deploy_cardano.md`)

The Aiken validators are **parameterized**; deployment first *applies* the params (deterministic, verifiable
with `aiken blueprint apply`), then publishes reference scripts and mints the CIP-68 genesis. See Step 2 doc.

---

## Step 3 — Wire the UI

Paste the generated `CKB` block (Step 1) and the `CARDANO` block (Step 2) into `ui/src/config.ts`. The
balance panels and caps/pause banner now read **live** Pudge/Preview state. `pnpm dev`, connect JoyID + a
CIP-30 wallet, and you'll see real balances.

---

## Step 3b — Redeploy the FINALIZE-capable BoundAsset verifier (REQUIRED for leap-out)

The verifier live on Pudge (`0x42f74fbc…`) was built from commit `5d0c078` — **genesis + transition only**.
It rejects a leap-out (a bound cell consumed with no output) with **code 6** ("no continuing bound cell"),
because FINALIZE didn't exist when it was deployed. The FINALIZE branch was added later (commit `dab1e4d`,
`spike/phase1/bound_asset_unified.rs`). So **before the CKB→Cardano leap-out path can run on-chain, redeploy
the current FINALIZE-capable verifier** and point bound cells at the new code hash. Genesis + transition
(leap-in / mint) work on the existing deployment as-is. The FINALIZE binary is **validated in CKB-VM**:
`relayer/validation/vmtest` runs the relayer's leap-out witness through it (accept) + a corrupted root
(reject), 2/2; so the redeploy ships a proven binary.

> Build note: a fresh build emits RISC-V **atomics** (from `bytes` via `molecule`). These run fine on the
> **live Pudge network** — CKB-VM **version 2** (ckb2023, RFC0048/0049) activated at epoch 9690 and includes
> the A extension; confirmed via `get_consensus`, and ckb-testtool (ckb-vm 0.24.12 @ v2) executes them
> (`relayer/validation/vmtest`, 2/2). `ckb-debugger 0.119` rejects them — that's a lagging *tool*, not the
> network. Recommended: one real on-chain smoke-run of the deployed binary before relying on it for value.

## Step 4 — The relayer (the piece that produces leap proofs)

A leap tx needs a witness: a **Mithril/BoundAsset proof** (CKB→Cardano) or a **Groth16 proof**
(Cardano→CKB). The relayer watches one chain for a leap, produces that proof, and submits the
mint/burn on the other. See `relayer/README.md` for the interface + skeleton. This is the operational
service; the proving backends (already proven on the live testnets) must be connected to it.

---

## Step 5 — Before any real value
Per `README.md` §5 item 10: per-tx/global caps sized, pause tested, decimals mapping reviewed end-to-end,
and a **third-party audit** of the guard + verifiers. Until then: testnet / listing-prep only.
