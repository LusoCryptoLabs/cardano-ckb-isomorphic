# STATUS — the DEX-token layer (a SUB-scope; authoritative project status is elsewhere)

> ⚠️ **AUTHORITATIVE project status = [`../../docs/CHIRAL_STATUS.md`](../../docs/CHIRAL_STATUS.md) +
> [`../../docs/LIVE_STATUS.md`](../../docs/LIVE_STATUS.md) + `../../docs/TESTNET_LOG.md`.** Read those FIRST.
> This doc covers ONLY the DEX-token layer (the xUDT/CIP-68 token + the leap-mint guard + caps/pause + the
> UI) built ON TOP of the already-live bridge core. Twice in this arc I "discovered"/"rebuilt" things the
> authoritative docs already showed as DONE & LIVE (the #2 consensus circuit — F8/F12; and the leap-out
> FINALIZE — F14). The bridge core (both legs, the ZK circuit, the finalize) is **built and live on
> testnets** per those docs; this sub-scope is the token/DEX integration on top.

**Read this first, update it as you go.** Records what is DONE/PROVEN/BLOCKED for the DEX layer. The
**Findings & Decisions log** (bottom) is the anti-circling memory — check it (and the authoritative docs)
before re-investigating anything.

Last updated: after commit `d1cfd65` + this reconciliation (leap-out is LIVE; #2 already built).

---

## 0. The system in one paragraph
A bidirectional Cardano⇄CKB **isomorphic** bridge whose bridged token is a JoyID-visible **xUDT** (CKB) and
a wallet-visible **CIP-68** FT (Cardano). Security lives **on-chain**: the BoundAsset verifier (CKB) + the
`cardano_bound` Groth16 verifier (Cardano) prove leaps; the **leap-mint guard** enforces conservation +
caps/pause on the token supply. A permissionless **relayer** carries proofs between chains. The UI
(JoyID + CIP-30) drives it.

---

## 1. Component inventory

| # | Component | Path | Status | Verified by |
|---|---|---|---|---|
| A | **Leap-mint guard — core logic** (no-inflation / exact-burn / replay-once + caps/pause) | `guard/core` | ✅ done | `cargo test` **22/22** |
| B | **Guard — CKB script** (xUDT owner lock; matches xUDT by code-hash + owner) | `guard/ckb_script` | ✅ done | builds riscv64; see C |
| C | **Guard — real-VM integration** (real deployed xUDT + Unique, owner-mode, caps/pause) | `guard/integration` | ✅ done | ckb-testtool **16/16** |
| D | **Guard — Cardano** (`leap_guard` + `leap_mint_guard` + `chiral_policy`) | `../ckb-to-cardano/groth16` | ✅ done | `aiken check` **59** tests |
| E | **Amount/decimals mapping spec** (u128 LE, decimals display-only) | `guard/MAPPING_SPEC.md` | ✅ locked | cross-chain test vectors |
| F | **Token builders** (CKB xUDT genesis+token-info; Cardano CIP-68) | `ckb_leap_token.mjs`, `cardano_cip68.mjs` | ✅ done | — |
| G | **UI** (JoyID + CIP-30, live balances + caps/pause, leap form, sign+broadcast plumbing) | `ui/` | ✅ done | typecheck + **7/7** + build + preview |
| H | **CKB deploy tooling** (guard + policy → out-points for config) | `ui/scripts/deploy_ckb.mjs` | ✅ built | offline-validated (addr/args/owner) |
| I | **Cardano deploy runbook** (aiken blueprint apply) | `ui/scripts/deploy_cardano.md` | ✅ built | `apply` flow validated |
| J | **Relayer** (watch→prove→submit; CKB FINALIZE builder; Cardano mint plan) | `relayer/` | ✅ built | selftest; builders offline-validated |
| K | **Proof providers** (Mithril FINALIZE-witness encoder; Groth16 prover adapter) | `relayer/{mithril_proof,groth16_prover}.mjs` | ✅ built | encoder byte-exact vs reference; #3 |
| L | **#3 verifier validation harness** | `relayer/validation/` | ✅ done | see §2 |
| M | **Leap-out FINALIZE — proven in VM** | `relayer/validation/vmtest` | ✅ proven | ckb-testtool **2/2** |

---

## 2. What is PROVEN (with evidence)

- **Conservation + caps/pause** (both chains): guard-core 22/22, Cardano 59, real-VM 16/16.
- **Real xUDT + Unique run in the VM**: the integration tests use the *actual deployed* xUDT + Unique
  binaries (fetched from Pudge), owner-mode mint/burn gated by the guard; token-info type-id enforced
  (wrong id rejected); the real xUDT rejects a non-owner supply increase. (`guard/integration`, 16/16.)
- **Leap-in verifier (genesis + transition)** is **live on Pudge** — `deployed/pudge/unified-instance.json`
  (deploy `0xf8644bd3`, code_hash `0x42f74fbc`); a real genesis (`0x0318d35f`) + transition (`0x94d0620f`)
  verified real Mithril data in-script. We also re-ran the deployed verifier on the live genesis (exit 0).
- **Leap-out (FINALIZE)** works in CKB-VM: the FINALIZE-capable verifier **accepts** the relayer-encoded
  leap-out witness and **rejects** a corrupted checkpoint root (`vmtest`, 2/2).
- **Relayer witness encoder** is verifier-format-correct: byte-identical to the reference (320 B), and the
  *deployed* verifier parsed it + verified BOTH MMR levels (negative controls: corruption → code 5). (#3.)
- **Atomics OK on Pudge**: CKB-VM v2 (ckb2023, RFC0048/0049) active since epoch 9690 (now ~13238) includes
  the A extension → the FINALIZE binary deploys as-is. (`get_consensus`; ckb-testtool runs the atomics.)

---

## 3. What is NOT done / BLOCKED (and what unblocks it)

| Gap | Why it matters | Status / blocker | Unblock |
|---|---|---|---|
| ~~Redeploy the FINALIZE verifier~~ **DONE & LIVE** | leap-out on-chain | ✅ FINALIZE verifier `0x97ca700d` deployed; **leap-out finalize `0x795f4bb9` committed on Pudge** (block 21,358,183) — verified on-chain. My F1/vmtest/Step-3b were stale (I analyzed the OLD `0x42f74fbc`). | none — already live (F14) |
| **Deploy guard + policy cells** | the token's owner script + caps/pause must be on-chain | tooling built (`deploy_ckb.mjs`); not run | funded Pudge key |
| **Deploy Cardano side** (apply params + CIP-68 genesis) | the Cardano leg | runbook built; not run | funded Preview key |
| **Running Mithril aggregator** | relayer fetches live CardanoTransactions proofs from it | adapter built to the API shape | stand up / point at an aggregator |
| **CKB-consensus Groth16 leap circuit (#2)** | proves the real CKB leap (R1 PoW + R2 MMR + R3 CBMT + R4 commitment) for the Cardano leg | ✅ **ALREADY BUILT** — `../ckb-to-cardano/circuit/prover/` + `SPEC.md`; on-chain-verified (F8) | production ceremony / lookups / advance throughput / testnet + audit (F13) — NOT a rebuild |
| **Wire config.ts to live out-points** | UI reads live balances + can submit | waits on the deploys above | paste deploy outputs |
| **Third-party audit** | before any real value | not done | external |
| ~~Deployed-verifier source reconciliation~~ **RESOLVED** | which verifier is live | ✅ the FINALIZE-capable verifier is live as `0x97ca700d` (the older `0x42f74fbc` was genesis/transition-only); leap-out ran live under it (F14) | none |

**Roach-motel rule:** never enable leap-in *for value* until leap-out is deployed + proven on-chain too.

---

## 4. Go-live checklist (mirrors README §5)
1–8 ✅ done & tested (visibility, owner=script, token-info under owner mode, guard both sides, conservation
battery, real-VM + real-xUDT, caps/pause, mapping locked).
9 🟡 deploy/relayer/submit **code built**; remaining is operational (run deploys with keys, redeploy FINALIZE
verifier, connect a Mithril aggregator, real consensus circuit).
10 ⚠️ third-party audit before real value.

---

## 5. Findings & Decisions log (anti-circling memory — check before re-investigating)

- **F14 — leap-out is ALREADY LIVE (my F1 was stale). Authoritative docs first.** `docs/LIVE_STATUS.md` +
  `TESTNET_LOG.md`: a FINALIZE-capable verifier `0x97ca700d` was deployed and the **leap-out finalize
  `0x795f4bb9…` is COMMITTED on Pudge** (block 21,358,183) — I verified the tx is on-chain. So my F1
  ("leap-out can't run, needs redeploy"), the `vmtest`, and `DEPLOY.md` Step 3b were re-deriving an
  already-closed, already-live result — I analyzed the OLD pre-FINALIZE `0x42f74fbc` and never read
  `CHIRAL_STATUS.md`/`LIVE_STATUS.md`. **Process fix (same as F12): read `docs/CHIRAL_STATUS.md` +
  `LIVE_STATUS.md` + `TESTNET_LOG.md` BEFORE investigating any "gap".** F1 below is correct *about the old
  binary* but its conclusion is superseded by this.
- **F1 — "code 6" = pre-FINALIZE (correct about the OLD `0x42f74fbc`; conclusion superseded by F14).** That
  verifier was built from git `5d0c078` (genesis + transition only); its line 89 returns 6 on "no GroupOutput".
  A leap-out *is* a
  no-output bound cell, so that version rejects it with 6. FINALIZE (codes 20–23) was added later in
  `dab1e4d`. → **leap-out needs the FINALIZE verifier redeployed.** Don't re-investigate code 6.
- **F2 — atomics.** A fresh verifier build emits RISC-V atomics (from `bytes`/`molecule`). `ckb-debugger
  0.119` rejects them, but **live Pudge (VM v2) supports them** (confirmed via `get_consensus`; ckb-testtool
  runs them). → deploy as-is; don't waste time on a no-atomics rebuild. Use **ckb-testtool**, not
  ckb-debugger, to run atomics-containing CKB binaries locally.
- **F3 — xUDT owner circularity (SOLVED).** The guard can't take the xUDT's full type hash as an arg (that
  hash embeds the owner = the guard). Fixed: guard matches xUDT by `type.code_hash == configured code hash`
  AND `owner args == the guard's own script hash` (`load_script_hash`). Guard args = `xudt_code ‖ bound ‖
  [policy]`.
- **F4 — token metadata.** JoyID/CCC read the **Unique token-info** cell, co-minted in the **same owner-mode
  genesis tx**. Cardano = CIP-68 ((100) ref NFT + (333) FT); CIP-26 is a dead end for script policies.
- **F5 — CIP-30 vs CIP-68.** Orthogonal: CIP-30 = wallet connector (UI), CIP-68 = on-chain token metadata.
  Both used; not an either/or.
- **F6 — value encoding.** ONE encoding on the value path: `u128` base units, **16-byte LE**; decimals are
  display-only metadata. Recipient width is chain-native (32 CKB / 28 Cardano). See `guard/MAPPING_SPEC.md`.
- **F7 — relayer is permissionless.** Holds no privileged key; security is in the on-chain verifiers/guard.
  Anyone can run one (liveness/censorship-resistance); proving backends are the heavy operational part.
- **D1 — branch/landing.** Land work on `main` directly (fast-forward), no side branches. Commit directly.
- **F8 — #2 IS ALREADY BUILT (do NOT rebuild). Correction of an earlier miss.** The full CKB-consensus
  leap circuit exists at `../ckb-to-cardano/circuit/prover/` with `../ckb-to-cardano/circuit/SPEC.md`:
  real **Eaglesong PoW + compact-target (R1)**, **header-MMR (R2)**, **tx-CBMT (R3)**, **ckbhash commitment
  (R4)** on real Pudge block 21,341,101; gadgets (Eaglesong, blake2b/`ckbhash` with the correct
  `ckb-default-hash` personalization) **differential-tested against native CKB**; full leap ≈ **2.7M
  constraints** (Eaglesong PoW 464,192; ckbhash 48,820/block); the proof **verifies on-chain under the real
  Aiken `g16` verifier** (`aiken check` → 59 passed, 0 failed; test `leap_proof_verifies_onchain` in
  `lib/g16/leap_test.ak`). Bins: `leap_prove`, `advance_prove`, `batch_advance`, `relay_prove`, `ceremony`
  (trusted setup). So both the leap circuit and the consensus/advance circuit + a dev ceremony already exist.
  **Note:** the placeholder `../ckb-to-cardano/prover/` (`SquaresCircuit`) is a *separate, older* fixture
  tool — not the real circuit. Don't confuse the two.
- **F12 — LESSON (the circles you warned about): survey existing spikes before scoping.** This turn I
  scoped (`CIRCUIT_SCOPE.md`/`STATEMENT.md`) and partially rebuilt #2 (a standard-blake2b R1CS gadget +
  membership demo in `circuits/blake2b-r1cs`) before discovering `circuit/prover` already had it — built
  better and with the *correct* `ckb-default-hash` variant (mine used standard blake2b). Those redundant
  artifacts were **removed**; this finding records the miss. Process fix: before "building #2 from scratch,"
  `grep` the repo for existing gadgets/circuits (`ConstraintSynthesizer`, `eaglesong`, `ckb_mmr`, the
  validator test fixtures) — the STATUS inventory now lists `circuit/prover` so it won't be missed again.
- **F13 — what's ACTUALLY open on #2** (from `circuit/SPEC.md`, not "build it"): production **trusted-setup
  ceremony** (the `ceremony` bin is dev-grade) or move to a universal-SRS Plonk/KZG-BLS12-381; optional
  **lookup-based** proving to cut ~2.7M → ~1M constraints; the **advance/batch** consensus-checkpoint
  throughput + end-to-end on testnets (mirroring the live preview↔Pudge runs); and **audit**. The hard
  on-chain question (does the SNARK verify fit Cardano? ~22.7% of a tx) is already answered yes.
- **D2 — sequencing.** Agreed: #3 (verifier validation) → reconcile F1 → de-risk atomics (F2) → #2.
  #2 turned out to be **already built** (F8); the redundant rebuild was reverted (F12). Real remaining work
  is production-hardening + audit (F13), plus the operational testnet deploys (the FINALIZE-verifier redeploy
  + deploy tooling with funded keys).

---

## 6. NEXT STEP
**#2 (the CKB-consensus Groth16 leap circuit) is ALREADY BUILT** — `../ckb-to-cardano/circuit/prover/` +
`circuit/SPEC.md`, on-chain-verified (F8). It is **not** a thing to build from scratch. Real remaining work
(F13): production trusted-setup ceremony (or universal-SRS Plonk), optional lookup speedups, the
advance/batch consensus-checkpoint throughput + end-to-end testnet runs, and audit.
Highest-leverage actual next step: the **operational testnet deploys** — redeploy the FINALIZE verifier
(F1) + run the deploy tooling with funded keys — so the already-built legs (token, guard, caps/pause,
verifiers, and this circuit) go live. That needs your keys.

## 7. Commit arc (this effort)
`f5e5c0d` guard built → `9b79700` real layouts → `2fd6e29` live verifier re-run → `d52e8e0` caps/pause+mapping
→ `59191f1` UI → `6dd98be` real xUDT+Unique in VM → `d5bbb2c` CKB deploy tooling → `5db1905` Cardano runbook +
relayer → `95897b8` UI submit plumbing → `981e346` relayer builders → `6b0da19` proof providers → `ae94004`
+ `088bde8` + `1c50532` #3 + F1 → `46bba0b` leap-out proven in VM → `656c397` atomics de-risked.
