# Chiral readiness — honest gap status (what's proven vs. what's left)

> Companion to CHIRAL_STATUS.md / LIVE_STATUS.md. Plain map of every gap between "the cryptography
> works on testnets" and "a production, trust-minimized, usable bridge." No hand-waving: each item is
> marked CLOSED / MECHANISM-PROVEN / BUILD / EXTERNAL, with what it would take.

## TL;DR
The hard, novel cryptography is **done and verified live on testnets**: each chain verifies the other's
consensus/certificates on-chain, both directions, on real data. It is **not** a production bridge: it is
testnet-only, unaudited, has no liquidity/ecosystem integration, and is coordinator-driven. A real wrapped
token (ckCKB) was minted on Cardano gated by a ZK proof, then burned (supply now 0) — so nothing is held or
freely usable today.

## What is demonstrated live (independently re-verified on-chain)
- **CKB→Cardano (Groth16-in-Plutus):** CKB lock → ZK proof → Cardano verify → mint 100k ckCKB → burn → CKB
  unlock. ckCKB asset `8f11f2b1…636b434b42`: mint_cnt 1, burn_cnt 1, supply 0 (Koios).
- **Cardano→CKB (Mithril-in-CKB-VM, binding/seal):** seal mint `83dd51d2` (preview) → bound-cell genesis
  `0x0318d35f` → transition `0x94d0620f` → **leap-out finalize `0x795f4bb9` (block 21,358,183)** — all
  committed; the finalize verifier ran on the live node and destroyed the bound cell against the real
  certified Unbind `6c729ea6`. (Re-confirmed via CKB RPC + Koios.)

## Gap table

| # | Gap | Status | What it took / takes |
|---|-----|--------|----------------------|
| 1 | **Mint amount/name binding** (mint qty was by convention, not enforced) | **CLOSED (validator-level, aiken-tested)** | `zk_chiral_mint.ak` now enforces minted qty == the amount committed in the CKB-bound state (transitively bound to the real lock via the existing `commitment` public input — **no trusted-setup change**) + name pinned to the commitment + exactly one asset; burns allowed. `aiken check` 12/12 incl. 5 binding tests. **Remaining:** relayer wiring (ckb_lock encodes amount in state; cardano_mint passes state/seal) + redeploy + a fresh proof. |
| 2 | **Burn-gated CKB unlock** (return unlock was operator-key authorized) | **CLOSED on-chain (positive + negative tested)** | New CKB lock script `spike/burn-gated-unlock/` releases the locked CKB **only** if a Mithril-certified Cardano burn is proven in-VM: it reads the certified tx-set root from a light-client checkpoint cellDep and verifies the two-level Blake2s256 MKMapProof that burn `6608c4c8` is under it. Built to riscv64 (codeHash `0x7d251a83…`), **deployed + unlocked LIVE on Pudge**: lock `0x3e4b81a5` → **unlock `0xefb60dfce…` (block 21,358,984)**, cell now spent. Negative test: a spend WITHOUT the checkpoint cellDep is **rejected by the lock script, error code 10** — so no key authorizes the spend, the certified burn does. **Remaining refinement:** gating binds the *specific* burn `6608c4c8` (which burned the full 100k supply, so amount is bound); parsing *arbitrary* Conway burn amounts in-VM generalizes it. **Progress — generalized lock BUILT + VM-tested.** `burn_gated_unlock_v2` (`spike/burn-gated-unlock/src/bin/`) is the full generalization: witness-driven (any certified burn tx, not a hardcoded one), it verifies the burn's two-level MKMapProof against the **authenticated** checkpoint (type-hash from args), parses the Conway `mint` field, and **binds the release to the exact burned amount of the bound `(policy, asset_name)`**. Builds to riscv64; **4/4 in the real CKB-VM (ckb-testtool, `integration/`):** a certified burn of the bound amount unlocks; a wrong amount, a tampered proof, and a missing checkpoint are each rejected. The Conway parser core is separately host-tested (`conway-mint`). **Remaining: EXTERNAL only** — redeploy the v2 lock + a live demo (needs keys). |
| 3 | **Mainnet deployment** | **EXTERNAL (not closeable in sandbox)** | Everything is testnet (Cardano preview + CKB Pudge). Needs real funds, a launch decision, mainnet params. |
| 4 | **Third-party security audit** | **EXTERNAL (still required); INTERNAL audit done** | Phase 5. An **internal adversarial audit** was performed — see **`docs/SECURITY_AUDIT.md`**: **8 Critical / 12 High / 10 Medium** findings (burn-replay; redeemer-supplied vk; unconstrained seal-spend in the circuit; unauthenticated/unpinned checkpoint roots both legs; circuit↔validator public-input encoding mismatch; STM lottery index rules; ceremony is a demo). **These mean the bridge is research-grade, NOT value-safe as coded.** The Criticals must be fixed AND an independent third-party audit (BLS/Mithril crypto + ZK soundness + ceremony) completed before any value. **Progress (code-level):** the trusted-setup ceremony is **no longer a demo** — a real two-phase Groth16 ceremony (`spike/ckb-to-cardano/circuit/prover/src/setup_mpc.rs`: multi-contributor Powers-of-Tau + per-circuit δ, verifiable Schnorr PoK + batched pairing checks, OS-entropy secrets) is implemented, self-tested (derived key **element-wise == arkworks**), and being re-run on the production *windowed* circuits to replace the deterministic `seed_from_u64` keys; the **circuit↔validator public-input encoding** mismatch and the **CKB-reorg depth-0** gap (#9) are addressed in code. The independent third-party audit + the redeploys remain required. (Caveat that is irreducible in a sandbox: ceremony *contributor independence* — ≥1 honest external party on an airgapped machine — is simulated; the machinery + verifiable transcript let real contributors slot in.) |
| 5 | **Permissionless relayer / liveness** | **ON-CHAIN PRIMITIVES DONE; daemon EXTERNAL** | The on-chain mechanics are proven live (`spike/relay-escrow/`, Pudge): **permissionless relay** (escrow consumed with NO key, gated on the authenticated checkpoint — `0x6e9a291e`) + **timeout refund** (depositor reclaims after deadline — `0x78cf1071`) + reject. Combined with the no-admin-key, proof-gated validators, a relayer can't forge — only fail to relay, and the user self-relays/refunds. What's left is **off-chain**: a hosted, monitored daemon that watches both chains, builds proofs, submits, and handles Mithril cert latency. See TESTNET_LOG.md §F. |
| 6 | **Ecosystem usability** (wallets, DEX listing, liquidity) | **EXTERNAL** | The minted ckCKB is a real native asset (transferable in principle) but was minted→burned in a closed loop; never held/used. Needs market participants. |
| 7 | **Key custody** (a deploy key was lost ⇒ a stranded cell) | **PROCESS, mitigated** | The leap-out closure used a fresh faucet-funded key reproducibly. Lesson: escrow/commit deploy keys (never an uncommitted ephemeral file). Original stranded cell `0xc40d4a39:0` stays unspendable but is no longer a blocker. |
| 8 | **Asymmetric models** (lock-mint one way, binding/seal the other) | **BY DESIGN** | Not a defect: each direction uses the verifier appropriate to the destination chain. A symmetric same-asset Cardano→CKB→Cardano round trip of one fungible token is a product choice, not built. |
| 9 | **CKB-reorg theft** (a CKB-native leap could mint on Cardano at depth 0, then a cheap CKB reorg erases the lock — keep both the asset and the wrapped FT) | **CLOSED IN CODE (circuit + validators, 101/101 aiken tests); pending re-ceremony + redeploy + audit** | **SEC-D6** (`spike/ckb-to-cardano/circuit/D6_REORG.md`). (a) the windowed leap **and** finalize circuits now enforce `tip_height − height ≥ K` with **K a governance-tunable public input** (validated: `is_satisfied` iff `diff ≥ K`; a K=12 proof verifies); (b) `cardano_bound` **pins K** from the governor-signed policy, located by a **one-shot policy NFT** (`chiral_policy_thread`) at the chiral_policy script hash, range-asserted — so K cannot be forced to 0; (c) a thread-pinned **`leap_ratelimit`** singleton caps **aggregate** value-in-flight per rolling window (mint-coupled, upper-bound-anchored time semantics) so a thief can't split below the cap; (d) trust-root hardening (exactly-one checkpoint/registry/policy reads, 32-byte seal pin, commitment byte-binding). Two adversarial-review passes (design + implementation); every must-fix landed. **Honest scope:** a reorg can't be *shallow* (depth K) or *profit* (value capped below depth-K reorg cost) — **not** "impossible" (CKB PoW is the ceiling). The dropped maturation-lock keeps it simple (Phroi's concern). **Remaining:** finish the in-flight re-ceremony on the windowed circuits, redeploy `cardano_bound` (now 6 params) + the new minters, external audit. |

## Authenticated checkpoint — the load-bearing primitive, now demonstrated live
The biggest trust caveat (my unlock/leap-out demos read *hand-made* checkpoints) is now substantially
addressed: the full Mithril **AdvanceCert** verifier (`spike/light-client-cell/advance-cert/`) was rebuilt
for CKB-VM and **runs on Pudge** — it advances the stake checkpoint epoch 320→321 ONLY by verifying a real
Mithril cert in-VM (BLS aggregate + 2330-index stake lottery + Merkle + quorum), **164.4M cycles**, tx
`0xb7ada085` (block 21,358,958). So a CKB script verifying a real Cardano certificate on-chain — the hardest
primitive — is **proven live**. **DONE:** a *CardanoTransactions* cert is verified against this checkpoint (TxSetCert, 164.4M cycles,
tx `0xe4e1b0c6`) to authenticate the *tx-set* root, and the burn-gated unlock now REQUIRES that
type-authenticated checkpoint — positive unlock `0xe6ea066a` committed, unauthenticated checkpoint rejected.
The full Cardano→CKB trust chain is on-chain. See TESTNET_LOG.md §D.1.

## Bottom line
Both code-level trust gaps are now closed: **#1 (mint amount/name binding)** — validator-level, aiken-tested;
**#2 (burn-gated unlock)** — deployed + unlocked live on Pudge, positive- and negative-tested on-chain, and
now **gated on an AUTHENTICATED checkpoint** (the C↔D link is wired: TxSetCert verifies the real tx cert
in-VM → authenticated tx-set checkpoint → unlock requires it; positive `0xe6ea066a` committed, unauthenticated
rejected). So conservation is no longer enforced by operator trust: minting is bound to the proven locked
amount, and the return unlock is gated on a Mithril-certified Cardano burn whose tx-set root was itself
cert-verified in-VM. Gaps **#3–#6 remain
external** (mainnet, audit, liquidity, permissionless ops) and cannot be closed from a sandbox — they are
productionization, not cryptography. Net: a working, verified, **trust-minimized** cross-chain prototype both
directions on testnets, with the on-chain Mithril verifier proven live — not yet a mainnet, audited, liquid
bridge with freely-usable wrapped tokens.
