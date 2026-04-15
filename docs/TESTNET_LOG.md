# Testnet log — every on-chain step (Cardano preview ⇄ CKB Pudge)

> Append-only record of the live testnet actions, with tx hashes, cycle costs, what each proves, and the
> honest caveat for each. All independently re-verifiable via CKB RPC (`https://testnet.ckb.dev`) and Koios
> (`https://preview.koios.rest`). Source + build harness + lifecycle tooling for each are committed (the
> earlier CKB tooling was lost precisely because it wasn't — never again).

## Keys (public only)
- Pudge relayer/test key: faucet-funded (300,000 CKB, claim id 703410). Address committed nowhere as a
  private key; the private key lives outside the repo. **Lesson applied:** scripts read the key from a
  file path, never embed it.

## A. Forward-leg conservation (CKB→Cardano), re-verified (prior work)
| step | tx | check |
|---|---|---|
| ckCKB mint (preview) | `21ad4a44…` | Koios: ckCKB `8f11f2b1…636b434b42` mint_cnt 1 |
| ckCKB burn (preview) | `6608c4c8…` | Koios: burn_cnt 1, **total_supply 0** |
| seal mint (preview) | `83dd51d2…` | Koios: block 4,355,257, epoch 1320 |
| seal Unbind (preview) | `6c729ea6…` | Koios: block 4,355,361, epoch 1320 |
| CKB genesis bind (Pudge) | `0x0318d35f…` | committed, block 21,339,914 |
| CKB transition (Pudge) | `0x94d0620f…` | committed, block 21,339,956 |

## B. Leap-out FINALIZE — closed live (this session)
Recreated the checkpoint cells from committed proof data (p1t_hex/p1f_hex) under a fresh funded key, reusing
the deployed finalize verifier `0x97ca700d`. Tooling: `deploy/pudge/close-leapout-fresh.mjs`.
| step | tx |
|---|---|
| checkpoint cells (transfer 5acd33ab @:0, unbind 0bc33aa8 @:1) | `0x8d637bd3…` |
| bound cell genesis (seal a98b6636 v2) | `0x8de55d8b…` (verifier accepted the certified-transfer bind) |
| **LEAP-OUT FINALIZE** | **`0x795f4bb9…`** (block 21,358,183) |
- Proves: the bound cell is destroyed (now dead) against the REAL certified Unbind `6c729ea6`; outputs are
  plain cells (no type script) ⇒ asset unbound.
- Caveat: used the existing certified Unbind (reused, not a fresh Cardano Unbind + Mithril wait).

## C. Burn-gated unlock — built + closed live (this session)
New CKB **lock** script `spike/burn-gated-unlock/` (codeHash `0x7d251a83…`, 23.9 KB). Releases locked CKB
ONLY on a Mithril-certified Cardano burn: reads the certified root from a checkpoint cellDep and verifies
the burn `6608c4c8` MKMapProof (two-level Blake2s256 MMR) in-VM. Tooling: `deploy/pudge/burn_unlock.mjs`,
`burn_unlock_neg.mjs`.
| step | tx | result |
|---|---|---|
| deploy script + checkpoint | `0x973f164c…` | code cell + `LCKP‖ee048053…` |
| lock 150 CKB | `0x3e4b81a5…` | locked behind the burn-gated script |
| **UNLOCK (proof-gated)** | **`0xefb60dfc…`** (block 21,358,984) | script ran, accepted the proof, cell spent |
| negative test (no checkpoint) | rejected | **lock error code 10** — spend without the proof fails |
- Proves: the unlock is gated by a certified burn, not an operator key (positive + negative on-chain).
- Caveat: the checkpoint cell here is supplied (not yet authenticated — see D); and it binds the *specific*
  burn `6608c4c8` (which burned the full 100k supply, so amount is bound). Arbitrary-amount Conway parse is
  a generalization.

## D. Authenticated checkpoint — the full Mithril verifier, live (this session)
Rebuilt the load-bearing **AdvanceCert** type script `spike/light-client-cell/advance-cert/` (codeHash
`0x84a83dcc…`, 121 KB) — pure-Rust `bls12_381` + `num-bigint` + `sha2` + `blake2b-ref`, no_std on CKB-VM —
which rolls the Cardano stake-checkpoint forward ONLY by verifying a real Mithril certificate in-VM
(compute_hash recheck + BLS12-381 aggregate + the **2330-index stake lottery** + Merkle batch + quorum).
Added a trusted-genesis branch. Tooling: `deploy/pudge/lca.mjs`, `lca_advance.mjs`.
| step | tx | result |
|---|---|---|
| deploy verifier | `0xb34aa21a…` | committed, block 21,358,946 |
| genesis checkpoint (epoch 320, trusted) | `0x122b71f0…` | type script ran genesis branch, cell live |
| **AUTHENTICATED ADVANCE 320→321** | **`0xb7ada085…`** (block 21,358,958) | **164.4M cycles** — full Mithril verify in-VM; epoch-321 cell live with the advanced root |
- Proves: a CKB type script verifies a **real Mithril BLS-STM certificate on-chain** (~4.7% of a block's
  3.5e9 budget) to advance the trust anchor — the hardest, load-bearing primitive of the whole bridge.
- Caveat: this authenticates the **AVK/stake** checkpoint (epoch 320 data, hardcoded cert). To fully gate
  the burn-unlock (C) on an authenticated **tx-set** root, the remaining link is verifying a
  CardanoTransactions cert against this AVK checkpoint to authenticate the tx-set root (same machinery,
  different cert) — then have the unlock require *that* authenticated checkpoint instead of a supplied one.

### D.1 — C↔D wiring: DONE, the full trust chain links on-chain
The tx-set root `ee048053` is now authenticated on-chain (no hand-supplied root). Three sub-steps, all live:
1. **Extracted** the real verifier constants from the cert's 13.7 KB `multi_signature` via the mithril_verify
   host (`src/bin/extract.rs`, mithril-stm) — per-signer sigma/vk/stake/winning-indices (2 signers, 1127 +
   1197 = 2324 indices), the merkle batch path, host-RE-VERIFIED. **Finding:** the cert's `avk_root a15b4c16`
   and `total_stake 64116908740696` are IDENTICAL to the live AVK checkpoint (D) — the chain composes.
   (`tx_cert_constants.json`, committed.)
2. **TxSetCert verifier** (`spike/light-client-cell/txset-cert/`, codeHash `0x7514c13e`): verifies the real
   CardanoTransactions cert (M1 signed_message + BLS aggregate + 2324-index lottery + Merkle batch + quorum)
   against the avk from the AVK-checkpoint cellDep, and publishes `LCKP‖ee048053`. Validated in **ckb-debugger**
   (146.2M cycles, run result 0) before deploy. LIVE: deploy `0x94bbd19b`; **authenticated tx-set checkpoint
   `0xe4e1b0c6` @164.4M cycles** (block 21,358,964) — cert verified in-VM against the live AVK checkpoint;
   cell carries the TxSetCert type script.
3. **Re-wired burn-gated unlock** (`spike/burn-gated-unlock/`, now requires the checkpoint carry type-hash
   `0x69b443c6` via `load_cell_type_hash`). LIVE on Pudge:
   - **POSITIVE** unlock via the authenticated checkpoint: `0xe6ea066a` (committed, block 21,358,940) — released.
   - **NEGATIVE** via a hand-made unauthenticated `LCKP` cell: **rejected** (lock ValidationFailure).
   (Tooling: `deploy/pudge/txset.mjs`, `burn_unlock_authenticated.mjs`. NB the molecule `load_cell_type`
   path emits an AMO instruction CKB-VM rejects; `load_cell_type_hash` avoids it.)
=> The locked CKB now releases ONLY against a tx-set root that was authenticated by verifying the real
Mithril CardanoTransactions cert in-VM, which in turn is verified against the AVK checkpoint advanced by
verifying a real Mithril cert in-VM. The whole Cardano→CKB trust chain is on-chain; no operator key, no
supplied root. (Genesis AVK is the one trusted bootstrap — inherent to any light client.)

## E. Mint amount/name binding — validator-level (this session)
`spike/ckb-to-cardano/groth16/validators/zk_chiral_mint.ak`: minted qty == the amount committed in the
CKB-bound state (bound to the real lock via the existing `commitment` public input — no trusted-setup
change), name pinned to the commitment, exactly one asset; burns allowed. **`aiken check` 12/12**, incl. 5
binding tests (accepts correct; rejects wrong amount / wrong name / replayed inputs; detects burn).
- Caveat: validator-level (compiles + tested); relayer wiring + redeploy + a fresh proof is the integration.

## Net trust state after this session
- Operator-**key** unlock gap: **closed** (C, on-chain). Mint **amount** convention gap: **closed**
  (E, validator-level). Authenticated-checkpoint **mechanism**: **demonstrated live** (D).
- Remaining to a coherent testnet bridge: wire C↔D (authenticated tx-set checkpoint), a running relayer,
  the fee/self-relay/refund incentives, then Phase-5 hardening. See CHIRAL_READINESS.md.
- Inherent anchors unchanged: Mithril honest-stake threshold + Groth16 trusted setup; not post-quantum at
  the chains' signature layer. A bridge can't be more trust-minimized or more PQ than its two endpoints.

## F. Decentralized-relayer escrow — permissionless relay + timeout refund (this session)
The relayer is already trustless for SAFETY (proof-gated validators, no admin keys), so decentralizing it is
a liveness/incentive problem. `spike/relay-escrow/` (CKB lock, codeHash from escrow.bin) demonstrates the two
needed primitives, LIVE on Pudge (`deploy/pudge/escrow.mjs`):
- **(A) PERMISSIONLESS RELAY** — `0x6e9a291e` (block 21,358,963): the escrow was consumed with **NO signature**,
  purely because the tx references the AUTHENTICATED tx-set checkpoint (type-hash 0x69b443c6) as a cellDep —
  i.e. anyone who proves the bridge event happened may relay and keep the escrow as the fee. No operator key.
- **(B) TIMEOUT REFUND** — `0x78cf1071` (block 21,358,971): after the deadline (input `since` >= deadline in
  the cell data), the depositor reclaims to their own lock — so liveness never depends on a third party,
  worst case is a refund. (Config in cell DATA = depositor_lock_hash||deadline; plain syscalls, no molecule.)
- **(C) NEGATIVE** — a spend with neither an authenticated checkpoint nor a matured deadline is **rejected**
  (lock ValidationFailure).
=> The on-chain mechanics for a permissionless, incentivized, self-relayable-with-refund relayer are proven.
What remains (gap #5, off-chain): a hosted, monitored daemon that watches both chains, builds proofs, and
submits — productionization, not new cryptography.

## G. PARAMETERIZED verifier — cert via witness (not fixture), live (this session)
The AdvanceCert/TxSetCert verifiers embedded a single cert. `spike/light-client-cell/cert-verify/` now PARSES
the cert from a WITNESS cell (a cellDep whose data starts "MWIT") and verifies it — so the light client can
verify ANY live Mithril cert. The relayer transcodes the cert with `mithril_verify/src/bin/transcode_witness.rs`
(decodes the multi_signature → a compact 10,439-byte binary: signed_message, avk_root, params, M1 parts,
per-signer sigma/vk/stake/indexes, the Merkle batch, tx_root).
- Validated in **ckb-debugger** on the real witness: run result 0, 147.5M cycles (parses + full verify).
- LIVE on Pudge (`deploy/pudge/txset_witness.mjs`): deploy `0x4b3aacfa`; witness cell `0xe33e1d3b`;
  **authenticated checkpoint via the WITNESS-supplied cert `0xf1d61caf` @165.9M cycles** (block 21,358,…) —
  the verifier read the witness, bound its avk_root to the live AVK checkpoint cellDep, verified the cert,
  and published `LCKP‖ee048053`. Cell live, type = parameterized verifier `0x2e9d2f01`.
=> The on-chain verifier is no longer a fixture. The relayer (G) fetches a live aggregator cert, transcodes
it to a witness, and submits it; the verifier checks it in-VM. This is the continuous light client: advance
to each new epoch/cert by supplying its witness. (Demonstrated with cert 7356eaa1 as the test vector; a fresh
epoch advance is the same mechanism with the next cert's witness + the matching AVK checkpoint.)

## H. MULTI-EPOCH advance with LIVE certs — verifier validated; genesis live (this session)
The parameterized verifier (cert-verify) gained an `advance` mode: input checkpoint (epoch||avk||total) + a
cert witness -> verify the cert against the input avk, EXTRACT next_avk (root+total) from the signed
next_aggregate_verification_key part (in-VM hex-decode + targeted JSON parse), output checkpoint
(epoch+1||next_avk||next_total). M1 generalized to any cert type (Sha256(parts)==signed_message; the tx-root
binding moved to the TxSetCert mode only). The relayer transcoder (`transcode_witness.rs`, preserve_order)
handles any cert type.
- The live Mithril cert CHAIN is real and links: cert_e.next_avk == cert_{e+1}.avk, walked 1321->...->1283
  via previous_hash. Genesis at 1319 (avk 0f3c0c7f) -> 1320 (13a8810b) -> 1321 (a15b4c16, == the live state).
- **ckb-debugger validated** on the REAL LIVE certs: cert_1319 (MithrilStakeDistribution) run result 0,
  148.2M cycles; cert.example (CardanoTransactions) 147.5M — the verifier verifies BOTH cert types.
- **LIVE on Pudge — the full chain committed**: deploy `0xd2416208`; witness cells `0x6c9eafd4`/`0x67121e12`;
  GENESIS epoch 1319 `0x977ff631`; **ADVANCE 1319->1320 `0x7f2111e7` @166.6M cycles** (verify cert_1319);
  **ADVANCE 1320->1321 `0xdc0a7461` @163.0M cycles** (verify cert_1320). Final checkpoint cell LIVE: epoch
  1321, avk a15b4c16 (== the live Cardano state). The light client advanced THREE epochs by verifying two
  real Mithril certs on-chain, each extracting the next stake commitment. Tooling: `deploy/pudge/advchain.mjs`.
=> The continuous light client is built and validated: it advances epoch-by-epoch by verifying each live
Mithril cert in-VM and extracting the next stake-distribution commitment. This is the general mechanism the
relayer daemon drives (fetch live cert -> transcode -> submit advance).

## I. SOUNDNESS FIX — genesis pinning + avk-source binding + differential test (this session)
Fixing the real gap I flagged: without pinning, an attacker could genesis a FAKE-avk checkpoint, sign a fake
cert under it, and authenticate a fake tx-set root. Two-part fix in `spike/light-client-cell/cert-verify/`:
- **Genesis pinning** (advance mode): the genesis branch now requires the output == the ONE canonical
  pinned genesis (epoch 1319, avk 0f3c0c7f, total) — a fake-avk chain CANNOT be created. The advance path
  (verify real cert -> extract next avk) is unchanged and already proven live (§H).
- **avk-source binding** (TxSetCert/deploy mode): the avk is trusted ONLY from a 48-byte checkpoint cell
  that CARRIES the canonical advance-verifier type (`load_cell_type_hash == 0x59efd99d`) — not any 48-byte
  cell. So the avk traces to the pinned genesis chain. (burn-gated unlock already requires the TxSetCert type.)
  Chain of type-bindings: unlock -> TxSetCert-typed checkpoint -> advance-verifier-typed AVK checkpoint ->
  pinned genesis -> real Cardano stake. Both modes compile; demo `deploy/pudge/advchain_pinned.mjs` (fake
  genesis rejected, canonical genesis + advances).
- **Differential test** (`mithril_verify/difftest_results.txt`): **25/25 live certs** (epochs 1298-1321,
  both CardanoTransactions + MithrilStakeDistribution) transcoded + host-verified vs `mithril-stm` (the
  oracle), 0 failures — broad correctness coverage for the verifier path (ckb-debugger validated on reps).
=> The fake-avk attack is closed in code (genesis pinning + avk-source type binding); the verifier is
differentially validated against mithril-stm on 25 real certs. On-chain re-demo of the pinned negative test
was gated by public-RPC flakiness (ops), not logic — the advance path itself is proven live (§H).

### I.1 — correction: avk-source binding must NOT be circular (codeHash stability)
The first cut of the avk-source binding (commit `a1c5d6f`) defined `ADV_TYPEHASH` and imported
`load_cell_type_hash` at module scope — un-gated. That pulled both into the **advance** binary too, which
**changed the advance binary's own codeHash** (it deployed as `0xfe0a6c17` instead of the canonical
`0xe877a80…`). But `ADV_TYPEHASH` is the type-hash of the canonical advance verifier, so making the advance
binary depend on it is a circular reference: the value can never match the binary that contains it.
Fix: cfg-gate `ADV_TYPEHASH` and `avk_checkpoint()` (the only user of `load_cell_type_hash`) to deploy/
TxSetCert mode only — `#[cfg(all(not(feature="standalone"),not(feature="embedtest"),not(feature="advance")))]`
— and reference `load_cell_type_hash` by fully-qualified path so it's absent from the advance import set.
Verified after the fix (`@ckb-ccc/core` over the rebuilt `adv.bin`, 104,952 B):
- advance **codeHash** = `0xe877a8028eac379e962a596671d1cd918aceddfa4c4cd78163168ba3b533ac55` — STABLE (== pre-bug, the value
  the deployed/demo scripts already use).
- advance **type-hash** (data1, args `0x`) = `0x59efd99d82ac49779594ce7f9b99d4ef5e51cfe9f6c7c807b3a67ab27869155b`
  == the `ADV_TYPEHASH` constant in deploy mode. So the binding is now **one-directional** (deploy → advance's
  type-hash) and non-circular; advance mode references nothing of itself. Both modes compile clean.

## J. PHASE-5 ADVERSARIAL HARDENING — forged / replay / equivocation / reorg suite (this session)
The differential test (§I) proves *valid* certs are accepted (25/25 vs `mithril-stm`). Phase-5 is the
offensive counterpart: a `ckb-debugger` suite that proves *invalid* inputs are **rejected**, and that the
chain-integrity guards we built (genesis pinning, epoch/avk binding, avk-source type binding) actually fire.
`spike/light-client-cell/cert-verify/adversarial/` — `python3 suite.py` (no network/node), **23/23**:
- **A. forged cert (11)** — a real witness mutated one field at a time: BLS `sigma`, `mvk`, signer stake,
  `signed_message` (M1), `avk_root`, Merkle batch value, inflated quorum `k`, and a forged
  `next_aggregate_verification_key` (**equivocation** — the next key is in the M1-signed message, so a
  conflicting key can't be published under the same signature) → all rejected (`verify()`→`20`); truncated/
  wrong-magic inputs fail closed.
- **B. chain integrity (8, advance mode)** — fake genesis (attacker avk) rejected (`7`); canonical pinned
  genesis accepted (`0`); real `1319→1320` advance accepted (`0`); **replay** of a wrong-epoch cert (`10`);
  doctored input avk (`11`); **reorg**/epoch-skip output (`5`); attacker-chosen output avk not from the cert (`5`);
  forged cert inside an advance (`20`).
- **C. avk-source binding (4, deploy mode)** — only a checkpoint cell carrying the canonical advance-verifier
  type (`type-hash 0x59efd99d…`) is trusted as an avk source: untyped (`3`) and wrong-type (`3`) cells are not
  trusted; a correctly-typed checkpoint with a mismatched avk is rejected (`6`); a correctly-typed, avk-matching
  checkpoint passes the binding (`14`, the tx-root gate). This directly exercises the §I/§I.1 soundness fix.
Verifier codeHashes under test: standalone `0x2d0ed47a…`, deploy `0xdfc0aad0…`, advance `0xe877a80…`
(canonical). Captured in `adversarial/RESULTS.txt`; rerun with the checked-in prebuilt binaries or `./build.sh`.

## K. FORWARD-LEG (CKB→Cardano) CHECKPOINT GENESIS PIN (this session)
The reverse leg pins its light-client checkpoint to one canonical genesis (§I.1). The **forward** leg's
`advance_ckbcert.ak` enforced heaviest-chain (`new_total > old_total`) but had **no genesis pin** — the
initial Cardano-side CKB checkpoint was whatever the deployer set, so an attacker could seed a parallel
checkpoint with a fake genesis. Closed with the Cardano-idiomatic mirror of the reverse-leg pin: a one-shot
**thread token**.
- `validators/ckbcert_thread.ak` — a minting policy parameterized by `(genesis_ref, pinned, cp_script)`.
  It can mint the thread token **at most once** (it must consume the unique `genesis_ref` outpoint) and
  **only** if exactly one token is minted onto an output at the checkpoint script whose inline datum equals
  the `pinned` canonical genesis `Checkpoint{chain_root, total_difficulty}`. Burning is always allowed.
- `validators/advance_ckbcert.ak` — now parameterized by `(vk, thread_policy)` and additionally requires the
  thread token on **both** the spent checkpoint input and the continuing output. So every advance is tied to
  the single pinned-genesis lineage; a fake checkpoint (no token) is unspendable as a checkpoint.
- Shared logic + canonical pin live in `lib/g16/ckbcert.ak` (the `Checkpoint` type now imported by both
  validators). Pinned anchor = real CKB ChainRootMMR root `0xfbd2fcba…` (deploy-time parameter, auditable).
- **Adversarial battery** `lib/g16/ckbcert_test.ak` — **18/18** (`aiken check`, `GENESIS_PIN_RESULTS.txt`),
  the Cardano-side mirror of Battery B: genesis accepted only with unique-outpoint + exactly-one-token +
  pinned datum at the right address; **rejected** for fake datum, wrong address, non-unique (parallel) mint,
  double-mint; thread presence/absence; and heaviest-chain (equal/lighter reorg rejected). Both validators
  compile to UPLC (`aiken build`, blueprint entries `advance_ckbcert` + `ckbcert_thread`). 30/30 total checks.
Relayer wiring (mint the thread at the pinned genesis, carry it through advances) + redeploy is the
integration step; the on-chain logic and pin are done and tested.
