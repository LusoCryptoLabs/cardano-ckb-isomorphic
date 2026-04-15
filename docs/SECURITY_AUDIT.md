# Security audit — Chiral (Cardano⇄CKB isomorphic binding protocol)

**Status: COMPLETE (internal) + REMEDIATION PASS COMPLETE.** Internal adversarial security audit — four
independent component reviews + cross-cutting analysis, every Critical/High re-verified against source.
**Original result: 8 Critical, 12 High, 10 Medium** — research-grade, not value-safe as coded.

## Remediation closeout (final)
Every finding fixable + verifiable in-sandbox has been **fixed and tested**; what remains is precisely scoped
as inherently external or design-variant. Headline:
- **All 8 Criticals closed + tested:** C1 (burn replay → SMT nullifier, genesis-pinned, ckb-testtool 10/10),
  A1/A7/A8 (auth), B1 (redeemer vk), B2/D1 + D1b (PI encoding, +finalize), D2 (seal-bound), D3/B4 (root pinned).
- **High/Medium closed + tested:** A3 (sound Conway decoder, 8/8), A4/A5/A6, B3 (mint replay), B5–B8, C3/C5/C8,
  **C7** (escrow event-binding, 6/6), N1, N-2 (finalize provable), N-FIN-1 (forward seal-nullifier, wired,
  aiken 77/77), **D4** (full MMR-digest), **D7** (compact overflow), **D8** (mul256 carry).
- **D6 (ceremony):** machinery hardened — **Schnorr PoK** (rogue contribution rejected) + OS entropy; the
  *trust* (≥1 honest external party + real phase-1) is the **one fundamentally out-of-sandbox** item.
- **Scoped residuals (cores already closed, rigorously analyzed):** **D5** — economic heaviest-chain is honest
  work (PoW + `difficulty_verify` + cumulative `add256`); the residual is CKB *epoch-schedule conformance*, not
  a cheap-fork hole. **D2-A** — with `seal == cbmt_leaf` the seal IS the confirmed leap tx; outpoint-∈-inputs
  is an *alternative* (outpoint-seal) design the bridge doesn't use.
- **Still REQUIRED before value:** an **independent third-party audit** (gap #4) and a **real multi-party
  ceremony** (D6 trust). These are external by nature, not internal gaps.

Detailed per-finding status is in the "Remediation status" sections below (v2 → v4 + the circuit/finalize/
nullifier/escrow/decoder/ceremony closeouts).

## ⚠️ Disclaimer (read first)
This is a **rigorous internal audit**, not a substitute for an **independent third-party audit** by a
specialist firm — which remains REQUIRED before mainnet or any real value (BRIDGE_READINESS gap #4). An
internal audit shares blind spots with the authors; treat it as defense-in-depth and a pre-audit cleanup,
not a clearance. In particular, **Groth16 circuit soundness** and **BLS/Mithril cryptographic correctness**
need specialist ZK/crypto review with tooling (not just code reading).

## Scope
Testnet codebase at repo HEAD. In scope — the trust-minimized core both directions:
- **Reverse leg (Cardano→CKB), CKB-VM scripts:** `spike/phase1/bound_asset_unified.rs` (BoundAsset),
  `spike/light-client-cell/{advance-cert,txset-cert,cert-verify}` (Mithril cert + checkpoint auth).
- **Forward leg (CKB→Cardano), Aiken validators:** `groth16/lib/g16/verifier.ak`,
  `groth16/validators/{cardano_bound,zk_chiral_mint,advance_ckbcert,ckbcert_thread}.ak`.
- **Value release / liveness:** `spike/burn-gated-unlock/` (v1 + v2), `spike/relay-escrow/`, the relayers.
- **Forward proving:** `spike/ckb-to-cardano/circuit/prover/` (the consensus circuit + ceremony).
Out of scope: the DEX-integration layer (separate project), third-party deps' internals, mainnet params.

## Methodology
Adversarial code review per component (attacker goals: mint unbacked tokens, forge a leap, replay, break
conservation, unlock without backing, forge/halt the checkpoint), four parallel deep reviews + cross-cutting
analysis + manual verification of every Critical/High finding against the source. Severity:
**Critical** (funds loss / unbacked mint), **High** (conditional funds loss / trust-model break),
**Medium** (DoS/griefing/liveness), **Low** (hardening), **Info** (note/by-design).

## System architecture & trust model
Two directions, each verifying the *other* chain's consensus/cert on the destination chain:
- **CKB→Cardano:** a Groth16 proof of CKB consensus (PoW + MMR + CBMT + commitment) is verified in Plutus;
  the wrapped-token mint policy binds (amount, name) to the proof's committed CKB lock state.
- **Cardano→CKB:** a Mithril certificate (BLS-STM stake multisig) is verified directly in CKB-VM; an
  authenticated light-client checkpoint pins the certified tx-set root; the binding lock / burn-gated unlock
  read that checkpoint.

**Core trust assumptions (if any fails, security fails):**
1. **Mithril honest-majority stake** (reverse leg): the BLS-STM threshold reflects ≥ the honest Cardano
   stake quorum. Standard Mithril assumption.
2. **CKB PoW heaviest-chain** (forward leg): the consensus circuit + advance verifier track the heaviest
   valid chain; a checkpoint reflects real cumulative work.
3. **Groth16 trusted setup** (forward leg): the per-circuit ceremony's toxic waste was destroyed (≥1 honest
   party). A full break ⇒ forge proofs ⇒ mint unbacked.
4. **Verifier/circuit soundness:** the on-chain verifiers and the circuit actually constrain what they claim
   (the subject of the component audits below).
5. **Genesis pinning:** each chain's checkpoint lineage is pinned to one canonical genesis (thread token /
   pinned root), so a parallel fake-genesis checkpoint can't be advanced.

## Cross-cutting / system-level findings

- **X1 — Trusted-setup ceremony is a single point of total failure (HIGH, by-design for Groth16).** A
  forward-leg Groth16 break (all ceremony parties collude or toxic waste retained) ⇒ forge a consensus
  proof ⇒ mint unbacked wrapped tokens, undetectable on-chain. Mitigation present: a real 3-party phase-2
  ceremony (verifiable). Recommendations: maximize independent participants + publish the transcript; or
  move to a **universal-SRS** system (Plonk/KZG-BLS12-381) to eliminate the per-circuit ceremony (noted as
  an option in `circuit/SPEC.md`). The circuit-audit section assesses ceremony soundness.

- **X2 — Key custody / operational keys (HIGH, process).** A deploy key was already lost once, stranding a
  cell (gap #7). Governor/admin/deploy keys (where present — e.g. checkpoint genesis-pin minting, any
  governance) are catastrophic if compromised. Recommendation: HSM/multisig for all privileged keys;
  enumerate every key and its blast radius before mainnet. **Verify** no validator has an admin key that can
  bypass proof-gating (the component audits check this; the design claim is "no admin keys — proof-gated").

- **X3 — Replay / once-only across the system (CRITICAL if broken — under component audit).** Conservation
  depends on "spend-once seal ⇒ mint-once" and "one certified burn ⇒ one unlock." This must be enforced by
  real UTxO/seal consumption + per-event uniqueness, not by convention. Two concrete questions handed to the
  component audits: (a) can one Mithril-certified **burn** unlock **multiple** locked cells (no per-burn
  nonce)? (b) can one CKB **seal**/proof mint **twice** on Cardano? Findings fold in below; this is the
  highest-priority class.

- **X4 — Checkpoint authentication is load-bearing (HIGH — under component audit).** Both legs' value
  release reads a "certified root" from a checkpoint cell. If a checkpoint with an attacker-chosen root can
  be accepted (hand-made, wrong type, unauthenticated), the attacker forges arbitrary leaps. The design
  authenticates by (CKB) the checkpoint cell's TYPE-script hash (cert-verified in-VM) and (Cardano) a
  genesis-pinned thread token. The component audits verify these are sufficient and correctly checked.

- **X5 — Liveness / censorship (MEDIUM, mitigated).** The bridge is coordinator-driven today; a relayer can
  withhold service. Mitigations proven live: permissionless relay (anyone relays, no key) + timeout refund.
  Residual: Mithril cert latency and checkpoint-advance liveness are operational; a stalled checkpoint halts
  releases (funds safe, not stuck-forever given refund paths). No funds-loss, but a real availability SLA +
  monitoring is needed (hosted daemon, gap #5, external).

- **X6 — Two distinct verifier stacks doubles the audit surface (INFO, by-design).** Lock-mint (forward,
  Groth16) and binding/seal (reverse, Mithril-in-VM) are different trust models and codebases. Not a defect
  (each fits its destination chain), but both must independently hold; a bug in either breaks that leg.

- **X7 — Quantum (INFO, documented).** Hash/commitment cores are PQ; signature/pairing layers (Mithril BLS,
  Groth16, Cardano Ed25519, CKB secp256k1) are not — same as all production chains. Endgame: STARK-Mithril
  (FRI) + a STARK/Plonk forward verifier. Not a near-term finding.

- **X8 — Conway CBOR parsing in CKB-VM (MEDIUM — under component audit).** Both BoundAsset and burn-gated-v2
  hand-parse Cardano Conway tx CBOR in-VM. Hand-rolled parsers risk OOB/panic on malformed input (DoS) or
  parser-confusion (security) — e.g. map-vs-array output forms, multiple mint entries. The component audits
  stress this; any panic-on-malformed-input is at least a Medium (a script that panics may be unspendable or
  exploitable depending on context).

## Headline result
Three independent component reviews **converged** on the same conclusion, and I **verified each Critical
against source**: as currently coded, the bridge's core guarantee — *"a wrapped token / a leap exists only
against a real, confirmed lock on the other chain"* — **does NOT hold**. There are **multiple independent
paths to mint unbacked tokens or forge a leap.** The live testnet round-trips succeeded because the relayer
was honest (real vk, real data); the on-chain code does not *enforce* honesty. This is consistent with the
project's own "feasibility / spike, unaudited" framing — but it means the system is **research-grade, not
value-safe**, and the Criticals below are blockers before any value.

## Component findings
Severity legend: **C**ritical / **H**igh / **M**edium / **L**ow / **I**nfo. ✔ = re-verified against source.

### A. Reverse-leg CKB-VM verifiers (`bound_asset_unified.rs`, `light-client-cell/*`)
- **A1 (C) ✔ — BoundAsset checkpoint root is unauthenticated.** `checkpoint_root()`
  (`bound_asset_unified.rs:95-104`) accepts **any** cell-dep whose data starts with `"LCKP"` — no
  `load_cell_type_hash` check tying it to the cert-verified checkpoint (contrast `cert-verify` which checks
  `ADV_TYPEHASH`, and `burn_gated_unlock` v1 which checks the type hash). An attacker references a hand-made
  `"LCKP"‖attacker_root` cell, builds a tx + MKMapProof against their own root, and any GENESIS/TRANSITION/
  FINALIZE passes → forge leaps, double-spend, mint without backing. **Fix:** require the LCKP cell to carry
  the canonical TxSetCert/AdvanceCert type hash.
- **A2 (C→ DoS) ✔ — Hand-rolled Conway CBOR parser has no bounds checks** (`bound_asset_unified.rs:26-61`):
  `R::u32/lp`, `parse`, `copy_from_slice(&b[bj..bj+bl])` index attacker-supplied lengths with no validation
  → slice-OOB panic on malformed witness. In CKB-VM a panic fails the script (so it's fail-closed / DoS, not
  direct theft) — but the parser's *output* is security-load-bearing (A3). **Fix:** fallible bounds-checked reads.
- **A3 (H) — `seal_recreated_at_lock` is evadable** (`bound_asset_unified.rs:65-93`). The "seal NOT recreated
  at the lock" guard that authorizes a FINALIZE is a hand-rolled output walker matching exact `LOCK_ADDR` +
  `SEAL_POLICY` only when `vm==4 && vlen>=2`. An attacker who genuinely recreates the seal in an
  encoding the walker doesn't recognize (alternate value/address shaping, the `258`-tag set form) makes it
  return `false` → FINALIZE succeeds though the seal lives on → cross-chain double-spend. **Fix:** use a
  sound, exhaustively-tested canonical decoder; fail-closed on any unparseable output.
- **A4 (H) — Seal/proof replay & shared hardcoded instance.** `SEAL_POLICY`/`LOCK_ADDR` are hardcoded
  (`:18-19`, "in production: script args"); one deployed script serves every bound cell, so a FINALIZE proof
  crafted for one instance is reusable against another's bound cell. No nullifier ties a proof to a specific
  consumed CKB outpoint. **Fix:** make instance params cell args + bind the consumed outpoint/nullifier.
- **A5 (M) — GENESIS lacks a positive seal-mint check.** GENESIS only checks `out_seal_txid ==
  blake2b256(tx_body)` + commitment; it never verifies the certified tx actually minted `SEAL_POLICY` to
  `LOCK_ADDR`. **Fix:** require the positive mint-to-lock in GENESIS.
- **A6 (M) — Index-0/group-size assumptions** (`:124,132,142`): only GroupInput[0]/GroupOutput[0] checked;
  extra cells in the group ride free. **Fix:** iterate the group or enforce size 1.
- **A7 (C, witness-driven path) — STM lottery soundness: duplicate / unbounded indices.** In `cert-verify`
  (witness-driven, `:80-85`) the lottery loop counts indices with **no uniqueness and no `index < m` bound**
  → a signer repeats one winning index to inflate `count >= k` and forge a "valid" quorum without real
  stake. (`advance-cert`/`txset-cert` are hardcoded fixtures so not directly exploitable there, but share the
  pattern.) **Fix:** enforce unique, sorted indices, all `< m`, with `m` from the signed params.
- **A8 (C) — `txset-cert` AVK source unauthenticated in deploy mode** (`txset-cert/main.rs:88-99`): takes the
  AVK from the first 48-byte cell-dep with no type-hash check (same class as A1). **Fix:** authenticate by type hash.
- **A9 (H/Info) — `advance-cert` rolls forward to a hardcoded `NEXT_ROOT`/`NEXT_TOTAL`** not extracted from
  the signed cert (`advance-cert/main.rs:21-22,146`) — it's a fixed-epoch *fixture*, not a general advancer;
  the signed `next_aggregate_verification_key` is parsed but never bound. The correct pattern is in
  `cert-verify` (`extract_next`). **Fix:** extract next root/total from the verified signed part.

### B. Cardano validators + Groth16 (`groth16/`)
- **B1 (C) ✔ — `zk_chiral_mint` takes the verifying key from the redeemer.** `MintRedeemer { vk, .. }`
  (`zk_chiral_mint.ak:23-29,72,76`) — the policy verifies `verify(vk, proof, public_inputs)` with an
  **attacker-supplied `vk`**. An attacker runs their own trivial trusted setup, makes a valid proof for their
  vk with any `public_inputs`/`state`, and mints unlimited unbacked tokens. (This is the validator the live
  mint used.) `cardano_bound`/`advance_ckbcert` correctly take `vk` as a compile-time param. **Fix:** make
  `vk` a compile-time `validator zk_chiral_mint(vk)` parameter; remove it from the redeemer.
- **B2 (C, with D1) ✔ — Circuit public-input encoding ≠ on-chain `field_of`.** `field_of(b) =
  bytearray_to_integer(True /*BE*/, blake2b_256(b))` (`cardano_bound.ak:26`, `ckbcert.ak:86`) hashes the
  value again and reads big-endian; the circuit packs the value **little-endian with no extra hash**
  (`from_le_bytes_mod_order`, `leap_prove.rs:93-95`). Numerically verified against the shipped fixture: the
  two produce different field elements. So `inputs_bind` (the anti-replay/amount binding) can never
  legitimately hold for a real proof — and "fixing" it by relaxing the check destroys the binding. The
  commitment hash also differs (circuit `ckbhash`/personalized vs validator `blake2b_256`/standard). **Fix:**
  make the circuit's public-input hashing byte-identical to `field_of`, and add an Aiken test that runs
  `verify` AND `inputs_bind` on the same prover-produced inputs.
- **B3 (H/C) — `zk_chiral_mint` has no anti-replay.** Nothing binds the mint to a single-use on-chain event;
  the same `(proof, public_inputs, state, seal)` mints the same `(name, amount)` again in a new tx (the name
  is deterministic, so supply just grows). One CKB lock → N mints. **Fix:** consume a unique seal-UTxO/nonce
  per mint, or track used commitments in a state thread.
- **B4 (H) ✔ — `cardano_bound.ckb_checkpoint_root` is redeemer-supplied, never tied to the canonical
  checkpoint** (`cardano_bound.ak:19,55-63`; `continuing()` reads no Checkpoint UTxO). Combined with the
  circuit treating `chain_root` as a free witness (D3), an attacker fabricates headers + their own root.
  **Fix:** read the genesis-pinned `advance_ckbcert` checkpoint as a reference input and require equality.
- **B5 (M) — `verify`'s MSM silently truncates on a public-input/IC length mismatch** (`verifier.ak:27-40`);
  callers happen to pin length via `==`, but the verifier must `expect length(inputs)==length(ic)-1`.
- **B6 (M) ✔ — `Finalize` binds the commitment public input to `field_of(#"")`** (`cardano_bound.ak:69`) — a
  constant, removing that slot's anti-replay/finalization meaning. **Fix:** bind a real finalization commitment.
- **B7 (M) — `advance_ckbcert` compares `total_difficulty` with `less_than_bytearray` but never enforces
  32-byte length** (`advance_ckbcert.ak:43`); a shorter, lexicographically-greater-but-numerically-smaller
  value could advance a *lighter* chain. **Fix:** `expect length == 32` (and roots), or compare as integers.
- **B8 (M) — `cardano_bound.continuing` doesn't check the continuing output's value** — only the datum. The
  follower UTxO's value isn't conserved across a Transition. (Lower impact if it holds only min-ADA, not
  pooled bridged value — **confirm** no value is pooled there.) **Fix:** assert value preservation + exactly-one
  continuing output.
- **B9 (I) — Groth16 verifier subgroup check: OK.** The Plutus `bls12_381_g1/g2_uncompress` builtins validate
  curve+subgroup membership per CIP-0381 (cross-checked between reviewers), so no separate subgroup check is
  needed. Confirm against the deployed Plutus-core version; reject identity points for A/B/C as hardening.

### C. Burn-gated unlock + escrow + relayer
- **C1 (C) ✔ — Burn replay: one certified burn unlocks UNLIMITED locked cells.** Neither v1 nor v2 consumes
  a nullifier or binds the unlock to a specific burn or a specific locked cell. **v1**
  (`burn-gated-unlock/src/main.rs:66-83`) reads no input outpoint / `since` / output — the unlock is a pure
  function of compile-time constants + a public checkpoint cell-dep, so *every* cell with this lock accepts
  the identical witness-free spend forever. **v2** (`src/bin/burn_gated_unlock_v2.rs:112-144`, which I wrote)
  binds the *amount* but still consumes no nullifier, so any cell with args `(type_hash, A, policy, name)` is
  unlocked by the same freely-copyable burn proof. Economic impact: burning 100k once drains *every*
  100k-locked cell. **The no-forge property is broken not by forging a burn but by reusing a real one N
  times.** **Fix:** a global per-burn nullifier — a type-script-enforced "burn-receipt" cell keyed by
  `blake2b(burn_txid)`, created once per certified burn and consumed on unlock; bind each locked cell to its
  specific burn txid.
- **C2 (H) — v2 `range_key`/`sub_root` are unauthenticated witness inputs.** The membership chain
  (`v2:122-138`) anchors only the *final* master proof to the authenticated `cert_root`; `range_key`,
  `sub_root`, and the proof items come from the attacker's witness. Unless the certified master tree's leaf
  scheme cryptographically forces `sub_root` to be the genuine per-range tx-set root, the per-range
  membership isn't truly proven. (v1 is safer here — it hardcodes them.) **Fix:** constrain `range_key`
  + the leaf-domain so `sub_root` must be the certified sub-root.
- **C3 (H) ✔ — Amount-binding evadable: `mint_qty` returns on the FIRST match, no sum, no duplicate-key
  rejection** (`v2:79-84`, `conway-mint/src/main.rs:64-73`, which I wrote). A crafted Conway `mint` map with a
  decoy first `(policy,name): -amount` entry satisfies the lock while the real net mint differs; bignum/odd
  qty encodings read as 0. **Fix:** iterate ALL entries, **sum** the matching `(policy,name)` net quantity,
  reject duplicate keys + non-canonical encodings + trailing bytes.
- **C4 (H) — v2 accepts ANY certified burn tx, not bound to this lock/depositor** (`v2:128,135-141`) — the
  prover chooses which certified leaf to present. Same root cause as C1. **Fix:** bind a specific burn txid
  in args + the global nullifier.
- **C5 (M) ✔ — v1 `EXPECT_CERT_ROOT` is never enforced** — `main.rs:81` is a dead `let _ = EXPECT_CERT_ROOT;`
  despite the comment claiming it "must match the checkpoint." v1 validates against *any* authenticated
  checkpoint root, not the intended one. **Fix:** assert `cert_root == EXPECT_CERT_ROOT` or remove the constant.
- **C6 (H, robustness) — v2 CBOR/witness readers index attacker lengths with no bounds checks** (`v2:38-92`)
  → panic/abort (reject = fail-closed, so DoS not theft) + parser-confusion surface feeding C3. **Fix:**
  bounds-check every offset; reject non-canonical CBOR.
- **C7 (M) — relay-escrow: any live checkpoint lets anyone sweep every escrow.**
  (`relay-escrow/src/main.rs:23-33,52-55`) The escrow data commits only `depositor_lock‖deadline`, not which
  event it pays for, and `has_authenticated_checkpoint()` is true if *any* checkpoint cell-dep exists; the
  spend doesn't require the corresponding relay to happen in-tx. So a non-relaying party sweeps the reward.
  **Fix:** bind each escrow to a specific event commitment + require the completion output in the same tx.
- **C8 (M) — relay-escrow refund doesn't check the depositor output's capacity**
  (`relay-escrow/src/main.rs:34-51`) — a refund need only include *an* output to the depositor; the remainder
  is pocketable by whoever submits it (no signature). **Fix:** require capacity ≥ escrow − bounded fee (and/or
  the depositor's signature).
- **C9 (I) — Relayers are correctly liveness-only.** `relayer-daemon/relayer.mjs` and the python relayer hold
  only their own keys and submit proof-gated txs — they cannot forge or mint (the validators are keyless/
  proof-gated). They do inherit C7 (rewarded without doing real work). Minor: the daemon's Mithril-sig check
  is log-only (no fund impact); hardcoded key path is a deployment smell.

### D. Consensus circuit + trusted setup (`circuit/prover/`)
- **D1 (C, == B2) — public-input encoding mismatch** (numerically verified). See B2.
- **D2 (C) ✔ — R4 ("spends the seal cell") is unconstrained.** In `leap_prove.rs:55-98`, the CBMT `leaf` is
  an opaque witness (the tx is never opened), and `seal`/`new_state` are **free witnesses** used only to form
  `commitment` + the public inputs. Nothing links `seal` to `tx.inputs` or `commitment`/`new_state` to the
  proven header/tx. So a prover presents a genuine PoW header + a real CBMT path for *any* tx, then chooses
  `seal` and the minted **amount** (`new_state[0..8]`) and **name** (`commitment`) freely → unbacked mint.
  **Fix:** open the tx from the CBMT leaf preimage (`leaf == ckbhash(serialize(T))`) and enforce
  `seal ∈ T.inputs` and that `commitment`/`new_state` is carried in `T`.
- **D3 (C) ✔ — leap `chain_root` unpinned.** It's a free witness, bound only to a public input; with B4
  (root redeemer-supplied, not tied to the canonical checkpoint) and **no in-circuit difficulty check** plus
  an attacker-chosen `compact_target` (→ target ≈ 2²⁵⁶−1, trivial PoW), a single self-mined header under a
  self-built MMR passes. **Fix:** pin `chain_root` to the canonical checkpoint (B4) + constrain difficulty.
- **D4 (H) ✔ CLOSED** — `enforce_membership` now DERIVES each parent digest via `merge_digest` and binds ALL
  120 bytes (was only `children_hash[0..32]`): difficulty/number/epoch/timestamp/compact fields can no longer
  be free witnesses. R2 still matches native (357634→362502 constraints); leap_prove still verifies. *(The
  free bytes were never a forgery given the pinned root + 2nd-preimage resistance, but they are now removed.)*
- **D5 (H) — ECONOMIC core closed; CKB epoch-schedule conformance is the residual.** Re-analysis: the advance
  circuit DOES enforce, per header, **PoW** (`hash ≤ target`), **difficulty = ⌊(2²⁵⁶−1)/target⌋**
  (`difficulty_verify`, now with the D8-hardened `mul256`), **parent-linking**, and the **cumulative**
  `add256` of `total_difficulty`. So the heaviest-chain metric is *honest work*: a prover cannot claim more
  `total_difficulty` than the PoW it actually performed (an easy `compact_target` ⇒ low per-header difficulty;
  the only way to accumulate work is to do it). The "cheaply-mined fork" attack does NOT yield a cheap
  advantage — total difficulty equals total work either way. What remains OPEN is **conformance to CKB's exact
  epoch retarget schedule** (constant `compact_target` within an epoch + the boundary adjustment formula): the
  circuit would accept a chain whose targets don't follow CKB's DAA even though its cumulative work is honest.
  Closing it requires carrying the parent header's epoch/target (a second header decode per step) + the
  adjustment formula — a large gadget that strengthens *consensus-rule conformance*, not the economic
  heaviest-chain security (which holds via the work accounting above). Scoped, not a cheap-fork hole.
- **D6 (H) — MACHINERY hardened (rogue-resistant + OS entropy); TRUST remains external.** `ceremony.rs` now
  (a) attaches a **Schnorr proof-of-knowledge** of each contributor's secret `s` (Σ-protocol on the delta
  discrete-log ratio, Fiat–Shamir bound to old/new deltas) so a rogue contribution with a valid delta ratio
  but a forged PoK is REJECTED — the in-run test confirms rejection at every step; and (b) draws each secret
  from **OS entropy** (`/dev/urandom`), not a deterministic seed. The `contribute()` transform only touches
  `pk.{delta_g1,delta_g2,h_query,l_query}` and is therefore **circuit-agnostic** — the identical multi-party
  flow runs on the real leap/advance proving keys. What CANNOT be done in-sandbox: a *trustworthy* ceremony
  needs **real, independent external participants** (≥1 honest party who destroys their `s` on a separate
  machine) + a genuine phase-1/Powers-of-Tau. So D6's machinery is real and rogue-resistant; its TRUST is
  inherently external (the one fundamentally-out-of-sandbox item) — or switch to universal-SRS Plonk/KZG.
- **D7 (M) ✔ CLOSED** — `compact_to_target` now REJECTS high-side overflow (non-canonical compact whose
  mantissa exceeds 2²⁵⁶) via `u8_gt_const` (m2==0 if exp>32, m1 if exp>33, m0 if exp>34), matching CKB's
  overflow rule. Valid compacts unchanged; gadget_tests adds overflow-rejected cases.
- **D8 (M) ✔ CLOSED** — `mul256` now enforces the final column carry-out == 0 (a 256×256 product is < 2⁵¹²),
  so the multiply is a complete, non-truncating 512-bit product standalone. The 2²⁰ carry bound is a safe
  over-bound (actual carry < 2¹³); `difficulty_verify` still matches native (+1 constraint).
- **D9 (I) — Positives:** R1/R2/R3 gadgets *are* wired into the constraints (not computed off-circuit);
  `enforce_leq_be` correctly implements `≤`; differential tests vs native exist (but lack adversarial fuzzing).

## Cross-cutting amplification
The Criticals **compound**: A1 (reverse-leg root unauth) + D3/B4 (forward-leg root unpinned) + B1 (redeemer
vk) + D2 (seal unconstrained) each *independently* allow forging the respective leg; together they mean the
trust-minimization is not yet enforced anywhere that matters. The honest-relayer live demos do not exercise
these paths.

## Consolidated severity table (all four reviews)
| Sev | Findings |
|---|---|
| **Critical (8)** | **C1** (burn replay — one burn unlocks unlimited cells), A1 (LCKP unauth), A7 (lottery dup-index, witness path), A8 (txset AVK unauth), B1 (redeemer vk), B2/D1 (PI encoding ⇒ binding void), D2 (seal unconstrained), D3 (chain_root unpinned) |
| **High (12)** | A3 (FINALIZE evasion), A4 (proof replay/shared instance), A9 (advance fixture), B3 (mint replay), B4 (root not canonical), C2 (range_key unauth), C3 (amount-binding evadable), C4 (any burn substitutable), C6 (CBOR OOB), D4 (MMR under-constraint), D5 (no DAA), D6 (no real ceremony) |
| **Medium (10)** | A2 (CBOR OOB/DoS), A5 (GENESIS no seal-mint), A6 (index-0), B5 (MSM truncate), B6 (Finalize `#""`), B7 (difficulty length), B8 (value conservation), C5 (dead EXPECT_CERT_ROOT), C7 (escrow sweepable), C8 (refund capacity) |
| **Info/OK** | B9 (subgroup OK via CIP-0381), C9 (relayers liveness-only — good), D9 (gadgets wired correctly) |

## Remediation status (v2 — after the fix pass, RE-AUDITED)
A fix pass was performed in priority order, then **independently re-audited** (two fresh agents re-read the
changed files against the circuit ground-truth): **all 13 applied fixes CONFIRMED CLOSED, no regressions
introduced.** Honest split — what could be **fixed + verified in-sandbox** vs. what is **externally gated**
(a real multi-party trusted-setup ceremony + ZK circuit engineering that cannot be proof-verified without
that ceremony):

**APPLIED + compile/aiken-tested + RE-AUDIT-CONFIRMED CLOSED (no regressions):**
- **C8** relay-escrow refund now requires the depositor output's capacity ≥ escrow − 1 CKB (no dust-refund
  + pocket-the-remainder). ✔ riscv64 build.
- **B1** zk_chiral_mint `vk` → compile-time parameter (no attacker-supplied vk). ✔ aiken check.
- **B2/D1 (on-chain half)** `field_of` → little-endian, no re-hash (matches the circuit for root/seal). ✔
  *Residual:* the commitment hash (circuit `ckbhash` vs validator `blake2b_256`) still needs a **circuit
  change + fresh setup** to fully unify — see external list.
- **B4** cardano_bound reads the checkpoint root from a genesis-pinned **reference input**, not the redeemer. ✔
- **B5** verifier pins public-input count `== len(ic)-1`. **B6** Finalize binds a seal-specific commitment.
  **B7** advance enforces 32-byte difficulty/root. **B8** transition preserves the follower's value. ✔
- **A1** BoundAsset authenticates the checkpoint by type-hash. **A8** txset-cert authenticates the AVK by
  type-hash. **A7** cert-verify enforces strictly-increasing (unique) lottery indices. ✔ riscv64 build.
- **C5** burn-gated v1 enforces `cert_root == EXPECT_CERT_ROOT`. **C3** the Conway parser sums ALL matching
  mint entries (no decoy-first evasion). ✔ build + v2 integration 4/4 + conway-mint host test.

**APPLIED — tranche 2 (build/aiken-verified; not yet independently re-audited):**
- **N1** cardano_bound + advance_ckbcert require EXACTLY ONE continuing output (`list.filter==[o]`). ✔ aiken.
- **A4** BoundAsset reads `seal_policy(28)‖lock_addr(28)` from the type-script **args** (per-instance), not
  consts. **A5** GENESIS now POSITIVELY requires the certified tx mint the seal NFT to the lock. **A6**
  enforces a single bound cell in the type group (no decoy 2nd input/output). ✔ riscv64 build.
- **A2/C6** the witness reader `R` (BoundAsset + v2) is bounds-checked — malformed lengths fail the proof
  cleanly instead of panicking. ✔ build + v2 integration 4/4.

**STILL OPEN — needs a DESIGN pass, not incremental hardening (2 items):**
- **A3 (H) ✔ CLOSED + host-tested** — `seal_recreated_at_lock` is replaced by a SOUND `seal_at_lock` →
  `Option<bool>`: a canonical, bounds-checked Conway-output decoder (`ohdr`/`oskip`/`val_has_policy`) that
  returns `Some(true)` only when PROVEN the seal NFT is recreated at the lock, `Some(false)` only when PROVEN
  no output recreates it (every output fully parsed: Babbage-map AND legacy-array forms, value as uint or
  `[coin, multiasset]`), and `None` on ANY ambiguity (OOB / indefinite-length / unexpected major). GENESIS now
  demands `Some(true)`, FINALIZE demands `Some(false)` — so an unparseable/evasive encoding fails CLOSED in
  BOTH directions (no silent leap-out-and-keep). Verified by `spike/phase1/a3_decoder` (8 cases incl. the
  array-output evasion, an indefinite-length body, and truncation → `None`).
- **C7 (M) ✔ CLOSED + IN-VM TESTED** — relay-escrow now binds each escrow to the SPECIFIC bridge-event payout
  it pays for. Cell data carries `event_lock(32)‖event_amount(8)`; the permissionless-relay path requires BOTH
  an authenticated checkpoint cellDep AND an output delivering `>= event_amount` to `event_lock`. A live
  checkpoint alone no longer sweeps every escrow — the relayer must fulfil this escrow's event. The trusted
  checkpoint type-hash is now a per-instance LOCK ARG (was a const, A1-style). ckb-testtool 6/6:
  relay-with-payout unlocks; checkpoint-without-payout, underpaid-payout, no-checkpoint all rejected; refund
  pays the depositor (C8) and a dust refund is rejected.

**STILL OPEN — substantial design (Critical/High):** **C1** burn replay — needs a global per-burn
**nullifier** (a new once-only receipt validator binding each unlock to a specific burn); **B3** Cardano mint
replay (same once-only need); **C2/C4** (v2 range_key/tx binding, subsumed by C1).

**STILL OPEN — EXTERNAL / NOT verifiable in-sandbox:** **B2/D1 commitment-hash** unification (circuit
change), **D2** in-circuit tx-opening to constrain the seal-spend, **D3** pin+difficulty in-circuit, **D4**
full MMR-digest constraint, **D5** in-circuit DAA, **D7/D8** compact/mul256 hardening — all require circuit
changes and therefore a **fresh trusted-setup ceremony (D6)**, which is inherently a multi-party external
process. These are the largest items and the reason the bridge **cannot be made value-safe in this
environment** — they need dedicated ZK engineering + a real ceremony + the independent third-party audit.

**Net:** **~18 of 30 findings fixed** — 13 independently re-audited closed + tranche 2 (N1,A4,A5,A6,A2/C6)
build/aiken-verified. The entire **on-chain** authentication / binding / parser / lottery / group / instance
/ escrow-refund layer is now hardened. Remaining in-sandbox: **A3** (sound Conway decoder) + **C7** (escrow
event-binding) — both **design passes**, not patches. The forge-the-leg Criticals that live in the
**circuit** (C1 nullifier, D2 seal unconstrained, D3 chain_root/difficulty, D1 commitment-hash) remain, so
the end-to-end "no unbacked mint" property is **not yet restored** — closing it requires the in-circuit work
+ a fresh **trusted-setup ceremony**, which is inherently external and cannot be done/verified in this
sandbox. I did not fake it.

## Remediation status (v3 — circuit-side fix pass, RE-AUDITED)
The three forward-leg **circuit** Criticals (D1 commitment-hash, D2 seal-spend, plus the encoding-reduction
bug D1b found while verifying D1) were implemented in-sandbox, the proofs regenerated, and the result
**independently re-audited** (fresh agent re-read the changed circuits + every `field_of`/commitment call
site against ground-truth, with numerical value-checks). Honest correction to v2's claim that these were
"NOT verifiable in-sandbox": writing the circuit AND verifying a valid proof verifies on-chain through the
*existing test verifying-key* **are** doable here; only a **trustworthy multi-party ceremony (D6)** is
fundamentally external, and full **soundness** (rejecting all cheating witnesses) needs review/formal tooling
beyond testing. What was done:

**APPLIED + cargo/aiken-verified + RE-AUDIT-CONFIRMED:**
- **D1 (commitment-hash) — CLOSED.** `leap_prove.rs`/`relay_prove.rs` now compute the bridge commitment with
  **standard** blake2b-256 (zero personalization, helper `b2b`), byte-identical to `cardano_bound.ak`'s
  `builtin.blake2b_256`; `ckbhash` (personalized) stays only for PoW/MMR/block-hash (real CKB consensus).
  Value-match verified: for the regenerated leap + live-relay fixtures, `field_of(blake2b_256(state‖seal))`
  equals `public_inputs[2]` exactly. Both regenerated proofs **verify on-chain** (`aiken check`, all pass).
- **D2 (seal-spend) — CLOSED for the free-seal forgery.** Both circuits enforce in-circuit `seal == cbmt_leaf`,
  so the seal must equal a tx hash proven (R1 PoW + R2 MMR + R3 CBMT) to be in the confirmed CKB chain — it
  is no longer a free witness. *Residual (D2-A, Medium) — re-analysis:* with this fix the `seal` IS, by
  definition, **the leap transaction** (its CKB tx hash). For the per-leap model (confirmed by the owner:
  one mint per leap, burned on return) that is a complete, sound binding — "this specific transaction occurred
  in a confirmed CKB block" — and the forward-leg replay is then closed by the seal-nullifier (N-FIN-1, one
  mint per seal). D2-A's *outpoint*-∈-`tx.inputs` proof is only required by an **alternative design** where
  the seal is a single-use anchor *outpoint* rather than the leap tx hash; that design would need an in-circuit
  CKB-tx **molecule parser** (data-dependent offset indexing over the witnessed `raw_tx` whose `ckbhash` is the
  CBMT leaf). The bridge as built does not use outpoint-seals, so this is a **design-variant feature, not a hole
  in the current design** — implemented only if the protocol switches to outpoint-based seals. Scoped honestly.
- **D1b (field_of reduction) — CLOSED.** `field_of` now reduces `% fr_order` (BLS12-381 scalar order) in
  `ckbcert.ak` (shared), `cardano_bound.ak`, and — found by the re-audit — **`zk_chiral_mint.ak`**, which had
  its own unreduced copy that would have rejected ~55% of valid mints (a 32-byte hash exceeds r ~55% of the
  time; the prover's public input is the reduced residue). `advance_ckbcert.ak` imports the shared reducer.
  Added a `field_of_reduces_mod_r` regression test (all-0xFF ⇒ result `< fr_order`). ✔ aiken check 60/60.
- **D3 (chain_root pin) — covered at the binding layer by B4** (cardano_bound reads the canonical root from
  the genesis-pinned checkpoint reference input; advance enforces cumulative-difficulty + heaviest-chain). An
  **in-circuit** minimum-difficulty/confirmations check (DAA, D5) remains open.

**NEW findings from the circuit re-audit:**
- **N-2 (Medium) — `Finalize` branch was unprovable → CLOSED.** `cardano_bound.ak`'s `Finalize` requires
  `public_inputs[2] == field_of(blake2b_256("FIN"‖seal))`, but no circuit produced that commitment, so the
  Finalize path could not be satisfied (it failed closed — no security hole, but a dead feature). Fixed by
  adding `finalize_prove.rs`: the finalize circuit proves the SAME chain-of-custody (R1 PoW + R2 MMR + R3
  CBMT + `seal == cbmt_leaf`) and computes the seal-specific commitment `blake2b256("FIN"‖seal)` **in-circuit**
  (the SNARK itself attests the FIN tag). Because its R1CS differs from the transition circuit, it has a
  distinct vk, so `cardano_bound` now takes a separate **`finalize_vk`** and verifies the `Finalize` branch
  against it. Live proof generated + verified; `finalize_test.ak` confirms it verifies on-chain and that its
  `public_inputs[2]` equals `field_of(finalize_commitment(seal))`. ✔ aiken check 62/62.
- **D1b-C (Low, soundness caveat) — reduction is non-injective.** Each residue `v` with `v+r < 2^256` has two
  32-byte LE preimages. Not exploitable today (seal is pinned to a tx hash, root to the checkpoint datum —
  neither is attacker-chosen raw bytes), but a caveat if seal/root ever become attacker-influenced raw bytes.
- **N-3 / N-4 (Low/Info, cosmetic) — sound:** duplicate witness allocations in `leap_prove.rs` (each
  independently enforced equal, wasteful not wrong); stale comments updated.

**Soundness caveats testing cannot establish:** (a) D1b-C non-injectivity is an encoding argument, not a
test; (b) D2-A's outpoint-membership gap is about what the circuit does **not** constrain (no passing test
can surface it); (c) the blake2b gadget's byte-for-byte equivalence to `builtin.blake2b_256` rests on the
param-block mapping — fixtures confirm specific vectors, not all inputs (a differential-fuzz/formal argument
would be needed). And **D6** — a trustworthy multi-party trusted-setup ceremony over these circuits — remains
inherently external; the fixtures use a test setup (`seed_from_u64(7)`), not a deployable vk.

**Net (v3):** the forward-leg circuit Criticals **D1 + D2 are closed** (D2 with a documented Medium residual)
and the **D1b** encoding bug is closed across **all four** validators (incl. the one the named scope missed).
The end-to-end "no forged leap" property for the forward leg now holds **modulo** the outpoint-membership
parser (D2-A), the Finalize circuit (N-2), and a real ceremony (D6). The reverse-leg burn-replay nullifier
(C1) and the design-pass items (A3, C7) remain as in v2.

### Independent re-audit of the FINALIZE feature (v3.1)
A fresh agent re-audited commit `d5cf987` (regenerated both vks, checked values numerically, ran the prover):
**N-2 CONFIRMED CLOSED; D1/D2/D1b CONFIRMED intact and extended to the finalize circuit.** Specifically: the
finalize circuit is structurally identical to `relay_prove.rs` through R1/R2/R3 + the `seal == cbmt_leaf` (D2)
binding (only R4 differs); the in-circuit `blake2b256("FIN"‖seal)` is byte-identical to the validator's
`builtin.blake2b_256(#"46494e"++seal)`; and the **two vks' `ic` vectors differ in all 4 elements**, so a
Transition proof is cryptographically rejected under `finalize_vk` and vice-versa — no branch confusion. The
`no_cont` check makes the two actions mutually exclusive on output shape, and both branches bind the same
canonical (B4) root. The finalize work is **sound and introduces no regression.**

New/residual findings (all **inherited or external — none introduced by the finalize work**):
- **N-FIN-1 (Medium) — Finalize binds `st.ckb_seal` but not the consumed outpoint.** `no_cont` stops replay
  against the *same* UTxO, but if two `BoundState` UTxOs ever shared a `ckb_seal`, one proof+redeemer would
  finalize both. This is the **same replay/nullifier class as C1/B3** (the seal is meant to be single-use; no
  validator enforces global uniqueness). Fix with the C1/B3 nullifier design pass — bind the consumed outpoint
  / a per-UTxO nullifier into the public inputs, or enforce `ckb_seal` uniqueness at `BoundState` creation.
- **N-FIN-2 (Medium) — test-only vks; shared toxic waste.** Both `relay` and `finalize` vks derive from
  `seed_from_u64(7)`, so they share α/β/γ/δ (harmless for branch separation since `ic` differs, but a real
  deployment needs an **independent per-circuit ceremony** — this is **D6**). The fixtures are byte-reproducible
  from the prover (confirmed), i.e. real proofs, but not ceremony keys.
- **N-FIN-3 (Medium) — = D2-A, inherited.** The finalize CBMT proves tx *inclusion in a block*, not that the
  tx *spent the anchor cell*; needs the in-circuit CKB-tx input-membership parser. Unchanged by this work.
- **N-FIN-4 (Low) — code drift risk.** `finalize_prove.rs` is a near-verbatim copy of `relay_prove.rs`; a
  future D2-A patch could diverge. Recommend factoring the shared R1/R2/R3+D2 constraints into the
  `ckb_consensus_circuit` lib and parameterizing only the R4 commitment.
- **N-FIN-5 (Info) — benign.** `finalize_prove.rs` recomputes the commitment natively to bind pi[2] while the
  in-circuit value attests it; both are enforced equal — sound, belt-and-suspenders.

### Replay / nullifier design pass (v4) — C1 (Critical) + B3 (High) + N-FIN-1
The replay class — "a unique cross-chain event must authorize at most ONE action" — was addressed on both
legs. Identifier per leg: reverse = the Cardano burn tx hash (consumed on CKB); forward = the CKB leap seal
(consumed on Cardano).

- **C1 (Critical) — CLOSED + IN-VM TESTED.** `burn_gated_unlock` released locked CKB on a certified burn but
  nothing marked the burn consumed → one burn could drain unlimited cells. Added **`burn_nullifier_registry`**
  — a singleton cell holding the root of a fixed-depth (256-bit) **sparse Merkle tree** of consumed burn keys.
  A spend inserts one key only if a proof shows it was **ABSENT under the old root** (value 0 = non-membership)
  and **PRESENT under the new root** — so a burn key can be inserted at most once, ever. `burn_gated_unlock_v2`
  now (a) requires the registry to insert *its* burn key (`= blake2b256(tx_body)`) in the same tx, and (b)
  forbids a second identically-locked cell in the tx (single-GroupInput, mirrors A6). Together: each certified
  burn authorizes at most one unlock, across all txs. The SMT is self-contained pure-Rust (blake2b-ref,
  personalization `"ckb-smt-null-set"`) — the stock `sparse-merkle-tree` crate hard-depends on the C
  `blake2b-rs`, which can't cross-compile to this riscv target. **ckb-testtool: 9/9**, incl.
  `replay_same_burn_rejected` (re-using the same burn against the post-insert root fails on non-membership)
  and `missing_registry_rejected`. *(v1 `main.rs` is the legacy fixed-burn PoC and keeps C5; v2 is the
  generalized, registry-gated path.)*
  - **C1-R1 (High, found by re-audit) — registry singleton/genesis now SELF-ENFORCED.** The first cut relied
    on a deployment convention for the singleton and was un-genesisable (it unconditionally required an
    input). Fixed with the CKB **type-id** pattern: the registry's args = `ckbhash(first_input_outpoint)`,
    verified in a dedicated **genesis branch** (no registry input ⇒ exactly one output, EMPTY root, args bound
    to the consumed outpoint). The outpoint is consumed once in all history, so the registry's type hash
    cannot be duplicated — a parallel/empty registry with the same hash is impossible, which is what makes the
    replay guarantee real (the unlock pins this type hash). Driven THROUGH the validator by
    `registry_genesis_ok` / `registry_genesis_wrong_typeid_rejected` / `registry_genesis_nonempty_rejected`.
  - **C1-R2 (Low) — functional limitation:** the registry inserts one key/tx, so a legitimate multi-burn
    unlock needs one tx per burn. Not a soundness issue.
  - **C1-R3 (Low, pre-existing) — CLOSED.** The `mint_qty` Conway/CBOR walker now bounds-checks every access
    (`hdr`/`skip`/`cbor_int` return `Option`, with `checked_add` on offsets); a malformed/truncated `tx_body`
    yields a `PARSE_ERR` sentinel (`i128::MAX`) that can never equal a real `-(amount)`, so the lock fails
    cleanly with a defined code instead of relying on a VM OOB trap. `malformed_txbody_rejected` (a certified
    but truncated body) confirms no unlock. ckb-testtool now **10/10**.
- **B3 (High) — CLOSED.** `leap_mint_guard` read the leap `BoundState` from an **output** (which triggers no
  validator) with `fact_consumed` hardcoded `True` — so a decoy output could mint, and a leap could mint
  repeatedly. Fixed: `LeapInMint` now requires EXACTLY ONE cardano_bound **input** to be spent, which (a)
  forces cardano_bound's own validator to verify the Groth16 leap proof and (b) consumes a unique outpoint
  spendable only once → the mint is 1:1 with a verified, once-only leap. (`LeapOutBurn` is a pure burn — non
  inflationary — so it keeps the output read.) ✔ aiken check 62/62.
- **N-FIN-1 (Medium) — mint path CLOSED by B3; nullifier MECHANISM now built + tested; integration specified.**
  The mint-side replay is gone (B3 ties minting to a consumed leap UTxO). For the remaining
  finalize/transition-across-duplicate-seals vector, the **Cardano seal-nullifier is now implemented**, the
  exact mirror of the CKB SMT registry:
  - **`lib/g16/seal_set.ak`** — a self-contained 256-bit sparse Merkle tree (`blake2b_256`) with `inserts`
    enforcing NON-MEMBERSHIP (key absent under old root) → membership under new root. Soundness core
    unit-tested: `inserts_into_empty_tree`, `non_membership_of_empty_holds`, `replay_rejected`,
    `empty_sibs_has_256` (4/4).
  - **`validators/seal_nullifier.ak`** — a singleton registry spend that inserts one seal via `seal_set`,
    preserving the thread token on the continuing output. Mock-tx tested: `insert_accepted`,
    `replay_rejected_at_registry`, `missing_thread_token_rejected` (3/3).
  - **`validators/seal_thread.ak` (SEC N-SEAL-1, found by re-audit — now CLOSED)** — the one-shot GENESIS PIN:
    a mint policy that mints the registry thread token at most once (consumes a unique `genesis_ref`) onto an
    EMPTY-root registry output. This is the prerequisite the re-audit flagged: without it the singleton was
    asserted, not enforced (an attacker could stand up a parallel empty registry and re-insert a consumed
    seal). Mirrors `ckbcert_thread`. Mock-tx tested: `genesis_mint_ok`, `genesis_without_unique_ref_rejected`,
    `genesis_nonempty_root_rejected` (3/3). aiken check **72/72**. *(N-SEAL-2/3 — `fold` length self-guard and
    extra negative tests — remain Info; the validator enforces the lengths it relies on.)*
  - **ECONOMIC MODEL (confirmed by the owner):** **one mint per leap** — each CKB→Cardano leap mints once;
    the asset is burned when it returns to the origin chain (the reverse leg, already C1-closed). So the
    integration is the clean genesis case.
  - **Integration — WIRED + tested (per-leap model).** `leap_mint_guard`'s `LeapInMint` now requires the
    leap's `ckb_seal` to be CONSUMED in the seal-nullifier registry in the same tx: it finds the registry
    input by its script-hash param, reads its `Insert` redeemer from `tx.redeemers`, and requires the inserted
    key == `bs.ckb_seal`. The `seal_nullifier` validator independently proves the insert is sound (non
    membership), and `seal_thread` pins the registry to one genesis lineage — so a given CKB anchor authorizes
    at most ONE Cardano mint, across all txs (two BoundState UTxOs sharing a seal cannot both mint). Mock-tx
    tested: `leapin_accepts_when_seal_consumed`, `leapin_rejects_without_nullifier`,
    `leapin_rejects_wrong_seal_key`, + two direct `seal_consumed` tests (leap_mint_guard 5/5). aiken **77/77**.
    **N-FIN-1 status: CLOSED end-to-end** (SMT + genesis-pinned singleton + mint-path wiring, all tested).

**Net (v4):** the Critical reverse-leg burn replay (C1) is closed with a real, in-VM-tested nullifier whose
singleton is now self-enforced via type-id (C1-R1 closed, 9/9); the forward-leg mint replay (B3) is closed;
N-FIN-1's mint path is covered and its residual has a concrete, specified fix (Cardano seal-nullifier). The
remaining open items are the in-circuit seal-consumption parser (D2-A), the Cardano seal-nullifier registry
(N-FIN-1 residual), the Cardano seal-nullifier registry (N-FIN-1 residual) and the ceremony (D6).

## Overall assessment
- **The hard cryptography and the live demos are real** (Mithril-in-VM, Groth16-in-Plutus, real testnet
  round trips). As *feasibility*, the project delivers.
- **As a secure bridge, it is not there.** Verified Critical soundness/authentication gaps let an attacker
  mint unbacked tokens or forge a leap on both legs; the trusted setup is a demo; the circuit's central R4
  claim is unconstrained. None are exotic — they are the standard hard parts (root authentication, vk
  pinning, in-circuit tx-opening, real ceremony, STM index rules) — but all are currently open.
- **Do not deploy with value.** **8 Critical, 12 High, 10 Medium.** Remediation priority:
  1. **C1 — burn replay** (the single most economically-fatal: one real burn drains every locked cell). Add a
     global per-burn nullifier. *(Affects both the live-deployed v1 and the v2 written this session.)*
  2. **B1 — redeemer-supplied vk** (trivial unbacked mint). Pin `vk` as a compile-time parameter.
  3. **D2 — constrain the seal-spend** (open the tx in-circuit; enforce `seal ∈ tx.inputs`).
  4. **A1 / B4 / D3 / A8 — authenticate & pin every checkpoint/AVK root** (type-hash auth on the CKB side;
     reference-input pin on the Cardano side).
  5. **B2 / D1 — unify the public-input encoding** circuit↔validator (and add a `verify`+`inputs_bind` test).
  6. **A7 — STM lottery index rules** (unique, `< m`).
  7. **D6 — a real multi-party ceremony** over the actual circuits (or move to universal-SRS Plonk).
  8. The remaining High/Mediums (C2–C8, A3–A6, B3–B8, D4–D8).
  Then an **independent professional audit** (gap #4).
- This internal audit reduces, but does not remove, the need for that external audit — especially for the
  BLS/Mithril cryptography and the ZK circuit soundness, which need specialist tooling beyond code reading.
- **Honesty note:** several findings (C1, C3, C6) are in code I wrote this session (burn_gated_unlock_v2 +
  conway-mint) — I focused those on amount-binding and missed the nullifier + sum-all-entries. Recorded here
  rather than glossed.
