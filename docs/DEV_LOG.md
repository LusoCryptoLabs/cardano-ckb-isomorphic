# Dev log (chronological build line)

> **Chronological, append-only.** Each entry is a committed step; earlier entries may record
> "not yet" states that later entries resolve (e.g. the BLS-acceptance gap, resolved in the
> "ACCEPTANCE GREEN" entry). Read top-to-bottom as history, not as current status — the current
> state is in `CHIRAL_STATUS.md` / `LIVE_STATUS.md` / `CHIRAL_READINESS.md`. Now lives in
> `github.com/tecmeup123/cardano-ckb-isomorphic` (the build env that produced it was ephemeral).

## 2026-06 — source-port toward cryptographic acceptance

Goal: turn the one open 🔴 (a real Mithril cert verifying in-script) green.

**Done — message construction confirmed.** `spike/mithril-verify/message/compute_hash.py`
reproduces `ProtocolMessage::compute_hash` exactly and matches a real preview cert's
`signed_message` bit-for-bit: **SHA-256** over the `BTreeMap`(enum)-ordered parts, hashing
`key.to_string()` then `value` for each. So the message the signers sign is pinned:
`compute_hash()` (the 64-char hex string), signed as `…as_bytes()`.

**Narrowed gap — the BLS verify layer.** With the confirmed message + empty DST (what
mithril-stm 0.10.5 source passes: `verify(false, msg, &[], &[], …)`), **blst (ground truth)
still does not verify** a real preview cert — tested single-sig (msg ∈ {ascii-hex-64,
raw-32} × DST ∈ {empty, NUL/AUG/POP, bare} × {no-aug, aug=pk}), plain aggregate, and
multiplicity aggregate. So the deployed preview convention differs from the 0.10.5 source we
read (version skew in DST/aggregation), and reverse-engineering it black-box has bottomed out.

**Next concrete step (definitive):** compile the **version-matched** `mithril-stm` /
`mithril-common` (the version the preview aggregator runs) and call its *own* `verify` on the
deserialized cert. That resolves the exact DST + aggregate-VK construction with zero guessing;
then port that exact construction into the in-script `bls12_381` verifier and confirm
`verified = true` in CKB-VM. (The cert's preview aggregator version can be read from its
`/` or release metadata.)

**Unchanged:** feasibility verdict GO; cost measured ~135M cycles ≈ 3.85% of a block on real
data; real points decode + pair in-script. Acceptance is the only open item and it is now a
version-pinned source-port, not a research unknown.

## 2026-06 — ACCEPTANCE GREEN: real Mithril cert verifies in CKB-VM

Cracked the exact construction via mithril-stm's own verify (host, ground truth) +
reading `concatenate_with_message` from vendored source. **A real Cardano preview cert's
aggregate signature now verifies in-script** (`bls12_381`, no blst): `verified = true`,
**146,223,644 cycles (4.18% of a block)**.

The missing detail was **`msgp = msg || root`** (the signed message bytes, then the avk
merkle batch-commitment root — message FIRST). Full recipe in
`spike/mithril-verify/VERIFIED_RECIPE.md`.

**Status:** the load-bearing assumption is now fully proven end-to-end — granularity 🟢,
cost 🟢 (measured), and **acceptance 🟢** (a real cert verifies in-script). Remaining for
full trust-minimization (not feasibility): port the eligibility/lottery `check_indices` and
the Merkle batch-membership re-derivation (both cheap hashing) into the in-script verifier,
then wrap in the light-client cell + binding lock (ROADMAP Phases 2–3).

## 2026-06 — eligibility (stake lottery) in-script + full-verify cost

Reproduced mithril's eligibility exactly in pure-Rust num-bigint/num-rational (no blst/float):
`ev = Blake2b512(b"map"||msgp||index_le||sigma)`, `is_lottery_won` via the rational Taylor
comparison. Cross-checked on the real preview cert: all winning indices WON.

Cost measured in CKB-VM:
- naive (rational per index): ~996k cyc/idx -> k=1944 ~ 1.94e9 (55% of a block).
- **per-party-target optimization** (per-index = `ev < target`, 512-bit compare): ~14.6k
  cyc/idx (68x) -> k=1944 ~ 28.5M (0.81%).

**Full trust-minimized verify ~= 165M cycles ~= ~5% of a block** (BLS aggregate ~135M +
eligibility ~28.5M, optimized). Comfortably fits.

### Done so far on the in-script Mithril verifier
- [x] aggregate BLS signature (real cert verifies in-script)
- [x] message construction (compute_hash; msgp = msg||root)
- [x] eligibility / stake lottery (exact; optimized cost)
- [ ] **Merkle batch-membership** of the winning (mvk,stake) leaves in the avk root — the
      last verify piece (hashing only; tractable). Read path.rs/tree.rs next.
- [ ] quorum wiring (Σ unique winning indices ≥ k) + assemble the single full-verify entrypoint
- [ ] light-client cell (advance the certified root per epoch) + binding lock (ROADMAP P2–P3)

The two cryptographically hard parts (BLS aggregate + stake lottery) are proven in-script on
real data. Remaining is Merkle hashing + the cell/lock architecture.

## 2026-06 — full signature verify complete + light-client cell started

- [x] **Merkle batch-membership** in CKB-VM (blake2b-256): reconstructs the real preview cert's
      avk root, 72k cycles. => **FULL Mithril signature verify now proven in-script** (BLS
      aggregate + stake lottery + Merkle membership + quorum) ~= ~175M cycles ~= ~5% of a block.
- [x] **Light-client cell** design (`docs/LIGHT_CLIENT_CELL.md`) + skeleton
      (`spike/light-client-cell/light_client_cell.rs`): a self-advancing Cardano checkpoint cell
      {epoch, avk_root, total_stake} whose AdvanceCert consumes a newer Mithril cert, verifies it
      against the current avk via the proven verifier, and rolls to epoch N+1 (the Mithril cert
      chain). The binding lock (P3) consumes this cell + a Cardano tx-membership proof.

### Remaining
- [ ] Assemble the proven components into one `verify_certificate` and a real AdvanceCert type
      script (molecule schema + type-id uniqueness + cell I/O); host differential-test vs
      mithril-stm, then live on CKB devnet -> Pudge across real preview epochs.
- [ ] Phase 3: binding lock (Plutus) + bound-cell (CKB) consuming the light-client cell.

## 2026-06 — first AdvanceCert type script works in CKB-VM

Assembled `verify_certificate` (compute_hash + aggregate BLS + stake lottery (all 2330 indices)
+ batch-Merkle + quorum) and a real checkpoint-cell transition into
`spike/light-client-cell/light_client_advance.rs`. Test PASSES: a real preview cert advances the
checkpoint cell epoch 320 -> 321 in CKB-VM. Cost 2.46e9 cycles (70% of a block; naive eligibility).
=> per-party-target optimization drops it to ~5% (the next step).

### Remaining
- [ ] per-party-target optimization (eligibility 2.3B -> 28.5M): relayer computes T via mithril's
      is_lottery_won boundary; script verifies 2 points + ev<=T per index.
- [ ] bind next_avk to the authenticated next_aggregate_verification_key part; parse cert from the
      witness (relayer transcode) instead of embedded consts; molecule schema + type-id uniqueness.
- [ ] host differential-test vs mithril-stm; live devnet -> Pudge across real epochs.
- [ ] Phase 3: binding lock (Plutus) + bound-cell (CKB) consuming the light-client cell.

## 2026-06 — optimization finding + cross-chain status

- Per-party-target eligibility optimization attempted: FAILS to help because verifying the target
  via the is_lottery_won BOUNDARY runs the Taylor series without early-stop (~1e9 cycles/call) —
  *more* expensive than naive. Kept the naive per-index lottery (correct, ~70% of a block; once per
  epoch). The real ~5% optimization needs mithril's SNARK-lottery target (compute_target_value_
  for_snark_lottery), future work. AdvanceCert remains correct + passing at 2.46e9 cycles.
- Cross-chain primitive mapped with REAL data: fetched a certified preview tx + its Mithril
  membership proof (spike/cross-chain/). The proof is an MKMapProof (MMR master + sub-proofs),
  verification in mithril-common (not stm) — a separate two-level port. Full path to a live
  cross-chain transfer sized in docs/CROSS_CHAIN_STATUS.md (items 1–6).

## 2026-06 — CROSS-CHAIN reached: a real Cardano tx verified inside the CKB VM

Ported the Mithril Cardano-transactions MKMapProof verification in-script using
ckb-merkle-mountain-range (no_std, CKB-ecosystem) + Blake2s256. A REAL preview transaction's
inclusion in the certified tx-set root VERIFIES in CKB-VM (139,185 cycles); host ground truth via
mithril-common confirmed. Two-level MMR (tx ascii leaf -> range sub_root -> CERT_ROOT).

With the AdvanceCert cert verifier authenticating CERT_ROOT (cardano_transactions_merkle_root),
the **full cross-chain VERIFICATION oracle is proven in-script on real data**: a Cardano
transaction is verifiable on CKB, trust-minimized (Mithril stake-threshold), no committee.

### Remaining for a value-flow transfer (engineering, sized)
- bind CERT_ROOT to a verified CardanoTransactions cert's protocol message (mechanical);
- bound cell (CKB) + binding lock (Plutus) — the leap-in/leap-out value flow (DESIGN §3);
- witness-driven verifier + relayer transcode; molecule + type-id;
- SNARK-lottery target for the AdvanceCert cost; live devnet -> Pudge.

## 2026-06 — isomorphic-binding CORE in CKB-VM (§6.2 + §6.3)

- §6.2: minimal in-script Conway tx-body CBOR parser. On a REAL preview tx (64fbcc23…): parses the
  body map, extracts the tag-258 input set + detects the real seal input 3c2dce14…#1, extracts
  output[0]'s tag-24 inline datum. 26,738 cycles. (The one genuinely-new hard piece — done.)
- §6.3: the BoundAsset transition — seal consumed AND commitment == blake2b256(new_state||new_seal).
  VERIFIED in CKB-VM (30,323 cycles). The actual isomorphic-binding step.

With the oracle (cardano_tx_is_certified) + cert verifier, the full binding TRANSITION is now
demonstrated in-script on real Conway CBOR: a certified Cardano seal-spend -> committed CKB state.

### Remaining to a running bridge
- wire cardano_tx_is_certified INTO the BoundAsset script (§6.3 used a constructed tx);
- binding lock (Plutus) + seal NFT minting policy; leap-in / leap-out flows;
- witness-driven verifier + relayer transcode; molecule schemas; type-id;
- SNARK-lottery target (AdvanceCert cost); a real deployed seal + live preview<->Pudge run.

## 2026-06 — Cardano-side binding: seal NFT + binding lock (Aiken, tested)

Built the OTHER half of the bind (cardano/binding/, aiken v1.1.21, aiken check 91 checks/0 errors):
- seal_nft.ak: one-shot SEAL NFT (the seal UTxO = the asset's ownership).
- binding_lock.ak: Transfer (owner-signed; one continuing seal output with a fresh 32-byte
  commitment) | Unbind (owner-signed; seal leaves -> value released).
- binding_tests.ak: 6 tests PASS.

BOTH halves of isomorphic binding now exist + tested in their VMs:
  CKB    — cert verifier + tx-membership oracle + Conway parser + BoundAsset transition;
  Cardano— seal NFT + binding lock.

### Remaining to a live transfer
- leap-in / leap-out flows + relayer;
- wire cardano_tx_is_certified into the BoundAsset script (the §6.3 oracle call);
- deploy seal+lock on preview, mint a bound cell on Pudge, drive a real seal-spend transfer;
- SNARK-lottery target (AdvanceCert cost); molecule/witness plumbing.

## 2026-06 — WIRED leap transition + leap flows

bound_asset_leap.rs: ONE BoundAsset script combining cardano_tx_is_certified (MMR tx-set
membership, Blake2s256) + Conway tx parse (seal consumed) + commitment binding. VERIFIED
end-to-end in CKB-VM (70,306 cycles): a certified Cardano seal-spend -> committed CKB bound-cell
state. (CERT_ROOT synthetic stand-in; real Mithril proof authenticating it proven on real data.)
docs/LEAP_FLOWS.md: leap-in / transfer / leap-out orchestration + relayer.

ASSEMBLED STATUS — both halves + the wired transition exist and are tested:
  Cardano: seal NFT + binding lock (Aiken, 6 tests).
  CKB:     cert verify + tx-membership oracle + Conway parse + BoundAsset + WIRED leap (CKB-VM).
Remaining = the LIVE run (deploy on preview, real seal spend, real Mithril cert, real CKB
transition) + relayer + molecule/witness plumbing. No new in-script cryptography.

## 2026-06 — LIVE leap-in: seal minted on Cardano preview

Started the live path. Parameter-applied the seal NFT + binding lock and minted a REAL seal on
preview (cardano/binding/deploy_seal.py): seal policy 8855af1b…, binding_lock
addr_test1wqwthgsg3cjfsr…, commitment cad8d630…=blake2b256(S0), seal mint tx 83dd51d2… (block
4,355,257). Confirmed on-chain: seal NFT at the binding lock with its inline SealDatum.

Pending Mithril certification (the latency gap: tx block 4,355,257 vs certified tip 4,355,249).
Next: once certified, fetch the cert+MKMapProof and mint the bound cell on Pudge (the wired
BoundAsset genesis check). See docs/LIVE_STATUS.md.

## 2026-06 — CARDANO -> CKB CLOSED LIVE (first real cross-chain bind)

Mithril certified the seal-mint tx 83dd51d2 (cert c8a6986f, certified tx-set root 30a3465e;
host-verified). Built genesis_mint.rs (real two-level MKMapProof verify + Conway parse of the
seal-tx output[0] SealDatum + commitment==blake2b256(S0)); verified in CKB-VM (191k cycles) on the
REAL data; then DEPLOYED on Pudge (code 0x5ae1cb33, deploy tx 0xd2a650ec) and MINTED the bound cell
(tx 0xab2f93a7, committed). The type script ran ON THE LIVE NODE -> verified the Mithril-certified
Cardano seal-mint in-script -> bound cell created. Cardano->CKB is closed live, on real testnets.
spike/bound-asset/genesis_mint.rs, cardano/binding/deploy-bound-cell.mjs, deployed/pudge/.

### Remaining
- transfer (spend the seal on preview -> cert -> CKB bound-cell transition via the wired leap);
- leap-out; relayer; molecule/witness plumbing; SNARK-lottery target. No new in-script crypto.

## 2026-06 — transfer's CKB leg LANDED + leap-out + costs

- Reclaimed Pudge capacity (spent the genesis_mint code cell + a leftover; deploy tx 0x9eb56c3b)
  and POSTED the transfer's CKB transition: bound cell S1 ("...owner=bob") minted on Pudge
  (tx 0xf930cd8c, block 0xa8867f15), type transition_mint verified the certified Cardano transfer
  (a98b6636) on the LIVE node. The transfer is now reflected on BOTH chains.
- LEAP-OUT: binding_lock Unbind ran live on preview (tx 6c729ea6); seal released to a plain UTxO.
  All three Cardano validator paths exercised live (mint / Transfer / Unbind).
- docs/COSTS.md: measured per-transfer user cost ~0.24 ADA + ~0.05 CKB + ~114 CKB refundable; 45k is
  the operator's one-time reclaimable script; advance amortized.

### Genuinely remaining (honest)
- CKB finalize of leap-out (symmetric leg) — not posted (cert+capacity).
- Production: ONE witness-driven script (cert-verify + tx-membership unified; proof in witness, not
  embedded) deployed once + referenced; relayer; molecule schemas; monitoring.
- SNARK-lottery target (the AdvanceCert ~70%-block cost; the boundary approach is too costly).
- Reorg/finality handling; **security audit**; mainnet. (Out of scope for in-session work.)

## 2026-06 — PHASE 1 keystone: unified witness-driven BoundAsset (real transition in CKB-VM)

bound_asset_unified.rs: ONE type script (deployed once, referenced by all cells); proof rides in the
WITNESS, not embedded. Verified a REAL UTXO-consuming transition (S0 -> S1) in CKB-VM on the
certified Cardano transfer a98b6636: cardano_tx_is_certified (MKMapProof) + old seal consumed + new
seal created by the tx + commitment binds the new state. 240,682 cycles. Fixed a real bug: Conway
outputs in both Babbage-map and legacy-array forms. This is the production per-transfer model
(~0.05 CKB/transfer, not 45k-per-step). spike/phase1/.

Remaining in Phase 1: fold in genesis mode + read cert_root from a referenced light-client
checkpoint cell (so AdvanceCert authenticates it on-chain); then deploy once on Pudge + a live
witness-driven transfer (consume old bound cell, create new). Then Phases 2-5 per BUILD_PLAN.

## 2026-06 — PHASE 1 in-script COMPLETE: genesis + transition + checkpoint-cell root

bound_asset_unified.rs now: (a) reads cert_root from a referenced light-client CHECKPOINT cell
(cell dep "LCKP"||root, maintained by AdvanceCert) instead of the witness; (b) handles GENESIS
(bind, output-only) and TRANSITION (consume old -> create new). Both verified in CKB-VM on real
certified preview data: genesis (seal-mint 83dd51d2) 225,655 cycles; transition (transfer a98b6636)
240,085 cycles. One deployed script + proof-in-witness + shared checkpoint = the production
per-transfer model. spike/phase1/.

Remaining in Phase 1 (LIVE): deploy the one script on Pudge + checkpoint cell + a live
witness-driven genesis+transfer. Then Phases 2-5 per BUILD_PLAN.

## 2026-06 — PHASE 1 COMPLETE & LIVE ON PUDGE: unified verifier, proof-in-witness, real transition

The keystone now ran on the public CKB testnet (Pudge), the production per-transfer model end-to-end:
- ONE unified `BoundAsset` verifier deployed (code_hash `0x42f74fbc…`, tx `0xf8644bd3…`, 47,248 B),
  reclaimable, referenced by every bound cell as a cellDep. Funded by reclaiming the demo code cell
  `0x9eb56c3b`.
- **Genesis** (bind) bound cell `0x0318d35f…` (block 21,339,914): the live node verified, in-script,
  the MKMapProof that seal-mint `83dd51d2` ∈ certified root `30a3465e` (read from a light-client
  checkpoint cellDep, `"LCKP"||root`) ∧ commitment == blake2b256(S0). Proof in witness `input_type`
  (1,136 B) — NOT the cert_root, which comes from the checkpoint cell.
- **Transition** (the headline) bound cell `0x94d0620f…` (block 21,339,956): **consumed the genesis
  bound cell** and created the v2 cell. The live node verified: MKMapProof that transfer `a98b6636`
  ∈ root `5acd33ab` ∧ the certified transfer **consumed the OLD seal** (`83dd51d2:0`) ∧
  commitment(new SealDatum) == blake2b256(S1). State `…:v1` → `…:v2 owner=bob`; seal `83dd51d2` →
  `a98b6636`; genesis cell spent. NOT create-only.

Fix landed during the live run: completeInputsByCapacity (re)sets witness[0], so the proof
`input_type` must be set AFTER it and before completeFeeBy (else the ~1.1 KB witness is undercounted
→ PoolRejectedTransactionByMinFeeRate). Scripts: deploy/pudge/{deploy-unified-genesis-tx3,
deploy-unified-transition,stage-transition}.mjs + p1b_hex.json/p1t_hex.json. Hashes:
deployed/pudge/unified-instance.json. **Phase 1 done.** Next: Phase 2 (SNARK-lottery target).

## 2026-06 — PHASE 2 COMPLETE: the SNARK-lottery target (eligibility ~70% -> ~1% of a block)

The Mithril stake lottery was the AdvanceCert cost driver: mithril's per-index is_lottery_won runs a
num-rational Taylor of exp(x) PER winning index — ~2.37e9 cycles (68% of a block) for the real
preview cert's 2330 indices. (The Phase-1 boundary-verify idea was measured WORSE: at ev≈boundary
the Taylor never early-exits.)

Replaced with mithril's compute_target_value_for_snark_lottery, made cheap + exact in-script:
is_lottery_won(ev) <=> ev_int < T*, T* = 2^512*(1-(1-phi_f)^w). Derive the per-party target
T = ceil(T*) ONCE via a FIXED-POINT integer Taylor for exp(w*c) at scale 2^768 (NO num-rational /
gcd — the gcd-per-term on growing rationals is what blew the budget; it didn't fit even at 3.5e9).
T = 2^512 - (acc >> 256); per index the check is one 512-bit integer compare ev<T.

Bug found + fixed during bring-up: the term counter incremented before the first divide (term_1
divided by 2 not 1), halving exp's linear term -> 1158/2330 disagreements; fixed -> exact.

Measured (CKB-VM, ckb-testtool, same harness, apples-to-apples):
  NAIVE  is_lottery_won x2330  = 2,368,167,479 cycles (67.66%)
  TARGET per-party + ev<T x2330 =    39,746,866 cycles ( 1.14%)  => 59.6x.
Exact: (ev<T) == is_lottery_won(ev) for all 2330 real preview indices (0 disagreements, host
differential test). Full optimized AdvanceCert ~= BLS ~146M + eligibility ~40M + Merkle/compute_hash
~= ~190M ~= ~5% of a block (was ~70%). Folded into light_client_advance.rs. spike/phase2/.
Next: Phase 3 (relayer + flows).

## 2026-06 — PHASE 3: permissionless relayer + leap-out FINALIZE (the symmetric leg)

RELAYER (relayer/): transcode.py turns a real Mithril CardanoTransactions proof (two-level Blake2s256
MMR) + the raw spend-tx CBOR into the compact length-prefixed witness the unified BoundAsset reads.
relay.py is the full pipeline: watch binding_lock seal spends (Blockfrost) -> wait for the Mithril
cert -> fetch proof + tx CBOR + cert root -> transcode -> CLASSIFY (seal recreated at lock =>
TRANSITION, else FINALIZE) -> emit a CKB submission descriptor. Liveness only; cannot forge (the
script re-verifies). validate_transcode.py PROVES correctness: the transcode reproduces, byte-for-byte
(1173 B), the transition witness the live unified script accepted on Pudge (0x94d0620f), from only
the raw proof JSON + tx CBOR. Full pipeline exercised live: unbind 6c729ea6 -> FINALIZE (1132 B),
transfer a98b6636 -> TRANSITION (1209 B).

LEAP-OUT FINALIZE: added a FINALIZE mode to the unified BoundAsset (spike/phase1/bound_asset_unified.rs):
spend the bound cell with NO output, requiring the certified Unbind tx to be in the cert root + consume
the old seal + NOT recreate the seal NFT at the binding_lock. New logic = seal_recreated_at_lock (a
Conway output/multiasset parse: scan outputs for SEAL_POLICY at LOCK_ADDR). The Unbind released the
seal to a plain 60-address (not the 70-lock), so finalize is valid; a transfer (seal at lock) is
correctly rejected. PROVEN IN CKB-VM on the REAL certified Unbind 6c729ea6 (cert root 0bc33aa8):
finalize verify = 205,581 cycles (0.006% of a block). Host differential: unbind seal_at_lock=False,
transfer=True.

LIVE on Pudge: finalize-capable unified deployed (codeHash 0xbeaff4d3, tx 0x97ca700d) and a bound
cell minted under it (seal a98b6636, state v2, tx 0xc40d4a39). The final finalize SPEND is gas-dust
blocked — every isomorphic cell is at min capacity, the unbind-checkpoint tx is ~0.02 CKB short, and
the only free capacity is in unrelated committee-bridge code cells (not reclaimed without asking).
The verification is proven in-VM on the real certified Unbind. Next: Phase 4 (hardening + correctness).

## 2026-06 — PHASE 4: hardening — differential/tamper gate + live drift watch + HARDENING.md

Built spike/phase4/difftest: a HOST copy of the exact in-script verifier (compute_hash + aggregate
BLS over bls12_381 + the Phase-2 lottery target + avk Merkle reconstruction), run on a REAL preview
cert fixture. 11/11: ACCEPT the genuine cert (BLS verifies; all indices win + count>=k; avk root
reconstructs; compute_hash == mithril's own signed_message — a cross-check vs mithril-common's
output) AND REJECT every single tamper (flipped sigma/mvk/message/avk-root-in-msgp/message-part/
Merkle-leaf/lowered-stake). This is the soundness gate.

spike/phase4/live_drift_check.py: fetch the CURRENT preview cert, re-confirm compute_hash (SHA-256
over BTreeMap-ordered key||value) == signed_message. FINDING: mithril CHANGED the message-part set
since the epoch-320 fixture (added latest_block_number, cardano_blocks_transactions_*) and our
generic construction STILL matches — exactly the silent-drift protection Phase 4 wanted. Wired both
into .github/workflows/verifier-difftest.yml (difftest required; live-drift non-blocking).

docs/HARDENING.md: reorg/finality (bridge only acts on Mithril-certified immutable history -> tip
reorgs invisible; trails the tip by the cert gap), Mithril liveness/availability (permissionless
relayer cannot forge; aggregator downtime = liveness not safety), certification-latency UX,
replay/monotonicity invariants table, verifier size (BoundAsset ~48 KB no-BLS shared/reclaimable;
AdvanceCert larger; num-rational already dropped in P2; further shrink levers). Next: Phase 5 (audit).

SP1 reverse-leg ZK — ALL FOUR Mithril relations proven + composed (sp1/m2all). M1 (signed_message
Sha256), M2 (BLS12-381 STM aggregate — the crypto core), M3 (tx-inclusion two-level Blake2s MKMapProof),
M4 (cert-hash) now prove in ONE SP1 STARK on the real preview cert 7356eaa1: M2_ALL_PROVED true,
cycles=3,931,058. KEY: M3 re-grounded on the SAME cert as M1/M2/M4 (decoded mithril_verify/
proof.example.json for burn 6608c4c8), and CERT_ROOT is asserted == the cardano_transactions_merkle_root
PART that M1 hashes and M2's BLS signs — so one proof attests the complete statement (a stake threshold
signed a message whose tx-set root contains the burn). Recovery note: a container rollback wiped the
session's local commits (isomorphic repo had NO remote); recreated faithfully from the surviving
proof.example.json (identical cycles on rebuild) and pushed to github.com/tecmeup123/cardano-ckb-isomorphic.
Groth16 wrap (SP1_WRAP=groth16, for cheap CKB-VM verify): wired; the wrap computation RUNS (needs ~33 GB
effective, demonstrated with 18 GB swap past the prior OOM) but wrap+gnark can't co-reside on this box's
~38 GB disk (18 GB swap + 8 GB gnark artifacts at once). Resource-gated: needs a >=32 GB-RAM prover or the
SP1 network — no new code. Full measurement + directory map in spike/cardano-to-ckb-zk/{M2_SCOPE.md,sp1/README.md}.
NB the LIVE reverse leg already verifies the full M1..M4 directly in CKB-VM; SP1 is the optional succinct/PQ optimization.
