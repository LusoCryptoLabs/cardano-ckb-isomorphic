# Chiral

**Chiral** is a trust-minimized **isomorphic binding protocol** for moving assets between Cardano
and CKB (the RGB++ lineage) plus **on-chain light-client verification** — *not a custodial bridge,
no bonded committee*. Each chain verifies the other's consensus/certificates **in-script**, on real
data, both directions. The two legs are mirror images — hence *Chiral*.

> **Chiral is the *protocol* (the binding construction + verification rules, anchor-agnostic and
> oracle-swappable). This repo is its *reference implementation*** — the Cardano⇄CKB instantiation,
> testnet-only, unaudited, pre-ceremony. "Protocol" describes the design; it does **not** imply a
> ratified standard, multiple implementers, or a production deployment. The construction is in the
> RGB++ lineage (Cipher / Nervos) — see [`docs/LIGHTPAPER.md`](docs/LIGHTPAPER.md) §1.2.

This repo is the sibling of [`cardano-ckb-bridge`](https://github.com/tecmeup123/cardano-ckb-bridge),
a complete, testnet-proven **optimistic, bonded-committee** lock-and-mint bridge. That one is the
safe baseline that works today; this one chases the trust-minimizing endgame its docs flag as
future work (`THREAT_MODEL.md §9`, `CHALLENGE_PROTOCOL.md` option 3). The two are kept separate so
they can be compared on equal terms.

> **Status: prototype — the hard cryptography is done and proven live on public testnets
> (Cardano preview ⇄ CKB Pudge), both directions, on real data.** It is **not** production:
> testnet-only, unaudited, no liquidity/ecosystem, coordinator-driven, not post-quantum at
> the chains' signature layer. The honest gap map is in [`docs/CHIRAL_READINESS.md`](docs/CHIRAL_READINESS.md);
> the live tx-by-tx record is in [`docs/LIVE_STATUS.md`](docs/LIVE_STATUS.md) and
> [`docs/TESTNET_LOG.md`](docs/TESTNET_LOG.md).

## The one-paragraph thesis

A lock-and-mint bridge has to verify **both** chains on **both** sides — and verifying CKB's
Eaglesong PoW inside a Plutus budget is the killer. Isomorphic binding is **asymmetric**: an
asset's ownership is *anchored* to one chain's UTxOs while its state and transition logic live on
the other, and only the follower chain verifies the anchor. We built **both** asymmetric legs:

- **Cardano → CKB** (the natural, cheap direction): ownership anchored to a Cardano **seal** UTxO,
  state on CKB. CKB verifies a **Mithril** certificate (a stake-based BLS threshold multisig) **in
  CKB-VM** — feasible because CKB scripts run arbitrary RISC-V crypto.
- **CKB → Cardano** (the hard, mirror direction): ownership anchored to a CKB cell, state on
  Cardano. Cardano verifies a **Groth16 SNARK of CKB consensus** (Eaglesong PoW + header-MMR +
  tx-inclusion) **in Plutus**, using Cardano's BLS12-381 builtins.

## What is proven live (independently re-verifiable via CKB RPC + Koios)

### Cardano → CKB — Mithril verified inside CKB-VM
- **Full Mithril certificate verify in CKB-VM** — aggregate BLS + the 2330-index stake lottery +
  batch-Merkle membership + quorum, on a real preview cert (~134–146M cycles, ~4–5% of a 3.5e9
  block). Acceptance is **bit-exact** (`msgp = signed_message ‖ avk_root`).
- **AdvanceCert light-client cell LIVE on Pudge** — a Cardano stake checkpoint that advances
  epoch 320→321 **only** by verifying a real Mithril cert in-VM (164.4M cycles, tx `0xb7ada085`).
  **TxSetCert** then authenticates the certified tx-set root the same way (`0xe4e1b0c6`).
- **Isomorphic binding lifecycle LIVE** — one unified `BoundAsset` verifier (deployed once,
  proof-in-witness, checkpoint cellDep): genesis bind `0x0318d35f` → transition `0x94d0620f`
  (consumed the genesis cell) → **leap-out finalize** `0x795f4bb9`. Driven by a real Cardano seal
  lifecycle (mint `83dd51d2` → transfer `a98b6636` → unbind `6c729ea6`).

### CKB → Cardano — CKB consensus verified inside Plutus (Groth16)
- **Groth16 verifier in Aiken** over Cardano's BLS12-381 builtins — on-chain verify ≈ **22.7% CPU /
  0.27% mem** of a Cardano tx.
- **Full CKB-consensus circuit** (measured ~1.3M demo / ~4.9M at production MMR depth → 2²³ setup; see
  `spike/ckb-to-cardano/circuit/CIRCUIT_SIZING.md`): R1 Eaglesong PoW + Blake2b + compact-target ·
  R2 ChainRootMMR membership · R3 CBMT tx-inclusion · R4 commitment — every gadget
  differential-tested vs native CKB on real Pudge blocks. **AdvanceCKBCert** trustless checkpoint
  (difficulty-verify + variable-carry MMR-append + N-batching). 3-party Groth16 phase-2 ceremony
  *mechanism* (verifiable, Schnorr-PoK rogue-resistant) — demonstrated single-machine on a toy circuit;
  a real multi-party run on the production circuit is external (see `docs/PRODUCTION_PLAN.md`).
- **LIVE round trip** — CKB lock `0x4923241a` → ZK proof → Cardano verify `f99c3461` → mint 100k
  ckCKB `21ad4a44` → burn `6608c4c8` (supply→0) → CKB unlock `0xde70a26d`. Conservation closed.
- **Trust gaps closed (validator + on-chain):** mint amount/name binding (`zk_chiral_mint.ak`,
  12/12 aiken) and a **burn-gated CKB unlock** that releases only against a Mithril-certified burn,
  gated on an **authenticated** checkpoint (positive `0xe6ea066a`; unauthenticated rejected;
  negative test error code 10).

### Operations & hardening
- **Permissionless relayer** (liveness only, cannot forge): on-chain escrow primitives LIVE —
  permissionless relay with no key `0x6e9a291e` + timeout refund `0x78cf1071`; a two-chain relayer
  daemon that relayed 4 escrow deposits in one pass. Python transcoder validated **byte-for-byte**
  against the on-chain-accepted witness.
- **Phase-4 hardening** — a differential/tamper gate (11/11) in CI + a live drift watch that
  already caught Mithril evolving its message-part set while our construction still matched.

### Optional v2 (not required — the direct CKB-VM Mithril verify above is what's live)
- **SP1 STARK-Mithril** — all four Mithril relations (signed-message, BLS aggregate, tx-inclusion,
  cert-hash) **composed in one SP1 STARK** on a real cert (3.93M cycles, proven+verified). The
  succinct/post-quantum upgrade path; a Groth16 wrap is wired but resource-gated.

## What is NOT done (external — see `docs/CHIRAL_READINESS.md`)
Mainnet deployment · third-party security audit · ecosystem/liquidity integration · a hosted,
monitored relayer daemon (the on-chain mechanics are proven; the ops layer is not). The wrapped
ckCKB was minted→burned in a closed loop (supply 0); nothing is held or usable today.

## Trust model
- **Ownership / double-spend:** the anchor chain's consensus (Cardano for the Cardano→CKB leg).
- **Cross-chain soundness:** the **Mithril honest-stake-majority** assumption (verified in-script,
  no committee), and for the CKB→Cardano leg the **Groth16 soundness + trusted setup** / CKB PoW
  honest-majority. No bonded committee, no governor in the safety path.
- **Not** more trust-minimized or more post-quantum than the two chains' own signature layers.

## Layout
```
docs/
  DESIGN.md            architecture: isomorphic binding, the asymmetry, the two verifiers
  CHIRAL_READINESS.md  honest gap map (CLOSED / proven / external) — start here for "what's real"
  LIVE_STATUS.md       the live Cardano→CKB lifecycle, tx by tx
  CHIRAL_STATUS.md     both legs, authoritative summary
  TESTNET_LOG.md       append-only on-chain record (every tx, cost, caveat)
  CKB_TO_CARDANO.md    the CKB→Cardano (Groth16-in-Plutus) leg
  NEXT_ANCHORS.md      generalizing the binding to more chains (Sui, Polkadot, Tezos)
  ROADMAP.md / BUILD_PLAN.md   phased plan (Phases 1–4 done; Phase 5 = audit + mainnet)
  PRIMITIVES.md        what's reused from the sibling repo + provenance
  FEASIBILITY*.md      the original Phase-1 feasibility spikes (historical; verdicts since proven)
  LIGHT_CLIENT_CELL.md / BINDING_SPEC.md / LEAP_FLOWS.md / HARDENING.md / COSTS.md   component docs

spike/                 the build — each subdir is a proven experiment with a RESULTS.txt
  mithril-verify/ light-client-cell/ cross-chain/ bound-asset/ phase1..phase4/   Cardano→CKB
  ckb-to-cardano/      the CKB→Cardano Groth16 circuit + Aiken verifier + relayer
  cardano-to-ckb-zk/   the optional SP1 STARK-Mithril reverse leg
  burn-gated-unlock/ relay-escrow/ relayer-daemon/   on-chain ops primitives

cardano/binding/       Cardano seal NFT + binding lock (Aiken, tested) + deploy tooling
deploy/pudge/          CKB Pudge deployment scripts (the live lifecycle)
deployed/              instance records of the live deployments (tx hashes, code hashes)
relayer/               the permissionless relayer (transcode / relay / validate)
primitives/            self-contained building blocks lifted from the sibling repo
```
