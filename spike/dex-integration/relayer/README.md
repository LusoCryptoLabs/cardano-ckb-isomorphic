# Bridge relayer (skeleton)

The operational service that turns "verifier deployed" into "user can leap." It watches one chain for a
leap event, produces the **proof** the other chain's verifier needs, and submits the mint/burn there.

```
CKB leap-out  --(watch)-->  produce Groth16-of-CKB-consensus  --(submit)-->  Cardano leap_mint_guard mint
Cardano leap  --(watch)-->  produce Mithril/BoundAsset proof  --(submit)-->  CKB BoundAsset + guard mint
```

## The honest division of labour

- ✅ **Verifiers exist on testnet.** BoundAsset (Pudge) and `cardano_bound` Groth16 (Preview) are deployed
  and proven on live data. The relayer does **not** re-implement verification — it produces the witness the
  on-chain verifier already accepts.
- 🟡 **The proving backends are the heavy, external part.** The Mithril cert pipeline (CKB→Cardano) and the
  Groth16 prover (Cardano→CKB) are existing components from the broader project; the relayer **connects** to
  them via the `ProofProvider` interface in `relayer.mjs`. Wiring those backends + running them is the
  operational lift — it is not more contract code.
- ❌ **Not value-safe yet.** Caps/pause are on-chain (good), but a production relayer also needs durable
  replay state, retries/idempotency, monitoring, and the §5-item-10 audit before real value.

## What's built

- `relayer.mjs` — `LeapEvent` parsing (same MAPPING_SPEC LE encoding as the guard/UI), the `ProofProvider`
  interface for the external provers, and the `watch → prove → submit` loop.
- `ckb_leap.mjs` — **the real CKB leap-out builder**. `assembleFinalizeLeapOut` / `buildFinalizeLeapOut`
  construct the complete **FINALIZE + burn** tx exactly as the deployed `bound_asset_unified` verifier
  requires: the user's **bound cell consumed with no output** (its witness = the FINALIZE proof, at index 0),
  the bridge **owner cell** input recreated (owner-mode + the guard runs), the **"LCKP" checkpoint** +
  guard + BoundAsset + xUDT cell-deps, and the xUDT burned to exactly the leaped amount (remainder
  returned). Offline-validated: bound is input[0], proof in witness[0], owner recreated, change correct.
- `cardano_leap.mjs` — **the Cardano leap-in mint plan**. `buildLeapInMintPlan` emits a lib-agnostic plan for
  `leap_mint_guard` `LeapInMint`: mint `amount` of the (333) FT to the recipient, the `cardano_bound` output
  carrying `BoundState{ ckb_seal, state = amount16 ‖ recipient28 }`, the policy reference input, and the
  Groth16 proof for `cardano_bound`'s redeemer. Serialize with Lucid/MeshJS + sign with the relayer key.

### The `ProofProvider` — now wired to the real backends
- `mithril_proof.mjs` — **`proveCardanoToCkb`**: encodes a Mithril CardanoTransactions MKMapProof into the
  exact FINALIZE witness `bound_asset_unified` parses (`lp`/`items`/`u64` layout, read from its reader).
  Round-trip validated, fully consumed. `fetchCardanoTxProof` adapts a live Mithril aggregator response.
  The two-level Blake2s256 MMR math is already proven on real Mithril data in `spike/{cross-chain,phase3}`.
- `groth16_prover.mjs` — **`proveCkbToCardano`**: drives the arkworks BLS12-381 prover
  (`spike/ckb-to-cardano/prover`) and returns the CIP-0381 `{ vk, proof, public_inputs }` fixture
  `cardano_bound` consumes (validated: reads the real fixture, flows into the leap-in mint plan's redeemer).
- `makeProvider({ groth16, mithril })` composes both.

Still external/operational: a **running Mithril aggregator** to fetch live proofs from, and swapping the
prover's placeholder `SquaresCircuit` for the real consensus circuit (the proof *format* is already real).
The one validation not yet run in-repo: feeding a generated witness through the **compiled** verifier in
ckb-debugger — that needs the verifier's build project + captured Mithril data (`p3_data`) wired up.

**Key safety:** the relayer's submit keys come from env at runtime (`RELAYER_CKB_KEY`, `RELAYER_CARDANO_KEY`)
and are never stored. Run on infrastructure you control.

## Run

```
RELAYER_CKB_KEY=0x...  RELAYER_CARDANO_KEY=...  node relayer.mjs
```

Until a `ProofProvider` is connected, the loop logs the parsed `LeapEvent` and the witness it *would*
request — so you can validate event parsing + submission wiring before standing up the provers.
