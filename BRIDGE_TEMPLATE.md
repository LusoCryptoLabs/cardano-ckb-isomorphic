# Isomorphic Binding Template: add any chain to CKB, both ways

This is the repeatable recipe for binding a new chain **X** to CKB as an *isomorphic binding* (mutual on-chain
verification), in both directions, reusing everything that is chain-agnostic and only writing the parts that are
chain-specific. It generalizes the worked Cosmos implementation (`spike/cosmos-ckb`, `spike/cosmwasm-ckb`,
`spike/burn-gated-unlock`).

Read `BRIDGE_STATUS.md` first for the Cardano leg (the original instance) and every live hash.

## 0. What "isomorphic binding" means here

Each chain verifies the OTHER chain's consensus **on-chain**, so value is represented and moved across the pair
with no trusted relayer for safety (only for liveness). This is NOT an HTLC swap (that is liquidity-based and
does not mint). Topology is **hub-and-spoke around CKB**: every spoke chain X needs exactly one verifier of CKB,
and CKB hosts one verifier of each X. Adding a chain is then linear, not N^2.

A per-leg **trust ceiling** is a first-class label: you can never be more trust-minimized than the source chain.
A federated chain (Stellar SCP) leg is weaker than a stake/work leg; say so in the leg's docs.

## 1. The three layers (only one is chain-specific)

| Layer | Chain-specific? | Reuse |
|---|---|---|
| **Finality verification** | YES, per chain, per direction | none, this is the work |
| **Asset binding** (mint wrapped on lock / burn on release) | shape is agnostic, glue is small | `xada_mint.rs` / `catom_mint.rs` shape |
| **Replay-once nullifier registry** | NO | one registry, per-leg domain tag |

So "add chain X" = write **two finality verifiers** (X-verifies-CKB and CKB-verifies-X), then wire the existing
asset binding and the existing nullifier registry to the pair. The hub abstraction is
`FinalityVerifier { LightClient | ZkState }` + a chain-agnostic core + per-chain config (section 4).

## 2. The components to build per chain (the checklist)

A pair (CKB, X) has two value directions. Each direction needs a verifier on the destination plus an asset
script. Tick these off for every new chain.

### Direction A: lock native on X -> mint wrapped-X on CKB

- [ ] **A1. CKB-VM light client of X** (`spike/burn-gated-unlock/src/bin/<x>_inclusion.rs`). Prove "this X tx is
  in a final X block" inside CKB-VM: reconstruct the block id, verify X's finality rule (BFT signatures /
  PoW / committee), and verify tx inclusion against the block's tx root. Pin every encoding off-chain first
  against REAL chain data, then port. Reference: `tendermint_inclusion.rs`.
- [ ] **A2. CKB wrapped-mint type script** (`spike/burn-gated-unlock/src/bin/<x>_mint.rs`). xUDT-style policy;
  mint gated on A1 + parse the escrow tx in-VM to bind (amount, recipient) 1:1 + replay-once nullify the X tx.
  Reference: `catom_mint.rs` (mirrors `xada_mint.rs`).
- [ ] **A3. Validator/committee-set lineage** if X has a rotating signer set: anchor + sequential advance +
  skip. References: `tendermint_advance.rs`, `tendermint_skip.rs`. (PoW chains skip this; use cumulative work.)

### Direction B: lock/burn wrapped on CKB -> release native on X

- [ ] **B1. X-VM verifier of the CKB-state proof** (the bridge's Groth16 over BLS12-381, the same proof Cardano
  verifies). Lives in X's smart-contract VM. Reference: `spike/cosmwasm-ckb/contract` (CosmWasm). Feasible iff
  X's VM can afford a BLS12-381 pairing (section 5 has the per-chain curve/VM matrix).
- [ ] **B2. CKB burn-receipt + a burn-proving circuit instance** that commits an **X recipient**. The receipt
  type script self-enforces a real burn (Σ in - Σ out == amount) and the circuit proves it, binding the X
  recipient. Reference: `xada_burn_receipt.rs` + the leap circuit family (`spike/ckb-to-cardano/circuit`).
  NOTE: this is the genuinely hard, new-cryptography part for each chain (a new circuit instance, not plumbing).
- [ ] **B3. X-side release/mint contract** gated on B1 + the CKB burn proof + a replay nullifier on X. Reference:
  `RecordCkbEvent` in `spike/cosmwasm-ckb/contract` (the replay-once registry shape on the X side).

### Shared (write once, reuse for every chain)

- [ ] **Nullifier registry** with a per-leg domain tag so keyspaces are disjoint. CKB side:
  `burn_nullifier_registry.rs` (genesis-pinned SMT). X side: a `Map`-keyed set under a tag like
  `chiral:<x>-ckb:nf:` (see `NF_DOMAIN` in the CosmWasm contract). Existing tags: χADA mint `0x01`, CKB-release
  `0x02`, χCKB-leap `0x03`, cosmos-escrow `0x04`. Pick the next free byte for X.
- [ ] **Public-input binding**: the B1 verifier must gate on a NAMED CKB event, not just "some valid proof".
  Derive the circuit's public inputs from the event fields in-contract (`VerifyCkbEvent` / `derive_inputs.mjs`),
  so a relayer cannot present a valid proof and substitute different inputs.

## 3. Build & deploy playbook (generalized gotchas)

### CKB-VM side (A1, A2, A3, B2 receipt)
- Build `no_std` for `riscv64imac-unknown-none-elf` with `RUSTFLAGS="-C target-feature=-a,+forced-atomics"`
  (CKB-VM has no atomics; the `sync_polyfill` module supplies the `__sync_*` builtins). Toolchain lives in the
  WSL distro `ChiralSP1`, not on Windows.
- Validate every script in `ckb-debugger` with a mock tx FIRST (positive `Run result: 0` + adversarial cases
  with distinct error codes). For the light client, use a SYNTHETIC self-signed block in the simulator (you
  control the validator keys) but pin the ENCODINGS against real chain data separately, a real signed block
  cannot carry your escrow. Reference mocks: `build_inclusion_mock.mjs`, `build_catom_mock.mjs`,
  `build_skip_mock.mjs`.
- Code-cell deploy costs ~1 CKB/byte. Cycle budget is ~3.5B/block; a ~150-validator BFT commit is ~300M cycles,
  fine. Keep the verifier under budget (precompute, stop at 2/3).

### X smart-contract VM side (B1, B3) — wasm chains (CosmWasm)
- The CKB-state proof is **Groth16 over BLS12-381**. Prefer the chain's native BLS host function
  (`bls12_381_pairing_equality` in CosmWasm 2.x): smaller, cheaper. BUT not every node exposes it, osmo-test-5
  returns `not implemented: unknown request`. Provide an `inwasm` fallback that does the whole pairing in wasm
  (cargo feature; see `spike/cosmwasm-ckb/contract`).
- Recent Rust (1.96) emits **bulk-memory** opcodes that older `wasmd` rejects (`bulk memory support is not
  enabled`). Lower to MVP with binaryen: `wasm-opt in.wasm --enable-bulk-memory --enable-sign-ext
  --llvm-memory-copy-fill-lowering --signext-lowering --strip-target-features -o out.wasm` (do NOT add `-O2`
  after lowering, it reintroduces `memory.copy`; verify clean with `wasm-dis | grep memory.copy`, not a byte
  count which false-positives).
- Heavy in-wasm pairing may exceed the free smart-query gas cap, provide an **execute** path that verifies as a
  gas-paid tx (`AssertCkbProof`), which succeeds iff the proof verifies. Pass an explicit `StdFee` (a `GasPrice`
  instance can mismatch cosmjs's internal copy). Match the chain's min gas price (osmo-test-5 = 0.03 uosmo/gas).
- Deployer keys live in `~/.chiral/`, never printed, never committed.

### X smart-contract VM side — non-wasm chains
- **EVM**: BLS12-381 via EIP-2537 precompiles (live post-Pectra). Write B1 in Solidity using those precompiles.
- **Soroban (Stellar)**: BLS12-381 host functions exist; B1 is a Soroban contract.
- **Solana**: only `alt_bn128` (BN254) syscalls, NOT BLS12-381, see section 5, this needs a BN254 proof
  variant, not a drop-in.

## 4. The FinalityVerifier abstraction (the SDK shape)

The chain-agnostic core dispatches on a per-chain verifier descriptor. Sketch (the SDK is still backlogged):

```
enum FinalityVerifier {
    LightClient {            // CKB-verifies-X (A1): re-run X's consensus on-chain
        kind: BftEd25519 | BftBls | SyncCommittee | PoWCumulativeWork | ...,
        anchor: ValidatorSetHash | Difficulty | CommitteeRoot,
        advance: Sequential | Skip | WorkOnly,
    },
    ZkState {                // X-verifies-CKB (B1): verify the CKB-state SNARK
        system: Groth16Bls12_381,
        host: NativePairing | InWasmPairing | Precompile,
    },
}
// chain-agnostic: asset_binding(amount, recipient), nullifier_registry(domain_tag, key)
// per-chain config: { rpc, finality_rule, escrow_format, recipient_encoding, denom }
```

`AssetBinding` and `NullifierRegistry` are reused verbatim; only `FinalityVerifier` and the per-chain config
change. Adding a chain = implement the verifier descriptor + fill the config.

## 5. Per-chain curve/VM matrix (what's feasible, what isn't)

| Chain | CKB-verifies-X finality rule (A1) | X-verifies-CKB host for BLS12-381 (B1) | Notes |
|---|---|---|---|
| **Cardano** | Mithril STM cert (BLS), live | Plutus BLS12-381 builtins, live | the original instance |
| **Cosmos** | Tendermint BFT ed25519, **live on Pudge** | CosmWasm: host fn OR in-wasm, **live osmo-test-5** | worked example, this template |
| **Ethereum** | Altair sync committee (512 BLS signers) | EIP-2537 BLS precompiles (post-Pectra) | both sides BLS-friendly; strong leg |
| **Stellar/Soroban** | SCP federated quorum (harder light client) | Soroban BLS12-381 host fns | B1 easy, A1 harder (federated) |
| **Solana** | Tower BFT ed25519 votes (large stake set) | only alt_bn128 (BN254), **no BLS12-381** | B1 needs a BN254 proof variant |
| **Bitcoin/XRPL** | PoW cumulative work / no smart VM | cannot host a verifier | binding NOT possible; HTLC only (dropped) |

CKB-VM (general RISC-V) can run ANY of the A1 light clients (it already runs ed25519, BLS12-381, Blake2b,
SHA256). The asymmetric constraint is always B1: can X's VM afford to verify the CKB-state SNARK.

## 6. Worked example: Cosmos (every component, with status)

| Component | File | Status |
|---|---|---|
| A1 CKB-VM Tendermint inclusion | `burn-gated-unlock/src/bin/tendermint_inclusion.rs` | LIVE on Pudge (unlock tx `0x18f519b6`) |
| A3 anchor advance | `tendermint_advance.rs` | ckb-debugger 0/21 |
| A3 skip (non-adjacent) | `tendermint_skip.rs` | ckb-debugger 0 + 4 fail-closed |
| A2 χATOM wrapped mint | `catom_mint.rs` | ckb-debugger end-to-end 0 + 4 fail-closed (NOT yet a live Pudge mint) |
| B1 X-verifies-CKB | `cosmwasm-ckb/contract` | **LIVE osmo-test-5** (`VerifyCkbProof -> valid:true`, codeId 13217) |
| Public-input binding | `VerifyCkbEvent` + `derive_inputs.mjs` | tested |
| Replay registry (X side) | `RecordCkbEvent` (tag `chiral:cosmos-ckb:nf:`) | tested |
| B2/B3 CKB->Cosmos release leg | none | NOT built (needs a burn circuit committing a Cosmos recipient) |

What is LIVE is the mutual verification (both directions). What remains to be a fully working two-way *value*
bridge for Cosmos: a live χ-token mint on Pudge from a real Cosmos lock (A2 deployed live), and the entire
Direction B release leg (B2 + B3).

## 7. Order of work for a new chain

1. Pin A1 encodings off-chain against real chain data (the cheap de-risk; this is where the surprises are).
2. A1 light client in CKB-VM + ckb-debugger validation.
3. A3 set lineage (advance + skip) if applicable.
4. A2 wrapped mint + end-to-end ckb-debugger mock.
5. B1 verifier in X's VM + a LIVE deploy + a live verify of the real CKB proof.
6. Wire the shared nullifier registry + public-input binding to the pair.
7. A2 LIVE: deploy the mint on Pudge, lock native on X's testnet, mint the wrapped token live.
8. B2 + B3 the release leg (the hardest; a new burn circuit). Gate mainnet on an external audit.

Steps 1-6 are mostly plumbing on top of this template; step 8 is real new cryptography each time.
