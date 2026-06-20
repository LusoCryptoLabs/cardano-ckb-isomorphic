# Transfer manifest — dev box -> Hostinger VPS

The repo CODE goes via git. Three classes of files are **not** in git (or must be the *current* live copy) and must
be copied separately. Target repo root on the VPS: `/opt/chiral` (== `CHIRAL_REPO_SH`).

## 1. Prover binaries (Linux x86-64 ELF — they run natively on the VPS, no rebuild)
Source: `spike/ckb-to-cardano/circuit/prover/target/release/`
Copy at least: `leap_bound_windowed`, `relay_bind`, `advance_live` (+ any others the pipeline calls).
```
rsync -avz spike/ckb-to-cardano/circuit/prover/target/release/{leap_bound_windowed,relay_bind,advance_live} \
  USER@VPS:/opt/chiral/spike/ckb-to-cardano/circuit/prover/target/release/
```
(They are dynamically-linked glibc ELFs; Ubuntu/Debian on the VPS already has the loader + libstdc++.)

## 2. Ceremony proving keys (~1 GB total — large, gitignored)
Source: `spike/ckb-to-cardano/circuit/ceremony/*.bin` and `circuit/ceremony_xada_burn/*.bin`
Essential: `ceremony_xada_burn/leap_bound_windowed_pk.bin` (480 MB, the return prover) and
`ceremony/advance_live_pk.bin` (426 MB, checkpoint advance). Transfer the matching `*_redeemer.json` (the baked vk)
alongside each.

## 3. Live on-chain state + deployed configs (must be the CURRENT copies)
These are pointers/roots the relayer reads; a stale copy breaks releases. Copy the live versions:
- `relayer/onchain/registry_state.json`, `xada_seal_state.json`, `chain_state.json`,
  `boundasset_v2_state.json`, `xada_owner_cell.json`, `checkpoint_v2.json`, `*_live.json`, `xada_*_deploy.json`
- `deployed/cardano/preview/*.json` (escrow config, ckbcert-genesis, groth16-deploy, refscripts, …)

## 4. Secret keys -> `/opt/chiral/.secrets/` (chmod 600, NEVER in git)
| file on VPS | what | source on dev box |
|---|---|---|
| `pudge_relayer.key` | CKB Pudge relayer | `C:\Users\telmo\.chiral\pudge_relayer.key` |
| `preview_relayer.key` | Cardano preview (bech32 ed25519_sk) | `C:\Users\telmo\.chiral\preview_relayer.key` |
| `cardano_key.json` | Cardano preview `{sk_hex,…}` (Blockfrost CLI tools) | WSL `/tmp/cardano_key.json` (same key as preview_relayer.key; regenerate if gone) |

Then point the env at them (see `deploy/.env.example`): `RELAYER_KEY`, `CHIRAL_PREVIEW_KEY`, `CHIRAL_CARDANO_KEY`.

## Do NOT copy
- `node_modules/` (any) — rebuild on the VPS with `npm ci` (native bindings differ).
- `dapp/dist/` — `npm run build` on the VPS.
- The Rust `target/` except the release binaries above.

## Network egress the VPS needs
`testnet.ckb.dev` (CKB RPC), `cardano-preview.blockfrost.io` + `preview.koios.rest` (Cardano), the Mithril preview
aggregator. All outbound HTTPS — no inbound except your reverse-proxy/tunnel port.
