# Bridged-token DEX UI (JoyID + Cardano)

A real React + TypeScript + Vite front-end for the Chiral binding protocol's bridged token. It shows the token
on **both** chains and drives the leap flow, with amount handling and caps/pause that match the on-chain
guard exactly.

```
pnpm install
pnpm dev        # local dev server
pnpm test       # unit tests (amount + policy encoding vectors)
pnpm typecheck  # tsc --noEmit
pnpm build      # production bundle
```

## What it does (real, no mock)

- **JoyID / CKB** via `@ckb-ccc/connector-react` — connect, resolve the account lock, and read the bridged
  **xUDT** balance straight from chain (`client.findCellsByLock` + the canonical 16-byte-LE amount decode).
  It surfaces the **CKB reserved** as state rent ("X wADA + Y CKB reserved across N cells"), the financial-app
  UX rule from the integration README §3 — not a bare token balance.
- **Cardano** via **CIP-30** (Eternl/Lace/…) — connect with no backend, read the bridged **(333) FT** balance
  by decoding the wallet's own `getBalance()` Value (a dependency-free CBOR decoder, unit-tested), and extract
  the 28-byte **payment credential** the Cardano leap-mint guard binds to.
- **Live caps/pause** — reads the admin policy cell (`flags ‖ min ‖ max`) and shows a halt banner + the
  per-leap limits, and **pre-validates** every amount against them client-side. The on-chain guard
  (`enforce_policy`) stays the authority; this is just fast UX feedback.
- **Leap form** — amount entered as a display string is converted to **u128 base units** per
  `../guard/MAPPING_SPEC.md` (rejects floats / excess precision / out-of-range), checked against decimals and
  the policy, then handed to the tx builders.

## Wiring to real deployments

`src/config.ts` mirrors `../token.config.mjs`. It ships with **placeholder** hashes and the UI degrades
gracefully (connect + validation still work; on-chain reads/submit light up once configured). Set:

- `CKB.xudtCodeHash` / `xudtHashType` — the deployed xUDT type script.
- `CKB.bridgeLockHash` — the **leap-mint guard** script hash (the xUDT owner; never a key).
- `CKB.policyType` — the admin policy cell's type script (caps/pause).
- `CARDANO.policyId` + `tokenNameAscii` — the wrapped-token policy and name.

## What it does NOT do (by design / out of scope)

Transaction **submission** needs the deployed hashes **and** a real leap-proof witness (Mithril cert on CKB
/ Groth16 on Cardano) produced by the operational pipeline. The form validates and prepares the
MAPPING_SPEC-correct intent and points at `../ckb_leap_token.mjs` (`buildLeapMint`/`buildLeapBurn`) and
`../cardano_cip68.mjs`; completing + signing + broadcasting a value-bearing leap is the same
operations/keys step tracked as README §5 item 9. No audit has been done — testnet/listing-prep only.
