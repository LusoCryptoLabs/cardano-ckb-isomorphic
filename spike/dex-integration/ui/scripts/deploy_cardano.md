# Cardano (Preview) deployment — apply params + publish

The Aiken validators are **parameterized**, so deployment first *applies* the params (deterministic and
re-verifiable with `aiken blueprint apply` — no trust in a binary), then publishes reference scripts and
mints the CIP-68 genesis. Run from `spike/ckb-to-cardano/groth16` after `aiken build`.

## Parameter dependency order

```
chiral_policy(nft_policy, nft_name)                         -> chiral_policy hash  (the policy script)
leap_mint_guard(ft_name, bound_script_hash, policy_hash)    -> the FT mint policy id
```

So: pick the policy singleton NFT first → apply it to `chiral_policy` → take that hash → apply it (with
`ft_name` and the deployed `cardano_bound` hash) to `leap_mint_guard`.

## Encoding params as Plutus-Data CBOR

`apply` takes one parameter (the first un-applied) as hex CBOR:
- a **ByteArray** of N bytes (N<24): `0x40+N` ‖ bytes. `"wADA"` = utf8 `77414441` (4 bytes) → `4477414441`.
- a **28-byte** script-hash / policy-id: `581c` ‖ hex. A **32-byte** value: `5820` ‖ hex.
- If unsure, use `cbor.serialise(<value>)` from the Aiken stdlib, or read the schema in `plutus.json`.

## Step A — chiral_policy

```sh
# nft_policy (28-byte one-shot NFT policy id) then nft_name
aiken blueprint apply 581c<nft_policy_hex>  -m chiral_policy -v chiral_policy -o /tmp/bp1.json
aiken blueprint apply <nft_name_cbor> -i /tmp/bp1.json -m chiral_policy -v chiral_policy -o /tmp/bp.applied.json
# the policy script hash (this is leap_mint_guard's policy_script_hash param):
aiken blueprint hash -i /tmp/bp.applied.json -m chiral_policy -v chiral_policy
# its address (where the policy cell lives, read by reference input):
aiken blueprint address -i /tmp/bp.applied.json -m chiral_policy -v chiral_policy
```

## Step B — leap_mint_guard (the FT mint policy)

```sh
aiken blueprint apply 4477414441            -m leap_mint_guard -v leap_mint_guard -o /tmp/g1.json   # ft_name "wADA"
aiken blueprint apply 581c<cardano_bound_hash> -i /tmp/g1.json -m leap_mint_guard -v leap_mint_guard -o /tmp/g2.json
aiken blueprint apply 581c<chiral_policy_hash> -i /tmp/g2.json -m leap_mint_guard -v leap_mint_guard -o /tmp/guard.applied.json
# the FT mint policy id (== CARDANO.policyId in the UI config):
aiken blueprint policy -i /tmp/guard.applied.json -m leap_mint_guard -v leap_mint_guard
```

(Validated: `apply 4477414441 -m leap_mint_guard -v leap_mint_guard` consumes `ft_name` and leaves
`bound_script_hash`, `policy_script_hash`.)

## Step C — genesis tx (one-shot, your funded Preview key)

Using cardano-cli or a JS lib (Lucid/MeshJS) and a funded Preview wallet:
1. mint the **policy singleton NFT** (`nft_policy`/`nft_name`) and create the **policy cell** at the
   `chiral_policy` address with inline datum `PolicyState { governor: <your key hash>, policy: <open> }`.
2. mint exactly one **CIP-68 (100) reference NFT** under the FT policy (redeemer `MintReference`) into an
   output whose inline datum is `cardano_cip68.mjs::cip68MetadataDatum()` (name/ticker/decimals/logo).
3. publish the applied validators as **reference scripts** (so leap txs reference them cheaply).

## Step D — wire the UI

```ts
export const CARDANO = {
  network: "preview",
  policyId: "<FT mint policy id from Step B>",
  ftLabelHex: "0014df10",
  refLabelHex: "000643b0",
  tokenNameAscii: "wADA",
};
```

The (333) FT is then minted only via the verified-leap path (`leap_mint_guard` `LeapInMint`,
`amount == bound state amount`, gated by the policy). Wallets resolve (333)→(100) and render the token.
