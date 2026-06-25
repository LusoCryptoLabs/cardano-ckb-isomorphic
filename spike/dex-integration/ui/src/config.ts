// config.ts - typed bridge/token config for the UI. Mirrors ../../token.config.mjs (the single source of
// truth used by the tx builders); kept as TS here so the UI typechecks and can flag placeholders. Replace
// the placeholder hashes with your deployed values to enable on-chain reads + tx submission.
//
// FINANCIAL-GRADE: `decimals` MUST equal the source asset's decimals (immutable after genesis); the xUDT
// owner is the leap-mint guard SCRIPT, never a key. See ../../README.md §2 and ../guard/MAPPING_SPEC.md.

import { utf8ToHex } from "./lib/amount";

export type CkbNetwork = "testnet" | "mainnet";
export type CardanoNetwork = "preview" | "mainnet";

export const TOKEN = {
  name: "Chiral ADA",
  symbol: "χADA",
  decimals: 6, // MUST match the source asset; immutable after genesis
  logoUri: "",
} as const;

export const CKB = {
  network: "testnet" as CkbNetwork,
  // deployed xUDT type-script code hash + hash type (network-specific)
  xudtCodeHash: "0x25c29dc317811a6f6f3fe6d3e8e3e4f9000000000000000000000000000000",
  xudtHashType: "data1" as "data1" | "type" | "data",
  // OWNER = the leap-mint guard script hash (the xUDT type args). NOT a wallet key.
  bridgeLockHash: "0xBA5A99AB00000000000000000000000000000000000000000000000000000000",
  // the admin policy cell's full TYPE script (caps/pause). A singleton (e.g. type-id). The UI reads this
  // cell to show limits + halt status and to pre-validate amounts; the on-chain guard remains the authority.
  policyType: {
    codeHash: "0xP0L1CY000000000000000000000000000000000000000000000000000000000",
    hashType: "type" as "data1" | "type" | "data",
    args: "0x",
  },
  minTokenCellCkb: 145, // CKB locked as the token cell's occupied capacity (surface to users)
} as const;

export const CARDANO = {
  network: "preview" as CardanoNetwork,
  policyId: "00000000000000000000000000000000000000000000000000000000",
  ftLabelHex: "0014df10", // CIP-67 (333) fungible token
  refLabelHex: "000643b0", // CIP-67 (100) reference NFT
  tokenNameAscii: "χADA", // UTF-8 (not literally ASCII): utf8('cf87') ++ "ADA"
} as const;

const PLACEHOLDER_RE = /0{8,}$|…|P0L1CY|BA5A99AB|25c29dc3/;
/** A hash field is "configured" if it isn't an obvious placeholder. Gates on-chain reads + submit. */
export const isConfigured = (h: string): boolean => !!h && !PLACEHOLDER_RE.test(h);

export const ckbConfigured = () =>
  isConfigured(CKB.xudtCodeHash) && isConfigured(CKB.bridgeLockHash);
export const policyConfigured = () => isConfigured(CKB.policyType.codeHash);
export const cardanoConfigured = () => isConfigured(CARDANO.policyId);

/** full Cardano FT asset name = label(333) ++ utf8(name); unit = policyId ++ assetName (hex, no 0x). */
export const ftAssetNameHex = (): string =>
  CARDANO.ftLabelHex + utf8ToHex(CARDANO.tokenNameAscii);
export const ftUnitHex = (): string => CARDANO.policyId.replace(/^0x/, "") + ftAssetNameHex();
