// cardano_cip68.mjs - Cardano-side wallet visibility for a bridged token, via CIP-68 (on-chain metadata).
//
// Why CIP-68 (not the CIP-26 off-chain registry): a bridge token's policy id is a SCRIPT hash, and the
// CIP-26 registry proves ownership with a signature from the policy KEY - which a script policy has no key
// for, so a registry PR fails. CIP-68 puts metadata on-chain in a one-shot (100) reference NFT that wallets
// read directly. (Documented the hard way in cardano-ckb-bridge/docs/TOKEN_METADATA.md.)
//
// FINANCIAL-GRADE NOTES:
//  • `decimals` is part of the metadata datum and MUST match the source asset (and the CKB side). Immutable.
//  • the (100) reference NFT is ONE-SHOT, gated on-chain to the genesis tx (see validators/wckb_mint.ak
//    `MintReference`), so metadata cannot be silently re-minted/changed. If you want upgradable logo/url,
//    gate the reference-datum update behind governance - never leave it open.
//  • the FT itself (label 333) is minted ONLY by the verified-leap path (MintWrapped: amount == claim.amount);
//    burns are negative-only. Those conservation invariants are ON-CHAIN in the mint validator, not here.
import { TOKEN, CARDANO } from "./token.config.mjs";

// CIP-67 asset-name labels (4-byte hex prefixes). (333)=fungible token, (100)=reference NFT. Fixed constants.
export const LABEL = { FT: CARDANO.ftLabelHex /* 0014df10 */, REF: CARDANO.refLabelHex /* 000643b0 */ };

const utf8hex = (s) => Buffer.from(s, "utf8").toString("hex");
/** full on-chain asset name = label ++ utf8(name). Use the FT name for balances, REF name for the metadata NFT. */
export const ftAssetName = () => LABEL.FT + utf8hex(CARDANO.tokenNameAscii);
export const refAssetName = () => LABEL.REF + utf8hex(CARDANO.tokenNameAscii);
export const ftUnit = () => CARDANO.policyId.replace(/^0x/, "") + ftAssetName();   // policyId ++ assetName

/**
 * The CIP-68 metadata datum carried by the (100) reference NFT's output (inline). Maps 1:1 to Plutus Data:
 *   Constr 0 [ metadata :: Map ByteArray Data, version :: Int, extra :: Data ]
 * Returned in a lib-agnostic shape; convert to your tx lib's Data (Lucid `Data`, CML, pycardano PlutusData).
 */
export function cip68MetadataDatum() {
  const meta = [
    [utf8hex("name"), utf8hex(TOKEN.name)],
    [utf8hex("ticker"), utf8hex(TOKEN.symbol)],
    [utf8hex("decimals"), { int: TOKEN.decimals }],     // INTEGER, immutable, must match source
    [utf8hex("description"), utf8hex(`Bridged ${TOKEN.name} (${TOKEN.symbol})`)],
    ...(TOKEN.logoUri ? [[utf8hex("url"), utf8hex(TOKEN.logoUri)], [utf8hex("logo"), utf8hex(TOKEN.logoUri)]] : []),
  ];
  return {
    constructor: 0,
    fields: [
      { map: meta.map(([k, v]) => ({ k: { bytes: k }, v: typeof v === "string" ? { bytes: v } : v })) },
      { int: 1 },          // CIP-68 metadata version
      { constructor: 0, fields: [] }, // extra (unused)
    ],
  };
}

// Genesis wiring (mirrors validators/wckb_mint.ak `MintReference` + cardano-scripts/mint_state.py):
//  1. In the SAME tx that mints the one-shot state NFT, also mint exactly ONE `refAssetName()` token
//     under your policy (redeemer MintReference), and place it in an output whose INLINE DATUM is
//     cip68MetadataDatum(). The validator enforces: ref_minted==1 && state_nft_minted==1 &&
//     only the ref name moves && a reference output carries an inline datum.
//  2. The user-facing FT (`ftAssetName()`) is then minted per verified leap (redeemer MintWrapped),
//     amount == claim.amount, to the recipient's address.
//  3. Wallets (Eternl/Lace/…) resolve (333)->(100) and render name/ticker/decimals/logo from the datum.
export const GENESIS_NOTE =
  "Mint the (100) reference NFT + inline CIP-68 datum in the state-NFT genesis tx (one-shot). " +
  "Mint the (333) FT only via the verified-leap MintWrapped path (amount==claim.amount).";
