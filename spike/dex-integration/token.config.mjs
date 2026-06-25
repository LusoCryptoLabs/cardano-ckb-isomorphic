// token.config.mjs - single source of truth for a bridged, DEX-tradeable, JoyID-visible token.
//
// FINANCIAL-GRADE RULES baked in here (read before changing any value):
//  • `decimals` MUST equal the SOURCE asset's decimals exactly (ADA=6, CKB=8). A mismatch silently
//    mis-prices the token on every DEX and wallet. It is IMMUTABLE after genesis.
//  • amounts are ALWAYS integers in base units (BigInt). Never floats. 1 display unit = 10**decimals base units.
//  • the xUDT OWNER is the bridge's enforcing SCRIPT hash, never a wallet key. Owner-mode mint is only
//    authorized inside a tx that satisfies that script (which must check amount == verified-leap amount).
//    If you set `bridgeLockHash` to a key-derived lock, the token is rug-mintable - do not.
export const TOKEN = {
  name: "Chiral ADA",           // human name (CIP-68 / Unique-cell) - ADA leaped onto CKB
  symbol: "χADA",               // ticker (U+03C7 chi = Chiral; UTF-8 'cf87' ++ "ADA")
  decimals: 6,                  // MUST match the source asset; immutable after genesis
  logoUri: "https://…/wada.png",// optional; wallets/explorers may show it
};

export const CKB = {
  network: "testnet",                 // "testnet" (Pudge) | "mainnet"
  xudtCodeHash: "0x25c29dc317811a6f6f3fe6d3e8e3e4f9…", // deployed xUDT type script code hash (network-specific)
  xudtHashType: "data1",              // per the deployed xUDT
  // OWNER = your bridge's enforcing script hash. Owner-mode mint is gated by THIS script's rules.
  // For the isomorphic bridge this is the BoundAsset/leap-mint guard type-script hash (see README §2).
  bridgeLockHash: "0xBA5A99AB…",      // <-- the leap-mint guard (NOT a wallet key)
  minTokenCellCkb: 145,               // CKB locked as the token cell's occupied capacity (surface to users)
};

export const CARDANO = {
  network: "preview",                 // "preview" | "mainnet"
  // the wrapped-token native policy id (script hash of your CIP-68 mint validator)
  policyId: "0x…",
  // CIP-67 labels: (333) fungible token, (100) reference NFT carrying metadata. Fixed constants.
  ftLabelHex: "0014df10",             // CIP-67 (333)
  refLabelHex: "000643b0",            // CIP-67 (100)
  tokenNameAscii: "χADA",             // the bare name (UTF-8, not literally ASCII); full asset name = label ++ utf8(name)
};
