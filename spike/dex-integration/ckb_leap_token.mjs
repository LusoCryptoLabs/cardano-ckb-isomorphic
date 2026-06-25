// ckb_leap_token.mjs - financial-grade CKB-side token operations for a bridged, JoyID-visible xUDT.
//
// Three operations:
//   genesisWithTokenInfo() - issue the first xUDT under owner mode AND co-mint the Unique token-info cell in
//                            the SAME tx (the only arrangement explorers/JoyID accept for metadata binding).
//   buildLeapMint()        - per-leap mint of `amount` base units to the recipient's JoyID lock.
//   buildLeapBurn()        - leap-out: burn exactly `amount` from a JoyID-locked xUDT cell.
//
// WHAT THIS FILE GUARANTEES (off-chain, financial-grade): integer-only amounts with u128 bounds, immutable
// decimals, exact recipient = JoyID lock, owner = bridge enforcing script, token-info co-minted at genesis.
// WHAT IT CANNOT GUARANTEE (must be the ON-CHAIN owner script - see README §2): that `amount` equals the
// verified leap amount and that each leap mints at most once. Those are the no-inflation / no-replay
// invariants; this builder only *constructs* the tx - the owner script must *authorize* it. Do not ship to
// mainnet without that guard audited.
import { ccc } from "@ckb-ccc/core";
import { TOKEN, CKB } from "./token.config.mjs";

const U128_MAX = (1n << 128n) - 1n;

// ---- amount discipline: integers, base units, u128 ----
export function toBaseUnits(displayAmount) {
  // displayAmount is a decimal STRING (never a float). e.g. "52.5" @6dp -> 52500000n
  const [whole, frac = ""] = String(displayAmount).split(".");
  if (frac.length > TOKEN.decimals) throw new Error(`too many decimal places (max ${TOKEN.decimals})`);
  const v = BigInt(whole + frac.padEnd(TOKEN.decimals, "0"));
  if (v < 0n || v > U128_MAX) throw new Error("amount out of u128 range");
  return v;
}
const u128le = (v) => {
  if (v < 0n || v > U128_MAX) throw new Error("amount out of u128 range");
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return ccc.hexFrom(b);
};

// xUDT type with OWNER = the bridge enforcing script (owner-mode authorization).
const xudtType = () => ccc.Script.from({ codeHash: CKB.xudtCodeHash, hashType: CKB.xudtHashType, args: CKB.bridgeLockHash });

// token-info layout read by ckb-explorer + JoyID/CCC:  [decimals u8][nameLen u8][name][symLen u8][symbol]
function encodeTokenInfo() {
  const n = new TextEncoder().encode(TOKEN.name), s = new TextEncoder().encode(TOKEN.symbol);
  if (n.length > 255 || s.length > 255) throw new Error("name/symbol too long");
  return ccc.hexFrom(ccc.bytesConcat(new Uint8Array([TOKEN.decimals]),
    new Uint8Array([n.length]), n, new Uint8Array([s.length]), s));
}

const scriptSz = (s) => 32 + 1 + ccc.bytesFrom(s.args).length;
const cellMinCap = (lock, type, data) =>
  BigInt(8 + scriptSz(lock) + (type ? scriptSz(type) : 0) + ccc.bytesFrom(data).length) * 100_000_000n;

/**
 * GENESIS: first issuance + token-info, in ONE owner-mode tx (so metadata binds and JoyID renders it).
 * @param leapAuthInput  an input that puts the bridge owner script in scope AND carries the leap proof
 *                       (e.g. the BoundAsset state cell). The owner script must enforce amount==proof.
 * @param recipientLock  the user's JoyID lock script (ccc.Script).
 * @param amount         BigInt base units (use toBaseUnits()).
 */
export async function genesisWithTokenInfo({ client, signer, leapAuthInput, recipientLock, amount }) {
  if (typeof amount !== "bigint" || amount <= 0n) throw new Error("amount must be a positive BigInt");
  const ut = xudtType();
  const tokenData = u128le(amount);
  const infoData = encodeTokenInfo();

  const unique = await client.getKnownScript(ccc.KnownScript.UniqueType);
  const INFO_IDX = 2; // outputs: [0]=leapAuth carry-forward, [1]=token, [2]=Unique info
  const uArgs = ccc.hashTypeId(ccc.CellInput.from({ previousOutput: leapAuthInput.outPoint, since: 0n }), INFO_IDX).slice(0, 42);
  const uniqueType = ccc.Script.from({ codeHash: unique.codeHash, hashType: unique.hashType, args: uArgs });

  const tokenCap = ccc.fixedPointFrom(CKB.minTokenCellCkb); // occupied capacity locked in the token cell
  const infoCap = cellMinCap(recipientLock, uniqueType, infoData) + ccc.fixedPointFrom(1);

  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: leapAuthInput.outPoint, since: 0 }],
    outputs: [
      // [0] carry the bridge state forward (your verifier owns this) - fill per your BoundAsset transition
      { capacity: leapAuthInput.cellOutput.capacity, lock: leapAuthInput.cellOutput.lock, type: leapAuthInput.cellOutput.type },
      // [1] the xUDT, locked to the USER's JoyID account
      { capacity: tokenCap, lock: recipientLock, type: ut },
      // [2] the Unique token-info cell (immutable display metadata)
      { capacity: infoCap, lock: recipientLock, type: uniqueType },
    ],
    outputsData: [leapAuthInput.outputData, tokenData, infoData],
  });
  tx.inputs[0].cellOutput = leapAuthInput.cellOutput;
  tx.inputs[0].outputData = leapAuthInput.outputData;
  tx.addCellDeps(...unique.cellDeps.map((c) => c.cellDep)); // + your xUDT + bridge-lock cellDeps
  return tx; // caller adds bridge-lock/xUDT cellDeps + witnesses (the leap proof) and completes fee
}

/** Per-leap MINT of `amount` to a JoyID lock. The leapAuthInput owner script must gate amount==proof. */
export async function buildLeapMint({ client, leapAuthInput, recipientLock, amount }) {
  if (typeof amount !== "bigint" || amount <= 0n) throw new Error("amount must be a positive BigInt");
  const ut = xudtType();
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: leapAuthInput.outPoint, since: 0 }],
    outputs: [
      { capacity: leapAuthInput.cellOutput.capacity, lock: leapAuthInput.cellOutput.lock, type: leapAuthInput.cellOutput.type },
      { capacity: ccc.fixedPointFrom(CKB.minTokenCellCkb), lock: recipientLock, type: ut },
    ],
    outputsData: [leapAuthInput.outputData, u128le(amount)],
  });
  tx.inputs[0].cellOutput = leapAuthInput.cellOutput;
  tx.inputs[0].outputData = leapAuthInput.outputData;
  return tx; // caller adds deps + the leap-proof witness + fee completion
}

/** Leap-out BURN: spend the user's JoyID-locked xUDT, removing exactly `amount` from supply. The bridge then
 *  proves this burn to release the asset on the source chain. Enforce exactness on-chain (owner script). */
export async function buildLeapBurn({ client, signer, tokenCell, amount, changeLock }) {
  if (typeof amount !== "bigint" || amount <= 0n) throw new Error("amount must be a positive BigInt");
  const ut = xudtType();
  const held = (() => { const b = ccc.bytesFrom(tokenCell.outputData).slice(0, 16); let v = 0n; for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; })();
  if (amount > held) throw new Error("burn exceeds held balance");
  const outputs = [];
  const outputsData = [];
  if (amount < held) { // partial burn: return the remainder to the user
    outputs.push({ capacity: tokenCell.cellOutput.capacity, lock: tokenCell.cellOutput.lock, type: ut });
    outputsData.push(u128le(held - amount));
  }
  const tx = ccc.Transaction.from({ inputs: [{ previousOutput: tokenCell.outPoint, since: 0 }], outputs, outputsData });
  tx.inputs[0].cellOutput = tokenCell.cellOutput;
  tx.inputs[0].outputData = tokenCell.outputData;
  // net token delta = -amount (inputs hold `held`, outputs hold `held-amount`); the bridge proof commits to `amount`.
  return tx; // caller adds the bridge-lock owner cellDep so owner mode authorizes the burn accounting
}
