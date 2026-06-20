import { ccc } from "@ckb-ccc/connector-react";

const u64le = (n) => leHex(n, 8);
const leHex = (n, bytes) => { let v = BigInt(n), s = ""; for (let i = 0; i < bytes; i++) { s += Number(v & 0xffn).toString(16).padStart(2, "0"); v >>= 8n; } return s; };
const noPfx = (h) => String(h || "").replace(/^0x/, "");

// The 28-byte Cardano payment credential from a CIP-30 hex address. Shelley addresses are
// header(1) | payment(28) | [stake(28)]; we take the payment credential as the leap recipient.
export function cardanoRecipientCred(addressHex) {
  const h = String(addressHex || "").replace(/^0x/, "").toLowerCase();
  if (h.length < (1 + 28) * 2) throw new Error("unexpected Cardano address (need a Shelley payment credential)");
  return h.slice(2, 2 + 56);
}

// The burn_gated_unlock_v2 lock for THIS leap: args bind the release to a Mithril-certified burn of exactly
// this χCKB amount/policy/name, gated on the authenticated checkpoint + nullifier registry. Layout (mirrors
// the proven relayer/onchain/bg_demo_lock.mjs):
//   lckp_type_hash(32) | amount(u128 LE,16) | policy_id(28) | registry_type_hash(32) | asset_name
// The bound amount IS the locked shannon amount — the same number the leap proof binds and the policy mints,
// so mint == burn == release. So the user CANNOT reclaim the receipt; only burning the minted χCKB releases it.
export function burnGatedLock(bg, amountShannons) {
  const args = "0x" + noPfx(bg.lckpTypeHash) + leHex(amountShannons, 16) + noPfx(bg.policyId)
    + noPfx(bg.registryTypeHash) + noPfx(bg.assetNameHex);
  return ccc.Script.from({ codeHash: bg.codeHash, hashType: "data1", args });
}

// Build the lock tx the USER signs: one receipt cell with
//   capacity == amount,  lock = burn_gated_unlock_v2 (conservation-safe; demo fallback = the user's lock),
//   type = bridge_lock_v1(data1, 32 zero args),
//   data = "BRG1" | kind(00) | amount(u64 LE) | zeros(8) | recipient(28)
// The user's wallet funds + signs it; the change returns to the user.
export async function buildLockTx({ signer, cfg, amountCKB, recipientCred28 }) {
  if (!cfg?.bridgeCodeHash || !cfg?.bridgeDep) throw new Error("bridge not configured (no bridge_lock_v1 deploy)");
  if (!/^[0-9a-f]{56}$/.test(recipientCred28)) throw new Error("recipient must be a 28-byte hex credential");
  const amount = BigInt(Math.round(Number(amountCKB) * 1e8)); // shannons; capacity == amount
  if (amount < BigInt(cfg.minLockCKB) * 100000000n) throw new Error(`minimum lock is ${cfg.minLockCKB} CKB`);
  const data = "0x" + "42524731" + "00" + u64le(amount) + "00".repeat(8) + recipientCred28; // 49 bytes
  const bridgeType = ccc.Script.from({ codeHash: cfg.bridgeCodeHash, hashType: "data1", args: "0x" + "00".repeat(32) });
  // conservation-safe receipt lock; fall back to the user's lock only if the backend hasn't surfaced burnGated.
  const receiptLock = cfg.burnGated
    ? burnGatedLock(cfg.burnGated, amount)
    : (await signer.getRecommendedAddressObj()).script;
  const tx = ccc.Transaction.from({
    outputs: [{ lock: receiptLock, type: bridgeType, capacity: amount }],
    outputsData: [data],
    cellDeps: [{ outPoint: { txHash: cfg.bridgeDep.txHash, index: cfg.bridgeDep.index }, depType: "code" }],
  });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer);
  return tx;
}

// build + sign + send; returns the lock tx hash (the receipt is at output 0).
export async function lockCkb({ signer, cfg, amountCKB, recipientCred28 }) {
  const tx = await buildLockTx({ signer, cfg, amountCKB, recipientCred28 });
  return await signer.sendTransaction(tx);
}
