import { ccc } from "@ckb-ccc/connector-react";

const u64le = (n) => { let v = BigInt(n), s = ""; for (let i = 0; i < 8; i++) { s += Number(v & 0xffn).toString(16).padStart(2, "0"); v >>= 8n; } return s; };

// The 28-byte Cardano payment credential from a CIP-30 hex address. Shelley addresses are
// header(1) | payment(28) | [stake(28)]; we take the payment credential as the leap recipient.
export function cardanoRecipientCred(addressHex) {
  const h = String(addressHex || "").replace(/^0x/, "").toLowerCase();
  if (h.length < (1 + 28) * 2) throw new Error("unexpected Cardano address (need a Shelley payment credential)");
  return h.slice(2, 2 + 56);
}

// Build the bridge_lock_v1 lock tx the USER signs: one receipt cell with
//   capacity == amount,  type = bridge_lock_v1(data1, 32 zero args),
//   data = "BRG1" | kind(00) | amount(u64 LE) | zeros(8) | recipient(28)
// The user's wallet funds + signs it; the change returns to the user. (Demo: receipt lock = the user's lock.)
export async function buildLockTx({ signer, cfg, amountCKB, recipientCred28 }) {
  if (!cfg?.bridgeCodeHash || !cfg?.bridgeDep) throw new Error("bridge not configured (no bridge_lock_v1 deploy)");
  if (!/^[0-9a-f]{56}$/.test(recipientCred28)) throw new Error("recipient must be a 28-byte hex credential");
  const amount = BigInt(Math.round(Number(amountCKB) * 1e8)); // shannons; capacity == amount
  if (amount < BigInt(cfg.minLockCKB) * 100000000n) throw new Error(`minimum lock is ${cfg.minLockCKB} CKB`);
  const data = "0x" + "42524731" + "00" + u64le(amount) + "00".repeat(8) + recipientCred28; // 49 bytes
  const bridgeType = ccc.Script.from({ codeHash: cfg.bridgeCodeHash, hashType: "data1", args: "0x" + "00".repeat(32) });
  const userLock = (await signer.getRecommendedAddressObj()).script;
  const tx = ccc.Transaction.from({
    outputs: [{ lock: userLock, type: bridgeType, capacity: amount }],
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
