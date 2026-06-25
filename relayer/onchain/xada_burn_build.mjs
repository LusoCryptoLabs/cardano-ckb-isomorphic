// xada_burn_build.mjs <recipientLockJSON> <burnAmount> <cardanoRecipient28> - build (UNSIGNED) the χADA burn tx
// for the self-serve return. The user's χADA is spent via xUDT owner mode (the relayer's owner authority cell +
// funding are added here); the user signs only THEIR χADA input in the browser, then the relayer signs funding
// and submits (xada_burn_submit.mjs). The two secp groups are independent in CKB, so order doesn't matter.
//
// Builds: inputs [user χADA…, owner authority, relayer funding]; outputs [xada_burn_receipt(amount,recipient),
// owner recreated, the user's χADA-or-CKB back (change/refund), relayer change]. Prints {txHex, burnAmount,
// recipient, chadaInputs}. NO signatures here.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";
import { pickPlain } from "./leap_common_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const O = JSON.parse(fs.readFileSync(path.join(HERE, "xada_owner_deploy.json"), "utf8"));
const BR = JSON.parse(fs.readFileSync(path.join(HERE, "xada_burn_deploy.json"), "utf8"));
const OWNER_STATE = JSON.parse(fs.readFileSync(path.join(HERE, "xada_owner_cell.json"), "utf8"));
const strip = (h) => (h || "").replace(/^0x/, "");
const out = (o) => { console.log(JSON.stringify(o)); process.exit(o.error ? 1 : 0); };
const FEE = 9_000000n, RECEIPT_CAP = 185_00000000n;   // 0.09 CKB - keeps the fee RATE under ccc's 0.1 CKB/kB cap on this ~1kB tx

const [recipArg, amtArg, cardanoRecip] = process.argv.slice(2);
let recipientLock;
try { recipientLock = ccc.Script.from(JSON.parse(recipArg)); } catch (e) { out({ error: "bad recipientLock JSON: " + e.message }); }
let burnAmount = BigInt(amtArg || "0");
const recip28 = strip(cardanoRecip);
if (burnAmount <= 0n) out({ error: "burnAmount must be > 0" });
if (!/^[0-9a-f]{56}$/.test(recip28)) out({ error: "cardanoRecipient must be a 28-byte hex payment credential" });

const { client, signer } = signerOf();
const lock = await myLock(signer);                            // relayer lock (funding + receipt + change)
const xadaType = ccc.Script.from({ codeHash: O.xudt.codeHash, hashType: O.xudt.hashType, args: O.ownerLockHash });
const xudtDep = { outPoint: { txHash: O.xudt.dep.txHash, index: O.xudt.dep.index }, depType: "code" };
const ownerLock = ccc.Script.from({ codeHash: O.ownerCode.codeHash, hashType: "data1", args: O.ownerArgs });
const ownerDep = { outPoint: { txHash: O.ownerCode.txHash, index: 0 }, depType: "code" };
const ownerOp = { txHash: OWNER_STATE.txHash, index: OWNER_STATE.index };
const brType = ccc.Script.from({ codeHash: BR.burnReceiptCode.codeHash, hashType: "data1", args: O.xadaTokenId });
const brDep = { outPoint: { txHash: BR.burnReceiptCode.txHash, index: 0 }, depType: "code" };

// CANONICAL LAYOUT: the return circuit's proving key bakes the receipt offsets, so EVERY burn must have the
// SAME molecule shape as the ceremony's instance - 1 χADA input, 3 outputs [receipt, owner, change], no χADA
// change. So we burn ONE WHOLE χADA cell (amount = the cell's χADA); the cell's CKB capacity rolls into the
// relayer change. Pick the smallest χADA cell that covers the requested amount, and burn all of it.
let xadaCell = null, have = 0n;
for await (const c of client.findCellsByLock(recipientLock, xadaType, true)) {
  const d = ccc.bytesFrom(c.outputData); if (d.length < 16) continue;
  let a = 0n; for (let i = 15; i >= 0; i--) a = (a << 8n) | BigInt(d[i]);   // u128 LE
  if (a >= burnAmount && (xadaCell === null || a < have)) { xadaCell = c; have = a; }
}
if (!xadaCell) out({ error: `no single χADA cell >= ${burnAmount} to burn (token ${O.xadaTokenId}); the return burns a whole cell` });
burnAmount = have;                                                          // burn the WHOLE cell
const xadaIns = [xadaCell]; const cap = BigInt(xadaCell.cellOutput.capacity);

// find the LIVE owner authority cell (plain, owner-locked) - robust to state drift across mints/burns.
let ownerCell = null, ownerLive = null;
for await (const c of client.findCellsByLock(ownerLock, null, true)) {
  if (c.cellOutput.type == null && c.outputData === "0x") { ownerCell = c; ownerLive = c.outPoint; break; }
}
if (!ownerCell) out({ error: "no live owner authority cell - relayer must --setup" });
const ownerCap = BigInt(ownerCell.cellOutput.capacity);
const fund = await pickPlain(client, lock, RECEIPT_CAP + FEE + 100_00000000n);
const fundCap = BigInt(fund.cellOutput.capacity);

const amtBuf = Buffer.alloc(16); amtBuf.writeBigUInt64LE(burnAmount, 0);
const receiptData = "0x58414431" + amtBuf.toString("hex") + recip28;       // "XAD1" ‖ amount(16 LE) ‖ recipient(28)
// canonical 3-output layout (matches the ceremony so the proving key's baked offsets hold): receipt, owner
// recreated, relayer change (absorbs the burned cell's CKB capacity + funding − receipt − fee).
const relayerChange = cap + fundCap - RECEIPT_CAP - FEE;
if (relayerChange < 61_00000000n) out({ error: "relayer funding too small for change" });

const tx = ccc.Transaction.from({
  inputs: [
    { previousOutput: xadaIns[0].outPoint, since: 0n },                     // user χADA cell (user signs in browser)
    { previousOutput: ownerLive, since: 0n },                               // owner authority → owner mode (no sig)
    { previousOutput: fund.outPoint, since: 0n },                           // relayer funding (relayer signs)
  ],
  outputs: [
    { lock, type: brType, capacity: RECEIPT_CAP },                          // 0: xada_burn_receipt
    { lock: ownerLock, capacity: ownerCap },                                // 1: owner recreated
    { lock, capacity: relayerChange },                                      // 2: relayer change
  ],
  outputsData: [receiptData, "0x", "0x"],
  cellDeps: [xudtDep, ownerDep, brDep],
});
// initialise an empty witness slot per input so the browser + relayer signers can each fill their own group.
tx.witnesses = tx.inputs.map(() => "0x");
out({ ok: true, txHex: ccc.hexFrom(tx.toBytes()), burnAmount: burnAmount.toString(), recipient: recip28,
  chadaInputs: xadaIns.length, token: O.xadaTokenId });
