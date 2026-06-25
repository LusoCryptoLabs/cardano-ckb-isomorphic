// bridge_lock_unified.mjs - submit the CONSERVATION-SAFE unified bridge receipt the self-serve dApp builds:
// one cell that is BOTH (a) locked under burn_gated_unlock_v2 (only a Mithril-certified χCKB burn releases
// it) AND (b) a bridge_lock_v1 receipt (type + BRG1 data) the leap circuit binds amount/recipient from.
// This is the headless equivalent of leap.js's buildLockTx - validates the unified receipt submits on Pudge
// and the ~269-CKB occupied-bytes calc. Run with the funded relayer key.   node bridge_lock_unified.mjs
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BL = JSON.parse(fs.readFileSync(path.join(HERE, "bridge_lock_live.json"), "utf8"));
const BG = JSON.parse(fs.readFileSync(path.join(HERE, "burn_gated_live.json"), "utf8"));
const CKB = 100_000_000n, FEE = 2_000_000n;

const AMOUNT_CKB = BigInt(process.env.AMOUNT_CKB || 300n);     // ≥ ~269 (unified receipt occupied bytes)
const AMOUNT = AMOUNT_CKB * CKB;                               // shannons; capacity == amount
const RECIPIENT = process.env.RECIPIENT || "2df44c71a4312463ba31315c5aa7725b6ad44cd544a055a3dde915a6";
const POLICY = process.env.CHI_POLICY_ID || "5b4f5525a155fd86757bb3ba20da6e2ef66bcfb72e8853ef31bcf268";
const NAME = "636869434b42";                                  // "chiCKB"

const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u128le = (n) => { const b = Buffer.alloc(16); let v = BigInt(n); b.writeBigUInt64LE(v & 0xffffffffffffffffn, 0); b.writeBigUInt64LE(v >> 64n, 8); return b; };
const hx = (h) => Buffer.from(String(h).replace(/^0x/, ""), "hex");

// burn_gated_unlock_v2 args: lckp(32) | amount(u128 LE,16) | policy(28) | registry(32) | name  (== leap.js)
const bgArgs = "0x" + Buffer.concat([hx(BG.lckp_type_hash), u128le(AMOUNT), hx(POLICY), hx(BG.registry_type_hash), hx(NAME)]).toString("hex");
const burnGated = ccc.Script.from({ codeHash: BG.burn_gated_code_hash, hashType: "data1", args: bgArgs });
// bridge_lock_v1 type (data1, 32 zero args) + BRG1 receipt data (kind=CKB)
const bridgeType = ccc.Script.from({ codeHash: BL.bridge_code_hash, hashType: "data1", args: "0x" + "00".repeat(32) });
const data = "0x" + Buffer.concat([Buffer.from("BRG1"), Buffer.from([0]), u64le(AMOUNT), Buffer.alloc(8), hx(RECIPIENT)]).toString("hex");

const { client, signer } = signerOf();
const lock = await myLock(signer);
const ps = await plainCells(client, lock);
// verify each candidate is LIVE on the node - the find-cells indexer can lag and return a spent cell
// (TransactionFailedToResolve / Unknown OutPoint on submit), which would otherwise be picked first.
let fund = null;
for (const c of ps) {
  if (BigInt(c.cellOutput.capacity) < AMOUNT + FEE + 63n * CKB) continue;
  if (await client.getCellLive(c.outPoint, true)) { fund = c; break; }
}
if (!fund) throw new Error("no LIVE plain funding cell large enough");
const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: fund.outPoint, since: 0n }],
  outputs: [
    { lock: burnGated, type: bridgeType, capacity: AMOUNT },                                  // the unified receipt
    { lock, capacity: BigInt(fund.cellOutput.capacity) - AMOUNT - FEE },                       // change
  ],
  outputsData: [data, "0x"],
  cellDeps: [{ outPoint: { txHash: BL.bridge_code_tx, index: 0 }, depType: "code" }],          // bridge_lock_v1 type dep
});
tx.cellDeps.push(...(await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep));
const h = await client.sendTransaction(await signer.signTransaction(tx));
console.log("UNIFIED RECEIPT lock tx:", h, "| amount", AMOUNT_CKB.toString(), "CKB | recipient", RECIPIENT.slice(0, 12) + "…");
await wait(client, h);
fs.writeFileSync(path.join(HERE, "unified_receipt.json"),
  JSON.stringify({ lock_txid: h, index: 0, amount: AMOUNT.toString(), recipient: RECIPIENT, bgArgs, receiptLock: "burn_gated_unlock_v2" }, null, 2));
console.log("  confirmed; wrote unified_receipt.json - prove with: POST /api/leap/prove {lockTxid:'" + h + "'}");
process.exit(0);
