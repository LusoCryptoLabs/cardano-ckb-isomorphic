// Lock 200 CKB under burn_gated_unlock_v2 with args bound to the demo burn (policy f59fd49e, name chiCKB, amount 200).
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BG = JSON.parse(fs.readFileSync(path.join(HERE, "burn_gated_live.json"), "utf8"));
const CKB = 100000000n, FEE = 2000000n;
const LCKP_TH = "cae4326684d06d3cdad0d5f683c4c33d066862b0fa0a753bc58791df5987552a";
const AMOUNT = 200n;                                  // bound BURN amount (chiCKB units)
const POLICY = "f59fd49e9d6229a545c434f02a359b0d29c97eb63eff3932481af2c1";
const REG_TH = "dc18fd562bca1834536c926ce8c9d94f608318c3a79a43959c0c46a84265a24e";
const NAME = "636869434b42";                          // "chiCKB"
const u128le = (n) => { const b = Buffer.alloc(16); let v = BigInt(n); b.writeBigUInt64LE(v & 0xffffffffffffffffn, 0); b.writeBigUInt64LE(v >> 64n, 8); return b; };
const args = "0x" + Buffer.concat([Buffer.from(LCKP_TH, "hex"), u128le(AMOUNT), Buffer.from(POLICY, "hex"), Buffer.from(REG_TH, "hex"), Buffer.from(NAME, "hex")]).toString("hex");
const burnGated = ccc.Script.from({ codeHash: BG.burn_gated_code_hash, hashType: "data1", args });
const RECEIPT_CAP = 200n * CKB;
const { client, signer } = signerOf(); const lock = await myLock(signer);
const ps = await plainCells(client, lock); const fund = ps.find((x) => BigInt(x.cellOutput.capacity) >= RECEIPT_CAP + FEE + 62n * CKB);
if (!fund) throw new Error("no plain cell big enough");
const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: fund.outPoint, since: 0n }],
  outputs: [{ lock: burnGated, capacity: RECEIPT_CAP }, { lock, capacity: BigInt(fund.cellOutput.capacity) - RECEIPT_CAP - FEE }],
  outputsData: ["0x", "0x"],
});
tx.cellDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);
const h = await client.sendTransaction(await signer.signTransaction(tx)); await wait(client, h);
fs.writeFileSync(path.join(HERE, "bg_receipt.json"), JSON.stringify({ txHash: h, index: 0, capacity: RECEIPT_CAP.toString(), lockArgs: args, burnGatedCodeHash: BG.burn_gated_code_hash }, null, 2));
console.log("RECEIPT LOCKED under burn_gated:", h + ":0 |", (Number(RECEIPT_CAP)/1e8), "CKB | args", args.slice(0, 30) + "...");
process.exit(0);
