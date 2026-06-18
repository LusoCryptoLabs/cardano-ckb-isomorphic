// Publish a fresh LCKP at the burn's certified root, under the NEW (Gate-1) cv_deploy + new AVK (epoch 1331).
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const D = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const CS = JSON.parse(fs.readFileSync(path.join(HERE, "chain_state.json"), "utf8"));
const CT = JSON.parse(fs.readFileSync(path.join(HERE, "bg_ctwit.json"), "utf8"));
const FEE = 2_000_000n;
const cvDep = ccc.Script.from({ codeHash: D.cv_deploy.codeHash, hashType: "data1", args: "0x" });
const depDep = { outPoint: { txHash: D.cv_deploy.txHash, index: 0 }, depType: "code" };
const minCap = (hex, t) => BigInt((8 + 53 + (t ? 33 : 0) + (hex.length - 2) / 2 + 1) * 1e8);
const u64le = (v) => Array.from({ length: 8 }, (_, k) => Number((BigInt(v) >> BigInt(8 * k)) & 0xffn).toString(16).padStart(2, "0")).join("");
const { client, signer } = signerOf(); const lock = await myLock(signer);
console.log("LCKP type hash:", cvDep.hash(), "(want 0xcae43266...)");
async function pickPlain(need) { const ps = await plainCells(client, lock); const c = ps.find((x) => BigInt(x.cellOutput.capacity) >= need); if (!c) throw new Error("no plain >= " + need); return c; }
// 1) witness cell carrying the MWIT cert
const wcCap = minCap(CT.witHex, false) + BigInt(1e8);
const f1 = await pickPlain(wcCap + FEE + BigInt(61e8));
const wtx = ccc.Transaction.from({ inputs: [{ previousOutput: f1.outPoint, since: 0n }], outputs: [{ lock, capacity: wcCap }, { lock, capacity: BigInt(f1.cellOutput.capacity) - wcCap - FEE }], outputsData: [CT.witHex, "0x"] });
const wh = await client.sendTransaction(await signer.signTransaction(wtx)); await wait(client, wh);
console.log("witness cell:", wh);
// 2) LCKP tx: publish LCKP||root||height under cv_deploy, reading the AVK checkpoint + witness
const ckptData = "0x4c434b50" + CT.root.replace(/^0x/, "") + u64le(CT.height);
if ((ckptData.length - 2) / 2 !== 44) throw new Error("not 44 bytes: " + ((ckptData.length - 2) / 2));
const ckCap = minCap(ckptData, true) + BigInt(50e8);
const f2 = await pickPlain(ckCap + FEE + BigInt(61e8));
const dtx = ccc.Transaction.from({
  inputs: [{ previousOutput: f2.outPoint, since: 0n }],
  outputs: [{ lock, type: cvDep, capacity: ckCap }, { lock, capacity: BigInt(f2.cellOutput.capacity) - ckCap - FEE }],
  outputsData: [ckptData, "0x"],
  cellDeps: [depDep, { outPoint: { txHash: wh, index: 0 }, depType: "code" }, { outPoint: CS.ckpt.outpoint, depType: "code" }],
});
const dh = await client.sendTransaction(await signer.signTransaction(dtx)); await wait(client, dh);
const res = { checkpoint: { txHash: dh, index: 0 }, root: CT.root, height: String(CT.height), data: ckptData, witnessCell: { txHash: wh, index: 0 }, lckpTypeHash: cvDep.hash() };
fs.writeFileSync(path.join(HERE, "checkpoint_v2.json"), JSON.stringify(res, null, 2));
console.log("LCKP REFRESHED:", dh, "| root", CT.root.slice(0, 18), "| height", CT.height);
process.exit(0);
