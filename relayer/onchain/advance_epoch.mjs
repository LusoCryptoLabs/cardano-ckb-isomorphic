// advance_epoch.mjs - advance the on-chain AVK light-client checkpoint by one Mithril epoch (reads advance.json
// from gen_advance.py). Generalized from advance_1332.mjs. Spends ck[from] -> ck[to]; cv_advance verifies the
// BLS-STM cert + AVK transition in CKB-VM. Keyless authority; our key only funds + carries state.
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const J = (f) => JSON.parse(fs.readFileSync(path.join(HERE, f), "utf8"));
const D = J("deployed.json"), CS = J("chain_state.json"), AV = J("advance.json");
const FEE = 2_000_000n;
const minCap = (hex, t) => BigInt((8 + 53 + (t ? 33 : 0) + (hex.length - 2) / 2 + 1) * 1e8);
const witHex = "0x" + fs.readFileSync(path.join(HERE, "chain", "witnesses", AV.witFile)).toString("hex");

const { client, signer } = signerOf(); const lock = await myLock(signer);
const cvAdv = ccc.Script.from({ codeHash: D.cv_advance.codeHash, hashType: "data1", args: "0x" });
const advDep = { outPoint: { txHash: D.cv_advance.txHash, index: 0 }, depType: "code" };

const ckptOp = { txHash: CS.ckpt.outpoint.txHash, index: Number(CS.ckpt.outpoint.index) };
const ckptCell = await client.getCellLive(ckptOp, true);
if (!ckptCell) throw new Error("AVK checkpoint cell not live: " + ckptOp.txHash + ":" + ckptOp.index);
if (ckptCell.outputData.toLowerCase() !== AV.ckFrom.toLowerCase())
  throw new Error(`ckFrom drift: live ${ckptCell.outputData} != derived ${AV.ckFrom}`);
const ckptCap = BigInt(ckptCell.cellOutput.capacity);
console.log(`ck[${AV.fromEpoch}] on-chain == derived OK | roll ${AV.fromEpoch} -> ${AV.toEpoch}`);

const pick = async (need) => { const c = (await plainCells(client, lock)).find((x) => BigInt(x.cellOutput.capacity) >= need); if (!c) throw new Error("no plain >= " + need); return c; };

const wcCap = minCap(witHex, false) + BigInt(1e8);
const f1 = await pick(wcCap + FEE + BigInt(61e8));
const wtx = ccc.Transaction.from({ inputs: [{ previousOutput: f1.outPoint, since: 0n }], outputs: [{ lock, capacity: wcCap }, { lock, capacity: BigInt(f1.cellOutput.capacity) - wcCap - FEE }], outputsData: [witHex, "0x"] });
const wh = await client.sendTransaction(await signer.signTransaction(wtx)); await wait(client, wh);

const f2 = await pick(FEE + BigInt(61e8));
const atx = ccc.Transaction.from({
  inputs: [{ previousOutput: ckptOp, since: 0n }, { previousOutput: f2.outPoint, since: 0n }],
  outputs: [{ lock, type: cvAdv, capacity: ckptCap }, { lock, capacity: BigInt(f2.cellOutput.capacity) - FEE }],
  outputsData: [AV.ckTo, "0x"],
  cellDeps: [advDep, { outPoint: { txHash: wh, index: 0 }, depType: "code" }],
});
atx.cellDeps.push(...(await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep));
const ah = await client.sendTransaction(await signer.signTransaction(atx)); await wait(client, ah);
CS.ckpt = { epoch: String(AV.toEpoch), outpoint: { txHash: ah, index: 0 } };
fs.writeFileSync(path.join(HERE, "chain_state.json"), JSON.stringify(CS, null, 2));
console.log(`*** AVK CHECKPOINT ADVANCED ${AV.fromEpoch} -> ${AV.toEpoch}: ${ah} ***`);
process.exit(0);
