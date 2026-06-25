// Step 2: reclaim old cv_advance (0xe877a802) + step-1 change -> deploy the re-baked cv_deploy code cell.
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/light-client-cell/cert-verify/adversarial/bin/cv_deploy_pinned.bin");
const D = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const PIN = JSON.parse(fs.readFileSync(path.join(HERE, "cv_pin_state.json"), "utf8"));
const CKB = 100000000n, FEE = 1000000n;
const to = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error("timeout")), ms))]);
const { client, signer } = signerOf();
const lock = await myLock(signer);

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const codeHash = ccc.hashCkb(data);
const lckpTh = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" }).hash();
const dataLen = BigInt((data.length - 2) / 2);
const cvCap = (8n + 53n + dataLen) * CKB;
console.log("new cv_deploy codeHash:", codeHash);
console.log("new CHIRAL_LCKP_TH    :", lckpTh, " (-> bake into bound_asset_v2 in step 3)");

const inOps = [
  { txHash: D.cv_advance.txHash, index: 0 },                              // old cv_advance 0xe877a802 (105,013)
  { txHash: PIN.cv_advance_deploy.txHash, index: 1 },                     // step-1 change (37,948.705)
];
let sum = 0n;
for (const op of inOps) {
  const c = await to(client.getCellLive(op, false), 20000);
  if (!c) throw new Error(`input ${op.txHash}:${op.index} not live`);
  if (c.cellOutput.lock.hash() !== lock.hash()) throw new Error(`input ${op.txHash}:${op.index} not ours`);
  sum += BigInt(c.cellOutput.capacity);
}
const change = sum - cvCap - FEE;
if (change < 62n * CKB) throw new Error(`change ${change} below min`);
console.log(`inputs ${(Number(sum)/1e8).toLocaleString()} | cv_deploy cell ${(Number(cvCap)/1e8).toLocaleString()} | change ${(Number(change)/1e8).toLocaleString()}`);

const tx = ccc.Transaction.from({ inputs: inOps.map((op) => ({ previousOutput: op, since: 0n })), outputs: [{ lock }, { lock }], outputsData: [data, "0x"] });
tx.outputs[0].capacity = cvCap; tx.outputs[1].capacity = change;
tx.cellDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);

if (!process.argv.includes("--live")) { console.log("DRY"); process.exit(0); }
const h = await client.sendTransaction(await signer.signTransaction(tx));
console.log("cv_deploy deploy+reclaim tx:", h);
await to(client.waitTransaction(h, 1, { timeout: 180000 }), 185000);
PIN.new_cv_deploy_codeHash = codeHash; PIN.new_CHIRAL_LCKP_TH = lckpTh;
PIN.cv_deploy_deploy = { txHash: h, index: 0, codeHash, size: Number(dataLen), reclaimed_old_cv_advance: D.cv_advance.txHash };
fs.writeFileSync(path.join(HERE, "cv_pin_state.json"), JSON.stringify(PIN, null, 2));
console.log("CONFIRMED. cv_deploy live. CHIRAL_LCKP_TH:", lckpTh);
process.exit(0);
