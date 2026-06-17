// Step 1: reclaim old M1 cv_deploy (0xdfc0aad0) + 2 plain cells -> deploy the FIXED cv_advance code cell.
// One explicit-input tx (no completeInputsByCapacity, so it can NEVER grab another code cell). Writes cv_pin_state.json.
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/light-client-cell/cert-verify/adversarial/bin/cv_advance_pinned.bin");
const D = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const PIN = JSON.parse(fs.readFileSync(path.join(HERE, "cv_pin_state.json"), "utf8"));
const CKB = 100000000n, FEE = 1000000n; // 0.01 CKB
const to = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error("timeout")), ms))]);
const { client, signer } = signerOf();
const lock = await myLock(signer);

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const codeHash = ccc.hashCkb(data);
if (codeHash !== PIN.new_cv_advance_codeHash) throw new Error(`codeHash ${codeHash} != staged ${PIN.new_cv_advance_codeHash}`);
const dataLen = BigInt((data.length - 2) / 2);
const cvCap = (8n + 53n + dataLen) * CKB;

// explicit inputs: M1 code cell + the two known plain cells (verified live in preflight)
const inOps = [
  { txHash: D.cv_deploy.txHash, index: 0 },                                                       // M1 cv_deploy 104,285
  { txHash: "0x56978f55bc5adc2ef3b22a9f758fa3f06c0c381bbbcdfe02ab2c598e5ecab398", index: 1 },     // plain 44,594.99
  { txHash: "0xe86b1ceffa985264defbd099ce76af43c187c7ea5448eb919206094324314318", index: 1 },     // plain 5,169.72
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
console.log(`inputs total ${(Number(sum)/1e8).toLocaleString()} CKB | cv_advance cell ${(Number(cvCap)/1e8).toLocaleString()} | change ${(Number(change)/1e8).toLocaleString()}`);

const tx = ccc.Transaction.from({
  inputs: inOps.map((op) => ({ previousOutput: op, since: 0n })),
  outputs: [{ lock }, { lock }],
  outputsData: [data, "0x"],
});
tx.outputs[0].capacity = cvCap;
tx.outputs[1].capacity = change;
const secpDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);
tx.cellDeps = secpDeps;

if (!process.argv.includes("--live")) { console.log("DRY. pass --live"); process.exit(0); }
const h = await client.sendTransaction(await signer.signTransaction(tx));
console.log("cv_advance deploy+reclaim tx:", h, "| codeHash", codeHash);
await to(client.waitTransaction(h, 1, { timeout: 180000 }), 185000);
PIN.cv_advance_deploy = { txHash: h, index: 0, codeHash, size: Number(dataLen), reclaimed_M1: D.cv_deploy.txHash };
fs.writeFileSync(path.join(HERE, "cv_pin_state.json"), JSON.stringify(PIN, null, 2));
console.log("CONFIRMED. wrote cv_pin_state.json. new cv_advance codeHash:", codeHash, "ADV_TYPEHASH:", PIN.new_ADV_TYPEHASH);
process.exit(0);
