// Step 3: reclaim old bound_asset (0xca24efc3) + step-2 change -> deploy the re-baked bound_asset_v2 (new LCKP_TYPE_HASH).
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2.pinned");
const D = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const PIN = JSON.parse(fs.readFileSync(path.join(HERE, "cv_pin_state.json"), "utf8"));
const CKB = 100000000n, FEE = 1000000n;
const to = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error("timeout")), ms))]);
const { client, signer } = signerOf();
const lock = await myLock(signer);
const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const codeHash = ccc.hashCkb(data);
const dataLen = BigInt((data.length - 2) / 2);
const cvCap = (8n + 53n + dataLen) * CKB;
console.log("new bound_asset_v2 codeHash:", codeHash, "| LCKP baked:", PIN.new_CHIRAL_LCKP_TH);
const inOps = [
  { txHash: D.bound_asset.txHash, index: 0 },          // old bound_asset 0xca24efc3 (57,869) - superseded by live v2 0x4cc7ae86
  { txHash: PIN.cv_deploy_deploy.txHash, index: 1 },   // step-2 change (27,620.7)
];
let sum = 0n;
for (const op of inOps) {
  const c = await to(client.getCellLive(op, false), 20000);
  if (!c) throw new Error(`input ${op.txHash}:${op.index} not live`);
  if (c.cellOutput.lock.hash() !== lock.hash()) throw new Error(`input not ours`);
  sum += BigInt(c.cellOutput.capacity);
}
const change = sum - cvCap - FEE;
if (change < 62n * CKB) throw new Error(`change ${change} below min`);
console.log(`inputs ${(Number(sum)/1e8).toLocaleString()} | bound_asset_v2 cell ${(Number(cvCap)/1e8).toLocaleString()} | change ${(Number(change)/1e8).toLocaleString()}`);
const tx = ccc.Transaction.from({ inputs: inOps.map((op) => ({ previousOutput: op, since: 0n })), outputs: [{ lock }, { lock }], outputsData: [data, "0x"] });
tx.outputs[0].capacity = cvCap; tx.outputs[1].capacity = change;
tx.cellDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);
if (!process.argv.includes("--live")) { console.log("DRY"); process.exit(0); }
const h = await client.sendTransaction(await signer.signTransaction(tx));
console.log("bound_asset_v2 deploy+reclaim tx:", h);
await to(client.waitTransaction(h, 1, { timeout: 180000 }), 185000);
PIN.new_bound_asset_v2_codeHash = codeHash;
PIN.bound_asset_v2_deploy = { txHash: h, index: 0, codeHash, size: Number(dataLen), reclaimed_old_bound_asset: D.bound_asset.txHash };
fs.writeFileSync(path.join(HERE, "cv_pin_state.json"), JSON.stringify(PIN, null, 2));
console.log("CONFIRMED. all 3 new code cells live. new bound_asset_v2:", codeHash);
process.exit(0);
