// Step 5 reclaim: spend the now-superseded pre-fix code cells (old cv_deploy_v2 0x75b288f3 + old leap
// bound_asset 0x4cc7ae86) into one plain cell. Decommissions the old verifier/leap lineage + recovers capacity.
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const D = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const reg = JSON.parse(fs.readFileSync(path.join(HERE, "v2_registry.json"), "utf8"));
const CKB = 100000000n, FEE = 1000000n;
const to = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error("timeout")), ms))]);
const { client, signer } = signerOf();
const lock = await myLock(signer);
const cands = [
  { name: "old cv_deploy_v2 (0x75b288f3)", op: { txHash: D.cv_deploy_v2_superseded.txHash, index: 0 } },
  { name: "old bound_asset (0x4cc7ae86)",  op: { txHash: reg.boundCode.txHash, index: 0 } },
];
const inputs = []; let sum = 0n;
for (const c of cands) {
  try {
    const cell = await to(client.getCellLive(c.op, false), 20000);
    if (!cell) { console.log(`  SKIP ${c.name}: spent/absent`); continue; }
    if (cell.cellOutput.lock.hash() !== lock.hash()) { console.log(`  SKIP ${c.name}: not ours`); continue; }
    if (cell.cellOutput.type != null) { console.log(`  SKIP ${c.name}: has type (not a code cell)`); continue; }
    inputs.push({ previousOutput: c.op, since: 0n }); sum += BigInt(cell.cellOutput.capacity);
    console.log(`  reclaim ${c.name}: ${(Number(BigInt(cell.cellOutput.capacity))/1e8).toLocaleString()} CKB`);
  } catch (e) { console.log(`  ${c.name}: ${String(e).slice(0,25)}`); }
}
if (!inputs.length) { console.log("nothing to reclaim"); process.exit(0); }
const out = sum - FEE;
console.log(`reclaiming ${inputs.length} cells -> ${(Number(out)/1e8).toLocaleString()} CKB plain`);
if (!process.argv.includes("--live")) { console.log("DRY"); process.exit(0); }
const tx = ccc.Transaction.from({ inputs, outputs: [{ lock, capacity: out }], outputsData: ["0x"] });
tx.cellDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);
const h = await client.sendTransaction(await signer.signTransaction(tx));
console.log("reclaim tx:", h);
await to(client.waitTransaction(h, 1, { timeout: 180000 }), 185000);
console.log("CONFIRMED. old lineage decommissioned + capacity recovered:", h);
process.exit(0);
