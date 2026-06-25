// deploy_bridge.mjs - redeploy the bridge_lock_v1 code cell (the forward CKB->Cardano lock) after the old one
// (0xd02058c5) was reclaimed. Deploys the STRIPPED binary (~13.7k CKB) from a plain cell, then rewrites
// bridge_lock_live.json with the new code hash + dep so the dApp backend serves a resolvable cellDep.
// NOTE: the new code hash differs from the old pinned 0x1c2589e8, so the forward-leg setup + Cardano mint must
// be redeployed against THIS hash (FR3/FR4) for a proof to verify.
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REL = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release");
const CKB = 100000000n, FEE = 1000000n;
const { client, signer } = signerOf();
const lock = await myLock(signer);

async function pickFunding(minCap) {
  let best = null;
  for await (const c of client.findCells({ script: lock, scriptType: "lock", scriptSearchMode: "exact", filter: { outputDataLenRange: ["0x0", "0x1"] } }, "asc", 200)) {
    const cap = BigInt(c.cellOutput.capacity);
    if (cap >= minCap && (!best || cap < BigInt(best.cellOutput.capacity))) best = c;
  }
  if (!best) throw new Error(`no plain cell >= ${minCap / CKB} CKB`);
  return best;
}

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(path.join(REL, "bridge_lock_v1.strip"))));
const codeHash = ccc.hashCkb(data);
const dataLen = BigInt((data.length - 2) / 2);
const codeCap = (8n + 53n + dataLen) * CKB;
const fund = await pickFunding(codeCap + FEE + 100n * CKB);
const secpDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);

const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: fund.outPoint, since: 0n }],
  outputs: [{ lock, capacity: codeCap }, { lock, capacity: BigInt(fund.cellOutput.capacity) - codeCap - FEE }],
  outputsData: [data, "0x"], cellDeps: secpDeps,
});
const h = await client.sendTransaction(await signer.signTransaction(tx));
await wait(client, h);
console.log("bridge_lock_v1 deployed:", h, "| codeHash", codeHash, "| size", Number(dataLen), "B");

const blPath = path.join(HERE, "bridge_lock_live.json");
const bl = fs.existsSync(blPath) ? JSON.parse(fs.readFileSync(blPath, "utf8")) : {};
bl.bridge_code_hash = codeHash;
bl.bridge_code_tx = h;
fs.writeFileSync(blPath, JSON.stringify(bl, null, 2));
console.log("updated bridge_lock_live.json: bridge_code_hash", codeHash, "bridge_code_tx", h);
