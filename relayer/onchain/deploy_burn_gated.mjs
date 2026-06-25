// deploy_burn_gated.mjs - BG2: deploy the burn_gated_unlock_v2 code cell (the Mithril-gated release lock that
// closes the receipt-reclaim hole: a forward-locked CKB receipt under this lock releases ONLY on a certified
// chiCKB burn of the bound amount). Publishes the stripped, atomic-free binary; writes burn_gated_live.json.
// NOTE: deploying the CODE is safe. A LIVE forward lock UNDER it stays gated on the production (STM-pinned)
// Mithril checkpoint (audit-deferred) -- this only makes the contract available + the relayer path ready.
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REL = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release");
const CKB = 100000000n, FEE = 1000000n;
const { client, signer } = signerOf();
const lock = await myLock(signer);

async function pickFunding(minCap) {
  let best = null, total = 0n, n = 0;
  for await (const c of client.findCells({ script: lock, scriptType: "lock", scriptSearchMode: "exact", filter: { outputDataLenRange: ["0x0", "0x1"] } }, "asc", 400)) {
    const cap = BigInt(c.cellOutput.capacity); total += cap; n++;
    if (cap >= minCap && (!best || cap < BigInt(best.cellOutput.capacity))) best = c;
  }
  if (!best) throw new Error(`no single plain cell >= ${minCap / CKB} CKB (have ${n} plain cells, ${total / CKB} CKB total; consolidate first)`);
  return best;
}

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(path.join(REL, "burn_gated_unlock_v2.strip"))));
const codeHash = ccc.hashCkb(data);
const dataLen = BigInt((data.length - 2) / 2);
const codeCap = (8n + 53n + dataLen) * CKB;
console.log(`burn_gated_unlock_v2: ${Number(dataLen)} B -> code cell needs ~${Number(codeCap / CKB)} CKB`);
const fund = await pickFunding(codeCap + FEE + 100n * CKB);
const secpDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);

const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: fund.outPoint, since: 0n }],
  outputs: [{ lock, capacity: codeCap }, { lock, capacity: BigInt(fund.cellOutput.capacity) - codeCap - FEE }],
  outputsData: [data, "0x"], cellDeps: secpDeps,
});
const h = await client.sendTransaction(await signer.signTransaction(tx));
await wait(client, h);
console.log("burn_gated_unlock_v2 deployed:", h, "| codeHash", codeHash, "| size", Number(dataLen), "B");

const out = path.join(HERE, "burn_gated_live.json");
fs.writeFileSync(out, JSON.stringify({ burn_gated_code_hash: codeHash, burn_gated_code_tx: h, size: Number(dataLen),
  lckp_type_hash: "0xa055798e911a4f7ed074d5e1ee6273683e9a446c70d3e22adab680d70eea5b74",
  registry_type_hash: "0xdc18fd562bca1834536c926ce8c9d94f608318c3a79a43959c0c46a84265a24e" }, null, 2));
console.log("wrote burn_gated_live.json");
