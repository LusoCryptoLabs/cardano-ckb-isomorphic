// fund_assess.mjs - read-only: what can fund the STM-pin redeploy? Sums plain-spendable (empty-data) cells vs
// data-bearing (code) cells under the relayer lock, and lists the largest reclaimable code cells. Uses the raw
// indexer with small pages to avoid the public RPC's 10MB get_cells cap on this heavily-loaded lock.
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";
const CKB = 100000000n;
const { client, signer } = signerOf();
const lock = await myLock(signer);

let plainSum = 0n, plainCount = 0, dataSum = 0n, dataCount = 0;
const big = [];
for await (const c of client.findCells({ script: lock, scriptType: "lock", scriptSearchMode: "exact" }, "asc", 50)) {
  const cap = BigInt(c.cellOutput.capacity);
  const dataLen = (c.outputData.length - 2) / 2;
  const hasType = c.cellOutput.type != null;
  if (dataLen === 0 && !hasType) { plainSum += cap; plainCount++; }
  else { dataSum += cap; dataCount++; if (dataLen > 1000) big.push({ op: `${c.outPoint.txHash.slice(0,18)}…:${Number(c.outPoint.index)}`, cap: Number(cap / CKB), dataLen, type: hasType ? c.cellOutput.type.codeHash.slice(0,14) : null }); }
}
big.sort((a, b) => b.cap - a.cap);
console.log("relayer lock:", lock.hash());
console.log(`plain-spendable : ${(plainSum/CKB).toString().padStart(8)} CKB  (${plainCount} empty-data cells)`);
console.log(`code/data cells : ${(dataSum/CKB).toString().padStart(8)} CKB  (${dataCount} cells)`);
console.log(`TOTAL           : ${((plainSum+dataSum)/CKB).toString().padStart(8)} CKB`);
console.log(`\nlargest reclaimable code cells (data > 1000 B):`);
for (const b of big.slice(0, 18)) console.log(`  ${b.cap.toString().padStart(7)} CKB  ${b.dataLen.toString().padStart(7)} B  ${b.op}  ${b.type ? 'type='+b.type : ''}`);
