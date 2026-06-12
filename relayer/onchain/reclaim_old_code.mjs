// reclaim_old_code.mjs — reclaim the capacity of the SUPERSEDED first-χOSMO-mint code cells (the bespoke
// catom_mint + its cosmos_nullifier_registry), freeing it back to a plain spendable cell. The bespoke χOSMO
// (token 0xf98bad86, a non-displayable custom-typed cell) is superseded by the xUDT χOSMO; its code cell is no
// longer needed. Identified by data hash so we never touch an unrelated cell.
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const TARGETS = new Set([
  "0x76d68a0209aec1a0fae41b7ea158af5f40cb5a05cac09763dd4a4691dba1a994", // bespoke catom_mint code
  "0xfbd01737e9c2becbf2edef927fda1688c2a7bb9abb5e5ff67eb94f4704607752", // its cosmos_nullifier_registry code
]);

const { client, signer } = signerOf();
const lock = await myLock(signer);

// withData=false keeps the iteration light (the relayer holds many big code cells); pre-filter by capacity
// (these two are 27k–73k CKB), then load + hash only the few candidates to confirm identity.
const candidates = [];
for await (const c of client.findCellsByLock(lock, null, false)) {
  if (c.cellOutput.type != null) continue;
  const cap = BigInt(c.cellOutput.capacity);
  if (cap >= 20000_00000000n && cap <= 80000_00000000n) candidates.push(c.outPoint);
}
const found = [];
for (const op of candidates) {
  const cell = await client.getCellLive(op, true);
  if (cell && cell.outputData && cell.outputData !== "0x" && TARGETS.has(ccc.hashCkb(cell.outputData))) found.push(cell);
}
if (!found.length) { console.log("no superseded code cells found (already reclaimed?)"); process.exit(0); }
let sum = 0n; for (const c of found) sum += BigInt(c.cellOutput.capacity);
console.log("reclaiming", found.length, "code cells =", sum / 100000000n, "CKB");

const FEE = 1_00000000n;
const tx = ccc.Transaction.from({
  inputs: found.map((c) => ({ previousOutput: c.outPoint, since: 0n })),
  outputs: [{ lock, capacity: sum - FEE }],
  outputsData: ["0x"],
});
const h = await client.sendTransaction(await signer.signTransaction(tx));
await wait(client, h);
console.log("reclaimed ->", h, "| freed", (sum - FEE) / 100000000n, "CKB to a plain cell");
