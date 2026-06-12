// reclaim_targeted.mjs — reclaim the superseded first-χOSMO-mint code cells WITHOUT a broad cell scan (which
// chokes on the RPC 10MB cap on this loaded lock). We read the exact code-cell outpoints from a known tx's
// cell_deps, resolve each, confirm it is one of the superseded binaries by data hash, and spend them back to a
// plain cell. The secp dep is added explicitly so signing never triggers a scan.
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const SRC_TX = process.env.SRC_TX || "0x8fbe7459e523c6c4f47a52c7198df9d9d1db3e8d827b0d3ed879ff781091b23c"; // first bespoke χOSMO mint
const TARGETS = new Set([
  "0x76d68a0209aec1a0fae41b7ea158af5f40cb5a05cac09763dd4a4691dba1a994", // bespoke catom_mint code
  "0xfbd01737e9c2becbf2edef927fda1688c2a7bb9abb5e5ff67eb94f4704607752", // its cosmos_nullifier_registry code
]);

const { client, signer } = signerOf();
const lock = await myLock(signer);
const myHash = lock.hash();

const tx = await client.getTransaction(SRC_TX);
const deps = tx.transaction.cellDeps;
console.log(`${SRC_TX.slice(0, 12)} has ${deps.length} cell_deps; checking which are our superseded code cells...`);

const found = [];
for (const d of deps) {
  const cell = await client.getCellLive(d.outPoint, true);
  if (!cell) continue;
  if (ccc.Script.from(cell.cellOutput.lock).hash() !== myHash) continue;  // only our own cells
  if (!cell.outputData || cell.outputData === "0x") continue;
  if (TARGETS.has(ccc.hashCkb(cell.outputData))) found.push(cell);
}
if (!found.length) { console.log("nothing to reclaim (already done?)"); process.exit(0); }
let sum = 0n; for (const c of found) sum += BigInt(c.cellOutput.capacity);
console.log("reclaiming", found.length, "code cells =", sum / 100000000n, "CKB");

const secp = await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160);
const rtx = ccc.Transaction.from({
  inputs: found.map((c) => ({ previousOutput: c.outPoint, since: 0n })),
  outputs: [], outputsData: [],
  cellDeps: secp.cellDeps.map((cd) => cd.cellDep),
});
// let CCC add the change output + fee the same way the (working) deploys do; inputs already cover it, so no
// capacity-completion scan is needed.
await rtx.completeFeeBy(signer, 1000);
const h = await client.sendTransaction(await signer.signTransaction(rtx));
await wait(client, h);
console.log("reclaimed ->", h, "| freed", (sum - FEE) / 100000000n, "CKB to a plain cell");
