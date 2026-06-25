// reclaim.mjs - consolidate every NON-protected, lock-only cell under our lock into one plain cell, recovering
// capacity orphaned by failed/partial deploys (stray code cells + recycled witness cells). NEVER touches the
// live code cells (deployed.json) or the live checkpoints (chain_state / checkpoint_v2) - those are protected,
// and typed cells (checkpoints) are skipped outright. Dry by default; --live broadcasts.
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";
import fs from "node:fs";

const dep = JSON.parse(fs.readFileSync(new URL("./deployed.json", import.meta.url), "utf8"));
const cs = JSON.parse(fs.readFileSync(new URL("./chain_state.json", import.meta.url), "utf8"));
const ck2 = JSON.parse(fs.readFileSync(new URL("./checkpoint_v2.json", import.meta.url), "utf8"));
const reg = JSON.parse(fs.readFileSync(new URL("./v2_registry.json", import.meta.url), "utf8"));
let xm = null; try { xm = JSON.parse(fs.readFileSync(new URL("./xada_mint_deploy.json", import.meta.url), "utf8")); } catch {}
let xo = null; try { xo = JSON.parse(fs.readFileSync(new URL("./xada_owner_deploy.json", import.meta.url), "utf8")); } catch {}
const PROT = new Set([
  `${dep.cv_advance.txHash}:0`, `${dep.cv_deploy.txHash}:0`, `${dep.bound_asset.txHash}:0`,
  `${dep.cv_deploy_v2.txHash}:0`, `${cs.ckpt.outpoint.txHash}:${cs.ckpt.outpoint.index}`,
  `${ck2.checkpoint.txHash}:${ck2.checkpoint.index}`,
  ...(ck2.witnessCell ? [`${ck2.witnessCell.txHash}:${ck2.witnessCell.index}`] : []),
  `${reg.registryCode.txHash}:0`, `${reg.registryGenesis.txHash}:${reg.registryGenesis.index}`,
  `${reg.boundCode.txHash}:0`,   // v2 bound_asset_v2 code cell - lock-only (no type), MUST be protected
  ...(xm && !process.env.RECLAIM_OLD_XADA_MINT ? [`${xm.xadaMintCode.txHash}:0`] : []),   // χADA (old type-script) mint code - protected unless explicitly reclaiming the obsolete one
  ...(xo ? [`${xo.ownerCode.txHash}:0`] : []),       // χADA xUDT owner-lock code cell - MUST be protected
]);
const FEE = 2_000_000n; // 0.02 CKB - well above min, under ccc's max-fee-rate for this small tx (~530 bytes)

const { client, signer } = signerOf();
const lock = await myLock(signer);
const inputs = []; let sum = 0n;
for await (const c of client.findCellsByLock(lock, null, true)) {
  const op = `${c.outPoint.txHash}:${Number(c.outPoint.index)}`;
  if (c.cellOutput.type != null) continue; // typed cells (checkpoints) - never spend here
  if (PROT.has(op)) continue;              // live code cells - keep
  inputs.push(ccc.CellInput.from({ previousOutput: c.outPoint, since: 0n }));
  sum += BigInt(c.cellOutput.capacity);
}
console.log("consolidating", inputs.length, "cells ->", (Number(sum - FEE) / 1e8).toLocaleString(), "CKB");
if (!process.argv.includes("--live")) { console.log("DRY. Pass --live to broadcast."); process.exit(0); }

const tx = ccc.Transaction.from({ inputs, outputs: [{ lock, capacity: sum - FEE }], outputsData: ["0x"] });
const h = await signer.sendTransaction(tx);
await client.waitTransaction(h, 1, { timeout: 180000 });
console.log("consolidated into one plain cell:", h);
process.exit(0);
