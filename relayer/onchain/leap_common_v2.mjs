// leap_common_v2.mjs - shared helpers for the v2 ownership-toggle LEAP builders (S4 leap-to-cardano,
// S5 leap-to-ckb). Factored out of the proven genesis builder (boundasset_v2.mjs) WITHOUT touching it:
// the bound_asset_v2 type/dep, the v2 cell-data encoders, the MKMapProof witness + 44-byte checkpoint
// alignment loop, and the faithful ckb-debugger ReprMockTransaction dumper.
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { refreshCheckpointV2 } from "./refresh_checkpoint_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RELAYER = path.resolve(HERE, "..");
export const REG = JSON.parse(fs.readFileSync(path.join(HERE, "v2_registry.json"), "utf8"));
export const SEAL = JSON.parse(fs.readFileSync(path.resolve(RELAYER, "../cardano/deployed/cardano/preview/seal-instance-ours.json"), "utf8"));
export const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
export const FEE = 2_000_000n;

// bound_asset_v2 instance: args = seal_policy(28) ‖ lock_addr(29), code = the deployed V2_BOUND_CODE_HASH.
export const SEAL_POLICY = SEAL.seal_policy;
export const LOCK_ADDR = "7047c5d94c9338243bf0624b4d3b25840c0f913f2c9b92387f66970263";
export const baArgs = "0x" + SEAL_POLICY + LOCK_ADDR;
export const baScript = ccc.Script.from({ codeHash: REG.boundCode.codeHash, hashType: "data1", args: baArgs });
export const baDep = { outPoint: { txHash: REG.boundCode.txHash, index: 0 }, depType: "code" };
export const regCodeDep = { outPoint: { txHash: REG.registryCode.txHash, index: 0 }, depType: "code" };

// IMMUTABLE code cells we must never consume as funding (verifier/registry binaries + their lineage). NOT
// the registry genesis SINGLETON - that's a STATE cell S5 deliberately spends+recreates to insert the
// nullifier (and pickPlain never selects it anyway: it is typed + carries data).
export const PROTECTED = new Set([
  `${DEPLOYED.cv_advance.txHash}:0`, `${DEPLOYED.cv_deploy.txHash}:0`, `${DEPLOYED.bound_asset.txHash}:0`,
  `${DEPLOYED.cv_deploy_v2.txHash}:0`, `${REG.boundCode.txHash}:0`, `${REG.registryCode.txHash}:0`,
]);

export const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b.toString("hex"); };
const strip = (h) => (h || "").replace(/^0x/, "");

// v2 cell encoders (layout: version(0x02) ‖ tag ‖ seal_txid(32) ‖ seal_idx(4 LE) ‖ lock_slot(32) ‖ state).
export function ckbOwnedData(sealTxid, idx, lockSlot, stateHex) {
  return "0x02" + "02" + strip(sealTxid) + u32le(idx) + strip(lockSlot) + strip(stateHex);
}
export function cardanoBoundData(sealTxid, idx, stateHex) {
  return "0x02" + "01" + strip(sealTxid) + u32le(idx) + "00".repeat(32) + strip(stateHex);  // CARDANO_BOUND, lock slot ZEROED
}

// MKMapProof witness for a certified Cardano tx (Windows python: relay + transcode, no pycardano).
export function getWitness(txid) {
  const out = execSync(`python produce_witness.py ${txid}`, { cwd: RELAYER, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out.trim());
}

// Refresh the 44-byte checkpoint AND fetch the MKMapProof for `txid`, aligning their roots (retry on
// Mithril snapshot drift). Returns { ckpt, wit, ckptDep } or throws if the tx isn't certified yet.
export async function alignCheckpointAndWitness(txid) {
  let ckpt, wit;
  for (let attempt = 0; attempt < 5; attempt++) {
    ckpt = await refreshCheckpointV2();
    wit = getWitness(txid);
    if (wit.status !== "ready") throw new Error("witness not ready (tx not Mithril-certified yet): " + JSON.stringify(wit));
    if (wit.root === ckpt.root) break;
    console.log(`  root drift (wit ${wit.root.slice(0, 14)} vs ckpt ${ckpt.root.slice(0, 14)}), retrying...`);
    ckpt = null;
  }
  if (!ckpt || wit.root !== ckpt.root) throw new Error("could not align witness root with checkpoint");
  console.log(`checkpoint ${ckpt.checkpoint.txHash.slice(0, 14)} root ${ckpt.root.slice(0, 14)}.. | witness ${(wit.witness.length - 2) / 2} bytes`);
  return { ckpt, wit, ckptDep: { outPoint: ckpt.checkpoint, depType: "code" } };
}

export async function plainCells(client, lock) {
  const out = [];
  for await (const c of client.findCellsByLock(lock, null, true)) {
    if (c.cellOutput.type == null && c.outputData === "0x") out.push(c);
  }
  out.sort((a, b) => (BigInt(b.cellOutput.capacity) > BigInt(a.cellOutput.capacity) ? 1 : -1));
  return out;
}
export async function pickPlain(client, lock, need) {
  const ps = await plainCells(client, lock);
  const elig = ps.filter((x) => BigInt(x.cellOutput.capacity) >= need);
  if (!elig.length) throw new Error(`no plain cell >= ${Number(need) / 1e8} CKB`);
  // Randomize among eligible cells (every one covers `need`) so two CONCURRENT orchestrators sharing the one
  // relayer key under different gates (a mint vs a release) rarely pick the SAME input -> far fewer
  // "All inputs are spent" self-collisions. No cross-process state; a residual collision is a caller retry.
  return elig[Math.floor(Math.random() * elig.length)];
}
export function guard(inputs) {
  for (const i of inputs)
    if (PROTECTED.has(`${i.previousOutput.txHash}:${Number(i.previousOutput.index)}`))
      throw new Error(`would consume protected cell ${i.previousOutput.txHash}:${Number(i.previousOutput.index)}`);
}

// Faithful ckb-debugger ReprMockTransaction (resolves inputs + cellDeps, EXPANDING dep_groups into their
// referenced cells so checkpoint_root() scans exactly what the live node scans). Identical to the genesis
// builder's dumper. Dry-run a group: ckb-debugger --tx-file <out> --script-group-type type --cell-type
// {input|output} --cell-index N.
export async function dumpMock(client, tx, outPath) {
  const scr = (s) => (s ? { code_hash: s.codeHash, hash_type: s.hashType, args: s.args } : null);
  const opn = (o) => ({ tx_hash: o.txHash, index: "0x" + Number(o.index).toString(16) });
  const resolve = async (op) => {
    const c = await client.getCell(op);
    return { output: { capacity: "0x" + BigInt(c.cellOutput.capacity).toString(16), lock: scr(c.cellOutput.lock), type: scr(c.cellOutput.type) }, data: c.outputData };
  };
  const inputs = [];
  for (const i of tx.inputs) {
    const r = await resolve(i.previousOutput);
    inputs.push({ input: { since: "0x" + BigInt(i.since).toString(16), previous_output: opn(i.previousOutput) }, output: r.output, data: r.data, header: null });
  }
  const cell_deps = [];
  for (const d of tx.cellDeps) {
    const r = await resolve(d.outPoint);
    const dt = d.depType === "depGroup" ? "dep_group" : "code";
    cell_deps.push({ cell_dep: { out_point: opn(d.outPoint), dep_type: dt }, output: r.output, data: r.data, header: null });
    if (d.depType === "depGroup") {
      const data = ccc.bytesFrom(r.data); const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const count = dv.getUint32(0, true);
      for (let k = 0; k < count; k++) {
        const off = 4 + k * 36;
        const refOp = { txHash: "0x" + Buffer.from(data.slice(off, off + 32)).toString("hex"), index: dv.getUint32(off + 32, true) };
        const rr = await resolve(refOp);
        cell_deps.push({ cell_dep: { out_point: opn(refOp), dep_type: "code" }, output: rr.output, data: rr.data, header: null });
      }
    }
  }
  const mock = {
    mock_info: { inputs, cell_deps, header_deps: [] },
    tx: {
      version: "0x0",
      cell_deps: tx.cellDeps.map((d) => ({ out_point: opn(d.outPoint), dep_type: d.depType === "depGroup" ? "dep_group" : "code" })),
      header_deps: [],
      inputs: tx.inputs.map((i) => ({ since: "0x" + BigInt(i.since).toString(16), previous_output: opn(i.previousOutput) })),
      outputs: tx.outputs.map((o) => ({ capacity: "0x" + BigInt(o.capacity).toString(16), lock: scr(o.lock), type: scr(o.type) })),
      outputs_data: tx.outputsData,
      witnesses: tx.witnesses,
    },
  };
  fs.writeFileSync(outPath, JSON.stringify(mock, null, 2));
}
