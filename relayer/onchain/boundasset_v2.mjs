// boundasset_v2.mjs - drive the v2 ownership-toggle bound cell on Pudge against the LIVE 44-byte checkpoint.
// GENESIS: create a CkbOwned cell (v2 layout) proving a Mithril-certified Cardano seal mint, validated by the
// deployed bound_asset_v2 (V2_BOUND_CODE_HASH). Mirrors v1 boundasset.mjs but with the v2 code hash, the
// 70-byte CkbOwned cell layout, and refresh_checkpoint_v2 (LCKP||root||height).
//   node boundasset_v2.mjs genesis <cardano_seal_mint_txid> [state]
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";
import { refreshCheckpointV2 } from "./refresh_checkpoint_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RELAYER = path.resolve(HERE, "..");
const REG = JSON.parse(fs.readFileSync(path.join(HERE, "v2_registry.json"), "utf8"));
const SEAL = JSON.parse(fs.readFileSync(path.resolve(RELAYER, "../cardano/deployed/cardano/preview/seal-instance-ours.json"), "utf8"));
const STATE_PATH = path.join(HERE, "boundasset_v2_state.json");
const FEE = 2_000_000n;

const SEAL_POLICY = SEAL.seal_policy;                                  // 28 bytes
const LOCK_ADDR = "7047c5d94c9338243bf0624b4d3b25840c0f913f2c9b92387f66970263"; // 0x70 ‖ v2 binding_lock hash (29B)
const baArgs = "0x" + SEAL_POLICY + LOCK_ADDR;                         // seal_policy(28) ‖ lock_addr(29) = 57B
const baScript = ccc.Script.from({ codeHash: REG.boundCode.codeHash, hashType: "data1", args: baArgs });
const baDep = { outPoint: { txHash: REG.boundCode.txHash, index: 0 }, depType: "code" };
const dep = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const PROTECTED = new Set([`${dep.cv_advance.txHash}:0`, `${dep.cv_deploy.txHash}:0`, `${dep.bound_asset.txHash}:0`,
  `${dep.cv_deploy_v2.txHash}:0`, `${REG.boundCode.txHash}:0`, `${REG.registryCode.txHash}:0`]);

const loadState = () => { try { return JSON.parse(fs.readFileSync(STATE_PATH, "utf8")); } catch { return {}; } };
const saveState = (s) => fs.writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
const minCap = (hex, t) => BigInt((8 + 53 + (t ? 33 : 0) + (hex.length - 2) / 2 + 1) * 1e8);
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b.toString("hex"); };

// v2 CkbOwned cell: version(0x02) ‖ tag(0x02) ‖ seal_txid(32) ‖ seal_idx(4 LE) ‖ lock_slot(32) ‖ state
function ckbOwnedData(sealTxid, idx, lockSlot, state) {
  return "0x02" + "02" + sealTxid.replace(/^0x/, "") + u32le(idx) + lockSlot.replace(/^0x/, "") + Buffer.from(state, "utf8").toString("hex");
}

function getWitness(txid) {
  const out = execSync(`python produce_witness.py ${txid}`, { cwd: RELAYER, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out.trim());
}
async function pickPlain(client, lock, need) {
  const ps = await plainCells(client, lock);
  const c = ps.find((x) => BigInt(x.cellOutput.capacity) >= need);
  if (!c) throw new Error(`no plain cell >= ${Number(need) / 1e8} CKB`);
  return c;
}
function guard(inputs) {
  for (const i of inputs) if (PROTECTED.has(`${i.previousOutput.txHash}:${Number(i.previousOutput.index)}`)) throw new Error(`would consume protected cell ${i.previousOutput.txHash}`);
}

// Dump the SIGNED tx + resolved cells as a ckb-debugger ReprMockTransaction (for `ckb-debugger --tx-file`).
async function dumpMock(client, tx, outPath) {
  const scr = (s) => s ? { code_hash: s.codeHash, hash_type: s.hashType, args: s.args } : null;
  const opn = (o) => ({ tx_hash: o.txHash, index: "0x" + Number(o.index).toString(16) });
  const resolve = async (op) => { const c = await client.getCell(op); return { output: { capacity: "0x" + BigInt(c.cellOutput.capacity).toString(16), lock: scr(c.cellOutput.lock), type: scr(c.cellOutput.type) }, data: c.outputData }; };
  const inputs = [];
  for (const i of tx.inputs) { const r = await resolve(i.previousOutput); inputs.push({ input: { since: "0x" + BigInt(i.since).toString(16), previous_output: opn(i.previousOutput) }, output: r.output, data: r.data, header: null }); }
  // FAITHFUL deps: include every cellDep (incl. the secp256k1 dep_group ccc adds) + resolve the cells a
  // dep_group references (its OutPointVec), so checkpoint_root scans exactly what the live node scans.
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

async function main() {
  const pos = process.argv.slice(2).filter((a) => !a.startsWith("--")); // flags (e.g. --dump) are not positionals
  const mode = pos[0];
  const txid = pos[1] || SEAL.seal_mint_tx;
  const state = pos[2] || Buffer.from(SEAL.S0_hex, "hex").toString("utf8");
  if (mode !== "genesis") throw new Error("mode must be genesis (leap modes are separate)");
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const lockSlot = lock.hash();
  const st = loadState();

  // 1) refresh the 44-byte checkpoint + 2) the MKMapProof witness, aligning roots (retry on snapshot drift)
  let ckpt, wit;
  for (let attempt = 0; attempt < 4; attempt++) {
    ckpt = await refreshCheckpointV2();
    wit = getWitness(txid);
    if (wit.status !== "ready") throw new Error("witness not ready (seal tx not certified yet?): " + JSON.stringify(wit));
    if (wit.root === ckpt.root) break;
    console.log(`  root drift (wit ${wit.root.slice(0, 14)} vs ckpt ${ckpt.root.slice(0, 14)}), retrying...`);
    ckpt = null;
  }
  if (!ckpt || wit.root !== ckpt.root) throw new Error("could not align witness root with checkpoint");
  console.log(`v2 checkpoint ${ckpt.checkpoint.txHash.slice(0, 14)} root ${ckpt.root.slice(0, 14)}.. | witness ${(wit.witness.length - 2) / 2} bytes`);
  const ckptDep = { outPoint: ckpt.checkpoint, depType: "code" };

  const data = ckbOwnedData(txid, 0, lockSlot, state);
  const bcCap = BigInt(260e8); // occupied = 8 + lock(53) + type(32+1+57 args = 90) + data(~89) = 240; +margin
  const fund = await pickPlain(client, lock, bcCap + FEE + BigInt(61e8));
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: fund.outPoint, since: 0n }],
    outputs: [{ lock, type: baScript, capacity: bcCap }, { lock, capacity: BigInt(fund.cellOutput.capacity) - bcCap - FEE }],
    outputsData: [data, "0x"],
    cellDeps: [baDep, ckptDep],
  });
  guard(tx.inputs);
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: wit.witness }));
  const signed = await signer.signTransaction(tx);
  if (process.argv.includes("--dump")) {
    const out = path.join(HERE, "genesis_dump.json");
    await dumpMock(client, signed, out);
    console.log("dumped ckb-debugger mock tx ->", out);
    process.exit(0);
  }
  const h = await client.sendTransaction(signed);
  console.log("GENESIS v2 CkbOwned bound cell:", h);
  await wait(client, h);
  st.bound = { txHash: h, index: 0, seal_txid: txid, seal_idx: 0, lock_slot: lockSlot, state }; saveState(st);
  console.log("  cell data:", data);
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
