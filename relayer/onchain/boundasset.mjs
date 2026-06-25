// boundasset.mjs - drive the BoundAsset lifecycle on Pudge under our key against our LIVE authenticated
// checkpoint: GENESIS (bind), TRANSITION (consume old -> new), FINALIZE (leap-out, destroy). For each, it
//   1) refreshes the authenticated tx-set checkpoint to the current Mithril root,
//   2) gets the relayer MKMapProof witness for the Cardano event tx (asserting witness root == checkpoint),
//   3) builds + signs + sends the CKB tx with the BoundAsset verifier as the bound cell's type script.
// Usage: node boundasset.mjs genesis|transition|finalize <cardano_txid> [state]
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";
import { refreshCheckpoint } from "./refresh_checkpoint.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RELAYER = path.resolve(HERE, "..");
const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const SEAL = JSON.parse(fs.readFileSync(path.resolve(RELAYER, "../cardano/deployed/cardano/preview/seal-instance-ours.json"), "utf8"));
const STATE_PATH = path.join(HERE, "boundasset_state.json");
const FEE = 2_000_000n;

// instance params: seal_policy(28) || lock_addr(full 29B address). lock_addr is the binding_lock output
// address bytes from the seal-mint (header 0x70 + 28B script hash).
const SEAL_POLICY = SEAL.seal_policy;
const LOCK_ADDR = "70f85cf52d53ad20baee1b1778b77c05274d54f12932e7531f96dce208";
const baArgs = "0x" + SEAL_POLICY + LOCK_ADDR;
const baScript = ccc.Script.from({ codeHash: DEPLOYED.bound_asset.codeHash, hashType: "data1", args: baArgs });
const baDep = { outPoint: { txHash: DEPLOYED.bound_asset.txHash, index: 0 }, depType: "code" };
const PROTECTED = new Set([`${DEPLOYED.cv_advance.txHash}:0`, `${DEPLOYED.cv_deploy.txHash}:0`, `${DEPLOYED.bound_asset.txHash}:0`]);

const loadState = () => { try { return JSON.parse(fs.readFileSync(STATE_PATH, "utf8")); } catch { return {}; } };
const saveState = (s) => fs.writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
const minCap = (hex, t) => BigInt((8 + 53 + (t ? 33 : 0) + (hex.length - 2) / 2 + 1) * 1e8);
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b.toString("hex"); };

function boundData(txid, idx, state) {
  return "0x" + txid.replace(/^0x/, "") + u32le(idx) + Buffer.from(state, "utf8").toString("hex");
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
  for (const i of inputs) if (PROTECTED.has(`${i.previousOutput.txHash}:${Number(i.previousOutput.index)}`))
    throw new Error(`would consume code cell ${i.previousOutput.txHash}`);
}

async function main() {
  const mode = process.argv[2];
  const txid = process.argv[3];
  const state = process.argv[4] || SEAL.S0_hex && Buffer.from(SEAL.S0_hex, "hex").toString("utf8") || "bound-asset:demo:v1";
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const st = loadState();

  // 1) refresh checkpoint + 2) witness, ensuring roots match (retry on snapshot drift)
  let ckpt, wit;
  for (let attempt = 0; attempt < 4; attempt++) {
    ckpt = await refreshCheckpoint();
    wit = getWitness(txid);
    if (wit.status !== "ready") throw new Error("witness not ready: " + JSON.stringify(wit));
    if (wit.root === ckpt.root) break;
    console.log(`  root drift (wit ${wit.root.slice(0, 14)} vs ckpt ${ckpt.root.slice(0, 14)}), retrying...`);
    ckpt = null;
  }
  if (!ckpt || wit.root !== ckpt.root) throw new Error("could not align witness root with checkpoint");
  console.log(`checkpoint ${ckpt.checkpoint.txHash.slice(0, 14)} root ${ckpt.root.slice(0, 14)}.. | witness ${(wit.witness.length - 2) / 2} bytes`);
  const ckptDep = { outPoint: ckpt.checkpoint, depType: "code" };

  if (mode === "genesis") {
    const data = boundData(txid, 0, state);
    const bcCap = BigInt(240e8);
    const fund = await pickPlain(client, lock, bcCap + FEE + BigInt(61e8));
    const tx = ccc.Transaction.from({
      inputs: [{ previousOutput: fund.outPoint, since: 0n }],
      outputs: [{ lock, type: baScript, capacity: bcCap }, { lock, capacity: BigInt(fund.cellOutput.capacity) - bcCap - FEE }],
      outputsData: [data, "0x"],
      cellDeps: [baDep, ckptDep],
    });
    guard(tx.inputs);
    tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: wit.witness }));
    const h = await client.sendTransaction(await signer.signTransaction(tx));
    console.log("GENESIS bound cell:", h);
    await wait(client, h);
    st.bound = { txHash: h, index: 0, seal_txid: txid, seal_idx: 0, state }; saveState(st);
  } else if (mode === "transition" || mode === "finalize") {
    const old = st.bound; if (!old) throw new Error("no existing bound cell in state");
    const oldCap = BigInt((await client.getCell(old)).cellOutput.capacity);
    const outs = []; const outsData = [];
    if (mode === "transition") {
      const data = boundData(txid, 0, state);
      const bcCap = BigInt(240e8);
      outs.push({ lock, type: baScript, capacity: bcCap }); outsData.push(data);
    }
    // funding + change
    const fund = await pickPlain(client, lock, BigInt(61e8) + FEE);
    const inCap = oldCap + BigInt(fund.cellOutput.capacity);
    const usedOut = outs.reduce((a, o) => a + o.capacity, 0n);
    outs.push({ lock, capacity: inCap - usedOut - FEE }); outsData.push("0x");
    const tx = ccc.Transaction.from({
      inputs: [{ previousOutput: old, since: 0n }, { previousOutput: fund.outPoint, since: 0n }],
      outputs: outs, outputsData: outsData,
      cellDeps: [baDep, ckptDep],
    });
    guard(tx.inputs);
    tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: wit.witness }));
    const h = await client.sendTransaction(await signer.signTransaction(tx));
    console.log(mode.toUpperCase() + ":", h);
    await wait(client, h);
    if (mode === "transition") st.bound = { txHash: h, index: 0, seal_txid: txid, seal_idx: 0, state };
    else st.bound = null;
    saveState(st);
  } else {
    throw new Error("mode must be genesis|transition|finalize");
  }
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
