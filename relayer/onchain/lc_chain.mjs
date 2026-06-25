// lc_chain.mjs - execute the authenticated light-client chain ON PUDGE under our key:
//   genesis(epoch 1319) -> advance x4 -> epoch-1323 AVK checkpoint -> authenticated tx-set checkpoint.
// Mirrors the off-chain ckb-debugger run (build_chain.py). Resumable (chain_state.json).
//
// MANUAL coin selection: the public indexer does not reliably honor the data-length filter, so ccc's
// auto-funding can grab our big verifier CODE cells. We instead pick a plain (empty-data) cell ourselves,
// set explicit output capacities, and emit explicit change - never touching the code cells. A guard
// double-checks no input is a code cell. The MWIT cert witness rides in a cellDep CELL (recycled).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, balance, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CHAIN = path.join(HERE, "chain");
const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const META = JSON.parse(fs.readFileSync(path.join(CHAIN, "chain.json"), "utf8"));
const STATE_PATH = path.join(HERE, "chain_state.json");
const FEE = 2_000_000n; // 0.02 CKB flat - far above the per-byte min for these txs

const witHex = (f) => ccc.hexFrom(new Uint8Array(fs.readFileSync(path.join(CHAIN, "witnesses", f))));
const loadState = () => { try { return JSON.parse(fs.readFileSync(STATE_PATH, "utf8")); } catch { return {}; } };
const saveState = (s) => fs.writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));

const cvAdvScript = ccc.Script.from({ codeHash: DEPLOYED.cv_advance.codeHash, hashType: "data1", args: "0x" });
const cvDepScript = ccc.Script.from({ codeHash: DEPLOYED.cv_deploy.codeHash, hashType: "data1", args: "0x" });
const advDep = { outPoint: { txHash: DEPLOYED.cv_advance.txHash, index: 0 }, depType: "code" };
const depDep = { outPoint: { txHash: DEPLOYED.cv_deploy.txHash, index: 0 }, depType: "code" };
// protect the CODE cells specifically (txHash:index) - NOT other outputs of the same deploy tx
// (the deploy tx's change cell shares the txHash but sits at index 1 and is perfectly spendable).
const PROTECTED = new Set([`${DEPLOYED.cv_advance.txHash}:0`, `${DEPLOYED.cv_deploy.txHash}:0`]);
const opKey = (op) => `${op.txHash}:${Number(op.index)}`;

const dataBytes = (hex) => (hex.length - 2) / 2;
// minimal occupied capacity (shannon) for a cell: 8 (capacity) + lock(53) + type(33 if present) + data
const minCap = (dataHex, hasType) => BigInt((8 + 53 + (hasType ? 33 : 0) + dataBytes(dataHex) + 1) * 1e8);

async function cellCap(client, outPoint) {
  const c = await client.getCell(outPoint);
  return BigInt(c.cellOutput.capacity);
}

// Build a fully-funded tx by hand. extraInputs: [{outPoint, capacity}] already-known cells to consume.
// outs: [{lock,type?,data,cap}]. Returns the signed-and-sent tx hash. Emits explicit change to `lock`.
async function buildSend(client, signer, lock, { extraInputs = [], outs, cellDeps = [] }, label) {
  const plains = await plainCells(client, lock);
  if (!plains.length) throw new Error("no plain funding cell");
  const fund = plains[0];
  const inputs = [
    ...extraInputs.map((e) => ({ previousOutput: e.outPoint, since: 0n })),
    { previousOutput: fund.outPoint, since: 0n },
  ];
  // guard: none of our inputs may be a code cell
  for (const i of inputs) if (PROTECTED.has(opKey(i.previousOutput))) throw new Error(`would consume code cell ${opKey(i.previousOutput)}`);

  const inCap = extraInputs.reduce((a, e) => a + e.capacity, 0n) + BigInt(fund.cellOutput.capacity);
  const outputs = outs.map((o) => ({ lock: o.lock ?? lock, type: o.type ?? null, capacity: o.cap }));
  const outData = outs.map((o) => o.data);
  const outCap = outs.reduce((a, o) => a + o.cap, 0n);
  const change = inCap - outCap - FEE;
  if (change < BigInt(61e8)) throw new Error(`change too small: ${change}`);
  outputs.push({ lock, type: null, capacity: change });
  outData.push("0x");

  const tx = ccc.Transaction.from({
    inputs, outputs, outputsData: outData,
    cellDeps: [...cellDeps],
  });
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  console.log(`  ${label}: ${h}`);
  await wait(client, h);
  return h;
}

async function makeWitnessCell(client, signer, lock, file, prev) {
  const data = witHex(file);
  const cap = minCap(data, false) + BigInt(1e8);
  const extra = prev ? [{ outPoint: prev, capacity: await cellCap(client, prev) }] : [];
  const h = await buildSend(client, signer, lock, { extraInputs: extra, outs: [{ data, cap }] }, `witness(${file})`);
  return { txHash: h, index: 0 };
}

async function refreshCtCert() {
  const { execSync } = await import("node:child_process");
  const cmd = `wsl -d ChiralSP1 -- bash -lc "source ~/.cargo/env; ` +
    `python3 -c \\"import urllib.request,json; AGG='https://aggregator.testing-preview.api.mithril.network/aggregator'; ` +
    `d=json.load(urllib.request.urlopen(AGG+'/proof/cardano-transaction?transaction_hashes=a98b6636b3f08670cf0fe64a6176b64094d5929165ec62eb2944ac66b0f74da7',timeout=25)); ` +
    `ch=d['certificate_hash']; cert=json.load(urllib.request.urlopen(AGG+'/certificate/'+ch,timeout=25)); ` +
    `open('/root/ct_now.json','w').write(json.dumps(cert)); ` +
    `print(cert['protocol_message']['message_parts']['cardano_transactions_merkle_root'])\\" && ` +
    `/root/mv/target/release/transcode_witness /root/ct_now.json >/dev/null && ` +
    `cp /tmp/cert_witness.bin /mnt/c/Users/telmo/chiral-study/relayer/onchain/chain/witnesses/wit_now.bin"`;
  const out = execSync(cmd, { encoding: "utf8" });
  return { txroot: out.trim().split(/\s+/).pop(), witFile: "wit_now.bin" };
}

async function main() {
  const phase = process.argv[2] || "all";
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const st = loadState();
  console.log("balance:", (Number(await balance(client, lock)) / 1e8).toLocaleString(), "CKB");

  // 1) GENESIS
  if (!st.genesis) {
    const data = META.epochs["1319"].checkpoint;
    const h = await buildSend(client, signer, lock,
      { outs: [{ type: cvAdvScript, data, cap: minCap(data, true) + BigInt(50e8) }], cellDeps: [advDep] }, "GENESIS(1319)");
    st.genesis = { txHash: h, index: 0 }; st.ckpt = { epoch: 1319, outpoint: { txHash: h, index: 0 } }; saveState(st);
  } else console.log("genesis: done", st.genesis.txHash);
  if (phase === "genesis") return fin(client, lock);

  // 2) ADVANCE x4
  st.witness = st.witness || null;
  for (const a of META.advances) {
    if (st.ckpt.epoch >= a.to) { console.log(`advance ${a.from}->${a.to}: done`); continue; }
    const wc = await makeWitnessCell(client, signer, lock, a.witness, st.witness);
    st.witness = wc; saveState(st);
    const inCap = await cellCap(client, st.ckpt.outpoint);
    const h = await buildSend(client, signer, lock, {
      extraInputs: [{ outPoint: st.ckpt.outpoint, capacity: inCap }],
      outs: [{ type: cvAdvScript, data: a.out_ck, cap: minCap(a.out_ck, true) + BigInt(50e8) }],
      cellDeps: [advDep, { outPoint: wc, depType: "code" }],
    }, `ADVANCE ${a.from}->${a.to}`);
    st.ckpt = { epoch: a.to, outpoint: { txHash: h, index: 0 } }; saveState(st);
  }
  if (phase === "advance") return fin(client, lock);

  // 3) DEPLOY authenticated tx-set checkpoint - M2 44-byte LCKP||root||height, taken from the
  // off-chain-validated chain.json (build_chain_pinned.py exported deploy.out_data + deploy.witness).
  if (!st.deploy) {
    const witFile = META.deploy.witness;   // wit_<TO>.bin (cert at the target epoch)
    const outData = META.deploy.out_data;   // 44-byte LCKP||root||height, validated off-chain
    const wc = await makeWitnessCell(client, signer, lock, witFile, st.witness);
    st.witness = wc; saveState(st);
    const h = await buildSend(client, signer, lock, {
      outs: [{ type: cvDepScript, data: outData, cap: minCap(outData, true) + BigInt(50e8) }],
      cellDeps: [depDep, { outPoint: wc, depType: "code" }, { outPoint: st.ckpt.outpoint, depType: "code" }],
    }, "DEPLOY authenticated tx-set checkpoint (M2 44-byte)");
    st.deploy = { txHash: h, index: 0, root: META.deploy.tx_root, height: META.deploy.height, checkpointData: outData }; saveState(st);
  } else console.log("deploy: done", st.deploy.txHash);

  console.log("\n=== LIGHT-CLIENT CHAIN LIVE ON PUDGE ===");
  console.log("AVK checkpoint (epoch 1323):", st.ckpt.outpoint.txHash);
  console.log("authenticated tx-set checkpoint:", st.deploy.txHash, "->", st.deploy.checkpointData);
  await fin(client, lock);
}

async function fin(client, lock) {
  console.log("balance:", (Number(await balance(client, lock)) / 1e8).toLocaleString(), "CKB");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
