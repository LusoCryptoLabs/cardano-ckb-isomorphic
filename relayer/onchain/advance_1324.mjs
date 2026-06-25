// advance_1324.mjs - broadcast the AVK epoch advance 1323->1324 on Pudge (spends the live epoch-1323 AVK
// checkpoint, emits the epoch-1324 one). Unblocks publishing a checkpoint against current (epoch-1324) Mithril
// certs - needed by BOTH the live v1 flow and the v2 44-byte checkpoint. Off-chain pre-validated by
// adversarial/advance_check_1324.py (exit 0). ck1324 is from that run. Dry by default; --live broadcasts.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, balance, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const STATE_PATH = path.join(HERE, "chain_state.json");
const STATE = JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
const WIT = path.join(HERE, "chain", "witnesses", "wit_1323.bin");
const FEE = 2_000_000n;

// from adversarial/advance_check_1324.py (PASS, exit 0)
const CK1323 = "0x2b05000000000000ebc245fb2f391d76e631e02fe396fe0813d9e0422cd910bf648b24c7778965ac66193dd65c3a0000";
const CK1324 = "0x2c0500000000000001ce65944748f2d5c19bd4097144d795fc2f8b3438d6bc753ba2704ab049c651fe9aaf78613a0000";

const cvAdvScript = ccc.Script.from({ codeHash: DEPLOYED.cv_advance.codeHash, hashType: "data1", args: "0x" });
const advDep = { outPoint: { txHash: DEPLOYED.cv_advance.txHash, index: 0 }, depType: "code" };
const PROTECTED = new Set([`${DEPLOYED.cv_advance.txHash}:0`, `${DEPLOYED.cv_deploy.txHash}:0`,
  `${DEPLOYED.bound_asset.txHash}:0`, `${DEPLOYED.cv_deploy_v2?.txHash}:0`]);
const opKey = (op) => `${op.txHash}:${Number(op.index)}`;
const dataBytes = (h) => (h.length - 2) / 2;
const minCap = (h, t) => BigInt((8 + 53 + (t ? 33 : 0) + dataBytes(h) + 1) * 1e8);

async function pickPlain(client, lock, need) {
  const ps = await plainCells(client, lock);
  const c = ps.find((x) => BigInt(x.cellOutput.capacity) >= need);
  if (!c) throw new Error(`no plain cell >= ${need}`);
  return c;
}
async function buildSend(client, signer, lock, { extraInputs = [], outs, cellDeps = [] }, label) {
  const fundNeed = outs.reduce((a, o) => a + o.cap, 0n) + FEE + BigInt(61e8)
    - extraInputs.reduce((a, e) => a + e.capacity, 0n);
  const fund = await pickPlain(client, lock, fundNeed > 0n ? fundNeed : BigInt(61e8));
  const inputs = [...extraInputs.map((e) => ({ previousOutput: e.outPoint, since: 0n })),
    { previousOutput: fund.outPoint, since: 0n }];
  for (const i of inputs) if (PROTECTED.has(opKey(i.previousOutput))) throw new Error(`would consume code cell ${opKey(i.previousOutput)}`);
  const inCap = extraInputs.reduce((a, e) => a + e.capacity, 0n) + BigInt(fund.cellOutput.capacity);
  const outputs = outs.map((o) => ({ lock: o.lock ?? lock, type: o.type ?? null, capacity: o.cap }));
  const outData = outs.map((o) => o.data);
  const change = inCap - outs.reduce((a, o) => a + o.cap, 0n) - FEE;
  if (change < BigInt(61e8)) throw new Error(`change too small: ${change}`);
  outputs.push({ lock, type: null, capacity: change }); outData.push("0x");
  const tx = ccc.Transaction.from({ inputs, outputs, outputsData: outData, cellDeps });
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  console.log(`  ${label}: ${h}`); await wait(client, h); return h;
}

async function main() {
  const live = process.argv.includes("--live");
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  console.log("balance:", (Number(await balance(client, lock)) / 1e8).toLocaleString(), "CKB");
  if (STATE.ckpt.epoch !== 1323) { console.log(`ckpt already at epoch ${STATE.ckpt.epoch}; nothing to do.`); process.exit(0); }

  // GUARD: the cell we are about to spend MUST be the epoch-1323 AVK checkpoint (data == CK1323).
  const ck = await client.getCell(STATE.ckpt.outpoint);
  if (!ck) throw new Error("AVK checkpoint cell not found at chain_state.ckpt.outpoint");
  if (ck.outputData.toLowerCase() !== CK1323.toLowerCase()) throw new Error(`AVK cell data ${ck.outputData} != expected ck1323`);
  console.log("AVK checkpoint (epoch 1323) confirmed:", opKey(STATE.ckpt.outpoint));
  console.log("ck1324 ->", CK1324);

  if (!live) { console.log("\nDRY run. Pass --live to broadcast the advance."); process.exit(0); }

  // 1) witness cell carrying wit_1323.bin (MWIT cert witness), referenced as a cellDep by the advance.
  const witData = ccc.hexFrom(new Uint8Array(fs.readFileSync(WIT)));
  const wh = await buildSend(client, signer, lock,
    { outs: [{ data: witData, cap: minCap(witData, false) + BigInt(1e8) }] }, "witness(wit_1323.bin)");
  const witCell = { txHash: wh, index: 0 };

  // 2) the advance tx: spend the epoch-1323 AVK checkpoint -> emit the epoch-1324 one.
  const inCap = BigInt(ck.cellOutput.capacity);
  const ah = await buildSend(client, signer, lock, {
    extraInputs: [{ outPoint: STATE.ckpt.outpoint, capacity: inCap }],
    outs: [{ type: cvAdvScript, data: CK1324, cap: minCap(CK1324, true) + BigInt(50e8) }],
    cellDeps: [advDep, { outPoint: witCell, depType: "code" }],
  }, "ADVANCE 1323->1324");

  STATE.ckpt = { epoch: 1324, outpoint: { txHash: ah, index: 0 } };
  fs.writeFileSync(STATE_PATH, JSON.stringify(STATE, null, 2));
  console.log("\nAVK advanced to epoch 1324:", ah);
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
