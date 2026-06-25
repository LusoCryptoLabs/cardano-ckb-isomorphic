// advance_1326.mjs - broadcast the AVK epoch advance 1325->1326 on Pudge (spends the live epoch-1325 AVK
// checkpoint, emits the epoch-1326 one). Unblocks the v2 checkpoint refresh against CURRENT (epoch-1326)
// Mithril certs, needed by the chi-ADA re-issue mint. Off-chain pre-validated by
// adversarial/advance_check_1326.py (RESULT: PASS). Recycles the old advance witness cell for funding.
// Dry by default; --live broadcasts. Mirror of advance_1325.mjs with the epoch bumped by one.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, balance, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const STATE_PATH = path.join(HERE, "chain_state.json");
const STATE = JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
const WIT = path.join(HERE, "chain", "witnesses", "wit_1325.bin");
const FEE = 2_000_000n;

// from adversarial/advance_check_1326.py (RESULT: PASS - ck1325 matches on-chain, cv_advance exit 0)
const CK_FROM = "0x2d05000000000000cbcbcee27edb35c2cddc0e073c827872bcffd840f35416a5039ac70736ddf38606f3b8ed663a0000"; // epoch 1325
const CK_TO   = "0x2e05000000000000f1c7f15a04099e7205ca8f0529e63a1ceceb3029e410fb69f8b4ed3851bba97cd67a70316c3a0000"; // epoch 1326

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
  if (!c) throw new Error(`no plain cell >= ${Number(need) / 1e8} CKB`);
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
  if (STATE.ckpt.epoch !== 1325) { console.log(`ckpt already at epoch ${STATE.ckpt.epoch}; nothing to do.`); process.exit(0); }

  const ck = await client.getCell(STATE.ckpt.outpoint);
  if (!ck) throw new Error("AVK checkpoint cell not found at chain_state.ckpt.outpoint");
  if (ck.outputData.toLowerCase() !== CK_FROM.toLowerCase()) throw new Error(`AVK cell data ${ck.outputData} != expected ck1325`);
  console.log("AVK checkpoint (epoch 1325) confirmed:", opKey(STATE.ckpt.outpoint));
  console.log("ck1326 ->", CK_TO);

  // recycle the OLD advance witness cell as funding for the new one. chain_state.witness (the epoch-1325
  // witness) is already spent, so fall back to the leftover epoch-1324 witness cell (10,134 CKB, my lock,
  // no type, not a live dep) which is the exact funding a fresh 10 KB witness cell needs.
  const OLD_WITNESS = { txHash: "0xf972c3887d122c7f6c97fb977f9714dc0b8aab4f1f8ebdb93ca47349b2a8f8ec", index: 0 };
  let recycle = [];
  for (const cand of [STATE.witness, OLD_WITNESS]) {
    if (!cand) continue;
    try { const wc = await client.getCellLive(cand, true);
      if (wc && wc.cellOutput.type == null) { recycle = [{ outPoint: cand, capacity: BigInt(wc.cellOutput.capacity) }];
        console.log("recycling witness cell:", opKey(cand), "(" + (BigInt(wc.cellOutput.capacity) / 100000000n) + " CKB)"); break; }
    } catch {}
  }

  if (!live) { console.log("\nDRY run. Pass --live to broadcast the advance."); process.exit(0); }

  // 1) witness cell carrying wit_1325.bin (MWIT cert witness), recycling the old witness cell for capacity.
  const witData = ccc.hexFrom(new Uint8Array(fs.readFileSync(WIT)));
  const wh = await buildSend(client, signer, lock,
    { extraInputs: recycle, outs: [{ data: witData, cap: minCap(witData, false) + BigInt(1e8) }] }, "witness(wit_1325.bin)");
  const witCell = { txHash: wh, index: 0 };

  // 2) the advance tx: spend the epoch-1325 AVK checkpoint -> emit the epoch-1326 one.
  const inCap = BigInt(ck.cellOutput.capacity);
  const ah = await buildSend(client, signer, lock, {
    extraInputs: [{ outPoint: STATE.ckpt.outpoint, capacity: inCap }],
    outs: [{ type: cvAdvScript, data: CK_TO, cap: minCap(CK_TO, true) + BigInt(50e8) }],
    cellDeps: [advDep, { outPoint: witCell, depType: "code" }],
  }, "ADVANCE 1325->1326");

  STATE.ckpt = { epoch: 1326, outpoint: { txHash: ah, index: 0 } };
  STATE.witness = witCell;
  fs.writeFileSync(STATE_PATH, JSON.stringify(STATE, null, 2));
  console.log("\nAVK advanced to epoch 1326:", ah);
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
