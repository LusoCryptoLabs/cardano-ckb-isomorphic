// refresh_checkpoint_v2.mjs - publish a FRESH 44-byte authenticated tx-set checkpoint for the v2 leap:
//   "LCKP" ‖ cardano_transactions_merkle_root(32) ‖ latest_block_number(8 LE)   (44 bytes)
// typed by the M2 cv_deploy_v2 verifier (codeHash 0x75b288f3...), so its type hash == CHIRAL_LCKP_TH
// (0xa055798e...) that bound_asset_v2 bakes. Differs from the v1 36-byte refresh_checkpoint.mjs only by:
// the cv_deploy_v2 type/dep, surfacing latest_block_number, and appending the 8-byte LE height.
// Re-runnable: each call mints a new LCKP cell at the latest certified root+height. Saves to checkpoint_v2.json.
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const STATE = JSON.parse(fs.readFileSync(path.join(HERE, "chain_state.json"), "utf8")); // AVK checkpoint (now epoch 1324)
const OUT = path.join(HERE, "checkpoint_v2.json");
const FEE = 2_000_000n;

if (!DEPLOYED.cv_deploy_v2) throw new Error("deployed.json has no cv_deploy_v2 - run deploy_cv_deploy_v2.mjs --live first");
const cvDepScript = ccc.Script.from({ codeHash: DEPLOYED.cv_deploy_v2.codeHash, hashType: "data1", args: "0x" });
const depDep = { outPoint: { txHash: DEPLOYED.cv_deploy_v2.txHash, index: 0 }, depType: "code" };
const PROTECTED = new Set([`${DEPLOYED.cv_advance.txHash}:0`, `${DEPLOYED.cv_deploy.txHash}:0`,
  `${DEPLOYED.bound_asset.txHash}:0`, `${DEPLOYED.cv_deploy_v2.txHash}:0`]);
const minCap = (hex, t) => BigInt((8 + 53 + (t ? 33 : 0) + (hex.length - 2) / 2 + 1) * 1e8);

async function pickPlain(client, lock, need) {
  const ps = await plainCells(client, lock);
  const c = ps.find((x) => BigInt(x.cellOutput.capacity) >= need);
  if (!c) throw new Error(`no plain cell >= ${need}`);
  return c;
}

// fetch latest CT cert, build its MWIT witness in the distro, return {root, height, witHex}
function buildCtWitness() {
  const cmd = `wsl -d ChiralSP1 -- bash -lc "source ~/.cargo/env; ` +
    `python3 -c \\"import urllib.request,json; A='https://aggregator.testing-preview.api.mithril.network/aggregator'; ` +
    `d=json.load(urllib.request.urlopen(A+'/proof/cardano-transaction?transaction_hashes=c07d8620807fc87ba8305d89adc9c91bd29d59f5b8777a4ab405dfde6258b669',timeout=25)); ` +
    `ch=d['certificate_hash']; c=json.load(urllib.request.urlopen(A+'/certificate/'+ch,timeout=25)); ` +
    `open('/root/ct_ref.json','w').write(json.dumps(c)); ` +
    `pm=c['protocol_message']['message_parts']; print(pm['cardano_transactions_merkle_root'], pm['latest_block_number'])\\" && ` +
    `/root/mv/target/release/transcode_witness /root/ct_ref.json >/dev/null && ` +
    `python3 -c \\"import sys;sys.stdout.write(open('/tmp/cert_witness.bin','rb').read().hex())\\""`;
  const out = execSync(cmd, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).trim().split(/\s+/);
  return { root: out[0], height: BigInt(out[1]), witHex: "0x" + out.slice(2).join("") };
}

const u64le = (v) => Array.from({ length: 8 }, (_, k) => Number((v >> BigInt(8 * k)) & 0xffn).toString(16).padStart(2, "0")).join("");

export async function refreshCheckpointV2() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const { root, height, witHex } = buildCtWitness();
  console.log("cert root:", root, "| latest_block_number:", height.toString());

  // 1) witness cell carrying the MWIT cert. Recycle the previous witness cell (checkpoint_v2.json) as an input.
  const wcCap = minCap(witHex, false) + BigInt(1e8);
  let prev = null;
  try { prev = JSON.parse(fs.readFileSync(OUT, "utf8")).witnessCell; } catch {}
  let prevCap = 0n, prevInput = [];
  // recycle the prior witness cell ONLY if it is still LIVE - a stale checkpoint_v2.json can point at a cell a
  // later refresh/leg already spent; getCellLive returns null for that (getCell would return the dead cell and
  // make us reference a spent input → TransactionFailedToResolve). Dead/absent → just fund a fresh witness cell.
  if (prev) { try { const pc = await client.getCellLive(prev, false); if (pc) { prevCap = BigInt(pc.cellOutput.capacity); prevInput = [{ previousOutput: prev, since: 0n }]; } } catch {} }
  const need = wcCap + FEE + BigInt(61e8) - prevCap;
  const f1 = await pickPlain(client, lock, need > 0n ? need : BigInt(61e8));
  const wtx = ccc.Transaction.from({
    inputs: [...prevInput, { previousOutput: f1.outPoint, since: 0n }],
    outputs: [{ lock, capacity: wcCap }, { lock, capacity: prevCap + BigInt(f1.cellOutput.capacity) - wcCap - FEE }],
    outputsData: [witHex, "0x"],
  });
  for (const i of wtx.inputs) if (PROTECTED.has(`${i.previousOutput.txHash}:${Number(i.previousOutput.index)}`)) throw new Error("would consume code cell");
  const wh = await client.sendTransaction(await signer.signTransaction(wtx));
  await wait(client, wh);
  const witCell = { txHash: wh, index: 0 };

  // 2) cv_deploy_v2 tx: publish LCKP||root(32)||height(8 LE) = 44 bytes, reading the 1324 AVK checkpoint + witness.
  const ckptData = "0x4c434b50" + root + u64le(height); // "LCKP" ‖ root ‖ height(8 LE)
  if ((ckptData.length - 2) / 2 !== 44) throw new Error(`checkpoint data not 44 bytes: ${(ckptData.length - 2) / 2}`);
  const ckCap = minCap(ckptData, true) + BigInt(50e8);
  const f2 = await pickPlain(client, lock, ckCap + FEE + BigInt(61e8));
  const dtx = ccc.Transaction.from({
    inputs: [{ previousOutput: f2.outPoint, since: 0n }],
    outputs: [{ lock, type: cvDepScript, capacity: ckCap }, { lock, capacity: BigInt(f2.cellOutput.capacity) - ckCap - FEE }],
    outputsData: [ckptData, "0x"],
    cellDeps: [depDep, { outPoint: witCell, depType: "code" }, { outPoint: STATE.ckpt.outpoint, depType: "code" }],
  });
  for (const i of dtx.inputs) if (PROTECTED.has(`${i.previousOutput.txHash}:${Number(i.previousOutput.index)}`)) throw new Error("would consume code cell");
  const dh = await client.sendTransaction(await signer.signTransaction(dtx));
  await wait(client, dh);

  const res = { checkpoint: { txHash: dh, index: 0 }, root: "0x" + root, height: height.toString(), data: ckptData, witnessCell: witCell, lckpTypeHash: cvDepScript.hash() };
  fs.writeFileSync(OUT, JSON.stringify(res, null, 2));
  return res;
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("refresh_checkpoint_v2.mjs")) {
  refreshCheckpointV2().then((r) => { console.log("v2 checkpoint:", r.checkpoint.txHash, "\n  data:", r.data, "\n  LCKP type hash:", r.lckpTypeHash); process.exit(0); })
    .catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
}
