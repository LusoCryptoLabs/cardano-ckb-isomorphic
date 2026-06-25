// refresh_checkpoint.mjs - publish a FRESH authenticated tx-set checkpoint at the CURRENT Mithril root,
// reusing our live epoch-1323 AVK checkpoint (0x0848f94e) + cv_deploy. Re-runnable: each call creates a new
// LCKP cell carrying the latest certified CardanoTransactions root. Saves {outpoint, root} to checkpoint.json.
// Use before each BoundAsset step so the relayer's MKMapProof (against the latest snapshot) matches the
// on-chain checkpoint root. Exports refreshCheckpoint() for the BoundAsset orchestrator.
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const STATE = JSON.parse(fs.readFileSync(path.join(HERE, "chain_state.json"), "utf8")); // has AVK checkpoint outpoint
const OUT = path.join(HERE, "checkpoint.json");
const FEE = 2_000_000n;

const cvDepScript = ccc.Script.from({ codeHash: DEPLOYED.cv_deploy.codeHash, hashType: "data1", args: "0x" });
const depDep = { outPoint: { txHash: DEPLOYED.cv_deploy.txHash, index: 0 }, depType: "code" };
const advDep = { outPoint: { txHash: DEPLOYED.cv_advance.txHash, index: 0 }, depType: "code" };
const PROTECTED = new Set([`${DEPLOYED.cv_advance.txHash}:0`, `${DEPLOYED.cv_deploy.txHash}:0`, `${DEPLOYED.bound_asset.txHash}:0`]);
const minCap = (hex, t) => BigInt((8 + 53 + (t ? 33 : 0) + (hex.length - 2) / 2 + 1) * 1e8);

async function pickPlain(client, lock, need) {
  const ps = await plainCells(client, lock);
  const c = ps.find((x) => BigInt(x.cellOutput.capacity) >= need);
  if (!c) throw new Error(`no plain cell >= ${need}`);
  return c;
}

// fetch latest CT cert, build its MWIT witness in the distro, return {root, witHex}
function buildCtWitness() {
  const cmd = `wsl -d ChiralSP1 -- bash -lc "source ~/.cargo/env; ` +
    `python3 -c \\"import urllib.request,json; A='https://aggregator.testing-preview.api.mithril.network/aggregator'; ` +
    `d=json.load(urllib.request.urlopen(A+'/proof/cardano-transaction?transaction_hashes=c07d8620807fc87ba8305d89adc9c91bd29d59f5b8777a4ab405dfde6258b669',timeout=25)); ` +
    `ch=d['certificate_hash']; c=json.load(urllib.request.urlopen(A+'/certificate/'+ch,timeout=25)); ` +
    `open('/root/ct_ref.json','w').write(json.dumps(c)); ` +
    `print(c['protocol_message']['message_parts']['cardano_transactions_merkle_root'])\\" && ` +
    `/root/mv/target/release/transcode_witness /root/ct_ref.json >/dev/null && ` +
    `python3 -c \\"import sys;sys.stdout.write(open('/tmp/cert_witness.bin','rb').read().hex())\\""`;
  const out = execSync(cmd, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).trim().split(/\s+/);
  const root = out[0];
  const witHex = "0x" + out.slice(1).join("");
  return { root, witHex };
}

export async function refreshCheckpoint() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const { root, witHex } = buildCtWitness();

  // 1) witness cell carrying the MWIT cert. Recycle the PREVIOUS witness cell (from checkpoint.json) as an
  // input so the ~10KB capacity doesn't pile up across refreshes.
  const wcCap = minCap(witHex, false) + BigInt(1e8);
  let prev = null;
  try { prev = JSON.parse(fs.readFileSync(OUT, "utf8")).witnessCell; } catch {}
  let prevCap = 0n, prevInput = [];
  if (prev) { try { prevCap = BigInt((await client.getCell(prev)).cellOutput.capacity); prevInput = [{ previousOutput: prev, since: 0n }]; } catch {} }
  const f1 = await pickPlain(client, lock, wcCap + FEE + BigInt(61e8) - prevCap > 0n ? wcCap + FEE + BigInt(61e8) - prevCap : BigInt(61e8));
  const wtx = ccc.Transaction.from({
    inputs: [...prevInput, { previousOutput: f1.outPoint, since: 0n }],
    outputs: [{ lock, capacity: wcCap }, { lock, capacity: prevCap + BigInt(f1.cellOutput.capacity) - wcCap - FEE }],
    outputsData: [witHex, "0x"],
  });
  for (const i of wtx.inputs) if (PROTECTED.has(`${i.previousOutput.txHash}:${Number(i.previousOutput.index)}`)) throw new Error("would consume code cell");
  const wh = await client.sendTransaction(await signer.signTransaction(wtx));
  await wait(client, wh);
  const witCell = { txHash: wh, index: 0 };

  // 2) cv_deploy tx: publish LCKP||root, reading the AVK checkpoint cellDep + witness cellDep
  const ckptData = "0x4c434b50" + root;
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

  const res = { checkpoint: { txHash: dh, index: 0 }, root: "0x" + root, witnessCell: witCell };
  fs.writeFileSync(OUT, JSON.stringify(res, null, 2));
  return res;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  refreshCheckpoint().then((r) => { console.log("checkpoint:", r.checkpoint.txHash, "root", r.root); process.exit(0); })
    .catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
}
