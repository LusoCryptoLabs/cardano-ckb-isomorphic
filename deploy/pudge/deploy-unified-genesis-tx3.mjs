// deploy-unified-genesis-tx3.mjs - LIVE Phase-1 Tx3 ONLY (Tx1 code-cell + Tx2 checkpoint
// already deployed on Pudge). Mints the witness-driven GENESIS bound cell referencing the
// ONE deployed unified BoundAsset script, with the genesis proof in the type witness
// (input_type). Fix vs. deploy-unified-genesis.mjs: set the witness BEFORE completeFeeBy
// so the ~1.1 KB proof is counted in the min-fee estimate (the prior PoolRejected min-fee).
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import { gasSigner, funderLockOf } from "./testnet-pq-common.mjs";
const D = JSON.parse(fs.readFileSync(new URL("./p1b_hex.json", import.meta.url)));

// Already-live cells (do NOT redeploy):
const CODE_TX = "0xf8644bd38a84749d67f877047eecd2dcce4d624dc02e3b832b01fe1195757c33";
const CKPT_TX = "0xca6c8ff0d39f056dfb11788d9f9bf4cc4cca8b7538c8f5915adb62781a762eda";
const CODE_HASH = "0x42f74fbcf2ccfc823820dd8e59af54063841d57a0365068c8cbde68dbf82a5dc";

async function main() {
  const { client, signer } = gasSigner();
  const gasLock = await funderLockOf(signer);
  const ty = ccc.Script.from({ codeHash: CODE_HASH, hashType: "data1", args: "0x" });

  const t3 = ccc.Transaction.from({
    outputs: [{ lock: gasLock, type: ty }],
    outputsData: [D.g_out],
    cellDeps: [
      { outPoint: { txHash: CODE_TX, index: 0 }, depType: "code" },
      { outPoint: { txHash: CKPT_TX, index: 0 }, depType: "code" },
    ],
  });
  // completeInputsByCapacity adds the funder input at index 0 and (re)sets witness 0, so the
  // proof witness MUST be set AFTER it - and before completeFeeBy, so the ~1.1 KB is counted.
  await t3.completeInputsByCapacity(signer);
  t3.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: D.g_witness }));
  await t3.completeFeeBy(signer, 1000);
  // Re-assert (same bytes; completeFeeBy already counted the size) - signTransaction fills .lock.
  t3.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: D.g_witness }));
  const signed = await signer.signTransaction(t3);
  const tx3 = await client.sendTransaction(signed);
  await Promise.race([client.waitTransaction(tx3), new Promise((r) => setTimeout(r, 120000))]);
  console.log(JSON.stringify({ unifiedCode: CODE_HASH, deployTx: CODE_TX, checkpointTx: CKPT_TX, genesisBoundCellTx: tx3 }, null, 2));
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); console.error((e.stack || "").split("\n").slice(1, 8).join("\n")); process.exit(1); });
