// deploy-unified-transition.mjs - LIVE Phase-1 TRANSITION: consume the genesis bound cell and
// create the v2 bound cell, referencing the ONE deployed unified BoundAsset script with the
// per-transfer proof in the witness (input_type). The certified tx-set root for the transfer
// (5acd33ab) is supplied by a fresh light-client CHECKPOINT cell dep. THE headline milestone:
// a real on-chain transition (not create-only) verified in-script against real Mithril data.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import { gasSigner, funderLockOf } from "./testnet-pq-common.mjs";
const D = JSON.parse(fs.readFileSync(new URL("./p1t_hex.json", import.meta.url)));

const CODE_TX = "0xf8644bd38a84749d67f877047eecd2dcce4d624dc02e3b832b01fe1195757c33";
const CODE_HASH = "0x42f74fbcf2ccfc823820dd8e59af54063841d57a0365068c8cbde68dbf82a5dc";
const GENESIS_TX = "0x0318d35f677a2608e85f673f14818852f0f0e45c1da30011f6f3557e410fe667"; // bound cell to consume

async function main() {
  const { client, signer } = gasSigner();
  const gasLock = await funderLockOf(signer);

  // TxA: the transfer's light-client CHECKPOINT cell ("LCKP"||5acd33ab...)
  const ta = ccc.Transaction.from({ outputs: [{ lock: gasLock }], outputsData: [D.t_checkpoint] });
  await ta.completeInputsByCapacity(signer); await ta.completeFeeBy(signer, 1000);
  const txa = await client.sendTransaction(await signer.signTransaction(ta)); await client.waitTransaction(txa);
  console.log("transition checkpoint cell:", txa);

  // TxB: consume genesis bound cell -> create v2 bound cell; proof in witness; deps = code + checkpoint
  const ty = ccc.Script.from({ codeHash: CODE_HASH, hashType: "data1", args: "0x" });
  const tb = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: GENESIS_TX, index: 0 } }],
    outputs: [{ lock: gasLock, type: ty }],
    outputsData: [D.t_out],
    cellDeps: [
      { outPoint: { txHash: CODE_TX, index: 0 }, depType: "code" },
      { outPoint: { txHash: txa, index: 0 }, depType: "code" },
    ],
  });
  await tb.completeInputsByCapacity(signer);
  tb.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: D.t_witness })); // bound cell is input[0] => witness[0]
  await tb.completeFeeBy(signer, 1000);
  tb.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: D.t_witness }));  // re-assert post-fee
  const signed = await signer.signTransaction(tb);
  const txb = await client.sendTransaction(signed);
  await Promise.race([client.waitTransaction(txb), new Promise((r) => setTimeout(r, 120000))]);
  console.log(JSON.stringify({ transitionCheckpointTx: txa, consumedGenesis: GENESIS_TX, transitionBoundCellTx: txb }, null, 2));
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); console.error((e.stack || "").split("\n").slice(1, 8).join("\n")); process.exit(1); });
