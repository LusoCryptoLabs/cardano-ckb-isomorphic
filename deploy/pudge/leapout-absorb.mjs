import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import { gasSigner, funderLockOf } from "./testnet-pq-common.mjs";
const T = JSON.parse(fs.readFileSync(new URL("./p1t_hex.json", import.meta.url)));
const F = JSON.parse(fs.readFileSync(new URL("./p1f_hex.json", import.meta.url)));
const CODE = { txHash: "0x97ca700d6ea2cdf1504e4a0fa71e0fd86bda19bf92faacf66a1c10738f1c4885", index: 0 };
const CODE_HASH = "0xbeaff4d349e7f75892747f8070c6a85c641c7bd97957de86773787c07548701a";
const XFER_CKPT = { txHash: "0xae6427d8e6e0a8ad37c58a0ba2fa13fe1fd5bd9bc9f6cacdf59d4c7d3b04987f", index: 0 };
const GENESIS_CKPT = { txHash: "0xca6c8ff0d39f056dfb11788d9f9bf4cc4cca8b7538c8f5915adb62781a762eda", index: 0 };
const setIT = (tx, hex) => tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: hex }));
const FEE = 2_000_000n; // 0.02 CKB flat

async function cap(client, op) { const c = await client.getCell(op); return BigInt(c.cellOutput.capacity); }

async function main() {
  const { client, signer } = gasSigner();
  const gasLock = await funderLockOf(signer);
  const ty = ccc.Script.from({ codeHash: CODE_HASH, hashType: "data1", args: "0x" });

  // find an empty-data funder cell to add alongside the genesis checkpoint
  let empty = null;
  for await (const c of client.findCellsByLock(gasLock, null, true)) {
    if (!c.cellOutput.type && (c.outputData === "0x" || c.outputData === "0x00") && c.cellOutput.capacity > 50_00000000n) { empty = c; break; }
  }
  const capG = await cap(client, GENESIS_CKPT);
  const capE = BigInt(empty.cellOutput.capacity);
  const boundCap = capG + capE - FEE;
  // (2) genesis-under-new, absorbing both inputs into the bound cell (no change cell)
  const t2 = ccc.Transaction.from({
    inputs: [{ previousOutput: GENESIS_CKPT }, { previousOutput: empty.outPoint }],
    outputs: [{ lock: gasLock, type: ty, capacity: boundCap }], outputsData: [T.t_out],
    cellDeps: [{ outPoint: CODE, depType: "code" }, { outPoint: XFER_CKPT, depType: "code" }],
  });
  setIT(t2, T.t_witness);
  const tx2 = await client.sendTransaction(await signer.signTransaction(t2)); await client.waitTransaction(tx2);
  console.log("bound cell (seal a98b6636, state v2, cap", Number(boundCap)/1e8, "CKB) minted under finalize-capable script:", tx2);

  // (3) unbind checkpoint (root 0bc33aa8): fund from the bound cell? no - deploy small, fund by splitting
  // the bound cell's surplus on finalize. Here we need a tiny funded cell; reuse the bound-cell tx2 has no change.
  // Deploy the checkpoint by spending the transfer checkpoint (no longer needed after tx2 mined) for capacity.
  const capX = await cap(client, XFER_CKPT);
  const t3 = ccc.Transaction.from({
    inputs: [{ previousOutput: XFER_CKPT }],
    outputs: [{ lock: gasLock, capacity: capX - FEE }], outputsData: [F.f_checkpoint],
  });
  const tx3 = await client.sendTransaction(await signer.signTransaction(t3)); await client.waitTransaction(tx3);
  console.log("unbind checkpoint cell:", tx3);

  // (4) FINALIZE: consume the bound cell -> a plain cell (leap-out), NO bound output
  const capB = await cap(client, { txHash: tx2, index: 0 });
  const t4 = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: tx2, index: 0 } }],
    outputs: [{ lock: gasLock, capacity: capB - FEE }], outputsData: ["0x"],
    cellDeps: [{ outPoint: CODE, depType: "code" }, { outPoint: { txHash: tx3, index: 0 }, depType: "code" }],
  });
  setIT(t4, F.f_witness);
  const tx4 = await client.sendTransaction(await signer.signTransaction(t4));
  await Promise.race([client.waitTransaction(tx4), new Promise((r) => setTimeout(r, 120000))]);
  console.log(JSON.stringify({ finalizeUnified: CODE_HASH, deployTx: CODE.txHash, boundCellTx: tx2, unbindCheckpointTx: tx3, leapOutFinalizeTx: tx4 }, null, 2));
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); console.error((e.stack || "").split("\n").slice(1, 8).join("\n")); process.exit(1); });
