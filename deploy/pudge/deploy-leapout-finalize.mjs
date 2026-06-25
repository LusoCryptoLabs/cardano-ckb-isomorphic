// deploy-leapout-finalize.mjs - LIVE Phase-3: the symmetric leg (leap-out finalize) on Pudge.
// (1) reclaim the Phase-1 unified code cell -> deploy the finalize-capable unified BoundAsset;
// (2) genesis a bound cell under it bound to seal a98b6636 (state v2), using the certified transfer
//     proof + the existing transfer checkpoint (root 5acd33ab, live @0xae6427d8);
// (3) deploy the UNBIND checkpoint (root 0bc33aa8); (4) FINALIZE: spend that bound cell with NO
//     output cell, proving the certified Unbind tx (6c729ea6) consumed the seal and did NOT recreate
//     it at the binding_lock. The asset is unbound; ownership is a plain Cardano UTxO again.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import { gasSigner, funderLockOf } from "./testnet-pq-common.mjs";
const T = JSON.parse(fs.readFileSync(new URL("./p1t_hex.json", import.meta.url)));
const F = JSON.parse(fs.readFileSync(new URL("./p1f_hex.json", import.meta.url)));
const RECLAIM = { txHash: "0xf8644bd38a84749d67f877047eecd2dcce4d624dc02e3b832b01fe1195757c33", index: 0 };
const XFER_CKPT = { txHash: "0xae6427d8e6e0a8ad37c58a0ba2fa13fe1fd5bd9bc9f6cacdf59d4c7d3b04987f", index: 0 }; // root 5acd33ab

const setIT = (tx, hex) => tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: hex }));

async function main() {
  const { client, signer } = gasSigner();
  const gasLock = await funderLockOf(signer);
  const bin = fs.readFileSync(new URL("./bound_asset_unified_v2.bin", import.meta.url));
  const code = ccc.hexFrom(new Uint8Array(bin));
  const codeHash = ccc.hashCkb(code);

  // (1) reclaim Phase-1 unified code cell -> deploy finalize-capable unified
  const t1 = ccc.Transaction.from({ inputs: [{ previousOutput: RECLAIM }], outputs: [{ lock: gasLock }], outputsData: [code] });
  await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer, 1000);
  const tx1 = await client.sendTransaction(await signer.signTransaction(t1)); await client.waitTransaction(tx1);
  console.log("finalize-capable unified deployed:", tx1, "codeHash", codeHash);

  const ty = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" });

  // (2) genesis a bound cell under the new script, bound to seal a98b6636 (state v2)
  const t2 = ccc.Transaction.from({
    outputs: [{ lock: gasLock, type: ty }], outputsData: [T.t_out],
    cellDeps: [{ outPoint: { txHash: tx1, index: 0 }, depType: "code" }, { outPoint: XFER_CKPT, depType: "code" }],
  });
  await t2.completeInputsByCapacity(signer); setIT(t2, T.t_witness); await t2.completeFeeBy(signer, 1000); setIT(t2, T.t_witness);
  const tx2 = await client.sendTransaction(await signer.signTransaction(t2)); await client.waitTransaction(tx2);
  console.log("bound cell (seal a98b6636, state v2) minted under new script:", tx2);

  // (3) deploy the UNBIND checkpoint cell (root 0bc33aa8)
  const t3 = ccc.Transaction.from({ outputs: [{ lock: gasLock }], outputsData: [F.f_checkpoint] });
  await t3.completeInputsByCapacity(signer); await t3.completeFeeBy(signer, 1000);
  const tx3 = await client.sendTransaction(await signer.signTransaction(t3)); await client.waitTransaction(tx3);
  console.log("unbind checkpoint cell:", tx3);

  // (4) FINALIZE: consume the bound cell, NO output bound cell (leap-out)
  const t4 = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: tx2, index: 0 } }],
    outputs: [{ lock: gasLock }], outputsData: ["0x"],     // a plain change cell, NOT a bound cell
    cellDeps: [{ outPoint: { txHash: tx1, index: 0 }, depType: "code" }, { outPoint: { txHash: tx3, index: 0 }, depType: "code" }],
  });
  await t4.completeInputsByCapacity(signer); setIT(t4, F.f_witness); await t4.completeFeeBy(signer, 1000); setIT(t4, F.f_witness);
  const tx4 = await client.sendTransaction(await signer.signTransaction(t4));
  await Promise.race([client.waitTransaction(tx4), new Promise((r) => setTimeout(r, 120000))]);
  console.log(JSON.stringify({ finalizeUnified: codeHash, deployTx: tx1, boundCellTx: tx2, unbindCheckpointTx: tx3, leapOutFinalizeTx: tx4 }, null, 2));
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); console.error((e.stack || "").split("\n").slice(1, 8).join("\n")); process.exit(1); });
