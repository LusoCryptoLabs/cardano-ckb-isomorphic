// close.mjs - close the stranded CKB leap-out FINALIZE with a fresh, funded key, reusing the
// already-deployed finalize verifier (0x97ca700d) as a cellDep. Recreates the checkpoint cells
// (data is committed in p1t_hex/p1f_hex) under our own lock, genesis-binds a fresh bound cell, then
// FINALIZE-spends it (no bound output) against the real certified Unbind 6c729ea6 - the leap-out.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const REPO = "/home/user/cardano-ckb-isomorphic/deploy/pudge";
const T = JSON.parse(fs.readFileSync(`${REPO}/p1t_hex.json`));
const F = JSON.parse(fs.readFileSync(`${REPO}/p1f_hex.json`));
const CODE = { txHash: "0x97ca700d6ea2cdf1504e4a0fa71e0fd86bda19bf92faacf66a1c10738f1c4885", index: 0 };
const CODE_HASH = "0xbeaff4d349e7f75892747f8070c6a85c641c7bd97957de86773787c07548701a";
const setIT = (tx, hex) => tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: hex }));

const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key", "utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const codeDep = { outPoint: CODE, depType: "code" };
const ty = ccc.Script.from({ codeHash: CODE_HASH, hashType: "data1", args: "0x" });

async function send(tx, label) {
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  console.log(`  ${label}: ${h}`);
  await client.waitTransaction(h);
  return h;
}

// (1) recreate the two light-client checkpoint cells under OUR lock (data == the certified roots)
const tCk = ccc.Transaction.from({
  outputs: [{ lock: myLock, capacity: 100_00000000n }, { lock: myLock, capacity: 100_00000000n }],
  outputsData: [T.t_checkpoint, F.f_checkpoint],
});
await tCk.completeInputsByCapacity(signer); await tCk.completeFeeBy(signer, 1000);
const ckTx = await send(tCk, "checkpoint cells (transfer root 5acd33ab @:0, unbind root 0bc33aa8 @:1)");
const xferCkptDep = { outPoint: { txHash: ckTx, index: 0 }, depType: "code" };
const unbindCkptDep = { outPoint: { txHash: ckTx, index: 1 }, depType: "code" };

// (2) GENESIS a bound cell under the deployed finalize verifier, bound to seal a98b6636 (state v2)
const tB = ccc.Transaction.from({
  outputs: [{ lock: myLock, type: ty, capacity: 200_00000000n }], outputsData: [T.t_out],
  cellDeps: [codeDep, xferCkptDep],
});
await tB.completeInputsByCapacity(signer); setIT(tB, T.t_witness); await tB.completeFeeBy(signer, 1000); setIT(tB, T.t_witness);
const boundTx = await send(tB, "bound cell (seal a98b6636 v2) minted under finalize verifier");

// (3) FINALIZE: consume the bound cell -> plain cell, NO bound output (leap-out), against Unbind 6c729ea6
const boundCell = await client.getCell({ txHash: boundTx, index: 0 });
const capB = BigInt(boundCell.cellOutput.capacity);
const tF = ccc.Transaction.from({
  inputs: [{ previousOutput: { txHash: boundTx, index: 0 } }],
  outputs: [{ lock: myLock, capacity: capB - 2_000_000n }], outputsData: ["0x"],
  cellDeps: [codeDep, unbindCkptDep],
});
setIT(tF, F.f_witness); await tF.completeFeeBy(signer, 1000); setIT(tF, F.f_witness);
const finalizeTx = await send(tF, "LEAP-OUT FINALIZE (bound cell destroyed, asset unbound)");

console.log("\nDONE " + JSON.stringify({ checkpointsTx: ckTx, boundCellTx: boundTx, leapOutFinalizeTx: finalizeTx }, null, 2));
process.exit(0);
