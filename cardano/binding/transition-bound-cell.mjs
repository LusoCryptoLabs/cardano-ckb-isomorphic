// transition-bound-cell.mjs - LIVE on Pudge: spend the bound cell (S0) -> new bound cell (S1).
// The new cell's transition_mint type script verifies the REAL certified Cardano transfer in-script.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import { gasSigner, funderLockOf, pudgeScripts } from "./testnet-pq-common.mjs";

const S1 = "0x" + Buffer.from("bound-asset:demo:v2 owner=bob").toString("hex");
const OLD_BOUND = { txHash: "0xab2f93a79a0517184a61f3456d96488988a2522f073fe41dcd2c92bbecc7997b", index: 0 };
const GENESIS_CODE = { txHash: "0xd2a650ec6000c027091aa87467fe19849e544037e825c901b0565945b5f29f68", index: 0 };

async function main() {
  const { client, signer } = gasSigner();
  const gasLock = await funderLockOf(signer);
  const { sighashDep } = await pudgeScripts(client);
  const bin = fs.readFileSync(new URL("./transition_mint.bin", import.meta.url));
  const code = ccc.hexFrom(new Uint8Array(bin));
  const codeHash = ccc.hashCkb(code);
  console.log("transition_mint codeHash:", codeHash, "size:", bin.length);

  // 1) deploy transition_mint code cell
  const dep = ccc.Transaction.from({ outputs: [{ lock: gasLock }], outputsData: [code] });
  await dep.completeInputsByCapacity(signer); await dep.completeFeeBy(signer, 1000);
  const depTx = await client.sendTransaction(await signer.signTransaction(dep));
  await client.waitTransaction(depTx);
  console.log("transition code cell:", depTx);

  // 2) spend old bound cell -> new bound cell (S1) with transition_mint type
  const newType = ccc.Script.from({ codeHash, hashType: "data1", args: "0x02" });
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: OLD_BOUND }],
    outputs: [{ lock: gasLock, type: newType }],
    outputsData: [S1],
    cellDeps: [
      { outPoint: { txHash: depTx, index: 0 }, depType: "code" },     // transition_mint (output type)
      { outPoint: GENESIS_CODE, depType: "code" },                    // genesis_mint (input type re-runs)
      sighashDep,                                                     // secp for the gas lock
    ],
  });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer, 1000);
  const txid = await client.sendTransaction(await signer.signTransaction(tx));
  await Promise.race([client.waitTransaction(txid), new Promise((r) => setTimeout(r, 90000))]);
  console.log(JSON.stringify({ transitionCode: codeHash, deployTx: depTx, transitionTx: txid, newState: S1 }));
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); console.error((e.stack||"").split("\n").slice(1,6).join("\n")); process.exit(1); });
