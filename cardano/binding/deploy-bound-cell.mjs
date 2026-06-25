// deploy-bound-cell.mjs - LIVE on Pudge: deploy the genesis_mint type script + mint the bound cell.
// The genesis_mint type script (embedding the REAL certified Cardano seal-mint proof) runs on the
// bound cell's CREATION, verifying Cardano->CKB. If it passes, a real bound cell exists on Pudge.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import { gasSigner, funderLockOf, findFund } from "./testnet-pq-common.mjs";

const S0 = "0x" + Buffer.from("bound-asset:demo:v1").toString("hex");

async function main() {
  const { client, signer } = gasSigner();
  const gasLock = await funderLockOf(signer);
  const bin = fs.readFileSync(new URL("./genesis_mint.bin", import.meta.url));
  const code = ccc.hexFrom(new Uint8Array(bin));
  const codeHash = ccc.hashCkb(code);
  console.log("genesis_mint codeHash:", codeHash, "size:", bin.length);

  // 1) deploy the script as a code cell (data1)
  const dep = ccc.Transaction.from({ outputs: [{ lock: gasLock }], outputsData: [code] });
  await dep.completeInputsByCapacity(signer);
  await dep.completeFeeBy(signer, 1000);
  const depTx = await client.sendTransaction(await signer.signTransaction(dep));
  await client.waitTransaction(depTx);
  console.log("code cell deployed:", depTx);
  const codeOutPoint = { txHash: depTx, index: 0 };

  // 2) mint the bound cell - type = genesis_mint; the type script RUNS on this output (creation)
  const typeScript = ccc.Script.from({ codeHash, hashType: "data1", args: "0x01" });
  const mint = ccc.Transaction.from({
    outputs: [{ lock: gasLock, type: typeScript }],
    outputsData: [S0],
    cellDeps: [{ outPoint: codeOutPoint, depType: "code" }],
  });
  await mint.completeInputsByCapacity(signer);
  await mint.completeFeeBy(signer, 1000);
  const mintTx = await client.sendTransaction(await signer.signTransaction(mint));
  await Promise.race([client.waitTransaction(mintTx), new Promise((r) => setTimeout(r, 90000))]);
  console.log(JSON.stringify({ codeHash, deployTx: depTx, boundCellTx: mintTx, boundState: S0 }) );
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); console.error((e.stack||"").split("\n").slice(1,5).join("\n")); process.exit(1); });
