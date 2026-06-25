// lca.mjs - deploy the Mithril AdvanceCert verifier, genesis the epoch-320 checkpoint, then ADVANCE it
// to epoch 321 - the advance runs the FULL Mithril cert verify in-VM (BLS aggregate + 2330-index stake
// lottery + Merkle batch + quorum). This is the authenticated light-client checkpoint, live on Pudge.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const GEN = fs.readFileSync("/tmp/lcadvance/genesis_state.hex", "utf8").trim();
const ADV = fs.readFileSync("/tmp/lcadvance/advance_state.hex", "utf8").trim();

const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key", "utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/lcadvance/lca.bin")));
const codeHash = ccc.hashCkb(code);
console.log("verifier codeHash:", codeHash, "size", (code.length - 2) / 2, "B");

async function send(tx, label) {
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  console.log(`  ${label}: ${h}`); await client.waitTransaction(h); return h;
}

// (1) deploy the verifier code cell
const t1 = ccc.Transaction.from({ outputs: [{ lock: myLock }], outputsData: [code] });
await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer, 1000);
const dTx = await send(t1, "deploy AdvanceCert verifier");
const codeDep = { outPoint: { txHash: dTx, index: 0 }, depType: "code" };
const verifier = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" });

// (2) genesis the trusted epoch-320 checkpoint (type script runs the genesis branch)
const t2 = ccc.Transaction.from({
  outputs: [{ lock: myLock, type: verifier, capacity: 300_00000000n }], outputsData: [GEN],
  cellDeps: [codeDep],
});
await t2.completeInputsByCapacity(signer); await t2.completeFeeBy(signer, 1000);
const genTx = await send(t2, "genesis checkpoint (epoch 320, trusted)");

// (3) ADVANCE to epoch 321 - the FULL Mithril cert verify runs in-VM here
const genCell = await client.getCell({ txHash: genTx, index: 0 });
const cap = BigInt(genCell.cellOutput.capacity);
const t3 = ccc.Transaction.from({
  inputs: [{ previousOutput: { txHash: genTx, index: 0 } }],
  outputs: [{ lock: myLock, type: verifier, capacity: cap - 5_000_000n }], outputsData: [ADV],
  cellDeps: [codeDep],
});
await t3.completeFeeBy(signer, 2000);
const advTx = await client.sendTransaction(await signer.signTransaction(t3));
console.log("  ADVANCE 320->321 (full Mithril verify in-VM):", advTx);
await client.waitTransaction(advTx);
console.log("\nDONE " + JSON.stringify({ codeHash, deployTx: dTx, genesisTx: genTx, advanceTx: advTx }, null, 2));
process.exit(0);
