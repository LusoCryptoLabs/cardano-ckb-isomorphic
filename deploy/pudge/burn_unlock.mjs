// burn_unlock.mjs - deploy the burn-gated-unlock LOCK script, lock CKB under it, then UNLOCK it by
// presenting the Mithril-certified-burn proof (the script reads the certified root from a checkpoint
// cellDep and verifies burn 6608c4c8 is in it). No key authorizes the unlock - the certified burn does.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const CERT_ROOT = "ee048053e89cc50814df37b07cb58505dfd07dc066ed5dc3c3b61f5fefffd519"; // certified tx-set root
const CKPT_DATA = "0x4c434b50" + CERT_ROOT; // "LCKP" || root

const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key", "utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/ckbunlock/bgu.bin")));
const codeHash = ccc.hashCkb(code);
console.log("script codeHash:", codeHash, "size", (code.length - 2) / 2, "B");

async function send(tx, label) {
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  console.log(`  ${label}: ${h}`); await client.waitTransaction(h); return h;
}

// (1) deploy the script code cell + the checkpoint cell (LCKP||cert_root), both under our lock
const t1 = ccc.Transaction.from({
  outputs: [{ lock: myLock }, { lock: myLock, capacity: 100_00000000n }],
  outputsData: [code, CKPT_DATA],
});
await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer, 1000);
const dTx = await send(t1, "deploy code cell @:0 + checkpoint cell @:1");
const codeDep = { outPoint: { txHash: dTx, index: 0 }, depType: "code" };
const ckptDep = { outPoint: { txHash: dTx, index: 1 }, depType: "code" };

// (2) lock CKB behind the burn-gated-unlock script (hashType data1, no args)
const lockScript = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" });
const t2 = ccc.Transaction.from({
  outputs: [{ lock: lockScript, capacity: 150_00000000n }], outputsData: ["0x"],
});
await t2.completeInputsByCapacity(signer); await t2.completeFeeBy(signer, 1000);
const lockTx = await send(t2, "LOCK 150 CKB behind the burn-gated-unlock script");

// (3) UNLOCK: spend the locked cell. The lock script runs, reads the checkpoint cellDep, and verifies
//     the certified-burn MKMapProof in-VM. No signature gates this - the proof does.
const locked = await client.getCell({ txHash: lockTx, index: 0 });
const cap = BigInt(locked.cellOutput.capacity);
const t3 = ccc.Transaction.from({
  inputs: [{ previousOutput: { txHash: lockTx, index: 0 } }],
  outputs: [{ lock: myLock, capacity: cap - 2_000_000n }], outputsData: ["0x"],
  cellDeps: [codeDep, ckptDep],
});
const unlockTx = await client.sendTransaction(await signer.signTransaction(t3));
console.log("  UNLOCK (gated by the certified burn, not a key):", unlockTx);
await client.waitTransaction(unlockTx);
console.log("\nDONE " + JSON.stringify({ codeHash, deployTx: dTx, lockTx, unlockTx }, null, 2));
process.exit(0);
