// Negative test: the burn-gated-unlock lock must REJECT a spend that lacks the certified-burn proof
// (no checkpoint cellDep). Proves the gate is real, not an always-success script.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key", "utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/ckbunlock/bgu.bin")));
const codeHash = ccc.hashCkb(code);
const DEPLOY = { txHash: "0x973f164ca35c062e833b880d71153bd9d6480a98ed08e66f0ca1dae9d337299a", index: 0 };
const codeDep = { outPoint: DEPLOY, depType: "code" };
const lockScript = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" });

// lock a fresh cell
const t1 = ccc.Transaction.from({ outputs: [{ lock: lockScript, capacity: 150_00000000n }], outputsData: ["0x"] });
await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer, 1000);
const lockTx = await client.sendTransaction(await signer.signTransaction(t1));
console.log("locked cell:", lockTx); await client.waitTransaction(lockTx);

// try to unlock WITHOUT the checkpoint cellDep -> the script returns 10 (no checkpoint) -> must fail
const locked = await client.getCell({ txHash: lockTx, index: 0 });
const cap = BigInt(locked.cellOutput.capacity);
const t2 = ccc.Transaction.from({
  inputs: [{ previousOutput: { txHash: lockTx, index: 0 } }],
  outputs: [{ lock: myLock, capacity: cap - 2_000_000n }], outputsData: ["0x"],
  cellDeps: [codeDep], // <-- NO checkpoint cellDep on purpose
});
try {
  const h = await client.sendTransaction(await signer.signTransaction(t2));
  console.log("UNEXPECTED: spend accepted without proof:", h);
  process.exit(2);
} catch (e) {
  const m = (e.message || String(e));
  console.log("EXPECTED REJECT (gate works):", m.split("\n")[0].slice(0, 200));
  process.exit(0);
}
