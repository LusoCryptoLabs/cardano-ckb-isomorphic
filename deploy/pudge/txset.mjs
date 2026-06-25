// txset.mjs - deploy the TxSetCert verifier, then create the AUTHENTICATED tx-set checkpoint: the type
// script verifies the REAL CardanoTransactions cert (M1+BLS+lottery+merkle, 146M cycles) against the avk
// from the LIVE AdvanceCert checkpoint cellDep, and publishes LCKP||ee048053. C<->D link, live.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const TX_ROOT = "ee048053e89cc50814df37b07cb58505dfd07dc066ed5dc3c3b61f5fefffd519";
const CKPT_DATA = "0x4c434b50" + TX_ROOT;
const AVK_CHECKPOINT = { txHash: "0xb7ada085ef6d800cc89a85ed5b025a94c5d65f932244cfbaf9b92040ad6b88f7", index: 0 };

const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key", "utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/txset/txset.bin")));
const codeHash = ccc.hashCkb(code);
console.log("TxSetCert codeHash:", codeHash, "size", (code.length - 2) / 2, "B");

async function send(tx, label) {
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  console.log(`  ${label}: ${h}`); return h;
}

// (1) deploy the TxSetCert verifier
const t1 = ccc.Transaction.from({ outputs: [{ lock: myLock }], outputsData: [code] });
await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer, 1000);
const dTx = await send(t1, "deploy TxSetCert verifier");
await client.waitTransaction(dTx, 1, { timeout: 180000 });
const codeDep = { outPoint: { txHash: dTx, index: 0 }, depType: "code" };
const verifier = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" });

// (2) create the AUTHENTICATED tx-set checkpoint (type script verifies the cert vs the AVK checkpoint cellDep)
const t2 = ccc.Transaction.from({
  outputs: [{ lock: myLock, type: verifier, capacity: 300_00000000n }], outputsData: [CKPT_DATA],
  cellDeps: [codeDep, { outPoint: AVK_CHECKPOINT, depType: "code" }],
});
await t2.completeInputsByCapacity(signer); await t2.completeFeeBy(signer, 2000);
const cTx = await send(t2, "AUTHENTICATED tx-set checkpoint (LCKP||ee048053, cert verified in-VM)");
console.log("TXSET_CHECKPOINT_TX", cTx, "codeHash", codeHash);
process.exit(0);
