// txset2.mjs - deploy the PARAMETERIZED cert verifier (witness-driven), then create an authenticated
// tx-set checkpoint where the cert is supplied via a WITNESS cellDep (transcoded by the relayer), not an
// embedded fixture. Proves the light client can verify ANY live cert. Reuses the live AVK checkpoint.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const AVK_CHECKPOINT = { txHash: "0xb7ada085ef6d800cc89a85ed5b025a94c5d65f932244cfbaf9b92040ad6b88f7", index: 0 };
const TX_ROOT = "ee048053e89cc50814df37b07cb58505dfd07dc066ed5dc3c3b61f5fefffd519";
const CKPT_DATA = "0x4c434b50" + TX_ROOT;
const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key","utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/certverify/cv.bin")));
const codeHash = ccc.hashCkb(code);
const witness = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/cert_witness.bin")));
console.log("cert_verify codeHash:", codeHash, "witness", (witness.length-2)/2, "B");
async function send(tx,l){ const h=await client.sendTransaction(await signer.signTransaction(tx)); console.log(`  ${l}: ${h}`); await client.waitTransaction(h,1,{timeout:180000}); return h; }

// (1) deploy the parameterized verifier
const t1 = ccc.Transaction.from({ outputs:[{lock:myLock}], outputsData:[code] });
await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer,1000);
const dTx = await send(t1,"deploy parameterized cert_verify");
const codeDep = { outPoint:{txHash:dTx,index:0}, depType:"code" };
const verifier = ccc.Script.from({ codeHash, hashType:"data1", args:"0x" });

// (2) create the WITNESS cell (relayer-transcoded cert)
const t2 = ccc.Transaction.from({ outputs:[{lock:myLock}], outputsData:[witness] });
await t2.completeInputsByCapacity(signer); await t2.completeFeeBy(signer,1000);
const wTx = await send(t2,"witness cell (MWIT||cert)");
const witDep = { outPoint:{txHash:wTx,index:0}, depType:"code" };

// (3) authenticated tx-set checkpoint via the PARAMETERIZED verifier reading the witness
const t3 = ccc.Transaction.from({
  outputs:[{lock:myLock, type:verifier, capacity:300_00000000n}], outputsData:[CKPT_DATA],
  cellDeps:[codeDep, {outPoint:AVK_CHECKPOINT,depType:"code"}, witDep],
});
await t3.completeInputsByCapacity(signer); await t3.completeFeeBy(signer,2000);
const cTx = await send(t3,"AUTHENTICATED checkpoint via WITNESS-supplied cert");
console.log("WITNESS_CHECKPOINT_TX", cTx);
process.exit(0);
