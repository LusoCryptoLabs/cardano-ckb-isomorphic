import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const AUTH_CKPT = { txHash: "0xe4e1b0c60509c784648debee6827f52043914c7f600bba9652bf1d558f619c2f", index: 0 };
const TX_ROOT = "ee048053e89cc50814df37b07cb58505dfd07dc066ed5dc3c3b61f5fefffd519";
const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key","utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/ckbunlock/bgu3.bin")));
const codeHash = ccc.hashCkb(code);
const lockScript = ccc.Script.from({ codeHash, hashType:"data1", args:"0x" });
console.log("bgu3 codeHash:", codeHash);
async function send(tx,l){ const h=await client.sendTransaction(await signer.signTransaction(tx)); console.log(`  ${l}: ${h}`); await client.waitTransaction(h,1,{timeout:180000}); return h; }
const t1=ccc.Transaction.from({outputs:[{lock:myLock}],outputsData:[code]}); await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer,1000);
const dTx=await send(t1,"deploy bgu3"); const codeDep={outPoint:{txHash:dTx,index:0},depType:"code"};
const t2=ccc.Transaction.from({outputs:[{lock:lockScript,capacity:200_00000000n}],outputsData:["0x"]}); await t2.completeInputsByCapacity(signer); await t2.completeFeeBy(signer,1000);
const lockTx=await send(t2,"lock 200 CKB");
const t3=ccc.Transaction.from({outputs:[{lock:myLock,capacity:100_00000000n}],outputsData:["0x4c434b50"+TX_ROOT]}); await t3.completeInputsByCapacity(signer); await t3.completeFeeBy(signer,1000);
const fakeTx=await send(t3,"unauthenticated checkpoint");
const lk=await client.getCell({txHash:lockTx,index:0}); const cap=BigInt(lk.cellOutput.capacity);
const tp=ccc.Transaction.from({inputs:[{previousOutput:{txHash:lockTx,index:0}}],outputs:[{lock:myLock,capacity:cap-2_000_000n}],outputsData:["0x"],cellDeps:[codeDep,{outPoint:AUTH_CKPT,depType:"code"}]});
const up=await client.sendTransaction(await signer.signTransaction(tp)); console.log("  POSITIVE unlock (authenticated):",up); await client.waitTransaction(up,1,{timeout:180000});
const t4=ccc.Transaction.from({outputs:[{lock:lockScript,capacity:200_00000000n}],outputsData:["0x"]}); await t4.completeInputsByCapacity(signer); await t4.completeFeeBy(signer,1000);
const lock2=await send(t4,"lock another 200"); const lk2=await client.getCell({txHash:lock2,index:0}); const cap2=BigInt(lk2.cellOutput.capacity);
const tn=ccc.Transaction.from({inputs:[{previousOutput:{txHash:lock2,index:0}}],outputs:[{lock:myLock,capacity:cap2-2_000_000n}],outputsData:["0x"],cellDeps:[codeDep,{outPoint:{txHash:fakeTx,index:0},depType:"code"}]});
try{const h=await client.sendTransaction(await signer.signTransaction(tn));console.log("  NEGATIVE UNEXPECTED accept:",h);}catch(e){console.log("  NEGATIVE expected reject:",(e.message||String(e)).split("\n")[0].slice(0,150));}
console.log("DONE_POS",up); process.exit(0);
