// escrow.mjs - demo the decentralized-relayer escrow on Pudge: (A) permissionless relay via the
// authenticated checkpoint, (B) timeout refund, (C) reject when neither holds.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const AUTH_CKPT = { txHash: "0xe4e1b0c60509c784648debee6827f52043914c7f600bba9652bf1d558f619c2f", index: 0 };
const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key","utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const myLockHash = myLock.hash();
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/escrow/escrow.bin")));
const codeHash = ccc.hashCkb(code);
const escrowLock = ccc.Script.from({ codeHash, hashType:"data1", args:"0x" });
const u64le = (n) => { const b=new Uint8Array(8); let v=BigInt(n); for(let i=0;i<8;i++){b[i]=Number(v&0xffn);v>>=8n;} return b; };
const escrowData = (deadline) => ccc.hexFrom(new Uint8Array([...ccc.bytesFrom(myLockHash), ...u64le(deadline)]));
async function send(tx,l){ const h=await client.sendTransaction(await signer.signTransaction(tx)); console.log(`  ${l}: ${h}`); await client.waitTransaction(h,1,{timeout:180000}); return h; }

const t1 = ccc.Transaction.from({ outputs:[{lock:myLock}], outputsData:[code] });
await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer,1000);
const dTx = await send(t1,"deploy escrow"); const codeDep={outPoint:{txHash:dTx,index:0},depType:"code"};

async function mkEscrow(deadline,label){
  const t = ccc.Transaction.from({ outputs:[{lock:escrowLock, capacity:200_00000000n}], outputsData:[escrowData(deadline)] });
  await t.completeInputsByCapacity(signer); await t.completeFeeBy(signer,1000);
  return await send(t, label);
}
// (A) permissionless relay: spend via the authenticated checkpoint (NO signature on the escrow input)
const e1 = await mkEscrow(1,"escrow #1 (relay)");
const c1 = await client.getCell({txHash:e1,index:0}); const cap1=BigInt(c1.cellOutput.capacity);
const tr = ccc.Transaction.from({ inputs:[{previousOutput:{txHash:e1,index:0}}], outputs:[{lock:myLock,capacity:cap1-2_000_000n}], outputsData:["0x"], cellDeps:[codeDep,{outPoint:AUTH_CKPT,depType:"code"}] });
const relayTx = await client.sendTransaction(await signer.signTransaction(tr));
console.log("  (A) PERMISSIONLESS RELAY (no key, via authenticated checkpoint):", relayTx); await client.waitTransaction(relayTx,1,{timeout:180000});

// (B) timeout refund: deadline=1 (past), input since=1, output to depositor
const e2 = await mkEscrow(1,"escrow #2 (refund)");
const c2 = await client.getCell({txHash:e2,index:0}); const cap2=BigInt(c2.cellOutput.capacity);
const tf = ccc.Transaction.from({ inputs:[{previousOutput:{txHash:e2,index:0}, since:1n}], outputs:[{lock:myLock,capacity:cap2-2_000_000n}], outputsData:["0x"], cellDeps:[codeDep] });
const refundTx = await client.sendTransaction(await signer.signTransaction(tf));
console.log("  (B) TIMEOUT REFUND (since>=deadline, to depositor):", refundTx); await client.waitTransaction(refundTx,1,{timeout:180000});

// (C) negative: deadline far future, since=0, no checkpoint -> reject
const e3 = await mkEscrow(99000000,"escrow #3 (neg)");
const c3 = await client.getCell({txHash:e3,index:0}); const cap3=BigInt(c3.cellOutput.capacity);
const tn = ccc.Transaction.from({ inputs:[{previousOutput:{txHash:e3,index:0}}], outputs:[{lock:myLock,capacity:cap3-2_000_000n}], outputsData:["0x"], cellDeps:[codeDep] });
try { const h=await client.sendTransaction(await signer.signTransaction(tn)); console.log("  (C) UNEXPECTED accept:",h); }
catch(e){ console.log("  (C) NEGATIVE expected reject:", (e.message||String(e)).split("\n")[0].slice(0,150)); }
console.log("DONE", JSON.stringify({relayTx, refundTx}));
process.exit(0);
