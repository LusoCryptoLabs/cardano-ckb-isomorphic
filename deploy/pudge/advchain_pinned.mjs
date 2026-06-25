// advchain_pinned.mjs - the SOUNDNESS-FIXED light client: genesis is PINNED to the one canonical bootstrap.
// Demonstrates: (NEG) a FAKE genesis (wrong avk) is REJECTED; (POS) the canonical genesis works, then the
// chain advances 1319->1320->1321 by verifying live certs. So no fake-avk chain can exist.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const ST = {
  gen1319: "0x27050000000000000f3c0c7f86ecb28acdc2fe03675a0c43ea00f4552e83bc620d4329646f3fe9da3d8b9dda433a0000",
  adv1320: "0x280500000000000013a8810b129d377a1ce7e7a2c29d0d93a2b22ab867c2ec7cabdf415215118f9a50910f94493a0000",
  adv1321: "0x2905000000000000a15b4c16a30a94208aab625b9796a5b1ecc0f88d9c14302450d79a4c418cd11658d09161503a0000",
  // a FAKE genesis: epoch 9999 + an attacker-controlled avk (all 0xAA). Must be rejected by the pinned verifier.
  fake:    "0x0f27000000000000" + "aa".repeat(32) + "0000000000000000",
};
const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key","utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/certverify/adv.bin")));
const verifier = ccc.Script.from({ codeHash: ccc.hashCkb(code), hashType:"data1", args:"0x" });
const w1319 = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/witness_1319.bin")));
const w1320 = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/witness_1320.bin")));
async function send(tx,l){ const h=await client.sendTransaction(await signer.signTransaction(tx)); console.log(`  ${l}: ${h}`); await client.waitTransaction(h,1,{timeout:180000}); return h; }

const t1=ccc.Transaction.from({outputs:[{lock:myLock}],outputsData:[code]}); await t1.completeInputsByCapacity(signer); await t1.completeFeeBy(signer,1000);
const dTx=await send(t1,"deploy PINNED advance verifier"); const codeDep={outPoint:{txHash:dTx,index:0},depType:"code"};
const tw1=ccc.Transaction.from({outputs:[{lock:myLock}],outputsData:[w1319]}); await tw1.completeInputsByCapacity(signer); await tw1.completeFeeBy(signer,1000);
const wTx1=await send(tw1,"witness cert_1319"); const wDep1={outPoint:{txHash:wTx1,index:0},depType:"code"};
const tw2=ccc.Transaction.from({outputs:[{lock:myLock}],outputsData:[w1320]}); await tw2.completeInputsByCapacity(signer); await tw2.completeFeeBy(signer,1000);
const wTx2=await send(tw2,"witness cert_1320"); const wDep2={outPoint:{txHash:wTx2,index:0},depType:"code"};

// (NEG) FAKE genesis - must be rejected
const fg=ccc.Transaction.from({outputs:[{lock:myLock,type:verifier,capacity:300_00000000n}],outputsData:[ST.fake],cellDeps:[codeDep,wDep1]});
await fg.completeInputsByCapacity(signer); await fg.completeFeeBy(signer,1000);
try{ const h=await client.sendTransaction(await signer.signTransaction(fg)); console.log("  (NEG) UNEXPECTED: fake genesis accepted",h); }
catch(e){ console.log("  (NEG) fake genesis REJECTED:", (e.message||String(e)).split("\n")[0].slice(0,150)); }

// (POS) canonical genesis -> advance 1319->1320->1321
const g=ccc.Transaction.from({outputs:[{lock:myLock,type:verifier,capacity:300_00000000n}],outputsData:[ST.gen1319],cellDeps:[codeDep,wDep1]});
await g.completeInputsByCapacity(signer); await g.completeFeeBy(signer,1000);
const genTx=await send(g,"(POS) CANONICAL genesis 1319");
const gc=await client.getCell({txHash:genTx,index:0}); const c1=BigInt(gc.cellOutput.capacity);
const a1=ccc.Transaction.from({inputs:[{previousOutput:{txHash:genTx,index:0}}],outputs:[{lock:myLock,type:verifier,capacity:c1-5_000_000n}],outputsData:[ST.adv1320],cellDeps:[codeDep,wDep1]});
await a1.completeFeeBy(signer,2000); const adv1=await send(a1,"ADVANCE 1319->1320");
const ac=await client.getCell({txHash:adv1,index:0}); const c2=BigInt(ac.cellOutput.capacity);
const a2=ccc.Transaction.from({inputs:[{previousOutput:{txHash:adv1,index:0}}],outputs:[{lock:myLock,type:verifier,capacity:c2-5_000_000n}],outputsData:[ST.adv1321],cellDeps:[codeDep,wDep2]});
await a2.completeFeeBy(signer,2000); const adv2=await send(a2,"ADVANCE 1320->1321");
console.log("DONE", JSON.stringify({genTx,adv1,adv2}));
process.exit(0);
