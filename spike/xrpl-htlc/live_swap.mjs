// live_swap.mjs - a FULLY LIVE on-chain HTLC swap: XRPL testnet <-> CKB Pudge, both legs real, one secret.
//
// Choreography (Alice has XRP, wants CKB; Bob has CKB, wants XRP; Alice picks s):
//   1. Alice locks 10 XRP to Bob on XRPL under Condition = PreimageSha256(H), CancelAfter.        [LIVE XRPL]
//   2. Bob locks 200 CKB to Alice in an htlc_lock cell on Pudge under the same H.                  [LIVE CKB tx1]
//   3. Alice claims the CKB on-chain by revealing s in the claim witness (SHA256(s)==H).           [LIVE CKB tx2]
//   4. The relay reads s from the on-chain CKB claim witness and finishes the XRPL escrow.         [LIVE XRPL]
// One secret settles both legs, on both real chains. (Roles are all played by our keys for the demo.)
import { Client, xrpToDrops } from "xrpl";
import cc from "five-bells-condition";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/htlc_lock");
const DEPLOY_JSON = path.join(HERE, "htlc_deploy.json");
const TESTNET = "wss://s.altnet.rippletest.net:51233";
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b.toString("hex"); };

function ckbSigner() {
  const client = new ccc.ClientPublicTestnet();
  const key = fs.readFileSync(path.join(os.homedir(), ".chiral", "pudge_relayer.key"), "utf8").trim();
  return { client, signer: new ccc.SignerCkbPrivateKey(client, key) };
}
const waitTx = (client, h) => client.waitTransaction(h, 1, { timeout: 180000 });

async function deployHtlc(client, signer, lock) {
  if (fs.existsSync(DEPLOY_JSON)) {
    const d = JSON.parse(fs.readFileSync(DEPLOY_JSON, "utf8"));
    if (await client.getCellLive({ txHash: d.txHash, index: 0 }, true).catch(() => null)) { console.log("htlc_lock already deployed:", d.codeHash); return d; }
  }
  const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
  const codeHash = ccc.hashCkb(data);
  const tx = ccc.Transaction.from({ outputs: [{ lock }], outputsData: [data] });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer, 1000);
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  await waitTx(client, h);
  const d = { txHash: h, index: 0, codeHash, dep: { outPoint: { txHash: h, index: 0 }, depType: "code" } };
  fs.writeFileSync(DEPLOY_JSON, JSON.stringify(d, null, 2));
  console.log("htlc_lock DEPLOYED:", h, "codeHash", codeHash);
  return d;
}

async function main() {
  const s = crypto.randomBytes(32);
  const H = sha256(s);
  console.log("secret s      :", s.toString("hex"));
  console.log("H = SHA256(s) :", H.toString("hex"));

  const { client, signer } = ckbSigner();
  const myLock = (await signer.getAddressObjs())[0].script;
  const deploy = await deployHtlc(client, signer, myLock);

  const xrpl = new Client(TESTNET); await xrpl.connect();
  const { wallet: alice } = await xrpl.fundWallet();
  const { wallet: bob } = await xrpl.fundWallet();

  // 1) LIVE XRPL: Alice locks 10 XRP to Bob under H
  const ffObj = new cc.PreimageSha256(); ffObj.setPreimage(s);
  const condition = ffObj.getConditionBinary().toString("hex").toUpperCase();
  const led = await xrpl.request({ command: "ledger", ledger_index: "validated" });
  const create = await xrpl.submitAndWait({ TransactionType: "EscrowCreate", Account: alice.address, Destination: bob.address,
    Amount: xrpToDrops("10"), Condition: condition, CancelAfter: led.result.ledger.close_time + 7200 }, { wallet: alice });
  const offerSequence = create.result.tx_json.Sequence;
  console.log("\n[1] XRPL  Alice locked 10 XRP to Bob under H:", create.result.hash, create.result.meta?.TransactionResult);

  // 2) LIVE CKB: lock 200 CKB in an htlc_lock cell under H (recipient + sender = our lock for the demo)
  const myHash = myLock.hash();
  const htlcArgs = "0x" + H.toString("hex") + myHash.slice(2) + myHash.slice(2) + u64le(4096n);
  const htlcLock = ccc.Script.from({ codeHash: deploy.codeHash, hashType: "data1", args: htlcArgs });
  const lockTx = ccc.Transaction.from({ outputs: [{ lock: htlcLock, capacity: 200_00000000n }], outputsData: ["0x"] });
  await lockTx.completeInputsByCapacity(signer);
  await lockTx.completeFeeBy(signer, 1000);
  const h1 = await client.sendTransaction(await signer.signTransaction(lockTx));
  await waitTx(client, h1);
  console.log("[2] CKB   locked 200 CKB in an htlc_lock cell under H:", h1 + ":0");

  // 3) LIVE CKB: claim the htlc cell by revealing s (no signature; the lock checks SHA256(s)==H + output to recipient)
  const FEE = 1_000_000n;
  const claimTx = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: h1, index: 0 }, since: 0n }],
    outputs: [{ lock: myLock, capacity: 200_00000000n - FEE }],
    outputsData: ["0x"], cellDeps: [deploy.dep],
  });
  claimTx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + s.toString("hex") }));
  const h2 = await client.sendTransaction(claimTx);
  await waitTx(client, h2);
  console.log("[3] CKB   claimed by revealing s (preimage in witness):", h2, "<- s is now public on CKB");

  // 4) RELAY: read s from the on-chain CKB claim witness, finish the XRPL escrow with it
  const claimed = await client.getTransaction(h2);
  const wlock = ccc.WitnessArgs.fromBytes(claimed.transaction.witnesses[0]).lock;
  const extracted = Buffer.from(ccc.bytesFrom(wlock));
  if (!sha256(extracted).equals(H)) throw new Error("relay: on-chain preimage does not hash to H");
  console.log("[4] RELAY extracted s from the CKB claim witness on-chain:", extracted.toString("hex"));
  const relayFf = new cc.PreimageSha256(); relayFf.setPreimage(extracted);
  const fulfillment = relayFf.serializeBinary().toString("hex").toUpperCase();
  const fee = String(400 + 10 * Math.ceil(Buffer.from(fulfillment, "hex").length / 16));
  const bobBefore = Number(await xrpl.getXrpBalance(bob.address));
  const finish = await xrpl.submitAndWait({ TransactionType: "EscrowFinish", Account: bob.address, Owner: alice.address,
    OfferSequence: offerSequence, Condition: condition, Fulfillment: fulfillment, Fee: fee }, { wallet: bob });
  console.log("    XRPL  RELAY finished the escrow with the on-chain s:", finish.result.hash, finish.result.meta?.TransactionResult);
  console.log("    Bob XRP:", bobBefore, "->", Number(await xrpl.getXrpBalance(bob.address)));

  console.log("\n=== FULLY LIVE HTLC SWAP, BOTH CHAINS ===");
  console.log("CKB claim:  https://testnet.explorer.nervos.org/transaction/" + h2);
  console.log("XRPL finish: https://testnet.xrpl.org/transactions/" + finish.result.hash);
  await xrpl.disconnect();
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
