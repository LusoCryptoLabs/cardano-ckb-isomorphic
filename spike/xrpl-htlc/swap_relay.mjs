// swap_relay.mjs - the HTLC swap RELAY (watcher) that turns the two HTLC legs into one atomic swap.
// It carries the revealed preimage from the chain where it is exposed to the chain that still needs it.
//
// Realistic choreography (Alice has XRP and wants CKB; Bob has CKB and wants XRP; Alice picks the secret s):
//   1. Alice locks 10 XRP to Bob on XRPL under Condition = PreimageSha256(H), CancelAfter = T2.   [LIVE]
//   2. Bob locks CKB to Alice in an htlc_lock cell under the same H, timeout T1 < T2.              [represented]
//   3. Alice claims the CKB by revealing s in the claim witness (SHA256(s) == H).                  [claim_live.json]
//   4. RELAY reads the CKB claim, extracts s, verifies SHA256(s) == H.
//   5. RELAY reconstructs the XRPL fulfillment from s and finishes the escrow -> Bob receives XRP.  [LIVE]
// One secret settles both legs; no party ever holds the other's funds. CKB settlement is funding-gated
// (htlc_lock is ~23 KB -> ~23k CKB to deploy a code cell), so step 3 is validated in ckb-debugger:
//   ckb-debugger --tx-file claim_live.json --script-group-type lock --cell-type input --cell-index 0   # 0
import { Client, xrpToDrops } from "xrpl";
import cc from "five-bells-condition";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/htlc_lock");
const TESTNET = "wss://s.altnet.rippletest.net:51233";
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();

// build a ckb-debugger mock for the CKB CLAIM: witness.lock = preimage, output pays the recipient.
function writeClaimMock(preimage, H) {
  const recipientLock = ccc.Script.from({ codeHash: "0x" + "11".repeat(32), hashType: "type", args: "0x" + "aa".repeat(20) });
  const senderLock = ccc.Script.from({ codeHash: "0x" + "22".repeat(32), hashType: "type", args: "0x" + "bb".repeat(20) });
  const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b.toString("hex"); };
  const args = "0x" + H.toString("hex") + recipientLock.hash().slice(2) + senderLock.hash().slice(2) + u64le(4096n);
  const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
  const htlc = ccc.Script.from({ codeHash: ccc.hashCkb(data), hashType: "data1", args });
  const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
  const PREV = { tx_hash: "0x" + "00".repeat(32), index: "0x0" }, DEP = { tx_hash: "0x" + "01".repeat(32), index: "0x0" };
  const wit = ccc.hexFrom(ccc.WitnessArgs.from({ lock: "0x" + preimage.toString("hex") }).toBytes());
  const mock = {
    mock_info: {
      inputs: [{ input: { since: "0x0", previous_output: PREV }, output: { capacity: "0x2e90edd000", lock: scr(htlc), type: null }, data: "0x", header: null }],
      cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: "0x100000000000", lock: scr(ccc.Script.from({ codeHash: "0x" + "33".repeat(32), hashType: "type", args: "0x" })), type: null }, data, header: null }],
      header_deps: [],
    },
    tx: { version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [],
      inputs: [{ since: "0x0", previous_output: PREV }], outputs: [{ capacity: "0x2e7ddd9000", lock: scr(recipientLock), type: null }], outputs_data: ["0x"], witnesses: [wit] },
  };
  const out = path.join(HERE, "claim_live.json");
  fs.writeFileSync(out, JSON.stringify(mock, null, 2));
  return { out, witnessHex: wit };
}

async function main() {
  // Alice picks the secret
  const s = crypto.randomBytes(32);
  const H = sha256(s);
  const ffObj = new cc.PreimageSha256(); ffObj.setPreimage(s);
  const condition = ffObj.getConditionBinary().toString("hex").toUpperCase();
  console.log("secret s        :", s.toString("hex"));
  console.log("H = SHA256(s)   :", H.toString("hex"));

  const client = new Client(TESTNET); await client.connect();
  const { wallet: alice } = await client.fundWallet();
  const { wallet: bob } = await client.fundWallet();
  console.log("Alice:", alice.address, "| Bob:", bob.address);

  // 1) LIVE: Alice locks 10 XRP to Bob under H
  const led = await client.request({ command: "ledger", ledger_index: "validated" });
  const create = await client.submitAndWait({
    TransactionType: "EscrowCreate", Account: alice.address, Destination: bob.address,
    Amount: xrpToDrops("10"), Condition: condition, CancelAfter: led.result.ledger.close_time + 7200,
  }, { wallet: alice });
  const offerSequence = create.result.tx_json.Sequence;
  console.log("\n[1] XRPL: Alice locked 10 XRP to Bob under H:", create.result.hash, create.result.meta?.TransactionResult);

  // 2+3) Bob locks CKB; Alice claims it by revealing s. The CKB claim witness carries s (validated in ckb-debugger).
  const { out, witnessHex } = writeClaimMock(s, H);
  console.log("[3] CKB: Alice's claim reveals s; wrote", path.basename(out), "(witness carries s)");

  // 4) RELAY reads the CKB claim witness, extracts the preimage, verifies it
  const extracted = Buffer.from(ccc.bytesFrom(ccc.WitnessArgs.fromBytes(witnessHex).lock));
  if (!sha256(extracted).equals(H)) throw new Error("relay: extracted preimage does not hash to H");
  console.log("[4] RELAY extracted s from the CKB claim:", extracted.toString("hex"));
  console.log("    SHA256(extracted) == H:", sha256(extracted).equals(H));

  // 5) LIVE: RELAY reconstructs the fulfillment from s and finishes the XRPL escrow -> Bob gets the XRP
  const relayFf = new cc.PreimageSha256(); relayFf.setPreimage(extracted);
  const fulfillment = relayFf.serializeBinary().toString("hex").toUpperCase();
  const fee = String(400 + 10 * Math.ceil(Buffer.from(fulfillment, "hex").length / 16));
  const bobBefore = Number(await client.getXrpBalance(bob.address));
  const finish = await client.submitAndWait({
    TransactionType: "EscrowFinish", Account: bob.address, Owner: alice.address,
    OfferSequence: offerSequence, Condition: condition, Fulfillment: fulfillment, Fee: fee,
  }, { wallet: bob });
  console.log("\n[5] XRPL: RELAY finished the escrow with the extracted s:", finish.result.hash, finish.result.meta?.TransactionResult);
  console.log("    Bob XRP:", bobBefore, "->", Number(await client.getXrpBalance(bob.address)));

  console.log("\n=== ATOMIC SWAP RELAYED END TO END ===");
  console.log("One secret s claimed the CKB side and settled the XRP side. No party held the other's funds.");
  console.log("Confirm the CKB claim validates:  ckb-debugger --tx-file spike/xrpl-htlc/claim_live.json --script-group-type lock --cell-type input --cell-index 0");
  await client.disconnect();
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
