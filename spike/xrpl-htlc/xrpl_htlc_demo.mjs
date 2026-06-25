// xrpl_htlc_demo.mjs - LIVE proof of bridge Mode B (HTLC) on the XRP Ledger testnet.
//
// Thesis: a non-programmable chain (XRPL, no smart contracts) still joins the bridge as an atomic-swap leg,
// because XRPL has NATIVE escrow with a PreimageSha256 crypto-condition (a hashlock) plus CancelAfter (a
// timelock). One shared secret s with H = SHA256(s) links this XRPL escrow to a CKB hashlock cell: whoever
// reveals s to claim one side exposes s for the other side. No light client, no SNARK, no wrapped asset.
//
// This script plays both roles with two funded testnet wallets to demonstrate the mechanism end to end:
//   Alice locks XRP to Bob under Condition=PreimageSha256(H), CancelAfter=T.
//   Bob finishes the escrow with Fulfillment=s  -> Bob receives the XRP, and s is now public on-ledger.
import { Client, Wallet, xrpToDrops } from "xrpl";
import cc from "five-bells-condition";
import crypto from "node:crypto";

const TESTNET = "wss://s.altnet.rippletest.net:51233";

// getXrpBalance already returns a value in XRP (not drops), so do not convert again.
async function bal(client, addr) {
  try { return Number(await client.getXrpBalance(addr)); } catch { return 0; }
}

async function main() {
  // 1) the shared secret and its hashlock (this exact H also locks the CKB side)
  const preimage = crypto.randomBytes(32);
  const H = crypto.createHash("sha256").update(preimage).digest("hex").toUpperCase();
  const ff = new cc.PreimageSha256();
  ff.setPreimage(preimage);
  const condition = ff.getConditionBinary().toString("hex").toUpperCase();
  const fulfillment = ff.serializeBinary().toString("hex").toUpperCase();
  console.log("shared secret s (preimage):", preimage.toString("hex"));
  console.log("H = SHA256(s)             :", H, "  <- same hashlock used on the CKB side");
  console.log("XRPL condition (PreimageSha256):", condition);

  const client = new Client(TESTNET);
  await client.connect();
  console.log("\nconnected to XRPL testnet:", TESTNET);

  // 2) fund two testnet wallets (faucet)
  console.log("funding Alice + Bob from the testnet faucet...");
  const { wallet: alice } = await client.fundWallet();
  const { wallet: bob } = await client.fundWallet();
  console.log("Alice:", alice.address, "balance", await bal(client, alice.address), "XRP");
  console.log("Bob  :", bob.address, "balance", await bal(client, bob.address), "XRP");
  const bobBefore = Number(await bal(client, bob.address));

  // 3) Alice locks 10 XRP to Bob under the hashlock + a 1h cancel timelock
  const ledger = await client.request({ command: "ledger", ledger_index: "validated" });
  const closeTime = ledger.result.ledger.close_time; // ripple-epoch seconds
  const cancelAfter = closeTime + 3600;
  const create = await client.submitAndWait({
    TransactionType: "EscrowCreate",
    Account: alice.address,
    Destination: bob.address,
    Amount: xrpToDrops("10"),
    Condition: condition,
    CancelAfter: cancelAfter,
  }, { wallet: alice });
  const createResult = create.result.meta?.TransactionResult;
  const offerSequence = create.result.tx_json.Sequence;
  console.log("\nEscrowCreate (Alice locks 10 XRP under H):", create.result.hash, createResult);
  console.log("  escrow OfferSequence:", offerSequence, "| CancelAfter:", cancelAfter, "(refund path)");
  if (createResult !== "tesSUCCESS") throw new Error("EscrowCreate failed: " + createResult);

  // 4) Bob finishes the escrow by revealing the fulfillment (the preimage) -> receives the XRP
  const ffBytes = Buffer.from(fulfillment, "hex").length;
  const fee = String(400 + 10 * Math.ceil(ffBytes / 16)); // >= 330 + 10/16B per the XRPL rule, with margin
  const finish = await client.submitAndWait({
    TransactionType: "EscrowFinish",
    Account: bob.address,
    Owner: alice.address,
    OfferSequence: offerSequence,
    Condition: condition,
    Fulfillment: fulfillment,
    Fee: fee,
  }, { wallet: bob });
  const finishResult = finish.result.meta?.TransactionResult;
  console.log("\nEscrowFinish (Bob reveals s to claim):", finish.result.hash, finishResult);
  if (finishResult !== "tesSUCCESS") throw new Error("EscrowFinish failed: " + finishResult);

  const bobAfter = Number(await bal(client, bob.address));
  console.log("  Bob balance:", bobBefore, "->", bobAfter, "XRP (delta ~+10 minus fee)");

  // 5) the secret is now public on-ledger (the Fulfillment), which is what settles the CKB side
  console.log("\n=== XRPL HTLC LEG PROVEN ===");
  console.log("Condition was met ONLY by revealing s; s = " + preimage.toString("hex"));
  console.log("That same s claims the CKB hashlock cell locked under H = " + H);
  console.log("explorer: https://testnet.xrpl.org/transactions/" + finish.result.hash);

  await client.disconnect();
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
