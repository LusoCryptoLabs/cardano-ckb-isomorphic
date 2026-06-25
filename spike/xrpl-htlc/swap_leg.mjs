// swap_leg.mjs - a reusable Mode B (HTLC) swap-leg interface between XRPL and CKB, with a bidirectional
// watcher and timelock-ordering safety. Generalizes live_swap.mjs into a unit a relayer/SDK can drive.
//
// The leg never holds either party's funds. Safety is the standard HTLC property: you either swap (one secret
// settles both sides) or refund (each side's timelock returns the funds). The one rule that MUST hold before
// you lock the second leg is timelock ordering: the chain you claim FIRST must time out BEFORE the chain you
// settle SECOND, with margin for the watcher to react. `safeToLockSecondLeg` enforces it.
import { Client, xrpToDrops } from "xrpl";
import cc from "five-bells-condition";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b.toString("hex"); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class XrplCkbHtlcLeg {
  constructor({ ckbClient, ckbSigner, ckbLock, xrplClient, htlcCodeHash, htlcDep }) {
    Object.assign(this, { ckbClient, ckbSigner, ckbLock, xrplClient, htlcCodeHash, htlcDep });
  }

  // a fresh shared secret and its XRPL condition (H is the hashlock used identically on both chains).
  static newSecret() {
    const s = crypto.randomBytes(32);
    const ff = new cc.PreimageSha256(); ff.setPreimage(s);
    return { s, H: sha256(s), condition: ff.getConditionBinary().toString("hex").toUpperCase() };
  }
  static fulfillmentFromSecret(s) { const ff = new cc.PreimageSha256(); ff.setPreimage(s); return ff.serializeBinary().toString("hex").toUpperCase(); }

  // SAFETY: claim-first chain must refund before settle-second chain, with margin. All args are seconds-from-now.
  static safeToLockSecondLeg({ claimFirstRefundInSec, settleSecondRefundInSec, marginSec = 1800 }) {
    return claimFirstRefundInSec + marginSec < settleSecondRefundInSec;
  }

  // ---- XRPL side ----
  async lockXrpl({ wallet, destination, amountXrp, condition, cancelAfter }) {
    const r = await this.xrplClient.submitAndWait({ TransactionType: "EscrowCreate", Account: wallet.address,
      Destination: destination, Amount: xrpToDrops(String(amountXrp)), Condition: condition, CancelAfter: cancelAfter }, { wallet });
    if (r.result.meta?.TransactionResult !== "tesSUCCESS") throw new Error("EscrowCreate: " + r.result.meta?.TransactionResult);
    return { hash: r.result.hash, offerSequence: r.result.tx_json.Sequence };
  }
  async finishXrpl({ wallet, owner, offerSequence, condition, fulfillment }) {
    const fee = String(400 + 10 * Math.ceil(Buffer.from(fulfillment, "hex").length / 16));
    const r = await this.xrplClient.submitAndWait({ TransactionType: "EscrowFinish", Account: wallet.address, Owner: owner,
      OfferSequence: offerSequence, Condition: condition, Fulfillment: fulfillment, Fee: fee }, { wallet });
    if (r.result.meta?.TransactionResult !== "tesSUCCESS") throw new Error("EscrowFinish: " + r.result.meta?.TransactionResult);
    return r.result.hash;
  }
  extractSecretFromXrplFinish(finishTx) {
    const ff = Buffer.from(finishTx.Fulfillment, "hex"); // A0 <len> 80 <plen> <preimage>
    return ff.subarray(4, 4 + ff[3]);
  }

  // ---- CKB side ----
  htlcScript({ H, recipientHash, senderHash, timeout }) {
    const args = "0x" + Buffer.from(H).toString("hex") + recipientHash.slice(2) + senderHash.slice(2) + u64le(BigInt(timeout));
    return ccc.Script.from({ codeHash: this.htlcCodeHash, hashType: "data1", args });
  }
  async lockCkb({ script, amount = 200_00000000n }) {
    const tx = ccc.Transaction.from({ outputs: [{ lock: script, capacity: amount }], outputsData: ["0x"] });
    await tx.completeInputsByCapacity(this.ckbSigner); await tx.completeFeeBy(this.ckbSigner, 1000);
    const h = await this.ckbClient.sendTransaction(await this.ckbSigner.signTransaction(tx));
    await this.ckbClient.waitTransaction(h, 1, { timeout: 180000 });
    return { txHash: h, index: 0 };
  }
  async claimCkb({ cell, preimage, recipientLock, amount = 200_00000000n }) {
    const tx = ccc.Transaction.from({ inputs: [{ previousOutput: cell, since: 0n }],
      outputs: [{ lock: recipientLock, capacity: amount - 1_000_000n }], outputsData: ["0x"], cellDeps: [this.htlcDep] });
    tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + Buffer.from(preimage).toString("hex") }));
    const h = await this.ckbClient.sendTransaction(tx);
    await this.ckbClient.waitTransaction(h, 1, { timeout: 180000 });
    return h;
  }
  async findSpenderTx(cell, htlcScript) {
    // the htlc lock args are unique, so only the lock tx and the claim tx touch it; the claim is the one that
    // spends `cell` as an input.
    for await (const tx of this.ckbClient.findTransactionsByLock(htlcScript, null, true)) {
      const h = tx.txHash || tx.transaction?.hash || tx;
      if (!h || h === cell.txHash) continue;
      const full = await this.ckbClient.getTransaction(h).catch(() => null);
      if (full && full.transaction.inputs.some((i) => i.previousOutput.txHash === cell.txHash && Number(i.previousOutput.index) === Number(cell.index)))
        return full;
    }
    return null;
  }
  extractSecretFromCkbClaim(claimTx) {
    return Buffer.from(ccc.bytesFrom(ccc.WitnessArgs.fromBytes(claimTx.transaction.witnesses[0]).lock));
  }

  // ---- watcher: CKB claim seen -> settle XRPL ----
  async watchCkbThenFinishXrpl({ cell, htlcScript, H, xrpl, pollMs = 12000, timeoutMs = 600000 }) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const live = await this.ckbClient.getCellLive(cell, true).catch(() => null);
      if (!live) {
        const claimTx = await this.findSpenderTx(cell, htlcScript);
        if (!claimTx) throw new Error("watcher: cell spent but spender not found");
        const s = this.extractSecretFromCkbClaim(claimTx);
        if (!sha256(s).equals(Buffer.from(H))) throw new Error("watcher: revealed preimage does not match H");
        const hash = await this.finishXrpl({ ...xrpl, fulfillment: XrplCkbHtlcLeg.fulfillmentFromSecret(s) });
        return { secret: s, xrplFinish: hash };
      }
      await sleep(pollMs);
    }
    throw new Error("watcher: CKB cell not spent within timeout");
  }

  // ---- watcher: XRPL finish seen -> claim CKB ----
  async watchXrplThenClaimCkb({ owner, offerSequence, cell, preimageHashH, recipientLock, pollMs = 6000, timeoutMs = 600000 }) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const txs = await this.xrplClient.request({ command: "account_tx", account: owner, ledger_index_min: -1, ledger_index_max: -1, limit: 30 }).catch(() => null);
      const fin = txs?.result?.transactions?.find((t) => t.tx_json?.TransactionType === "EscrowFinish" && Number(t.tx_json?.OfferSequence) === Number(offerSequence) && t.tx_json?.Fulfillment);
      if (fin) {
        const s = this.extractSecretFromXrplFinish(fin.tx_json);
        if (!sha256(s).equals(Buffer.from(preimageHashH))) throw new Error("watcher: XRPL preimage does not match H");
        const hash = await this.claimCkb({ cell, preimage: s, recipientLock });
        return { secret: s, ckbClaim: hash };
      }
      await sleep(pollMs);
    }
    throw new Error("watcher: XRPL finish not seen within timeout");
  }
}

// --- live demo of the AUTONOMOUS watcher (CKB claim -> watcher settles XRPL) ---
async function demo() {
  const HERE = path.dirname(fileURLToPath(import.meta.url));
  const D = JSON.parse(fs.readFileSync(path.join(HERE, "htlc_deploy.json"), "utf8"));
  const ckbClient = new ccc.ClientPublicTestnet();
  const ckbSigner = new ccc.SignerCkbPrivateKey(ckbClient, fs.readFileSync(path.join(os.homedir(), ".chiral", "pudge_relayer.key"), "utf8").trim());
  const ckbLock = (await ckbSigner.getAddressObjs())[0].script;
  const xrplClient = new Client("wss://s.altnet.rippletest.net:51233"); await xrplClient.connect();
  const leg = new XrplCkbHtlcLeg({ ckbClient, ckbSigner, ckbLock, xrplClient, htlcCodeHash: D.codeHash, htlcDep: D.dep });

  const { s, H, condition } = XrplCkbHtlcLeg.newSecret();
  console.log("H =", H.toString("hex"));

  // SAFETY GATE before locking the second leg: CKB is claimed first (refund in ~1h), XRPL settled second (cancel in ~2h).
  const safe = XrplCkbHtlcLeg.safeToLockSecondLeg({ claimFirstRefundInSec: 3600, settleSecondRefundInSec: 7200, marginSec: 1800 });
  console.log("timelock-ordering safe to lock second leg:", safe);
  if (!safe) throw new Error("unsafe timelock ordering, refusing to lock");

  const { wallet: alice } = await xrplClient.fundWallet();
  const { wallet: bob } = await xrplClient.fundWallet();
  const led = await xrplClient.request({ command: "ledger", ledger_index: "validated" });
  const { offerSequence } = await leg.lockXrpl({ wallet: alice, destination: bob.address, amountXrp: 10, condition, cancelAfter: led.result.ledger.close_time + 7200 });
  console.log("[lock] XRPL escrow open (Alice -> Bob under H), seq", offerSequence);

  const script = leg.htlcScript({ H, recipientHash: ckbLock.hash(), senderHash: ckbLock.hash(), timeout: 4096n });
  const cell = await leg.lockCkb({ script });
  console.log("[lock] CKB htlc cell:", cell.txHash + ":0");

  // Alice claims CKB on-chain (reveals s). In production this is the counterparty's action; here we trigger it,
  // then let the WATCHER notice and settle XRPL by itself.
  const claimHash = await leg.claimCkb({ cell, preimage: s, recipientLock: ckbLock });
  console.log("[event] CKB claimed on-chain (s revealed):", claimHash);

  console.log("[watch] watcher polling CKB for the claim, then it will settle XRPL autonomously...");
  const out = await leg.watchCkbThenFinishXrpl({ cell, htlcScript: script, H, xrpl: { wallet: bob, owner: alice.address, offerSequence, condition } });
  console.log("[watch] watcher extracted s and finished XRPL:", out.xrplFinish);
  console.log("        s =", out.secret.toString("hex"), "| Bob XRP:", await xrplClient.getXrpBalance(bob.address));
  console.log("\n=== AUTONOMOUS WATCHER SETTLED THE SWAP ===");
  await xrplClient.disconnect();
}
if (process.argv[1] && process.argv[1].endsWith("swap_leg.mjs")) demo().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
