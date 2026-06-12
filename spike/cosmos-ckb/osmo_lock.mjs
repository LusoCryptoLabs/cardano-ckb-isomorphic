// osmo_lock.mjs — STEP 1 of the live Cosmos->CKB mint. Lock OSMO on osmo-test-5 into an escrow account, with the
// 32-byte CKB recipient lock-hash carried (lowercase hex) in the tx memo, exactly the escrow shape catom_mint
// parses. Writes osmo_escrow.json (the tx hash + height + pinned fields) for build_catom_live_mock.mjs.
//
// The "escrow account" is HD index 1 of the same testnet mnemonic (a distinct address we treat as the escrow);
// for a real bridge it would be a module account or contract. The CKB recipient is a fixed demo lock; the minted
// chiOSMO will be locked to its hash.
import { DirectSecp256k1HdWallet, makeCosmoshubPath } from "@cosmjs/proto-signing";
import { SigningStargateClient } from "@cosmjs/stargate";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "../../relayer/onchain/_signer.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.OSMO_RPC || "https://rpc.testnet.osmosis.zone";
const DENOM = "uosmo";
const AMOUNT = process.env.AMOUNT || "1000000"; // 1 OSMO
const KEYFILE = path.join(os.homedir(), ".chiral", "osmo_testnet_deployer.key");

const mnemonic = fs.readFileSync(KEYFILE, "utf8").trim();
const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "osmo", hdPaths: [makeCosmoshubPath(0), makeCosmoshubPath(1)] });
const [sender, escrow] = await wallet.getAccounts();

// the CKB recipient lock; chiOSMO mints to its hash. We mint to the Pudge relayer's OWN lock so the token is
// spendable. memo = hex(recipient hash), 64 lowercase hex chars.
const { signer } = signerOf();
const recipientLock = await myLock(signer);
const recipient = recipientLock.hash().replace(/^0x/, "");

const client = await SigningStargateClient.connectWithSigner(RPC, wallet);
const fee = { amount: [{ denom: DENOM, amount: "7000" }], gas: "200000" };
console.log("sender:", sender.address, "| escrow:", escrow.address);
console.log("locking", AMOUNT, DENOM, "with memo = recipient", recipient.slice(0, 16), "...");
const res = await client.sendTokens(sender.address, escrow.address, [{ denom: DENOM, amount: AMOUNT }], fee, recipient);
if (res.code !== 0) { console.error("send failed:", res.rawLog); process.exit(1); }
console.log("tx:", res.transactionHash, "| height:", res.height);

const out = { txHash: res.transactionHash, height: res.height, escrow: escrow.address, sender: sender.address, denom: DENOM, amount: AMOUNT, recipient, recipientLock: { codeHash: recipientLock.codeHash, hashType: recipientLock.hashType, args: recipientLock.args } };
fs.writeFileSync(path.join(HERE, "osmo_escrow.json"), JSON.stringify(out, null, 2));
console.log("wrote osmo_escrow.json");
