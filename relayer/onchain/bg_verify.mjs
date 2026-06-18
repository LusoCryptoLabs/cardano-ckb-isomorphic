import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { signerOf } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const R = JSON.parse(fs.readFileSync(path.join(HERE, "bg_release.json"), "utf8"));
const RCPT = JSON.parse(fs.readFileSync(path.join(HERE, "bg_receipt.json"), "utf8"));
const to = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error("timeout")), ms))]);
const { client } = signerOf();
const rtx = await to(client.getTransaction(R.releaseTx), 25000);
console.log("release tx status:", rtx?.status, "| block", rtx?.blockNumber);
const receiptLive = await to(client.getCellLive({ txHash: RCPT.txHash, index: RCPT.index }, false), 25000);
console.log("receipt cell now:", receiptLive ? "STILL LIVE (unexpected)" : "SPENT (released) ✓");
// the new registry cell (output 1 of the release) should carry new_root
const newReg = await to(client.getCellLive({ txHash: R.releaseTx, index: 1 }, true), 25000);
console.log("new registry root:", newReg?.outputData, "| expected", R.regNewRoot, "| match:", newReg?.outputData?.toLowerCase() === R.regNewRoot.toLowerCase());
console.log("released:", R.releasedCKB, "CKB | nullifier", R.nullifier.slice(0,18), "| LCKP root", R.lckpRoot.slice(0,14));
