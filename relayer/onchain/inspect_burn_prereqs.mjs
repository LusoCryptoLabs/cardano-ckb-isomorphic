// inspect_burn_prereqs.mjs — confirm the χOSMO xUDT cell is spendable by the relayer and the relayer is funded
// enough to deploy xosmo_burn_receipt (~22 CKB) and run the burn tx. Read-only.
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, plainCells } from "./_signer.mjs";
import fs from "node:fs";

const LIVE = JSON.parse(fs.readFileSync(new URL("./catom_owner_live.json", import.meta.url)));
const [xtx, xidx] = LIVE.xosmoCell.split(":");
const { client, signer } = signerOf();
const lock = await myLock(signer);

// relayer total + largest plain cell
let total = 0n;
for await (const c of client.findCellsByLock(lock, null, true)) total += BigInt(c.cellOutput.capacity);
const plains = await plainCells(client, lock);
const biggest = plains.length ? BigInt(plains[0].cellOutput.capacity) : 0n;

// the χOSMO cell
const cell = await client.getCell({ txHash: xtx, index: BigInt(xidx) });
const co = cell.cellOutput;
const myLockHash = lock.hash();
const cellLockHash = co.lock.hash();
const amt = BigInt("0x" + Buffer.from(ccc.bytesFrom(cell.outputData).slice(0, 16)).reverse().toString("hex"));

console.log("relayer lock hash :", myLockHash);
console.log("relayer total CKB :", (total / 100000000n).toString(), "CKB  (largest plain", (biggest/100000000n).toString(), "CKB)");
console.log("");
console.log("χOSMO cell        :", LIVE.xosmoCell, "cap", (BigInt(co.capacity)/100000000n).toString(), "CKB");
console.log("  lock hash       :", cellLockHash, cellLockHash === myLockHash ? "(== relayer: SPENDABLE)" : "(NOT relayer!)");
console.log("  type hash       :", co.type ? co.type.hash() : "none");
console.log("  token id (live) :", LIVE.tokenId, co.type && co.type.hash() === LIVE.tokenId ? "(MATCH)" : "(differs)");
console.log("  χOSMO amount    :", amt.toString());
