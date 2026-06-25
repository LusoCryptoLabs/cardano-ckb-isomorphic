// check_funds.mjs - report the relayer's Pudge address, total vs. spendable (plain) capacity, and the gap for
// the xada_mint code cell. No secrets printed. (XADA_LEG.md P4b funding check.)
import { signerOf, myLock, balance, plainCells } from "./_signer.mjs";

const { client, signer } = signerOf();
const addr = (await signer.getAddressObjs())[0].address;
const lock = await myLock(signer);
const total = await balance(client, lock);
let plain = 0n;
for (const c of await plainCells(client, lock)) plain += BigInt(c.cellOutput.capacity);
const NEED = 121173n * 100000000n; // ~code cell capacity (121,112 data bytes + overhead)
console.log("relayer address :", addr);
console.log("total capacity  :", (total / 100000000n).toString(), "CKB (most locked in protected code cells)");
console.log("plain spendable :", (plain / 100000000n).toString(), "CKB");
console.log("xada_mint needs :", (NEED / 100000000n).toString(), "CKB");
const gap = NEED - plain;
console.log("shortfall       :", gap > 0n ? (gap / 100000000n).toString() + " CKB" : "none - can deploy now");
process.exit(0);
