// build_burn_lock.mjs — RETURN leg, witness step: reconstruct the EXACT RawTransaction body of the live χOSMO
// burn tx (ckbhash(body) == tx_hash) and compute the xosmo_burn_receipt field offsets the leap_burn_windowed
// circuit reads. Writes burn_lock_live.json (the 20-byte-recipient analog of bridge_lock_live.json).
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LIVE = JSON.parse(fs.readFileSync(path.join(HERE, "xosmo_burn_live.json"), "utf8"));
const OUT = path.join(HERE, "burn_lock_live.json");

// ---- molecule builders (identical to bridge_deploy_lock.mjs) ----
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const cat = (...a) => Buffer.concat(a.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(x))));
const fixvec = (items) => cat(u32(items.length), ...items);
const dynvec = (items) => { const n = items.length; let off = 4 + 4 * n; const offs = []; for (const it of items) { offs.push(u32(off)); off += it.length; } return cat(u32(off), ...offs, ...items); };
const table = dynvec;
const molbytes = (b) => cat(u32(b.length), b);
const HT = { data: 0, type: 1, data1: 2, data2: 4 };
const scriptMol = (s) => table([Buffer.from(s.codeHash.replace(/^0x/, ""), "hex"), Buffer.from([HT[s.hashType]]), molbytes(Buffer.from(s.args.replace(/^0x/, ""), "hex"))]);
const outpoint = (op) => cat(Buffer.from(op.txHash.replace(/^0x/, ""), "hex"), u32(Number(op.index)));
const cellInput = (i) => cat(u64(i.since), outpoint(i.previousOutput));
const cellOutput = (o) => table([u64(o.capacity), scriptMol(o.lock), o.type ? scriptMol(o.type) : Buffer.alloc(0)]);
const cellDep = (d) => cat(outpoint(d.outPoint), Buffer.from([d.depType === "depGroup" ? 1 : 0]));
function rawTxMolecule(tx) {
  return table([
    u32(0),
    fixvec(tx.cellDeps.map(cellDep)),
    fixvec([]),
    fixvec(tx.inputs.map(cellInput)),
    dynvec(tx.outputs.map(cellOutput)),
    dynvec(tx.outputsData.map((d) => molbytes(Buffer.from(d.replace(/^0x/, ""), "hex")))),
  ]);
}
const fieldOff = (b, i) => b.readUInt32LE(4 + 4 * i);
const celloutOff = (b) => { const o = fieldOff(b, 4); return o + b.readUInt32LE(o + 4); };
const typeOff = (b) => { const co = celloutOff(b); return co + b.readUInt32LE(co + 12); };
const typeCodeOff = (b) => { const t = typeOff(b); return t + b.readUInt32LE(t + 4); };
const dataOff = (b) => { const o = fieldOff(b, 5); return o + b.readUInt32LE(o + 4) + 4; };

const { client } = signerOf();
const [btx] = LIVE.burnTx ? [LIVE.burnTx] : [LIVE.receiptCell.split(":")[0]];
const resp = await client.getTransaction(btx);
if (!resp || !resp.transaction) throw new Error("burn tx not found on chain: " + btx);
const tx = resp.transaction;

const body = rawTxMolecule(tx);
const reTxHash = ccc.hashCkb(ccc.hexFrom(body));
if (reTxHash !== btx) throw new Error(`body reconstruction mismatch: ${reTxHash} != ${btx}`);

// xosmo_burn_receipt data = MAGIC(4) ‖ amount(16 LE) ‖ recipient(20): amount@+4, recipient@+20
const off = { type_code: typeCodeOff(body), amount: dataOff(body) + 4, recipient: dataOff(body) + 20 };
const slice = (a, n) => Buffer.from(body).slice(a, a + n).toString("hex");
const wantCode = LIVE.receiptCode.replace(/^0x/, "");
const wantAmt = u64(BigInt(LIVE.amount)).toString("hex") + "00".repeat(8);
if (slice(off.type_code, 32) !== wantCode) throw new Error(`type_code offset wrong: ${slice(off.type_code, 32)} != ${wantCode}`);
if (slice(off.amount, 16) !== wantAmt) throw new Error(`amount offset wrong: ${slice(off.amount, 16)} != ${wantAmt}`);
if (slice(off.recipient, 20) !== LIVE.recipient20) throw new Error(`recipient offset wrong: ${slice(off.recipient, 20)} != ${LIVE.recipient20}`);

const rec = {
  receipt_code_hash: LIVE.receiptCode, lock_txid: btx, amount: LIVE.amount,
  recipient: LIVE.recipient20, recipientAddr: LIVE.recipientAddr,
  body_hex: "0x" + body.toString("hex"), tx_hash: btx, offsets: off,
};
fs.writeFileSync(OUT, JSON.stringify(rec, null, 2));
console.log(`body ${body.length} bytes | tx_hash ${btx}`);
console.log(`offsets type_code@${off.type_code} amount@${off.amount} recipient@${off.recipient}`);
console.log(`  type_code  = ${slice(off.type_code, 32)}  (== receipt code ${wantCode.slice(0,16)}…)`);
console.log(`  amount     = ${slice(off.amount, 16)}  (== ${LIVE.amount})`);
console.log(`  recipient  = ${slice(off.recipient, 20)}  (== osmo ${LIVE.recipientAddr})`);
console.log("wrote", OUT);
