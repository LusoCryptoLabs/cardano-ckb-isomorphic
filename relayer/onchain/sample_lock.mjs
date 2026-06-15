// sample_lock.mjs — FR3 step 1: submit a sample bridge_lock_v1 receipt under the NEW bridge code (0x48548a94)
// and reconstruct the exact RawTransaction body + offsets, so the prover can generate the fresh forward-leg VK.
// Robust funding (indexer paged query, no plain-cell scan that the heavy relayer lock would truncate).
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BL = JSON.parse(fs.readFileSync(path.join(HERE, "bridge_lock_live.json"), "utf8"));
const CKB = 100000000n, FEE = 2000000n;
const AMOUNT = 200n * CKB;                       // capacity == amount (kind = CKB)
const RECIPIENT = "2df44c71a4312463ba31315c5aa7725b6ad44cd544a055a3dde915a6"; // 28-byte Cardano payment cred

// molecule builders (mirror CKB's spec; identical to bridge_deploy_lock.mjs)
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
const rawTxMolecule = (tx) => table([u32(0), fixvec(tx.cellDeps.map(cellDep)), fixvec([]), fixvec(tx.inputs.map(cellInput)), dynvec(tx.outputs.map(cellOutput)), dynvec(tx.outputsData.map((d) => molbytes(Buffer.from(d.replace(/^0x/, ""), "hex"))))]);
const fieldOff = (b, i) => b.readUInt32LE(4 + 4 * i);
const celloutOff = (b) => { const o = fieldOff(b, 4); return o + b.readUInt32LE(o + 4); };
const typeOff = (b) => { const co = celloutOff(b); return co + b.readUInt32LE(co + 12); };
const typeCodeOff = (b) => { const t = typeOff(b); return t + b.readUInt32LE(t + 4); };
const dataOff = (b) => { const o = fieldOff(b, 5); return o + b.readUInt32LE(o + 4) + 4; };

const { client, signer } = signerOf();
const lock = await myLock(signer);
async function pickFunding(minCap) {
  let best = null;
  for await (const c of client.findCells({ script: lock, scriptType: "lock", scriptSearchMode: "exact", filter: { outputDataLenRange: ["0x0", "0x1"] } }, "asc", 200)) {
    const cap = BigInt(c.cellOutput.capacity);
    if (cap >= minCap && (!best || cap < BigInt(best.cellOutput.capacity))) best = c;
  }
  if (!best) throw new Error(`no plain cell >= ${minCap / CKB} CKB`);
  return best;
}

const bridge = ccc.Script.from({ codeHash: BL.bridge_code_hash, hashType: "data1", args: "0x" + "00".repeat(32) });
const data = "0x" + Buffer.concat([Buffer.from("BRG1"), Buffer.from([0]), u64(AMOUNT), Buffer.alloc(8), Buffer.from(RECIPIENT, "hex")]).toString("hex"); // 49 bytes
const fund = await pickFunding(AMOUNT + FEE + 100n * CKB);
const secpDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);
const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: fund.outPoint, since: 0n }],
  outputs: [{ lock, type: bridge, capacity: AMOUNT }, { lock, capacity: BigInt(fund.cellOutput.capacity) - AMOUNT - FEE }],
  outputsData: [data, "0x"],
  cellDeps: [...secpDeps, { outPoint: { txHash: BL.bridge_code_tx, index: 0 }, depType: "code" }],
});
const signed = await signer.signTransaction(tx);
const body = rawTxMolecule(signed);
const reHash = ccc.hashCkb(ccc.hexFrom(body));
if (reHash !== signed.hash()) throw new Error(`body reconstruction mismatch: ${reHash} != ${signed.hash()}`);
const off = { type_code: typeCodeOff(body), amount: dataOff(body) + 5, recipient: dataOff(body) + 21 };
const sl = (a, n) => Buffer.from(body).slice(a, a + n).toString("hex");
if (sl(off.type_code, 32) !== BL.bridge_code_hash.replace(/^0x/, "")) throw new Error("type_code offset wrong");
if (sl(off.recipient, 28) !== RECIPIENT) throw new Error("recipient offset wrong");

const h = await client.sendTransaction(signed);
console.log("sample lock tx:", h, "| amount", (AMOUNT / CKB).toString(), "CKB | offsets", JSON.stringify(off));
await wait(client, h);
const blk = await client.getTransaction(h);
const height = Number(blk.blockNumber);
const rec = { ...BL, lock_txid: h, tx_hash: h, amount: AMOUNT.toString(), recipient: RECIPIENT, body_hex: "0x" + body.toString("hex"), offsets: off, lock_height: height };
fs.writeFileSync(path.join(HERE, "bridge_lock_live.json"), JSON.stringify(rec, null, 2));
console.log("confirmed at block", height, "| updated bridge_lock_live.json (body + offsets for the new bridge)");
