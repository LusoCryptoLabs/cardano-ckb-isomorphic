// bridge_deploy_lock.mjs - CKB→Cardano leg, live end-to-end step 1: deploy bridge_lock_v1 on Pudge and submit
// a canonical bridge-RECEIPT lock tx, then RECONSTRUCT + verify the exact RawTransaction body the leap circuit
// must hash (ckbhash(body) == tx_hash) and compute the receipt field offsets. Writes bridge_lock_live.json.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, deployCodeCell, wait, plainCells } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bridge_lock_v1");
const OUT = path.join(HERE, "bridge_lock_live.json");
const AMOUNT = 200n * 100_000_000n;                       // 200 CKB locked == the receipt's capacity (kind=CKB)
const RECIPIENT = "2df44c71a4312463ba31315c5aa7725b6ad44cd544a055a3dde915a6"; // 28-byte Cardano payment cred (our preview vkh)
const FEE = 2_000_000n;

// ---- molecule builders (mirror CKB's spec; identical to relayer/ckb_lock.py) ----
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
    fixvec([]),                                            // header_deps
    fixvec(tx.inputs.map(cellInput)),
    dynvec(tx.outputs.map(cellOutput)),
    dynvec(tx.outputsData.map((d) => molbytes(Buffer.from(d.replace(/^0x/, ""), "hex")))),
  ]);
}
// read RawTransaction field offset i + locate the receipt (output[0]) fields, exactly as the circuit will.
const fieldOff = (b, i) => b.readUInt32LE(4 + 4 * i);
const celloutOff = (b) => { const o = fieldOff(b, 4); return o + b.readUInt32LE(o + 4); };       // outputs dynvec item[0] (robust to N outputs)
const typeOff = (b) => { const co = celloutOff(b); return co + b.readUInt32LE(co + 12); };       // CellOutput.type = table field 2 (off at +12)
const typeCodeOff = (b) => { const t = typeOff(b); return t + b.readUInt32LE(t + 4); };          // type Script.code_hash (field 0)
const dataOff = (b) => { const o = fieldOff(b, 5); return o + b.readUInt32LE(o + 4) + 4; };      // outputs_data item[0] content (after molbytes len)

async function main() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);

  // 1) deploy bridge_lock_v1 (or reuse an already-deployed one via env, to avoid wasting capacity)
  let bridge;
  if (process.env.BRIDGE_CODE_TX && process.env.BRIDGE_CODE_HASH) {
    bridge = { txHash: process.env.BRIDGE_CODE_TX, index: 0, codeHash: process.env.BRIDGE_CODE_HASH };
    console.log("reusing bridge code:", bridge.txHash, "\n  BRIDGE_CODE_HASH:", bridge.codeHash);
  } else {
    console.log("deploying bridge_lock_v1…");
    const bin = fs.readFileSync(BIN);
    bridge = await deployCodeCell(client, signer, bin, "bridge_lock_v1");
    console.log("  bridge code:", bridge.txHash, "\n  BRIDGE_CODE_HASH:", bridge.codeHash);
  }

  // 2) build the canonical receipt lock tx. receipt: capacity==amount, type=bridge, data=MAGIC|kind|amount|recipient
  const data = "0x" + Buffer.concat([Buffer.from("BRG1"), Buffer.from([0]), u64(AMOUNT), Buffer.alloc(8), Buffer.from(RECIPIENT, "hex")]).toString("hex"); // 4+1+16+28=49
  const bridgeScript = ccc.Script.from({ codeHash: bridge.codeHash, hashType: "data1", args: "0x" + "00".repeat(32) });
  const ps = await plainCells(client, lock);
  const fund = ps.find((c) => BigInt(c.cellOutput.capacity) >= AMOUNT + FEE + 63n * 100_000_000n);
  if (!fund) throw new Error("no funding cell");
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: fund.outPoint, since: 0n }],
    outputs: [{ lock, type: bridgeScript, capacity: AMOUNT }, { lock, capacity: BigInt(fund.cellOutput.capacity) - AMOUNT - FEE }],
    outputsData: [data, "0x"],
    cellDeps: [{ outPoint: { txHash: bridge.txHash, index: 0 }, depType: "code" }],
  });
  const signed = await signer.signTransaction(tx);

  // 3) reconstruct + verify the RawTransaction body (what the circuit hashes), compute offsets
  const body = rawTxMolecule(signed);
  const reTxHash = ccc.hashCkb(ccc.hexFrom(body));
  if (reTxHash !== signed.hash()) throw new Error(`body reconstruction mismatch: ${reTxHash} != ${signed.hash()}`);
  const off = { type_code: typeCodeOff(body), amount: dataOff(body) + 5, recipient: dataOff(body) + 21 };
  console.log("offsets:", off, "| at type_code:", Buffer.from(body).slice(off.type_code, off.type_code + 32).toString("hex").slice(0, 16), "| expect:", bridge.codeHash.replace(/^0x/, "").slice(0, 16));
  // self-check the offsets against the known values
  if (Buffer.from(body).slice(off.type_code, off.type_code + 32).toString("hex") !== bridge.codeHash.replace(/^0x/, "")) throw new Error("type_code offset wrong");
  if (Buffer.from(body).slice(off.amount, off.amount + 16).toString("hex") !== u64(AMOUNT).toString("hex") + "00".repeat(8)) throw new Error("amount offset wrong");
  if (Buffer.from(body).slice(off.recipient, off.recipient + 28).toString("hex") !== RECIPIENT) throw new Error("recipient offset wrong");
  console.log(`\nbody ${body.length} bytes | tx_hash ${signed.hash()} | offsets type_code@${off.type_code} amount@${off.amount} recipient@${off.recipient}`);

  const h = await client.sendTransaction(signed);
  console.log("LOCK tx (bridge receipt):", h);
  await wait(client, h);
  const rec = { bridge_code_hash: bridge.codeHash, bridge_code_tx: bridge.txHash, lock_txid: h, amount: AMOUNT.toString(), recipient: RECIPIENT, body_hex: "0x" + body.toString("hex"), tx_hash: signed.hash(), offsets: off };
  fs.writeFileSync(OUT, JSON.stringify(rec, null, 2));
  console.log("  wrote", OUT, "- receipt mined; wait K_MIN confirmations then prove on its block.");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
