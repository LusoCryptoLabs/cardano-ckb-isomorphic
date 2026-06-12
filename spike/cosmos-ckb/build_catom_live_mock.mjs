// build_catom_live_mock.mjs — STEP 2 of the live Cosmos->CKB mint. Build the catom_mint witness from REAL
// osmo-test-5 data (the block/commit/validators that finalized the escrow tx from osmo_lock.mjs) and emit a
// ckb-debugger mock. Unlike build_catom_mock (synthetic single-validator block), this proves catom_mint against
// a real Tendermint commit: real validator set, real >2/3 ed25519 signatures, the real escrow MsgSend parsed
// in-VM, bound to the real (amount, recipient) the lock carried.
//   wsl: ckb-debugger --max-cycles 5000000000 --tx-file catom_live.json --script-group-type type --cell-type output --cell-index 0
import { ccc } from "@ckb-ccc/core";
import { blake2b } from "@noble/hashes/blake2.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.OSMO_RPC || "https://rpc.testnet.osmosis.zone";
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/catom_mint");
const E = JSON.parse(fs.readFileSync(path.join(HERE, "osmo_escrow.json"), "utf8"));
const SHA = (b) => crypto.createHash("sha256").update(b).digest();
const B2B = (b) => Buffer.from(blake2b(b, { dkLen: 32 }));
const get = async (p) => { const r = await (await fetch(RPC + p, { signal: AbortSignal.timeout(30000) })).json(); if (r.error) throw new Error(JSON.stringify(r.error)); return r.result; };

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const hx = (s) => Buffer.from(s, "hex");
const b64 = (s) => Buffer.from(s, "base64");
const varint = (n) => { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); };
const tag = (f, w) => varint((f << 3) | w);
const pbBytes = (f, b) => Buffer.concat([tag(f, 2), varint(b.length), b]);
const pbVar = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
const tsParts = (iso) => { const m = iso.match(/^(.*?)(?:\.(\d+))?Z$/); return { seconds: Math.floor(Date.parse(m[1] + "Z") / 1000), nanos: m[2] ? parseInt(m[2].padEnd(9, "0").slice(0, 9), 10) : 0 }; };

const cdcStr = (s) => (s ? pbBytes(1, Buffer.from(s, "utf8")) : Buffer.alloc(0));
const cdcInt = (n) => pbVar(1, n);
const cdcBytes = (hex) => { const b = hex ? hx(hex) : Buffer.alloc(0); return b.length ? pbBytes(1, b) : Buffer.alloc(0); };
const versionEnc = (bl, ap) => { const o = []; if (bl) o.push(pbVar(1, bl)); if (ap) o.push(pbVar(2, ap)); return Buffer.concat(o); };
const timeEnc = (iso) => { const t = tsParts(iso); const o = []; if (t.seconds) o.push(pbVar(1, t.seconds)); if (t.nanos) o.push(pbVar(2, t.nanos)); return Buffer.concat(o); };
const partSetEnc = (total, hash) => { const o = []; if (total) o.push(pbVar(1, total)); o.push(pbBytes(2, hx(hash))); return Buffer.concat(o); };
const blockIDEnc = (bid) => Buffer.concat([pbBytes(1, hx(bid.hash)), pbBytes(2, partSetEnc(bid.parts.total, bid.parts.hash))]);

const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0x00]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([0x01]), l, r]));
const splitPoint = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const merkleRoot = (items) => items.length === 1 ? leafHash(items[0]) : innerHash(merkleRoot(items.slice(0, splitPoint(items.length))), merkleRoot(items.slice(splitPoint(items.length))));
function buildAunts(items, index) { const out = []; (function rec(it, i) { if (it.length <= 1) return; const k = splitPoint(it.length); if (i < k) { out.push(merkleRoot(it.slice(k))); rec(it.slice(0, k), i); } else { out.push(merkleRoot(it.slice(0, k))); rec(it.slice(k), i - k); } })(items, index); return out.reverse(); }
function simpleValidator(pk, power) { const pubkeyMsg = Buffer.concat([Buffer.from([0x0a, 0x20]), pk]); return Buffer.concat([Buffer.from([0x0a]), varint(pubkeyMsg.length), pubkeyMsg, Buffer.from([0x10]), varint(power)]); }

async function fetchValidators(height) {
  let page = 1, all = [];
  for (;;) {
    const r = await get(`/validators?height=${height}&per_page=100&page=${page}`);
    all = all.concat(r.validators);
    if (all.length >= Number(r.total)) break;
    page++;
  }
  return all;
}

async function main() {
  const H = Number(E.height);
  const sh = await get(`/commit?height=${H}`);
  const header = sh.signed_header.header, commit = sh.signed_header.commit;
  const vals = await fetchValidators(H);
  const blk = await get(`/block?height=${H}`);
  const txs = (blk.block.data.txs || []).map((t) => b64(t));

  // 14 header leaves -> block_hash; must equal commit.block_id.hash
  const leaves = [
    versionEnc(Number(header.version.block || 0), Number(header.version.app || 0)), cdcStr(header.chain_id), cdcInt(header.height), timeEnc(header.time),
    blockIDEnc(header.last_block_id), cdcBytes(header.last_commit_hash), cdcBytes(header.data_hash), cdcBytes(header.validators_hash),
    cdcBytes(header.next_validators_hash), cdcBytes(header.consensus_hash), cdcBytes(header.app_hash), cdcBytes(header.last_results_hash),
    cdcBytes(header.evidence_hash), cdcBytes(header.proposer_address),
  ];
  const blockHash = merkleRoot(leaves);
  if (blockHash.toString("hex").toUpperCase() !== commit.block_id.hash) throw new Error("block_hash mismatch: leaf encoding wrong");

  // valset root must equal header.validators_hash
  const valsetHash = merkleRoot(vals.map((v) => simpleValidator(b64(v.pub_key.value), Number(v.voting_power))));
  if (valsetHash.toString("hex").toUpperCase() !== header.validators_hash) throw new Error("validators_hash mismatch");

  // tx inclusion: find our tx by hash, build aunts; root must equal data_hash
  const items = txs.map((t) => SHA(t));
  const index = txs.findIndex((t) => SHA(t).toString("hex").toUpperCase() === E.txHash.toUpperCase());
  if (index < 0) throw new Error("our escrow tx not found in block " + H);
  const aunts = buildAunts(items, index);
  const dataRoot = merkleRoot(items.length ? items : [Buffer.alloc(0)]);
  if (dataRoot.toString("hex").toUpperCase() !== header.data_hash) throw new Error("data_hash mismatch");

  // pack the inclusion blob (tendermint_inclusion layout)
  const parts = [Buffer.from([leaves.length])];
  for (const l of leaves) parts.push(u16(l.length), l);
  const cid = Buffer.from(header.chain_id, "utf8");
  parts.push(Buffer.from([cid.length]), cid, u64(header.height), u64(commit.round), u32(commit.block_id.parts.total), hx(commit.block_id.parts.hash));
  parts.push(u16(vals.length));
  for (const v of vals) parts.push(b64(v.pub_key.value), u64(v.voting_power));
  const addrIdx = new Map(vals.map((v, i) => [v.address, i]));
  const pre = commit.signatures.filter((s) => s.block_id_flag === 2 && s.signature);
  parts.push(u16(pre.length));
  for (const s of pre) { const t = tsParts(s.timestamp); parts.push(u16(addrIdx.get(s.validator_address)), i64(t.seconds), u32(t.nanos), b64(s.signature)); }
  const tx = txs[index];
  parts.push(u16(tx.length), tx, u32(index), u32(txs.length), Buffer.from([aunts.length]));
  for (const a of aunts) parts.push(a);
  const blob = Buffer.concat(parts);

  // ---- CKB mock cells ----
  const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
  const catomCodeHash = ccc.hashCkb(data);
  const regScript = ccc.Script.from({ codeHash: "0x" + "b2".repeat(32), hashType: "type", args: "0x" });
  const regTypeHash = hx(regScript.hash().replace(/^0x/, ""));
  const denomB = Buffer.from(E.denom), escrowB = Buffer.from(E.escrow);
  const anchor = Buffer.from(valsetHash); if (process.env.BADPIN) anchor[0] ^= 0xff;   // baked anchor (args[0..32])
  const catomArgs = Buffer.concat([anchor, regTypeHash, Buffer.from([denomB.length]), denomB, escrowB]);
  const catomType = ccc.Script.from({ codeHash: catomCodeHash, hashType: "data1", args: "0x" + catomArgs.toString("hex") });
  const outLock = ccc.Script.from(E.recipientLock);

  const outData = Buffer.alloc(16); outData.writeBigUInt64LE(BigInt(E.amount), 0);
  const nfKey = B2B(Buffer.concat([Buffer.from([0x04]), SHA(tx)]));

  const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
  const anyLock = scr(ccc.Script.from({ codeHash: "0x" + "55".repeat(32), hashType: "type", args: "0x" }));
  const OP = (h, i) => ({ tx_hash: "0x" + h, index: "0x" + i.toString(16) });
  const IN0 = OP("00".repeat(32), 0), IN1 = OP("11".repeat(32), 0), DEP_CODE = OP("ce".repeat(32), 0);
  const cap = "0x2e90edd000";
  const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);
  const wit0 = ccc.hexFrom(ccc.WitnessArgs.from({ inputType: "0x" + blob.toString("hex") }).toBytes());
  const wit1 = ccc.hexFrom(ccc.WitnessArgs.from({ inputType: "0x" + nfKey.toString("hex") }).toBytes());

  const mock = {
    mock_info: {
      inputs: [
        { input: { since: "0x0", previous_output: IN0 }, output: { capacity: cap, lock: anyLock, type: null }, data: "0x", header: null },
        { input: { since: "0x0", previous_output: IN1 }, output: { capacity: cap, lock: anyLock, type: scr(regScript) }, data: "0x", header: null },
      ],
      cell_deps: [
        { cell_dep: { out_point: DEP_CODE, dep_type: "code" }, output: { capacity: depCap, lock: anyLock, type: null }, data, header: null },
      ],
      header_deps: [],
    },
    tx: {
      version: "0x0",
      cell_deps: [{ out_point: DEP_CODE, dep_type: "code" }],
      header_deps: [], inputs: [{ since: "0x0", previous_output: IN0 }, { since: "0x0", previous_output: IN1 }],
      outputs: [{ capacity: cap, lock: scr(outLock), type: scr(catomType) }], outputs_data: ["0x" + outData.toString("hex")], witnesses: [wit0, wit1],
    },
  };
  const out = process.env.BADPIN ? "catom_live_badpin.json" : "catom_live.json";
  fs.writeFileSync(path.join(HERE, out), JSON.stringify(mock, null, 2));
  if (!process.env.BADPIN) {
    // the raw pieces the on-chain mint (live_catom_mint.mjs) needs.
    fs.writeFileSync(path.join(HERE, "catom_witness.json"), JSON.stringify({
      height: H, blob: blob.toString("hex"), nfKey: nfKey.toString("hex"), anchor: valsetHash.toString("hex"),
      recipient: E.recipient, recipientLock: E.recipientLock, amount: E.amount, denom: E.denom, escrow: E.escrow,
    }, null, 2));
  }
  console.log(`height ${H} | chain ${header.chain_id} | vals ${vals.length} | precommits ${pre.length} | txs ${txs.length} idx ${index} aunts ${aunts.length}`);
  console.log(`valset_hash ${valsetHash.toString("hex").slice(0, 16)} | block_hash OK | data_hash OK | minted ${E.amount} ${E.denom} -> recipient ${E.recipient.slice(0, 16)}`);
  console.log("wrote", out);
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
