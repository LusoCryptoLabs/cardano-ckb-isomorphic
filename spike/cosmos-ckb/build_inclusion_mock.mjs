// build_inclusion_mock.mjs — pack header leaves + commit + a tx inclusion proof into the tendermint_inclusion
// input blob and emit a ckb-debugger mock. The block_hash and data_hash are DERIVED on-chain from the leaves.
//   ckb-debugger --max-cycles 5000000000 --tx-file inc_mock.json --script-group-type lock --cell-type input --cell-index 0
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.COSMOS_RPC || "https://cosmos-rpc.publicnode.com";
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/tendermint_inclusion");
const get = async (p) => (await fetch(RPC + p, { signal: AbortSignal.timeout(20000) })).json();
const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
const vals = JSON.parse(fs.readFileSync(path.join(HERE, "validators.json"), "utf8"));
const H = sh.header, c = sh.commit;
const SHA = (b) => crypto.createHash("sha256").update(b).digest();

// LE packers
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const hx = (s) => Buffer.from(s, "hex");
const b64 = (s) => Buffer.from(s, "base64");
function tsParts(iso) { const m = iso.match(/^(.*?)(?:\.(\d+))?Z$/); return { seconds: Math.floor(Date.parse(m[1] + "Z") / 1000), nanos: m[2] ? parseInt(m[2].padEnd(9, "0").slice(0, 9), 10) : 0 }; }

// protobuf + header-leaf encoders (from reconstruct_header.mjs)
function varint(n) { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); }
const tag = (f, w) => varint((f << 3) | w);
const pbBytes = (f, b) => Buffer.concat([tag(f, 2), varint(b.length), b]);
const pbVar = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
const cdcStr = (s) => (s ? pbBytes(1, Buffer.from(s, "utf8")) : Buffer.alloc(0));
const cdcInt = (n) => pbVar(1, n);
const cdcBytes = (hex) => { const b = hex ? hx(hex) : Buffer.alloc(0); return b.length ? pbBytes(1, b) : Buffer.alloc(0); };
const versionEnc = (block, app) => { const o = []; if (block) o.push(pbVar(1, block)); if (app) o.push(pbVar(2, app)); return Buffer.concat(o); };
const timeEnc = (iso) => { const t = tsParts(iso); const o = []; if (t.seconds) o.push(pbVar(1, t.seconds)); if (t.nanos) o.push(pbVar(2, t.nanos)); return Buffer.concat(o); };
const partSetEnc = (total, hash) => { const o = []; if (total) o.push(pbVar(1, total)); o.push(pbBytes(2, hx(hash))); return Buffer.concat(o); };
const blockIDEnc = (bid) => Buffer.concat([pbBytes(1, hx(bid.hash)), pbBytes(2, partSetEnc(bid.parts.total, bid.parts.hash))]);

const leaves = [
  versionEnc(Number(H.version.block || 0), Number(H.version.app || 0)), cdcStr(H.chain_id), cdcInt(H.height), timeEnc(H.time),
  blockIDEnc(H.last_block_id), cdcBytes(H.last_commit_hash), cdcBytes(H.data_hash), cdcBytes(H.validators_hash),
  cdcBytes(H.next_validators_hash), cdcBytes(H.consensus_hash), cdcBytes(H.app_hash), cdcBytes(H.last_results_hash),
  cdcBytes(H.evidence_hash), cdcBytes(H.proposer_address),
];

// Merkle / aunts (tx tree leaf = leafHash(SHA256(tx)))
const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0x00]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([0x01]), l, r]));
function splitPoint(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function merkleRoot(items) { if (items.length === 1) return leafHash(items[0]); const k = splitPoint(items.length); return innerHash(merkleRoot(items.slice(0, k)), merkleRoot(items.slice(k))); }
function buildAunts(items, index) { const tmp = []; (function rec(items, index) { if (items.length <= 1) return; const k = splitPoint(items.length); if (index < k) { tmp.push(merkleRoot(items.slice(k))); rec(items.slice(0, k), index); } else { tmp.push(merkleRoot(items.slice(0, k))); rec(items.slice(k), index - k); } })(items, index); return tmp.reverse(); }

async function main() {
  const blk = await get(`/block?height=${H.height}`);
  const txs = (blk.result.block.data.txs || []).map((t) => b64(t));
  if (txs.length === 0) throw new Error("block has no txs; pick a height with txs");
  const items = txs.map((t) => SHA(t));
  const index = 0;
  const aunts = buildAunts(items, index);

  const parts = [];
  parts.push(Buffer.from([leaves.length]));
  for (const l of leaves) parts.push(u16(l.length), l);
  const chainId = Buffer.from(H.chain_id, "utf8");
  parts.push(Buffer.from([chainId.length]), chainId, u64(H.height), u64(c.round), u32(c.block_id.parts.total), hx(c.block_id.parts.hash));
  parts.push(u16(vals.length));
  for (const v of vals) parts.push(b64(v.pub_key.value), u64(v.voting_power));
  const addrIdx = new Map(vals.map((v, i) => [v.address, i]));
  const pre = c.signatures.filter((s) => s.block_id_flag === 2 && s.signature);
  parts.push(u16(pre.length));
  for (const s of pre) { const t = tsParts(s.timestamp); parts.push(u16(addrIdx.get(s.validator_address)), i64(t.seconds), u32(t.nanos), b64(s.signature)); }
  // tx inclusion. TAMPER=1 flips a tx byte -> its leaf changes -> the inclusion proof no longer reaches
  // data_hash, so the verifier must reject (a tx that is not in the block cannot be claimed).
  const tx = Buffer.from(txs[index]); if (process.env.TAMPER) tx[0] ^= 0xff;
  parts.push(u16(tx.length), tx, u32(index), u32(txs.length), Buffer.from([aunts.length]));
  for (const a of aunts) parts.push(a);
  const blob = Buffer.concat(parts);

  const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
  // the trusted validator-set anchor is now the lock's script args (the cell commits to it). BADPIN flips it.
  const trusted = hx(H.validators_hash); if (process.env.BADPIN) trusted[0] ^= 0xff;
  const lock = ccc.Script.from({ codeHash: ccc.hashCkb(data), hashType: "data1", args: "0x" + trusted.toString("hex") });
  const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
  const PREV = { tx_hash: "0x" + "00".repeat(32), index: "0x0" }, DEP = { tx_hash: "0x" + "01".repeat(32), index: "0x0" };
  const wit = ccc.hexFrom(ccc.WitnessArgs.from({ lock: "0x" + blob.toString("hex") }).toBytes());
  const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);
  const mock = {
    mock_info: { inputs: [{ input: { since: "0x0", previous_output: PREV }, output: { capacity: "0x2e90edd000", lock: scr(lock), type: null }, data: "0x", header: null }],
      cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: depCap, lock: scr(ccc.Script.from({ codeHash: "0x" + "33".repeat(32), hashType: "type", args: "0x" })), type: null }, data, header: null }], header_deps: [] },
    tx: { version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [], inputs: [{ since: "0x0", previous_output: PREV }], outputs: [{ capacity: "0x2e90edd000", lock: scr(lock), type: null }], outputs_data: ["0x"], witnesses: [wit] },
  };
  const outName = process.env.TAMPER ? "inc_mock_badtx.json" : process.env.BADPIN ? "inc_mock_badpin.json" : "inc_mock.json";
  fs.writeFileSync(path.join(HERE, outName), JSON.stringify(mock, null, 2));
  console.log("height:", H.height, "| txs:", txs.length, "| aunts:", aunts.length, "| blob bytes:", blob.length, process.env.TAMPER ? "| TAMPERED tx" : "");
  console.log("wrote", outName);
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
