// build_advance_mock.mjs — ckb-debugger mock for tendermint_advance. Lock args = current_anchor(32) ||
// new_anchor(32); witness = header leaves + commit + validator set (no tx inclusion). Proves the anchor
// transition current (validators_hash) -> new (next_validators_hash) is valid. BADNEW=1 sets a wrong new
// anchor -> reject (21).
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/tendermint_advance");
const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
const vals = JSON.parse(fs.readFileSync(path.join(HERE, "validators.json"), "utf8"));
const H = sh.header, c = sh.commit;

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const hx = (s) => Buffer.from(s, "hex");
const b64 = (s) => Buffer.from(s, "base64");
const ts = (iso) => { const m = iso.match(/^(.*?)(?:\.(\d+))?Z$/); return { seconds: Math.floor(Date.parse(m[1] + "Z") / 1000), nanos: m[2] ? parseInt(m[2].padEnd(9, "0").slice(0, 9), 10) : 0 }; };
function varint(n) { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); }
const tag = (f, w) => varint((f << 3) | w);
const pbBytes = (f, b) => Buffer.concat([tag(f, 2), varint(b.length), b]);
const pbVar = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
const cdcStr = (s) => (s ? pbBytes(1, Buffer.from(s, "utf8")) : Buffer.alloc(0));
const cdcInt = (n) => pbVar(1, n);
const cdcBytes = (h) => { const b = h ? hx(h) : Buffer.alloc(0); return b.length ? pbBytes(1, b) : Buffer.alloc(0); };
const versionEnc = (bl, ap) => { const o = []; if (bl) o.push(pbVar(1, bl)); if (ap) o.push(pbVar(2, ap)); return Buffer.concat(o); };
const timeEnc = (iso) => { const t = ts(iso); const o = []; if (t.seconds) o.push(pbVar(1, t.seconds)); if (t.nanos) o.push(pbVar(2, t.nanos)); return Buffer.concat(o); };
const partSetEnc = (t, h) => { const o = []; if (t) o.push(pbVar(1, t)); o.push(pbBytes(2, hx(h))); return Buffer.concat(o); };
const blockIDEnc = (b) => Buffer.concat([pbBytes(1, hx(b.hash)), pbBytes(2, partSetEnc(b.parts.total, b.parts.hash))]);

const leaves = [versionEnc(Number(H.version.block || 0), Number(H.version.app || 0)), cdcStr(H.chain_id), cdcInt(H.height), timeEnc(H.time),
  blockIDEnc(H.last_block_id), cdcBytes(H.last_commit_hash), cdcBytes(H.data_hash), cdcBytes(H.validators_hash), cdcBytes(H.next_validators_hash),
  cdcBytes(H.consensus_hash), cdcBytes(H.app_hash), cdcBytes(H.last_results_hash), cdcBytes(H.evidence_hash), cdcBytes(H.proposer_address)];

const parts = [Buffer.from([leaves.length])];
for (const l of leaves) parts.push(u16(l.length), l);
const cid = Buffer.from(H.chain_id, "utf8");
parts.push(Buffer.from([cid.length]), cid, u64(H.height), u64(c.round), u32(c.block_id.parts.total), hx(c.block_id.parts.hash), u16(vals.length));
for (const v of vals) parts.push(b64(v.pub_key.value), u64(v.voting_power));
const addrIdx = new Map(vals.map((v, i) => [v.address, i]));
const pre = c.signatures.filter((s) => s.block_id_flag === 2 && s.signature);
parts.push(u16(pre.length));
for (const s of pre) { const t = ts(s.timestamp); parts.push(u16(addrIdx.get(s.validator_address)), i64(t.seconds), u32(t.nanos), b64(s.signature)); }
const blob = Buffer.concat(parts);

// args = current_anchor (validators_hash) || new_anchor (next_validators_hash). BADNEW flips the new anchor.
const current = hx(H.validators_hash);
const newAnchor = hx(H.next_validators_hash); if (process.env.BADNEW) newAnchor[0] ^= 0xff;

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const lock = ccc.Script.from({ codeHash: ccc.hashCkb(data), hashType: "data1", args: "0x" + Buffer.concat([current, newAnchor]).toString("hex") });
const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const PREV = { tx_hash: "0x" + "00".repeat(32), index: "0x0" }, DEP = { tx_hash: "0x" + "01".repeat(32), index: "0x0" };
const wit = ccc.hexFrom(ccc.WitnessArgs.from({ lock: "0x" + blob.toString("hex") }).toBytes());
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);
const mock = {
  mock_info: { inputs: [{ input: { since: "0x0", previous_output: PREV }, output: { capacity: "0x2e90edd000", lock: scr(lock), type: null }, data: "0x", header: null }],
    cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: depCap, lock: scr(ccc.Script.from({ codeHash: "0x" + "33".repeat(32), hashType: "type", args: "0x" })), type: null }, data, header: null }], header_deps: [] },
  tx: { version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [], inputs: [{ since: "0x0", previous_output: PREV }], outputs: [{ capacity: "0x2e90edd000", lock: scr(lock), type: null }], outputs_data: ["0x"], witnesses: [wit] },
};
const out = process.env.BADNEW ? "adv_mock_bad.json" : "adv_mock.json";
fs.writeFileSync(path.join(HERE, out), JSON.stringify(mock, null, 2));
console.log("current anchor:", H.validators_hash.slice(0, 16), "| new (next_validators):", H.next_validators_hash.slice(0, 16), process.env.BADNEW ? "| BADNEW" : "");
console.log("wrote", out);
