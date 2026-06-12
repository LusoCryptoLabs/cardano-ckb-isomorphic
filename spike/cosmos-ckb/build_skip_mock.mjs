// build_skip_mock.mjs — ckb-debugger mock for tendermint_skip (the SKIPPING / non-adjacent light client). It
// builds a synthetic far-ahead block H2 with its OWN validator set, plus a distinct TRUSTED set, and checks the
// trust level. Scenario: TRUSTED = {T0,T1,T2,T3} (power 25 each, total 100); H2's own set = {T0,T1,N2,N3}
// (power 25 each, total 100), so two trusted validators carry over (50 trusted power available).
//   POSITIVE   : all of H2's set sign -> signed_new 100 (>2/3), signed_trust 50 (>1/3) -> 0
//   LOWTRUST=1 : only T1,N2,N3 sign  -> signed_new 75 (>2/3) but signed_trust 25 (<=1/3) -> 22
//   LOWNEW=1   : only N2,N3 sign     -> signed_new 50 (<=2/3) -> 20
//   BADNEW=1   : wrong new_anchor (args != leaf[8]) -> 21
//   BADTRUST=1 : wrong trusted_anchor (args != hash(trusted set)) -> 9
import { ccc } from "@ckb-ccc/core";
import nacl from "tweetnacl";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/tendermint_skip");
const SHA = (b) => crypto.createHash("sha256").update(b).digest();
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const varint = (n) => { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); };
const tag = (f, w) => varint((f << 3) | w);
const pbBytes = (f, b) => Buffer.concat([tag(f, 2), varint(b.length), b]);
const pbVar = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
const z32 = (x) => Buffer.alloc(32, x);

const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0x00]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([0x01]), l, r]));
function splitPoint(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function merkleRoot(items) { if (items.length === 1) return leafHash(items[0]); const k = splitPoint(items.length); return innerHash(merkleRoot(items.slice(0, k)), merkleRoot(items.slice(k))); }

const cdcStr = (s) => pbBytes(1, Buffer.from(s, "utf8"));
const cdcInt = (n) => pbVar(1, n);
const cdcBytes = (buf) => pbBytes(1, buf);
const versionEnc = (b, a) => Buffer.concat([pbVar(1, b), a ? pbVar(2, a) : Buffer.alloc(0)]);
const timeEnc = (sec, nanos) => Buffer.concat([pbVar(1, sec), nanos ? pbVar(2, nanos) : Buffer.alloc(0)]);
const partSetEnc = (total, hash) => Buffer.concat([pbVar(1, total), pbBytes(2, hash)]);
const blockIDEnc = (hash, total, ph) => Buffer.concat([pbBytes(1, hash), pbBytes(2, partSetEnc(total, ph))]);

function simpleValidator(pk, power) {
  const pubkeyMsg = Buffer.concat([Buffer.from([0x0a, 0x20]), pk]);
  return Buffer.concat([Buffer.from([0x0a]), varint(pubkeyMsg.length), pubkeyMsg, Buffer.from([0x10]), varint(power)]);
}
const valsetRoot = (vals) => merkleRoot(vals.map((v) => simpleValidator(v.pk, v.power)));

function canonicalBlockId(hash, total, ph) { return Buffer.concat([pbBytes(1, hash), pbBytes(2, partSetEnc(total, ph))]); }
function voteSignBytes(height, round, blockHash, total, ph, sec, nanos, chainId) {
  const parts = [tag(1, 0), varint(2), tag(2, 1), u64(height)];
  if (round !== 0) parts.push(tag(3, 1), u64(round));
  parts.push(pbBytes(4, canonicalBlockId(blockHash, total, ph)));
  parts.push(pbBytes(5, timeEnc(sec, nanos)));
  parts.push(pbBytes(6, Buffer.from(chainId, "utf8")));
  const body = Buffer.concat(parts);
  return Buffer.concat([varint(body.length), body]);
}

// validators (deterministic seeds)
const mk = (seed) => { const kp = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, seed)); return { kp, pk: Buffer.from(kp.publicKey), power: 25 }; };
const T0 = mk(10), T1 = mk(11), T2 = mk(12), T3 = mk(13), N2 = mk(22), N3 = mk(23);
const TRUSTED = [T0, T1, T2, T3];     // the set the anchor commits to
const NEWSET = [T0, T1, N2, N3];      // H2's own set (T0,T1 carry over)

const chainId = "chiral-skip-1", height = 99999999, round = 0, partTotal = 1, partHash = z32(0xaa);
const tsSec = 1700009999, tsNanos = 0;
const trustedAnchor = valsetRoot(TRUSTED);
const newValsHash = valsetRoot(NEWSET);
const newAnchor = z32(0x99);          // H2.next_validators_hash (the anchor we skip TO)

const leaves = [
  versionEnc(11, 0), cdcStr(chainId), cdcInt(height), timeEnc(tsSec, tsNanos),
  blockIDEnc(z32(0x00), 1, z32(0xbb)), cdcBytes(z32(0x11)), cdcBytes(z32(0x12)), cdcBytes(newValsHash),
  cdcBytes(newAnchor), cdcBytes(z32(0x22)), cdcBytes(z32(0x33)), cdcBytes(z32(0x44)),
  cdcBytes(z32(0x55)), cdcBytes(Buffer.alloc(20, 0x66)),
];
const blockHash = merkleRoot(leaves);
const sb = voteSignBytes(height, round, blockHash, partTotal, partHash, tsSec, tsNanos, chainId);

// which of NEWSET sign (indices into NEWSET)
let signerIdx = [0, 1, 2, 3];
if (process.env.LOWTRUST) signerIdx = [1, 2, 3]; // drop T0 -> only T1 trusted among signers
if (process.env.LOWNEW) signerIdx = [2, 3];      // only N2,N3 -> 50% of H2 power

const parts = [];
parts.push(Buffer.from([leaves.length]));
for (const l of leaves) parts.push(u16(l.length), l);
const cid = Buffer.from(chainId, "utf8");
parts.push(Buffer.from([cid.length]), cid, u64(height), u64(round), u32(partTotal), partHash);
// H2's own set
parts.push(u16(NEWSET.length));
for (const v of NEWSET) parts.push(v.pk, u64(v.power));
// trusted set
parts.push(u16(TRUSTED.length));
for (const v of TRUSTED) parts.push(v.pk, u64(v.power));
// precommits (val_idx into NEWSET)
parts.push(u16(signerIdx.length));
for (const idx of signerIdx) {
  const sig = Buffer.from(nacl.sign.detached(sb, NEWSET[idx].kp.secretKey));
  parts.push(u16(idx), i64(tsSec), u32(tsNanos), sig);
}
const blob = Buffer.concat(parts);

// args = trusted_anchor || new_anchor (BADNEW/BADTRUST corrupt one)
const argTrusted = Buffer.from(trustedAnchor); if (process.env.BADTRUST) argTrusted[0] ^= 0xff;
const argNew = Buffer.from(newAnchor); if (process.env.BADNEW) argNew[0] ^= 0xff;

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const lock = ccc.Script.from({ codeHash: ccc.hashCkb(data), hashType: "data1", args: "0x" + Buffer.concat([argTrusted, argNew]).toString("hex") });
const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const PREV = { tx_hash: "0x" + "00".repeat(32), index: "0x0" }, DEP = { tx_hash: "0x" + "01".repeat(32), index: "0x0" };
const wit = ccc.hexFrom(ccc.WitnessArgs.from({ lock: "0x" + blob.toString("hex") }).toBytes());
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);
const mock = {
  mock_info: { inputs: [{ input: { since: "0x0", previous_output: PREV }, output: { capacity: "0x2e90edd000", lock: scr(lock), type: null }, data: "0x", header: null }],
    cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: depCap, lock: scr(ccc.Script.from({ codeHash: "0x" + "33".repeat(32), hashType: "type", args: "0x" })), type: null }, data, header: null }], header_deps: [] },
  tx: { version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [], inputs: [{ since: "0x0", previous_output: PREV }], outputs: [{ capacity: "0x2e90edd000", lock: scr(lock), type: null }], outputs_data: ["0x"], witnesses: [wit] },
};
const flag = process.env.LOWTRUST ? "lowtrust" : process.env.LOWNEW ? "lownew" : process.env.BADNEW ? "badnew" : process.env.BADTRUST ? "badtrust" : null;
const out = flag ? `skip_mock_${flag}.json` : "skip_mock.json";
fs.writeFileSync(path.join(HERE, out), JSON.stringify(mock, null, 2));
console.log("trusted_anchor:", trustedAnchor.toString("hex").slice(0, 16), "| new_vals_hash:", newValsHash.toString("hex").slice(0, 16), "| signers:", signerIdx.join(","), flag ? `| ${flag.toUpperCase()}` : "");
console.log("wrote", out);
