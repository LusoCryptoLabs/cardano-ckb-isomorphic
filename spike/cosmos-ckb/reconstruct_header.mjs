// reconstruct_header.mjs — rebuild the Tendermint header hash from its 14 fields and check it equals the
// commit-signed block_id.hash. This binds data_hash (the tx Merkle root) and app_hash (the state root) to the
// block the commit verified. Nails the header encoding before porting to CKB-VM.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
const H = sh.header;
const SHA = (b) => crypto.createHash("sha256").update(b).digest();

function varint(n) { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); }
const tag = (f, w) => varint((f << 3) | w);
const pbBytes = (f, b) => Buffer.concat([tag(f, 2), varint(b.length), b]);
const pbVar = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
const hx = (s) => Buffer.from(s, "hex");

// cdcEncode: wrap a value as proto field 1; empty -> nil leaf.
const cdcStr = (s) => (s ? pbBytes(1, Buffer.from(s, "utf8")) : Buffer.alloc(0));
const cdcInt = (n) => pbVar(1, n);
const cdcBytes = (hex) => { const b = hex ? hx(hex) : Buffer.alloc(0); return b.length ? pbBytes(1, b) : Buffer.alloc(0); };

function versionEnc(block, app) { const o = []; if (block) o.push(pbVar(1, block)); if (app) o.push(pbVar(2, app)); return Buffer.concat(o); }
function timeEnc(iso) { const m = iso.match(/^(.*?)(?:\.(\d+))?Z$/); const seconds = Math.floor(Date.parse(m[1] + "Z") / 1000); const nanos = m[2] ? parseInt(m[2].padEnd(9, "0").slice(0, 9), 10) : 0; const o = []; if (seconds) o.push(pbVar(1, seconds)); if (nanos) o.push(pbVar(2, nanos)); return Buffer.concat(o); }
function partSetEnc(total, hash) { const o = []; if (total) o.push(pbVar(1, total)); o.push(pbBytes(2, hx(hash))); return Buffer.concat(o); }
function blockIDEnc(bid) { return Buffer.concat([pbBytes(1, hx(bid.hash)), pbBytes(2, partSetEnc(bid.parts.total, bid.parts.hash))]); }

// Tendermint simple Merkle tree
const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0x00]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([0x01]), l, r]));
function splitPoint(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function merkleRoot(items) {
  if (items.length === 0) return SHA(Buffer.alloc(0));
  if (items.length === 1) return leafHash(items[0]);
  const k = splitPoint(items.length);
  return innerHash(merkleRoot(items.slice(0, k)), merkleRoot(items.slice(k)));
}

const leaves = [
  versionEnc(Number(H.version.block || 0), Number(H.version.app || 0)),
  cdcStr(H.chain_id),
  cdcInt(H.height),
  timeEnc(H.time),
  blockIDEnc(H.last_block_id),
  cdcBytes(H.last_commit_hash),
  cdcBytes(H.data_hash),
  cdcBytes(H.validators_hash),
  cdcBytes(H.next_validators_hash),
  cdcBytes(H.consensus_hash),
  cdcBytes(H.app_hash),
  cdcBytes(H.last_results_hash),
  cdcBytes(H.evidence_hash),
  cdcBytes(H.proposer_address),
];
const root = merkleRoot(leaves).toString("hex").toUpperCase();
console.log("reconstructed header root:", root);
console.log("commit block_id.hash     :", sh.commit.block_id.hash);
console.log(root === sh.commit.block_id.hash ? "=> MATCH: header (data_hash + app_hash) is bound to the verified block" : "=> MISMATCH (encoding wrong)");
console.log("\ndata_hash (tx Merkle root):", H.data_hash);
console.log("app_hash  (state root)    :", H.app_hash);
