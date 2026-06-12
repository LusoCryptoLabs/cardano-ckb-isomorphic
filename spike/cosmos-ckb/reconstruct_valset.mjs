// reconstruct_valset.mjs — compute the Tendermint validators_hash from the validator set and check it equals
// the header's validators_hash. This is what lets the on-chain verifier BIND the signing set to the chain
// (and to a pinned trusted anchor) instead of trusting a witness-supplied set. Encoding pinned before porting.
//
// validators_hash = MerkleRoot([ SimpleValidator(v).Marshal() for v in set ]), in canonical (RPC) order.
// SimpleValidator = { pub_key (PublicKey{ed25519: 32 bytes}) field 1, voting_power int64 field 2 }.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
const vals = JSON.parse(fs.readFileSync(path.join(HERE, "validators.json"), "utf8"));
const SHA = (b) => crypto.createHash("sha256").update(b).digest();
const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0x00]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([0x01]), l, r]));
function splitPoint(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function merkleRoot(items) { if (items.length === 1) return leafHash(items[0]); const k = splitPoint(items.length); return innerHash(merkleRoot(items.slice(0, k)), merkleRoot(items.slice(k))); }
function varint(n) { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); }

function simpleValidator(pubkeyB64, power) {
  const key = Buffer.from(pubkeyB64, "base64");                                  // 32-byte ed25519 key
  const pubkeyMsg = Buffer.concat([Buffer.from([0x0a, 0x20]), key]);             // PublicKey{ ed25519 = key } (field 1)
  const field1 = Buffer.concat([Buffer.from([0x0a]), varint(pubkeyMsg.length), pubkeyMsg]); // SimpleValidator.pub_key
  const field2 = Buffer.concat([Buffer.from([0x10]), varint(power)]);           // SimpleValidator.voting_power
  return Buffer.concat([field1, field2]);
}

const items = vals.map((v) => simpleValidator(v.pub_key.value, Number(v.voting_power)));
const root = merkleRoot(items).toString("hex").toUpperCase();
console.log("computed validators_hash:", root);
console.log("header validators_hash  :", sh.header.validators_hash);
console.log(root === sh.header.validators_hash ? "=> MATCH: the signing set is bound to the header (and can be pinned as the trust anchor)" : "=> MISMATCH (encoding/order wrong)");
