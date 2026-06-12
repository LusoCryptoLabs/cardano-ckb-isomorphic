// verify_offchain.mjs — reproduce Tendermint precommit signature verification off-chain, so the exact
// canonical-vote sign-bytes are nailed before porting to CKB-VM. Builds VoteSignBytes = MarshalDelimited(
// CanonicalVote{type, height, round, block_id, timestamp, chain_id}) per precommit and ed25519-verifies it,
// then sums the voting power of valid signatures and checks > 2/3. This is exactly what the CKB script will do.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import nacl from "tweetnacl";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
const vals = JSON.parse(fs.readFileSync(path.join(HERE, "validators.json"), "utf8"));
const INCLUDE_ROUND = process.env.NO_ROUND ? false : true; // toggle to test the round=0 encoding rule

const b64 = (s) => Buffer.from(s, "base64");
const hex = (s) => Buffer.from(s, "hex");
function varint(n) { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); }
const tag = (field, wire) => varint((field << 3) | wire);
function fixed64le(n) { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; }
const lenDelim = (field, bytes) => Buffer.concat([tag(field, 2), varint(bytes.length), bytes]);

function partSetHeader(total, hashHex) { return Buffer.concat([tag(1, 0), varint(total), lenDelim(2, hex(hashHex))]); }
function canonicalBlockID(hashHex, total, partHashHex) { return Buffer.concat([lenDelim(1, hex(hashHex)), lenDelim(2, partSetHeader(total, partHashHex))]); }
function timestamp(iso) {
  const m = iso.match(/^(.*?)(?:\.(\d+))?Z$/);
  const seconds = Math.floor(Date.parse(m[1] + "Z") / 1000);
  const nanos = m[2] ? parseInt(m[2].padEnd(9, "0").slice(0, 9), 10) : 0;
  const parts = [Buffer.concat([tag(1, 0), varint(seconds)])];
  if (nanos !== 0) parts.push(Buffer.concat([tag(2, 0), varint(nanos)]));
  return Buffer.concat(parts);
}
function voteSignBytes({ type, height, round, blockHashHex, total, partHashHex, ts, chainId }) {
  const parts = [];
  parts.push(Buffer.concat([tag(1, 0), varint(type)]));            // 1 type
  parts.push(Buffer.concat([tag(2, 1), fixed64le(height)]));       // 2 height sfixed64
  if (INCLUDE_ROUND || round !== 0) parts.push(Buffer.concat([tag(3, 1), fixed64le(round)])); // 3 round sfixed64
  parts.push(lenDelim(4, canonicalBlockID(blockHashHex, total, partHashHex))); // 4 block_id
  parts.push(lenDelim(5, timestamp(ts)));                          // 5 timestamp
  parts.push(lenDelim(6, Buffer.from(chainId, "utf8")));           // 6 chain_id
  const msg = Buffer.concat(parts);
  return Buffer.concat([varint(msg.length), msg]);                 // MarshalDelimited (varint length prefix)
}

const valByAddr = new Map(vals.map((v) => [v.address, v]));
const totalPower = vals.reduce((a, v) => a + Number(v.voting_power), 0);
const c = sh.commit;
let ok = 0, bad = 0, okPower = 0;
for (const sig of c.signatures) {
  if (sig.block_id_flag !== 2 || !sig.signature) continue; // only committed precommits
  const v = valByAddr.get(sig.validator_address);
  if (!v) { bad++; continue; }
  const sb = voteSignBytes({ type: 2, height: Number(sh.header.height), round: Number(c.round),
    blockHashHex: c.block_id.hash, total: Number(c.block_id.parts.total), partHashHex: c.block_id.parts.hash,
    ts: sig.timestamp, chainId: sh.header.chain_id });
  const good = nacl.sign.detached.verify(new Uint8Array(sb), new Uint8Array(b64(sig.signature)), new Uint8Array(b64(v.pub_key.value)));
  if (good) { ok++; okPower += Number(v.voting_power); } else bad++;
}
console.log("INCLUDE_ROUND:", INCLUDE_ROUND);
console.log("verified sigs:", ok, "| failed:", bad);
console.log("voting power of valid sigs:", okPower, "/", totalPower, "=", (okPower / totalPower * 100).toFixed(2) + "%");
console.log(okPower * 3 > totalPower * 2 ? "=> COMMIT VALID: > 2/3 power signed (CKB can verify this)" : "=> NOT > 2/3 (encoding likely wrong)");
