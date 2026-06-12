// build_catom_mock.mjs — end-to-end ckb-debugger mock for catom_mint (Cosmos -> CKB wrapped mint). It builds a
// SYNTHETIC single-validator Tendermint block whose one tx is an escrow MsgSend (so a chosen escrow/amount/memo
// can sit in a signed block: a real cosmoshub block can't carry our escrow). The Tendermint encodings here are
// the SAME ones already proven against real cosmoshub data by build_inclusion_mock.mjs; what this mock proves is
// the MINT LOGIC: the inclusion proof gates the mint, the escrow MsgSend is parsed in CKB-VM, and the chiATOM
// output is bound 1:1 to (amount, recipient) with a replay-once nullifier.
//
//   wsl: ckb-debugger --max-cycles 5000000000 --tx-file catom_mock.json --script-group-type type --cell-type output --cell-index 0   # 0
//   BADAMOUNT/BADRECIP/BADPIN/BADTYPEURL=1 node build_catom_mock.mjs   # -> 24 / 28 / 9 / 30
import { ccc } from "@ckb-ccc/core";
import nacl from "tweetnacl";
import { blake2b } from "@noble/hashes/blake2.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/catom_mint");
const SHA = (b) => crypto.createHash("sha256").update(b).digest();
const B2B = (b) => Buffer.from(blake2b(b, { dkLen: 32 })); // vanilla BLAKE2b-256 (matches the script's b2b256)

// LE packers + protobuf
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const varint = (n) => { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); };
const tag = (f, w) => varint((f << 3) | w);
const pbBytes = (f, b) => Buffer.concat([tag(f, 2), varint(b.length), b]);
const pbVar = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
const hexBuf = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");

// ---- Tendermint simple Merkle (SHA256) — identical to the script ----
const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0x00]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([0x01]), l, r]));
function splitPoint(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function merkleRoot(items) { if (items.length === 1) return leafHash(items[0]); const k = splitPoint(items.length); return innerHash(merkleRoot(items.slice(0, k)), merkleRoot(items.slice(k))); }

// ---- header-leaf encoders (from build_inclusion_mock) ----
const cdcStr = (s) => (s ? pbBytes(1, Buffer.from(s, "utf8")) : Buffer.alloc(0));
const cdcInt = (n) => pbVar(1, n);
const cdcBytes = (buf) => (buf && buf.length ? pbBytes(1, buf) : Buffer.alloc(0));
const versionEnc = (block, app) => { const o = []; if (block) o.push(pbVar(1, block)); if (app) o.push(pbVar(2, app)); return Buffer.concat(o); };
const timeEnc = (sec, nanos) => { const o = []; if (sec) o.push(pbVar(1, sec)); if (nanos) o.push(pbVar(2, nanos)); return Buffer.concat(o); };
const partSetEnc = (total, hash) => Buffer.concat([pbVar(1, total), pbBytes(2, hash)]);
const blockIDEnc = (hash, total, partHash) => Buffer.concat([pbBytes(1, hash), pbBytes(2, partSetEnc(total, partHash))]);

// ---- canonical vote (matches the script's vote_sign_bytes) ----
function canonicalBlockId(hash, total, partHash) { return Buffer.concat([pbBytes(1, hash), pbBytes(2, partSetEnc(total, partHash))]); }
function voteSignBytes(height, round, blockHash, total, partHash, seconds, nanos, chainId) {
  const parts = [];
  parts.push(tag(1, 0), varint(2));                       // type = 2 (precommit)
  parts.push(tag(2, 1), u64(height));                     // height (fixed64 LE)
  if (round !== 0) { parts.push(tag(3, 1), u64(round)); } // round omitted when 0
  const bid = canonicalBlockId(blockHash, total, partHash);
  parts.push(pbBytes(4, bid));
  const ts = timeEnc(seconds, nanos);
  parts.push(pbBytes(5, ts));
  parts.push(pbBytes(6, Buffer.from(chainId, "utf8")));
  const body = Buffer.concat(parts);
  return Buffer.concat([varint(body.length), body]);
}
// ---- SimpleValidator (matches the script) ----
function simpleValidator(pk, power) {
  const pubkeyMsg = Buffer.concat([Buffer.from([0x0a, 0x20]), pk]);          // PublicKey { ed25519 = pk }
  return Buffer.concat([Buffer.from([0x0a]), varint(pubkeyMsg.length), pubkeyMsg, Buffer.from([0x10]), varint(power)]);
}

// ---- the escrow MsgSend TxRaw (matches the catom_mint protobuf reader) ----
const encBytes = (field, b) => Buffer.concat([varint((field << 3) | 2), varint(b.length), b]);
function buildTx(toAddr, denom, amountStr, memo) {
  const coin = Buffer.concat([encBytes(1, Buffer.from(denom)), encBytes(2, Buffer.from(amountStr))]);
  const msg = Buffer.concat([encBytes(1, Buffer.from("cosmos1from")), encBytes(2, Buffer.from(toAddr)), encBytes(3, coin)]);
  const typeUrl = process.env.BADTYPEURL ? "/ibc.applications.transfer.v1.MsgTransfer" : "/cosmos.bank.v1beta1.MsgSend";
  const any = Buffer.concat([encBytes(1, Buffer.from(typeUrl)), encBytes(2, msg)]);
  const body = Buffer.concat([encBytes(1, any), encBytes(2, Buffer.from(memo))]);
  return encBytes(1, body); // TxRaw.body_bytes
}

// ============================ assemble ============================
const ESCROW = "cosmos1escrowacctxxxxxxxxxxxxxxxxxxxxxxx"; // pinned escrow account
const DENOM = "uatom";
const AMOUNT = 20000000;

// the chiATOM output lock; recipient = its script hash; memo carries hex(recipient).
const outLock = ccc.Script.from({ codeHash: "0x" + "44".repeat(32), hashType: "type", args: "0x" });
const recipient = hexBuf(outLock.hash());
const memo = recipient.toString("hex"); // 64-char lowercase hex

const tx = buildTx(ESCROW, DENOM, String(AMOUNT), memo);
const txHash = SHA(tx);

// synthetic single validator
const kp = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7)); // deterministic
const pk = Buffer.from(kp.publicKey);
const POWER = 100;
const valsetHash = merkleRoot([simpleValidator(pk, POWER)]);

// block: data_hash = the 1-tx tree root; build the 14 header leaves
const dataHash = leafHash(SHA(tx)); // 1 tx
const z32 = (x) => Buffer.alloc(32, x);
const height = 12345678, round = 0, partTotal = 1, partHash = z32(0xaa);
const chainId = "chiral-catom-1";
const tsSec = 1700000000, tsNanos = 0;
const leaves = [
  versionEnc(11, 0), cdcStr(chainId), cdcInt(height), timeEnc(tsSec, tsNanos),
  blockIDEnc(z32(0x00), 1, z32(0xbb)), cdcBytes(z32(0x11)), cdcBytes(dataHash), cdcBytes(valsetHash),
  cdcBytes(valsetHash), cdcBytes(z32(0x22)), cdcBytes(z32(0x33)), cdcBytes(z32(0x44)),
  cdcBytes(z32(0x55)), cdcBytes(Buffer.alloc(20, 0x66)),
];
const blockHash = merkleRoot(leaves);
const sig = Buffer.from(nacl.sign.detached(voteSignBytes(height, round, blockHash, partTotal, partHash, tsSec, tsNanos, chainId), kp.secretKey));

// the Cosmos inclusion blob (tendermint_inclusion witness layout)
const parts = [];
parts.push(Buffer.from([leaves.length]));
for (const l of leaves) parts.push(u16(l.length), l);
const cid = Buffer.from(chainId, "utf8");
parts.push(Buffer.from([cid.length]), cid, u64(height), u64(round), u32(partTotal), partHash);
parts.push(u16(1), pk, u64(POWER));                 // 1 validator
parts.push(u16(1), u16(0), i64(tsSec), u32(tsNanos), sig); // 1 precommit (val_idx 0)
parts.push(u16(tx.length), tx, u32(0), u32(1), Buffer.from([0])); // incl: index 0, total 1, 0 aunts
const blob = Buffer.concat(parts);

// CKB scripts
const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const catomCodeHash = ccc.hashCkb(data);
const regScript = ccc.Script.from({ codeHash: "0x" + "b2".repeat(32), hashType: "type", args: "0x" });
const regTypeHash = hexBuf(regScript.hash());

// catom_mint args = valset_anchor(32) || reg_type(32) || u8 denom_len || denom || escrow_to  (anchor baked in)
const denomB = Buffer.from(DENOM), escrowB = Buffer.from(ESCROW);
const anchor = Buffer.from(valsetHash); if (process.env.BADPIN) anchor[0] ^= 0xff;
const catomArgs = Buffer.concat([anchor, regTypeHash, Buffer.from([denomB.length]), denomB, escrowB]);
const catomType = ccc.Script.from({ codeHash: catomCodeHash, hashType: "data1", args: "0x" + catomArgs.toString("hex") });

// chiATOM output: data = amount(16 LE); BADAMOUNT mints a different amount than the escrow's.
const mintedAmount = process.env.BADAMOUNT ? AMOUNT + 1 : AMOUNT;
const outData = Buffer.alloc(16); outData.writeBigUInt64LE(BigInt(mintedAmount), 0);
// BADRECIP: lock the output at a DIFFERENT lock than the memo's recipient.
const realOutLock = process.env.BADRECIP ? ccc.Script.from({ codeHash: "0x" + "45".repeat(32), hashType: "type", args: "0x" }) : outLock;

// registry nullifier key = b2b256(0x04 || sha256(tx))
const nfKey = B2B(Buffer.concat([Buffer.from([0x04]), txHash]));

const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const anyLock = scr(ccc.Script.from({ codeHash: "0x" + "55".repeat(32), hashType: "type", args: "0x" }));
const OP = (h, i) => ({ tx_hash: "0x" + h, index: "0x" + i.toString(16) });
const IN0 = OP("00".repeat(32), 0), IN1 = OP("11".repeat(32), 0);
const DEP_CODE = OP("ce".repeat(32), 0);
const cap = "0x2e90edd000";
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);

// witnesses: [0] output-type group (inclusion blob in input_type), [1] registry input (key in input_type)
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
    header_deps: [],
    inputs: [{ since: "0x0", previous_output: IN0 }, { since: "0x0", previous_output: IN1 }],
    outputs: [{ capacity: cap, lock: scr(realOutLock), type: scr(catomType) }],
    outputs_data: ["0x" + outData.toString("hex")],
    witnesses: [wit0, wit1],
  },
};

const flag = process.env.BADAMOUNT ? "badamount" : process.env.BADRECIP ? "badrecip" : process.env.BADPIN ? "badpin" : process.env.BADTYPEURL ? "badtypeurl" : null;
const out = flag ? `catom_mock_${flag}.json` : "catom_mock.json";
fs.writeFileSync(path.join(HERE, out), JSON.stringify(mock, null, 2));
console.log("recipient:", recipient.toString("hex").slice(0, 16), "| valset_hash:", valsetHash.toString("hex").slice(0, 16), "| block_hash:", blockHash.toString("hex").slice(0, 16));
console.log("tx bytes:", tx.length, "| blob bytes:", blob.length, "| minted:", mintedAmount, flag ? `| ${flag.toUpperCase()}` : "");
console.log("wrote", out);
