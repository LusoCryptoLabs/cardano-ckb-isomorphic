// derive_inputs.mjs — independent reference for the contract's event->public-inputs binding. The leap circuit
// (leap_bound_windowed.rs) builds its 5 Groth16 public inputs from a concrete CKB event:
//   pi[0] = LEmod(window_root)                                   (32-byte CKB header-window Merkle root)
//   pi[1] = LEmod(seal)                                          (32-byte spent-cell / tx hash = the event id)
//   pi[2] = LEmod( blake2b256( amount(16 LE) || recipient(28) || seal(32) ) )   (value+recipient commitment)
//   pi[3] = tip_height                                           (u64)
//   pi[4] = K                                                    (u64, confirmation depth)
// where LEmod(b) = (b interpreted little-endian) mod r, r = the BLS12-381 scalar field order, and the canonical
// encoding of a field element is its reduced value as 32 little-endian bytes. The CosmWasm contract derives the
// same 5 values in wasm; this script is the independent oracle the Rust test cross-checks against. blake2b256
// is standard BLAKE2b with a 32-byte digest (no key/personalization), matching the circuit's b2b().
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { blake2b } from "@noble/hashes/blake2.js";

const R = bls.fields.Fr.ORDER; // BLS12-381 scalar field modulus
const hx = (s) => Buffer.from(s.replace(/^0x/, ""), "hex");
const leBig = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const bigLe32 = (n) => { const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
const leModHex = (b) => bigLe32(leBig(b) % R).toString("hex");
const u64Hex = (n) => bigLe32(BigInt(n) % R).toString("hex");
const leModDec = (b) => (leBig(b) % R).toString(10);

// A deterministic constructed event. window_root is all-0xff to force a real mod-r reduction (value > r), so the
// from_bytes_wide reduction path in the contract is exercised, not just the canonical < r case.
const ev = {
  window_root: "ff".repeat(32),
  seal: [...Array(32).keys()].map((i) => i.toString(16).padStart(2, "0")).join(""), // 00 01 .. 1f
  amount: 123456789n,            // u128, encoded 16-byte LE
  recipient: "aa".repeat(28),    // 28-byte CKB recipient lock-arg
  tip_height: 21388353n,
  k: 12n,
};

const amount16 = Buffer.alloc(16);
{ let n = ev.amount; for (let i = 0; i < 16; i++) { amount16[i] = Number(n & 0xffn); n >>= 8n; } }
const seal = hx(ev.seal);
const commitPre = Buffer.concat([amount16, hx(ev.recipient), seal]); // 16 + 28 + 32 = 76 bytes
const commitment = Buffer.from(blake2b(commitPre, { dkLen: 32 }));

const pi = [
  { name: "window_root", le32: leModHex(hx(ev.window_root)), dec: leModDec(hx(ev.window_root)) },
  { name: "seal",        le32: leModHex(seal),               dec: leModDec(seal) },
  { name: "commitment",  le32: leModHex(commitment),         dec: leModDec(commitment) },
  { name: "tip_height",  le32: u64Hex(ev.tip_height),        dec: (ev.tip_height % R).toString(10) },
  { name: "k",           le32: u64Hex(ev.k),                 dec: (ev.k % R).toString(10) },
];

console.log("constructed event:", JSON.stringify({ ...ev, amount: ev.amount.toString(), tip_height: ev.tip_height.toString(), k: ev.k.toString() }));
console.log("commitment blake2b256(amount16||recip28||seal32) =", commitment.toString("hex"));
console.log("\n5 derived public inputs (canonical 32-byte little-endian hex | decimal):");
for (const p of pi) console.log(`  ${p.name.padEnd(12)} ${p.le32}  ${p.dec}`);

console.log("\n// Rust cross-check vectors (paste into the contract test):");
for (const p of pi) console.log(`    "${p.le32}", // ${p.name}`);

// RETURN-leg (CKB->Cosmos) burn event: same derivation, recipient is a 20-byte Osmosis account address.
const bev = { window_root: "ee".repeat(32), seal: [...Array(32).keys()].map((i) => ((i + 1) & 0xff).toString(16).padStart(2, "0")).join(""), amount: 7654321n, recipient: "bb".repeat(20), tip_height: 20000000n, k: 7n };
const bamount16 = Buffer.alloc(16);
{ let n = bev.amount; for (let i = 0; i < 16; i++) { bamount16[i] = Number(n & 0xffn); n >>= 8n; } }
const bseal = hx(bev.seal);
const bcommit = Buffer.from(blake2b(Buffer.concat([bamount16, hx(bev.recipient), bseal]), { dkLen: 32 }));
const bpi = [leModHex(hx(bev.window_root)), leModHex(bseal), leModHex(bcommit), u64Hex(bev.tip_height), u64Hex(bev.k)];
console.log("\n// BURN event (20-byte recipient) Rust cross-check vectors:");
const bnames = ["window_root", "seal", "commitment(amount||recip20||seal)", "tip_height", "k"];
bpi.forEach((h, i) => console.log(`    "${h}", // ${bnames[i]}`));
