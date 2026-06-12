// build_witness_mock.mjs — pack the real cosmoshub-4 commit + validator set into the tendermint_verify input
// blob and emit a ckb-debugger mock. Run:
//   ckb-debugger --max-cycles 5000000000 --tx-file tm_mock.json --script-group-type lock --cell-type input --cell-index 0
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/tendermint_verify");
const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
const vals = JSON.parse(fs.readFileSync(path.join(HERE, "validators.json"), "utf8"));

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const hx = (s) => Buffer.from(s, "hex");
const b64 = (s) => Buffer.from(s, "base64");
function tsParts(iso) { const m = iso.match(/^(.*?)(?:\.(\d+))?Z$/); return { seconds: Math.floor(Date.parse(m[1] + "Z") / 1000), nanos: m[2] ? parseInt(m[2].padEnd(9, "0").slice(0, 9), 10) : 0 }; }

const c = sh.commit;
const addrIdx = new Map(vals.map((v, i) => [v.address, i]));

// TAMPER=1 flips one byte of the signed block hash, so every signature (over the real hash) now fails ->
// the verifier must reject (< 2/3 power). Proves fail-closed.
const TAMPER = !!process.env.TAMPER;
const blockHash = hx(c.block_id.hash); if (TAMPER) blockHash[0] ^= 0xff;

const parts = [];
const chainId = Buffer.from(sh.header.chain_id, "utf8");
parts.push(Buffer.from([chainId.length]), chainId);
parts.push(u64(sh.header.height), u64(c.round), blockHash, u32(c.block_id.parts.total), hx(c.block_id.parts.hash));
parts.push(u16(vals.length));
for (const v of vals) parts.push(b64(v.pub_key.value), u64(v.voting_power));

const pre = c.signatures.filter((s) => s.block_id_flag === 2 && s.signature);
parts.push(u16(pre.length));
for (const s of pre) { const t = tsParts(s.timestamp); parts.push(u16(addrIdx.get(s.validator_address)), i64(t.seconds), u32(t.nanos), b64(s.signature)); }
const blob = Buffer.concat(parts);

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const codeHash = ccc.hashCkb(data);
const lock = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" });
const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const PREV = { tx_hash: "0x" + "00".repeat(32), index: "0x0" }, DEP = { tx_hash: "0x" + "01".repeat(32), index: "0x0" };
const wit = ccc.hexFrom(ccc.WitnessArgs.from({ lock: "0x" + blob.toString("hex") }).toBytes());
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);

const mock = {
  mock_info: {
    inputs: [{ input: { since: "0x0", previous_output: PREV }, output: { capacity: "0x2e90edd000", lock: scr(lock), type: null }, data: "0x", header: null }],
    cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: depCap, lock: scr(ccc.Script.from({ codeHash: "0x" + "33".repeat(32), hashType: "type", args: "0x" })), type: null }, data, header: null }],
    header_deps: [],
  },
  tx: { version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [],
    inputs: [{ since: "0x0", previous_output: PREV }], outputs: [{ capacity: "0x2e90edd000", lock: scr(lock), type: null }], outputs_data: ["0x"], witnesses: [wit] },
};
const outName = TAMPER ? "tm_mock_bad.json" : "tm_mock.json";
fs.writeFileSync(path.join(HERE, outName), JSON.stringify(mock, null, 2));
console.log("blob bytes:", blob.length, "| validators:", vals.length, "| committed precommits:", pre.length, TAMPER ? "| TAMPERED block hash" : "");
console.log("wrote", outName);
