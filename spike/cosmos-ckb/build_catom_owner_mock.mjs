// build_catom_owner_mock.mjs — ckb-debugger mock for catom_mint_owner (the χOSMO xUDT OWNER lock). Reuses the
// REAL osmo witness (catom_witness.json) and authorizes a STANDARD xUDT mint: the χOSMO output is a real xUDT
// cell (canonical code hash, args = the owner-lock hash). Runs the OWNER LOCK group on its input cell.
//   wsl: ckb-debugger --max-cycles 5000000000 --tx-file catom_owner.json --script-group-type lock --cell-type input --cell-index 0
//   BADPIN=1 -> 9 (wrong anchor); BADRECIP=1 -> 28 (xUDT output at wrong lock).
import { ccc } from "@ckb-ccc/core";
import { blake2b } from "@noble/hashes/blake2.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/catom_mint_owner");
const W = JSON.parse(fs.readFileSync(path.join(HERE, "catom_witness.json"), "utf8"));
const XUDT_CODE = "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb"; // canonical xUDT (Pudge)
const hx = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");
const amt16 = (n) => { const b = Buffer.alloc(16); b.writeBigUInt64LE(BigInt(n), 0); return b; };

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const ownerCode = ccc.hashCkb(data);
const regScript = ccc.Script.from({ codeHash: "0x" + "b2".repeat(32), hashType: "type", args: "0x" });
const regTypeHash = hx(regScript.hash());
const denomB = Buffer.from(W.denom), escrowB = Buffer.from(W.escrow);
const anchor = Buffer.from(hx(W.anchor)); if (process.env.BADPIN) anchor[0] ^= 0xff;
const ownerArgs = Buffer.concat([anchor, regTypeHash, Buffer.from([denomB.length]), denomB, escrowB]);
const ownerLock = ccc.Script.from({ codeHash: ownerCode, hashType: "data1", args: "0x" + ownerArgs.toString("hex") });
const owner = ownerLock.hash();
// the χOSMO token = canonical xUDT with args == the owner-lock hash.
const xudtType = ccc.Script.from({ codeHash: XUDT_CODE, hashType: "type", args: owner });
const recipientLock = ccc.Script.from(W.recipientLock);
const outLock = process.env.BADRECIP ? ccc.Script.from({ codeHash: "0x" + "45".repeat(32), hashType: "type", args: "0x" }) : recipientLock;

const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const anyLock = scr(ccc.Script.from({ codeHash: "0x" + "55".repeat(32), hashType: "type", args: "0x" }));
const OP = (h, i) => ({ tx_hash: "0x" + h, index: "0x" + i.toString(16) });
const IN0 = OP("00".repeat(32), 0), IN1 = OP("11".repeat(32), 0), DEP = OP("ce".repeat(32), 0);
const cap = "0x2e90edd000";
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);
const wit0 = ccc.hexFrom(ccc.WitnessArgs.from({ lock: "0x" + W.blob }).toBytes());          // owner-lock witness = inclusion blob
const wit1 = ccc.hexFrom(ccc.WitnessArgs.from({ inputType: "0x" + W.nfKey }).toBytes());     // registry witness = nullifier key

const mock = {
  mock_info: {
    inputs: [
      { input: { since: "0x0", previous_output: IN0 }, output: { capacity: cap, lock: scr(ownerLock), type: null }, data: "0x", header: null },
      { input: { since: "0x0", previous_output: IN1 }, output: { capacity: cap, lock: anyLock, type: scr(regScript) }, data: "0x", header: null },
    ],
    cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: depCap, lock: anyLock, type: null }, data, header: null }],
    header_deps: [],
  },
  tx: {
    version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [],
    inputs: [{ since: "0x0", previous_output: IN0 }, { since: "0x0", previous_output: IN1 }],
    outputs: [{ capacity: cap, lock: scr(outLock), type: scr(xudtType) }],          // the χOSMO xUDT cell
    outputs_data: ["0x" + amt16(W.amount).toString("hex")], witnesses: [wit0, wit1],
  },
};
const flag = process.env.BADPIN ? "badpin" : process.env.BADRECIP ? "badrecip" : null;
const out = flag ? `catom_owner_${flag}.json` : "catom_owner.json";
fs.writeFileSync(path.join(HERE, out), JSON.stringify(mock, null, 2));
console.log("owner(lock) hash:", owner.slice(0, 18), "| χOSMO token id (xUDT hash):", xudtType.hash().slice(0, 18), flag ? `| ${flag.toUpperCase()}` : "");
console.log("wrote", out);
