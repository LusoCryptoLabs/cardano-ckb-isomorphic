// build_burn_mock.mjs — ckb-debugger mock for xosmo_burn_receipt. Burns a chiOSMO cell and creates the return
// receipt binding (amount, cosmos_recipient). Positive: burned amount == receipt amount -> 0.
//   WRONGAMOUNT=1 -> receipt overstates (10); NOTBURN=1 -> a chiOSMO output cancels the burn (10); BADMAGIC=1 -> 2.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/xosmo_burn_receipt");
const AMOUNT = 1000000;
const recipient20 = Buffer.alloc(20, 0xab);             // 20-byte Osmosis account address (demo)

const amt16 = (n) => { const b = Buffer.alloc(16); b.writeBigUInt64LE(BigInt(n), 0); return b; };
const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const receiptCode = ccc.hashCkb(data);
const chiosmoType = ccc.Script.from({ codeHash: "0x" + "f9".repeat(32), hashType: "type", args: "0x1234" }); // the chiOSMO policy
const policy = chiosmoType.hash();
const receiptScript = ccc.Script.from({ codeHash: receiptCode, hashType: "data1", args: policy });

const magic = process.env.BADMAGIC ? Buffer.from("XXXX") : Buffer.from("XOS1");
const receiptAmt = process.env.WRONGAMOUNT ? AMOUNT + 1 : AMOUNT;
const receiptData = Buffer.concat([magic, amt16(receiptAmt), recipient20]); // 40 bytes

const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const anyLock = scr(ccc.Script.from({ codeHash: "0x" + "55".repeat(32), hashType: "type", args: "0x" }));
const OP = (h, i) => ({ tx_hash: "0x" + h, index: "0x" + i.toString(16) });
const IN0 = OP("00".repeat(32), 0), DEP = OP("ce".repeat(32), 0);
const cap = "0x2e90edd000";
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);

// inputs: one chiOSMO cell (amount). outputs: the receipt (0); NOTBURN also re-creates a chiOSMO output (1).
const inputs = [{ input: { since: "0x0", previous_output: IN0 }, output: { capacity: cap, lock: anyLock, type: scr(chiosmoType) }, data: "0x" + amt16(AMOUNT).toString("hex"), header: null }];
const outputs = [{ capacity: cap, lock: anyLock, type: scr(receiptScript) }];
const outputsData = ["0x" + receiptData.toString("hex")];
if (process.env.NOTBURN) { outputs.push({ capacity: cap, lock: anyLock, type: scr(chiosmoType) }); outputsData.push("0x" + amt16(AMOUNT).toString("hex")); }

const mock = {
  mock_info: {
    inputs,
    cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: depCap, lock: anyLock, type: null }, data, header: null }],
    header_deps: [],
  },
  tx: {
    version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [],
    inputs: [{ since: "0x0", previous_output: IN0 }],
    outputs, outputs_data: outputsData, witnesses: ["0x"],
  },
};
const flag = process.env.WRONGAMOUNT ? "wrongamount" : process.env.NOTBURN ? "notburn" : process.env.BADMAGIC ? "badmagic" : null;
const out = flag ? `burn_mock_${flag}.json` : "burn_mock.json";
fs.writeFileSync(path.join(HERE, out), JSON.stringify(mock, null, 2));
console.log("policy(chiOSMO):", policy.slice(0, 18), "| burn", AMOUNT, "-> recipient", recipient20.toString("hex").slice(0, 16), flag ? `| ${flag.toUpperCase()}` : "");
console.log("wrote", out);
