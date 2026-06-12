// build_reg_mock.mjs — ckb-debugger mocks for cosmos_nullifier_registry (type-id singleton append-only set).
// GENESIS (default): a funding input + the empty registry output; args must == type_id(input0 || out_idx).
//   BADTID=1 -> wrong args (6); NONEMPTY=1 -> non-empty genesis data (8).
// SPEND=1: registry input (data=old) + funding, registry output (data=old||key), witness input_type=key -> 0.
//   DOUBLE=1 -> the key already present (14); BADWIT=1 -> witness key != appended key (16).
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/cosmos_nullifier_registry");
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u32le4 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const hx = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const codeHash = ccc.hashCkb(data);
const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const anyLock = scr(ccc.Script.from({ codeHash: "0x" + "55".repeat(32), hashType: "type", args: "0x" }));
const OP = (h, i) => ({ tx_hash: "0x" + h, index: "0x" + i.toString(16) });
const DEP = OP("ce".repeat(32), 0);
const cap = "0x2e90edd000";
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);
const SEED = "ab".repeat(32);                 // funding input's previous_output tx_hash
const key = Buffer.from("9".repeat(64), "hex");

function mock(inputs, outputs, outputsData, witnesses, depCells = []) {
  return {
    mock_info: {
      inputs: inputs.map((i) => ({ input: { since: "0x0", previous_output: i.op }, output: { capacity: cap, lock: anyLock, type: i.type || null }, data: i.data || "0x", header: null })),
      cell_deps: [{ cell_dep: { out_point: DEP, dep_type: "code" }, output: { capacity: depCap, lock: anyLock, type: null }, data, header: null }, ...depCells],
      header_deps: [],
    },
    tx: { version: "0x0", cell_deps: [{ out_point: DEP, dep_type: "code" }], header_deps: [],
      inputs: inputs.map((i) => ({ since: "0x0", previous_output: i.op })),
      outputs: outputs.map((o) => ({ capacity: cap, lock: anyLock, type: o.type || null })),
      outputs_data: outputsData, witnesses },
  };
}

let out;
if (!process.env.SPEND) {
  // GENESIS: input0 funding -> registry output 0 (empty data), args = type_id(input0 || out_idx=0)
  const input0 = Buffer.concat([u64(0), hx(SEED), u32le4(0)]);   // CellInput molecule (struct): since||tx_hash||index
  const typeId = ccc.hashCkb("0x" + Buffer.concat([input0, u64(0)]).toString("hex"));
  const argsTid = hx(typeId); if (process.env.BADTID) argsTid[0] ^= 0xff;
  const reg = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" + argsTid.toString("hex") });
  const inputs = [{ op: OP(SEED, 0) }];
  const outputs = [{ type: scr(reg) }];
  const odata = [process.env.NONEMPTY ? "0x" + key.toString("hex") : "0x"];
  out = mock(inputs, outputs, odata, ["0x"]);
  fs.writeFileSync(path.join(HERE, process.env.BADTID ? "reg_genesis_badtid.json" : process.env.NONEMPTY ? "reg_genesis_nonempty.json" : "reg_genesis.json"), JSON.stringify(out, null, 2));
  console.log("GENESIS type_id", typeId.slice(0, 18), process.env.BADTID ? "| BADTID" : process.env.NONEMPTY ? "| NONEMPTY" : "");
} else {
  // SPEND: registry input (data=old) at idx1 + funding idx0; registry output 0 (data=old||key); witness1=key
  const reg = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" + "00".repeat(32) });
  const old = process.env.DOUBLE ? key : Buffer.alloc(0);       // DOUBLE: key already present
  const newData = Buffer.concat([old, key]);
  const inputs = [{ op: OP("00".repeat(32), 0) }, { op: OP("11".repeat(32), 0), type: scr(reg), data: "0x" + old.toString("hex") }];
  const outputs = [{ type: scr(reg) }];
  const witKey = Buffer.from(key); if (process.env.BADWIT) witKey[0] ^= 0xff;
  const w1 = ccc.hexFrom(ccc.WitnessArgs.from({ inputType: "0x" + witKey.toString("hex") }).toBytes());
  out = mock(inputs, outputs, ["0x" + newData.toString("hex")], ["0x", w1]);
  fs.writeFileSync(path.join(HERE, process.env.DOUBLE ? "reg_spend_double.json" : process.env.BADWIT ? "reg_spend_badwit.json" : "reg_spend.json"), JSON.stringify(out, null, 2));
  console.log("SPEND old", old.length, "-> new", newData.length, process.env.DOUBLE ? "| DOUBLE" : process.env.BADWIT ? "| BADWIT" : "");
}
