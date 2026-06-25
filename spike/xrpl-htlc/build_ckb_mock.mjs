// build_ckb_mock.mjs - build ckb-debugger mock txs for the CKB side of the XRPL<->CKB HTLC.
// Emits three cases against htlc_lock: claim (correct preimage -> recipient), refund (since>=timeout ->
// sender), and badclaim (wrong preimage, no timelock -> must fail). Run each with:
//   ckb-debugger --tx-file <case>.json --script-group-type lock --cell-type input --cell-index 0 --bin <htlc_lock>
import { ccc } from "@ckb-ccc/core";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/htlc_lock");

// the shared secret: in a real swap this is the SAME preimage revealed by the XRPL EscrowFinish.
const preimage = Buffer.from("d99fd673de9d006d63e9609a36e095ba677c2bf028fbc481d7ffc5c5a0a77d50", "hex");
const H = crypto.createHash("sha256").update(preimage).digest(); // 32 bytes == XRPL condition's H

const recipientLock = ccc.Script.from({ codeHash: "0x" + "11".repeat(32), hashType: "type", args: "0x" + "aa".repeat(20) });
const senderLock = ccc.Script.from({ codeHash: "0x" + "22".repeat(32), hashType: "type", args: "0x" + "bb".repeat(20) });
const recipientHash = recipientLock.hash();
const senderHash = senderLock.hash();

// timeout = absolute block number 4096 (since flag 0x00). Refund input uses since = block 8192 (>= 4096).
const TIMEOUT = 4096n;
const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b.toString("hex"); };
const htlcArgs = "0x" + H.toString("hex") + recipientHash.slice(2) + senderHash.slice(2) + u64le(TIMEOUT);

const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
const codeHash = ccc.hashCkb(data);
const htlcScript = ccc.Script.from({ codeHash, hashType: "data1", args: htlcArgs });
const scr = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
const sinceHex = (v) => "0x" + v.toString(16);
const CAP_IN = "0x" + (200n * 100000000n).toString(16);
const CAP_OUT = "0x" + (199n * 100000000n).toString(16);
const PREV = { tx_hash: "0x" + "00".repeat(32), index: "0x0" };
const DEP_OP = { tx_hash: "0x" + "01".repeat(32), index: "0x0" };
const depLock = ccc.Script.from({ codeHash: "0x" + "33".repeat(32), hashType: "type", args: "0x" });
const depCap = "0x" + (BigInt((data.length - 2) / 2 + 100) * 100000000n).toString(16);

function mock({ since, witnessLockHex, outLock }) {
  const wit = ccc.hexFrom(ccc.WitnessArgs.from({ lock: witnessLockHex }).toBytes());
  return {
    mock_info: {
      inputs: [{ input: { since: sinceHex(since), previous_output: PREV },
        output: { capacity: CAP_IN, lock: scr(htlcScript), type: null }, data: "0x", header: null }],
      cell_deps: [{ cell_dep: { out_point: DEP_OP, dep_type: "code" },
        output: { capacity: depCap, lock: scr(depLock), type: null }, data, header: null }],
      header_deps: [],
    },
    tx: {
      version: "0x0",
      cell_deps: [{ out_point: DEP_OP, dep_type: "code" }],
      header_deps: [],
      inputs: [{ since: sinceHex(since), previous_output: PREV }],
      outputs: [{ capacity: CAP_OUT, lock: scr(outLock), type: null }],
      outputs_data: ["0x"], witnesses: [wit],
    },
  };
}

// claim: correct preimage in witness.lock, output pays recipient, no timelock needed.
fs.writeFileSync(path.join(HERE, "claim.json"), JSON.stringify(mock({ since: 0n, witnessLockHex: "0x" + preimage.toString("hex"), outLock: recipientLock }), null, 2));
// refund: since (abs block 8192) >= timeout (4096), output pays sender, no preimage.
fs.writeFileSync(path.join(HERE, "refund.json"), JSON.stringify(mock({ since: 8192n, witnessLockHex: "0x", outLock: senderLock }), null, 2));
// badclaim: wrong preimage, no timelock -> neither path -> must FAIL (nonzero).
fs.writeFileSync(path.join(HERE, "badclaim.json"), JSON.stringify(mock({ since: 0n, witnessLockHex: "0x" + "ff".repeat(32), outLock: recipientLock }), null, 2));

console.log("htlc code hash:", codeHash);
console.log("H = SHA256(s) :", "0x" + H.toString("hex"));
console.log("htlc args     :", htlcArgs);
console.log("wrote claim.json, refund.json, badclaim.json");
