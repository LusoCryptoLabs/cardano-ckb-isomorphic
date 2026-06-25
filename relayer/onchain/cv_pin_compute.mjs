import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/light-client-cell/cert-verify/adversarial/bin");
const advHashOf = (codeHash) => ccc.Script.from({ codeHash, hashType: "data1", args: "0x" }).hash();
// 1. confirm the args convention: old cv_advance codeHash -> baked ADV_TYPEHASH 0x59efd99d...
const OLD_CV_ADV = "0xe877a8028eac379e962a596671d1cd918aceddfa4c4cd78163168ba3b533ac55";
const OLD_ADV_TYPEHASH = "0x59efd99d82ac49779594ce7f9b99d4ef5e51cfe9f6c7c807b3a67ab27869155b"; // from main.rs:21 baked array
const reproduced = advHashOf(OLD_CV_ADV);
console.log("OLD cv_advance codeHash :", OLD_CV_ADV);
console.log("OLD ADV_TYPEHASH (baked):", OLD_ADV_TYPEHASH);
console.log("reproduced via Script{code,data1,0x}.hash():", reproduced);
console.log("CONVENTION CONFIRMED (args=0x):", reproduced.toLowerCase() === OLD_ADV_TYPEHASH.toLowerCase());
// 2. new fixed cv_advance
const newBin = fs.readFileSync(path.join(BIN, "cv_advance_pinned.bin"));
const NEW_CV_ADV = ccc.hashCkb(ccc.hexFrom(new Uint8Array(newBin)));
const NEW_ADV_TYPEHASH = advHashOf(NEW_CV_ADV);
// emit the baked-array form for main.rs:21
const arr = Array.from(Buffer.from(NEW_ADV_TYPEHASH.slice(2), "hex"));
console.log("\nNEW cv_advance size      :", newBin.length, "B");
console.log("NEW cv_advance codeHash  :", NEW_CV_ADV);
console.log("NEW ADV_TYPEHASH         :", NEW_ADV_TYPEHASH);
console.log("NEW ADV_TYPEHASH (rust [u8;32] for main.rs:21):");
console.log("  [" + arr.join(",") + "]");
fs.writeFileSync(path.join(HERE, "cv_pin_state.json"), JSON.stringify({
  new_cv_advance_codeHash: NEW_CV_ADV, new_cv_advance_size: newBin.length,
  new_ADV_TYPEHASH: NEW_ADV_TYPEHASH, old_cv_advance_codeHash: OLD_CV_ADV, old_ADV_TYPEHASH: OLD_ADV_TYPEHASH,
}, null, 2));
console.log("\nwrote cv_pin_state.json (staging, separate from deployed.json)");
