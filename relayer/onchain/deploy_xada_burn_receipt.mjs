// deploy_xada_burn_receipt.mjs - deploy the χADA RETURN-leg burn-receipt type script on Pudge. The cell records
// a χADA burn (MAGIC "XAD1" ‖ amount(16 LE) ‖ cardano_recipient(28)) and self-enforces Σχada_in−Σχada_out==amount.
// args at instantiation = the χADA xUDT TYPE hash (the policy whose burn it counts). Writes xada_burn_deploy.json.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, deployCodeCell, balance } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/xada_burn_receipt.strip");
const O = JSON.parse(fs.readFileSync(path.join(HERE, "xada_owner_deploy.json"), "utf8"));

const { client, signer } = signerOf();
const lock = await myLock(signer);
const bin = fs.readFileSync(BIN);
console.log("xada_burn_receipt bin:", bin.length, "bytes | balance:", (await balance(client, lock)) / 100000000n, "CKB");
const r = await deployCodeCell(client, signer, bin, "xada_burn_receipt");
// the receipt's args = the χADA token TYPE hash (so it sums the right token's in/out). data1 hash type.
const state = {
  burnReceiptCode: { txHash: r.txHash, index: 0, codeHash: r.codeHash, size: bin.length },
  xadaTokenId: O.xadaTokenId,        // the χADA xUDT type hash this receipt counts (== receipt args)
};
fs.writeFileSync(path.join(HERE, "xada_burn_deploy.json"), JSON.stringify(state, null, 2));
console.log("xada_burn_receipt code:", r.txHash, "codeHash:", r.codeHash);
console.log("receipt args (χADA token id):", O.xadaTokenId);
process.exit(0);
