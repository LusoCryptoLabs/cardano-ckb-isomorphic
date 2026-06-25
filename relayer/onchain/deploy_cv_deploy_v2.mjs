// deploy_cv_deploy_v2.mjs - deploy the M2-UPGRADED cert-verify deploy-mode verifier (publishes the 44-byte
// "LCKP || root || height" checkpoint) as a NEW code cell on Pudge, DISJOINT from the live 36-byte cv_deploy
// (0xdfc0aad0). cv_advance is unchanged, so cv_deploy_v2's ADV_TYPEHASH binding (-> 0x59efd99d) still holds.
// Dry by default; --live broadcasts. Prints CHIRAL_LCKP_TH (the checkpoint type hash bound_asset_v2 bakes).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, balance, deployCodeCell } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/light-client-cell/cert-verify/adversarial/bin/cv_deploy_v2.bin");
const STATE = path.join(HERE, "deployed.json");
const EXPECT = "0x75b288f3774bfe553fc72895f940578214e2111208f5a85fb5c5dbf5e9017bf9"; // M2 cv_deploy codeHash

const bytes = fs.readFileSync(BIN);
const codeHash = ccc.hashCkb(ccc.hexFrom(new Uint8Array(bytes)));
if (codeHash !== EXPECT) throw new Error(`cv_deploy.bin codeHash ${codeHash} != expected M2 ${EXPECT} (rebuild it)`);
const lckpScript = ccc.Script.from({ codeHash, hashType: "data1", args: "0x" });
const CHIRAL_LCKP_TH = lckpScript.hash();

const { client, signer } = signerOf();
const lock = await myLock(signer);
const bal = await balance(client, lock);
console.log("cv_deploy_v2 bin :", bytes.length, "bytes  codeHash", codeHash);
console.log("CHIRAL_LCKP_TH   :", CHIRAL_LCKP_TH, " (Script{code, data1, args:0x}.hash())");
console.log("Pudge balance    :", (Number(bal) / 1e8).toLocaleString(), "CKB");

if (!process.argv.includes("--live")) { console.log("\nDRY run. Pass --live to broadcast the deploy."); process.exit(0); }

const state = JSON.parse(fs.readFileSync(STATE, "utf8"));
if (state.cv_deploy_v2?.txHash) { console.log("already deployed:", state.cv_deploy_v2.txHash); process.exit(0); }
console.log("\ndeploying cv_deploy_v2…");
const r = await deployCodeCell(client, signer, bytes, "cv_deploy_v2");
state.cv_deploy_v2 = { txHash: r.txHash, index: 0, codeHash, size: bytes.length, lckpTypeHash: CHIRAL_LCKP_TH };
fs.writeFileSync(STATE, JSON.stringify(state, null, 2));
console.log("deployed cv_deploy_v2:", r.txHash, "\nCHIRAL_LCKP_TH =", CHIRAL_LCKP_TH);
process.exit(0);
