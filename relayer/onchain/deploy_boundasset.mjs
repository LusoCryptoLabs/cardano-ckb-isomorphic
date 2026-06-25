// deploy_boundasset.mjs - deploy OUR BoundAsset verifier (LCKP_TYPE_HASH bound to our cv_deploy
// checkpoint type 0x855231b3) as a code cell on Pudge. Records to deployed.json.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, balance, deployCodeCell } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATE = path.join(HERE, "deployed.json");
const BIN = path.join(HERE, "bins", "bound_asset_ours.bin");

async function main() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const state = JSON.parse(fs.readFileSync(STATE, "utf8"));
  if (state.bound_asset?.txHash) { console.log("already deployed:", state.bound_asset.txHash); process.exit(0); }
  console.log("balance:", (Number(await balance(client, lock)) / 1e8).toLocaleString(), "CKB");

  const bytes = fs.readFileSync(BIN);
  const codeHash = ccc.hashCkb(ccc.hexFrom(new Uint8Array(bytes)));
  console.log(`deploying bound_asset_ours (${bytes.length} bytes, codeHash ${codeHash.slice(0, 18)}..)`);
  const r = await deployCodeCell(client, signer, bytes, "bound_asset");
  state.bound_asset = { txHash: r.txHash, index: 0, codeHash: r.codeHash, size: bytes.length };
  fs.writeFileSync(STATE, JSON.stringify(state, null, 2));
  console.log("bound_asset deployed:", r.txHash, "codeHash", r.codeHash);
  console.log("balance:", (Number(await balance(client, lock)) / 1e8).toLocaleString(), "CKB");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
