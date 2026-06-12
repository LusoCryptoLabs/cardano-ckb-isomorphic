// recover_paginated.mjs — enumerate the relayer lock's cells in SMALL pages (so each indexer response stays
// under the 10MB cap that breaks the normal scan on this loaded lock), find the orphaned catom_mint_owner +
// registry code cells, and write catom_owner_state.json so the mint REUSES them (no 72k/28k re-deploy). This
// small-page pagination is also the general fix for reclaiming the CKB locked in code cells.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = "https://testnet.ckb.dev/";
const OWNER_CODE = "0x70068086aa008179c500befce3f842ac0298de7b914212afbee94c74ad3317bb";
const REG_CODE = "0xfbd01737e9c2becbf2edef927fda1688c2a7bb9abb5e5ff67eb94f4704607752";
const REG_GENESIS = "0x550fc3d49bc767045e724584b5a320e9318a91ef7f67331baba8f6c41af9cecc";

const { client, signer } = signerOf();
const realLock = await myLock(signer);

async function rpc(method, params) {
  const r = await (await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }) })).json();
  if (r.error) throw new Error(JSON.stringify(r.error));
  return r.result;
}

const sk = { script: { code_hash: realLock.codeHash, hash_type: realLock.hashType, args: realLock.args }, script_type: "lock" };
let cursor = null, page = 0, scanned = 0, ownerOp = null, regOp = null;
for (;;) {
  const r = await rpc("get_cells", [sk, "asc", "0xa", cursor]); // 10 cells/page
  page++;
  for (const o of r.objects) {
    scanned++;
    if (o.output.type) continue;
    if (!o.output_data || o.output_data === "0x") continue;
    const h = ccc.hashCkb(o.output_data);
    if (h === OWNER_CODE && !ownerOp) ownerOp = o.out_point;
    if (h === REG_CODE && !regOp) regOp = o.out_point;
  }
  if (ownerOp && regOp) break;
  if (!r.objects.length || r.last_cursor === cursor) break;
  cursor = r.last_cursor;
  if (page % 5 === 0) console.log(`  scanned ${scanned} cells... owner=${!!ownerOp} reg=${!!regOp}`);
  if (page > 500) break;
}
console.log(`scanned ${scanned} cells over ${page} pages`);
if (!ownerOp) throw new Error("owner code cell not found");
if (!regOp) throw new Error("registry code cell not found");
console.log("owner code cell:", ownerOp.tx_hash + ":" + parseInt(ownerOp.index, 16));
console.log("registry code cell:", regOp.tx_hash + ":" + parseInt(regOp.index, 16));

const genCell = await client.getCellLive({ txHash: REG_GENESIS, index: 0 }, true);
const regType = ccc.Script.from(genCell.cellOutput.type);
const op = (o) => ({ txHash: o.tx_hash, index: parseInt(o.index, 16) });
const st = {
  ownerDep: { codeHash: OWNER_CODE, dataDep: { outPoint: op(ownerOp), depType: "code" } },
  regDep: { codeHash: REG_CODE, dataDep: { outPoint: op(regOp), depType: "code" } },
  regGenesis: { txHash: REG_GENESIS, index: 0, type: { codeHash: regType.codeHash, hashType: regType.hashType, args: regType.args } },
};
fs.writeFileSync(path.join(HERE, "catom_owner_state.json"), JSON.stringify(st, null, 2));
console.log("recovered -> catom_owner_state.json (reusing orphaned deploys; reg_type", regType.hash().slice(0, 14) + ")");
