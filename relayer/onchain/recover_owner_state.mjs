// recover_owner_state.mjs — find the ALREADY-deployed (but un-persisted/orphaned) catom_mint_owner + registry
// code cells and the registry genesis, and write catom_owner_state.json so live_catom_owner_mint.mjs REUSES
// them instead of re-deploying (each redeploy would re-lock ~72k/28k CKB). Code cells are found by a narrow
// data-length indexer query (small response) + a data-hash match, so we never scan the whole loaded lock.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OWNER_CODE = "0x70068086aa008179c500befce3f842ac0298de7b914212afbee94c74ad3317bb"; // catom_mint_owner.strip
const REG_CODE = "0xfbd01737e9c2becbf2edef927fda1688c2a7bb9abb5e5ff67eb94f4704607752";   // cosmos_nullifier_registry.strip
const OWNER_LEN = 72416, REG_LEN = 27800;
const REG_GENESIS = process.env.REG_GENESIS || "0x550fc3d49bc767045e724584b5a320e9318a91ef7f67331baba8f6c41af9cecc";

const { client, signer } = signerOf();
const lock = await myLock(signer);
const lh = (n) => "0x" + n.toString(16);

async function findCode(codeHash, approxLen) {
  for await (const c of client.findCells({ script: lock, scriptType: "lock", scriptSearchMode: "exact", filter: { outputDataLenRange: [lh(approxLen - 4), lh(approxLen + 4)] } }, "asc", 50)) {
    if (c.cellOutput.type == null && c.outputData && ccc.hashCkb(c.outputData) === codeHash) return c.outPoint;
  }
  return null;
}

const ownerOp = await findCode(OWNER_CODE, OWNER_LEN);
const regOp = await findCode(REG_CODE, REG_LEN);
if (!ownerOp) throw new Error("owner code cell not found on-chain");
if (!regOp) throw new Error("registry code cell not found on-chain");
console.log("owner code cell:", ownerOp.txHash + ":" + ownerOp.index);
console.log("registry code cell:", regOp.txHash + ":" + regOp.index);

const genCell = await client.getCellLive({ txHash: REG_GENESIS, index: 0 }, true);
if (!genCell || !genCell.cellOutput.type) throw new Error("registry genesis cell not live: " + REG_GENESIS);
const regType = ccc.Script.from(genCell.cellOutput.type);

const op = (o) => ({ txHash: o.txHash, index: Number(o.index) });
const st = {
  ownerDep: { codeHash: OWNER_CODE, dataDep: { outPoint: op(ownerOp), depType: "code" } },
  regDep: { codeHash: REG_CODE, dataDep: { outPoint: op(regOp), depType: "code" } },
  regGenesis: { txHash: REG_GENESIS, index: 0, type: { codeHash: regType.codeHash, hashType: regType.hashType, args: regType.args } },
};
fs.writeFileSync(path.join(HERE, "catom_owner_state.json"), JSON.stringify(st, null, 2));
console.log("recovered state -> catom_owner_state.json (reusing the orphaned deploys; reg_type", regType.hash().slice(0, 14) + ")");
