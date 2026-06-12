// recover_by_chain.mjs — recover the orphaned owner+registry code outpoints WITHOUT scanning the loaded lock,
// by chaining through known txs: the registry genesis tx references the registry code as a cell_dep, and the
// deploy txs' funding inputs chain back to the owner-code deploy. Writes catom_owner_state.json for reuse.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OWNER_CODE = "0x70068086aa008179c500befce3f842ac0298de7b914212afbee94c74ad3317bb";
const REG_CODE = "0xfbd01737e9c2becbf2edef927fda1688c2a7bb9abb5e5ff67eb94f4704607752";
const REG_GENESIS = "0x550fc3d49bc767045e724584b5a320e9318a91ef7f67331baba8f6c41af9cecc";

const { client } = signerOf();
const opn = (o) => ({ txHash: o.txHash, index: Number(o.index) });
const hashOf = async (op) => { const c = await client.getCellLive(op, true); return c && c.outputData ? ccc.hashCkb(c.outputData) : null; };

const C = (await client.getTransaction(REG_GENESIS)).transaction;
let regOp = null;
for (const d of C.cellDeps) { if (await hashOf(d.outPoint) === REG_CODE) { regOp = d.outPoint; break; } }
if (!regOp) throw new Error("registry code not found in genesis cell_deps");
console.log("registry code cell:", regOp.txHash + ":" + Number(regOp.index));

// owner code: walk candidate source txs (genesis inputs, reg-deploy tx + its inputs) and test their output 0.
const regDeployTx = regOp.txHash;
const B = (await client.getTransaction(regDeployTx)).transaction;
const candidates = new Set();
candidates.add(regDeployTx);
for (const i of C.inputs) candidates.add(i.previousOutput.txHash);
for (const i of B.inputs) candidates.add(i.previousOutput.txHash);
let ownerOp = null;
for (const txh of candidates) { if (await hashOf({ txHash: txh, index: 0 }) === OWNER_CODE) { ownerOp = { txHash: txh, index: 0 }; break; } }
if (!ownerOp) throw new Error("owner code not reachable by chaining; candidates: " + [...candidates].map((h) => h.slice(0, 12)).join(","));
console.log("owner code cell:", ownerOp.txHash + ":0");

const genCell = await client.getCellLive({ txHash: REG_GENESIS, index: 0 }, true);
const regType = ccc.Script.from(genCell.cellOutput.type);
const stt = {
  ownerDep: { codeHash: OWNER_CODE, dataDep: { outPoint: opn(ownerOp), depType: "code" } },
  regDep: { codeHash: REG_CODE, dataDep: { outPoint: opn(regOp), depType: "code" } },
  regGenesis: { txHash: REG_GENESIS, index: 0, type: { codeHash: regType.codeHash, hashType: regType.hashType, args: regType.args } },
};
fs.writeFileSync(path.join(HERE, "catom_owner_state.json"), JSON.stringify(stt, null, 2));
console.log("recovered -> catom_owner_state.json (reusing orphaned deploys; reg_type", regType.hash().slice(0, 14) + ")");
