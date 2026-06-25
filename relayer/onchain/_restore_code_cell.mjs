// _restore_code_cell.mjs <stateFile> <txField> <hashField> - restore a code cell whose deploy outpoint was
// swept. The deployed binary still lives as the output data of the (now-dead) deploy tx in chain history; fetch
// it, redeploy verbatim (same code hash, fresh outpoint), and repoint <stateFile>.<txField>. Used after a
// reclaim/consolidation accidentally consumed a code cell that scripts pin by hash (bridge_lock_v1, burn_gated).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, deployCodeCell } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const [stateFile, txField, hashField] = process.argv.slice(2);
const SF = path.join(HERE, stateFile);
const S = JSON.parse(fs.readFileSync(SF, "utf8"));
const deadTx = S[txField], wantHash = S[hashField];
const { client, signer } = signerOf();

const res = await client.getTransaction(deadTx);
if (!res?.transaction) { console.log(JSON.stringify({ error: "deploy tx not in history: " + deadTx })); process.exit(1); }
const data = res.transaction.outputsData[0];
const h = ccc.hashCkb(data);
if (h !== wantHash) { console.log(JSON.stringify({ error: `data hash ${h} != ${hashField} ${wantHash}` })); process.exit(1); }

const dep = await deployCodeCell(client, signer, ccc.bytesFrom(data), txField);
if (dep.codeHash !== wantHash) { console.log(JSON.stringify({ error: `redeploy hash ${dep.codeHash} != ${wantHash}` })); process.exit(1); }
S[txField] = dep.txHash;
fs.writeFileSync(SF, JSON.stringify(S, null, 2));
console.log(JSON.stringify({ ok: true, field: txField, redeployed: dep.txHash, codeHash: dep.codeHash, bytes: ccc.bytesFrom(data).length }));
