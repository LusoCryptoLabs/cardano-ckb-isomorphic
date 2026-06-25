// deploy_xada_owner_reclaim.mjs - deploy the NEW (salted) χADA owner-lock code cell by RECLAIMING the old
// owner code cell's capacity. The old owner (0xc4e9077f / codeHash 0xd409ffcf) gated only the retired token id
// 0xe3a8d7be, which is permanently un-namable on the explorer (its first sighting had no info cell). A 58 KB
// code cell costs ~58 k CKB (1 byte = 1 CKB), more than any free plain cell - so we spend the old owner code
// cell (58,325 CKB, my lock, unspent) to fund the new one. Derives the new owner args (salt-prefixed) +
// χADA token id and writes xada_owner_deploy.json (old one backed up to xada_owner_deploy.v1.json).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/xada_mint_owner");
const LCKP = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"))).cv_deploy_v2.lckpTypeHash;
const REGTH = JSON.parse(fs.readFileSync(path.join(HERE, "v2_registry.json"))).chiralRegTh;
const ESC = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-escrow.json")));
const ESCROW_ADDR = ESC.escrow_addr_hex;
const OLD = JSON.parse(fs.readFileSync(path.join(HERE, "xada_owner_deploy.json")));
const SALT = process.env.CHIRAL_OWNER_SALT || "01";
const FEE = 100000000n; // 1 CKB fee (big tx)
const strip = (h) => (h || "").replace(/^0x/, "");

const { client, signer } = signerOf();
const lock = await myLock(signer);
const bin = fs.readFileSync(BIN);
const data = ccc.hexFrom(new Uint8Array(bin));
const codeHash = ccc.hashCkb(data);
console.log("new owner binary:", bin.length, "bytes | new codeHash:", codeHash);
if (codeHash === OLD.ownerCode.codeHash) throw new Error("new codeHash == old - the binary did not change (salt not compiled in?)");

// reclaim: spend the old owner code cell + the largest plain cell -> new code cell + change.
const oldOwnerOp = { txHash: OLD.ownerCode.txHash, index: OLD.ownerCode.index };
const oldCell = await client.getCellLive(oldOwnerOp, true);
if (!oldCell) throw new Error("old owner code cell not live - already spent?");
const oldCap = BigInt(oldCell.cellOutput.capacity);

// a plain funding cell (no type, empty data), largest first
let fund = null;
for await (const c of client.findCellsByLock(lock, null, true)) {
  if (c.cellOutput.type == null && c.outputData === "0x") { if (!fund || BigInt(c.cellOutput.capacity) > BigInt(fund.cellOutput.capacity)) fund = c; }
}
if (!fund) throw new Error("no plain funding cell");
const fundCap = BigInt(fund.cellOutput.capacity);

const newCellCap = BigInt(bin.length + 33 + 8 + 200) * 100000000n; // generous occupied capacity for the new code cell
const change = oldCap + fundCap - newCellCap - FEE;
if (change < 62_00000000n) throw new Error("change below floor: " + Number(change) / 1e8);
console.log(`inputs: old code ${Number(oldCap)/1e8} + plain ${Number(fundCap)/1e8} CKB -> new code ${Number(newCellCap)/1e8} + change ${Number(change)/1e8}`);

const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: oldOwnerOp, since: 0n }, { previousOutput: fund.outPoint, since: 0n }],
  outputs: [{ lock, capacity: newCellCap }, { lock, capacity: change }],
  outputsData: [data, "0x"],
  cellDeps: [],
});
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
const txHash = await client.sendTransaction(await signer.signTransaction(tx));
console.log("deploy+reclaim tx:", txHash);
await wait(client, txHash);

// derive owner lock + χADA token id
const ownerArgs = "0x" + SALT + strip(LCKP) + strip(REGTH) + strip(ESCROW_ADDR);
const ownerLock = ccc.Script.from({ codeHash, hashType: "data1", args: ownerArgs });
const ownerHash = ownerLock.hash();
const XUDT = await client.getKnownScript(ccc.KnownScript.XUdt);
const xadaType = ccc.Script.from({ codeHash: XUDT.codeHash, hashType: XUDT.hashType, args: ownerHash });

fs.writeFileSync(path.join(HERE, "xada_owner_deploy.v1.json"), JSON.stringify(OLD, null, 2));
const state = {
  ownerCode: { txHash, index: 0, codeHash, size: bin.length },
  ownerArgs, ownerLockHash: ownerHash, salt: SALT,
  lckpTypeHash: LCKP, registryTypeHash: REGTH, escrowAddr: ESCROW_ADDR,
  xudt: { codeHash: XUDT.codeHash, hashType: XUDT.hashType, dep: { txHash: XUDT.cellDeps[0].cellDep.outPoint.txHash, index: Number(XUDT.cellDeps[0].cellDep.outPoint.index) } },
  xadaTokenType: { codeHash: xadaType.codeHash, hashType: xadaType.hashType, args: ownerHash },
  xadaTokenId: xadaType.hash(),
  supersedes: { tokenId: OLD.xadaTokenId, ownerCode: OLD.ownerCode.txHash, reason: "0xe3a8d7be poisoned: first explorer sighting lacked an info cell" },
};
fs.writeFileSync(path.join(HERE, "xada_owner_deploy.json"), JSON.stringify(state, null, 2));
console.log("\nNEW owner code:", txHash, "codeHash:", codeHash);
console.log("NEW owner lock hash (xUDT args):", ownerHash);
console.log("NEW χADA token id:", state.xadaTokenId);
console.log("(old owner deploy backed up to xada_owner_deploy.v1.json)");
process.exit(0);
