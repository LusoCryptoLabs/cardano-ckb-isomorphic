// live_catom_owner_mint.mjs — mint χOSMO as a REAL, displayable xUDT (Fix #1), gated on the real osmo-test-5
// escrow. χOSMO = canonical xUDT(args = owner_lock_hash); the mint is authorized via xUDT OWNER MODE: the tx
// spends a cell locked by catom_mint_owner, the xUDT type then skips its amount check, and the owner lock
// enforces the exact bound mint (Cosmos inclusion + MsgSend binding + replay). The token-info (Unique) cell is
// issued IN the same mint tx so the explorer/wallets show "Chiral OSMO". Reads catom_witness.json.
// Stages: deploy owner+registry code -> genesis registry -> setup owner authority cell -> mint (xUDT + Unique).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, deployCodeCell, plainCells, wait } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REL = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release");
const W = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../spike/cosmos-ckb/catom_witness.json"), "utf8"));
const hb = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };

const XUDT_CODE = "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb";
const XUDT_DEP = { outPoint: { txHash: "0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f", index: 0 }, depType: "code" };
const UNIQUE_CODE = "0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b";
const UNIQUE_DEP = { outPoint: { txHash: "0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef", index: 0 }, depType: "code" };
const TOKEN = { name: "Chiral OSMO", symbol: "xOSMO", decimals: 6 };
const tokenInfoBytes = (dec, name, sym) => { const n = new TextEncoder().encode(name), s = new TextEncoder().encode(sym);
  return "0x" + Buffer.concat([Buffer.from([dec]), Buffer.from([n.length]), Buffer.from(n), Buffer.from([s.length]), Buffer.from(s)]).toString("hex"); };
const uniqueArgs = (firstOp, outIdx) => { const ib = ccc.bytesFrom(ccc.CellInput.from({ previousOutput: firstOp, since: 0n }).toBytes());
  const pre = new Uint8Array(ib.length + 8); pre.set(ib, 0); pre[ib.length] = outIdx & 0xff; return ccc.hashCkb(pre).slice(0, 42); };

const OWNER_CAP = 150_00000000n, XOSMO_CAP = 200_00000000n, UNIQUE_CAP = 150_00000000n, REG_CAP = 150_00000000n, FEE = 1_00000000n;

const { client, signer } = signerOf();
const lock = await myLock(signer);
const recipientLock = ccc.Script.from(W.recipientLock);
console.log("relayer:", (await signer.getAddressObjs())[0].toString());

// 1) deploy the owner lock + registry code (stripped)
const ownerDep = await deployCodeCell(client, signer, fs.readFileSync(path.join(REL, "catom_mint_owner.strip")), "catom_mint_owner");
const regDep = await deployCodeCell(client, signer, fs.readFileSync(path.join(REL, "cosmos_nullifier_registry.strip")), "cosmos_nullifier_registry");
console.log("owner code:", ownerDep.codeHash, "\nregistry code:", regDep.codeHash);

// 2) genesis the registry (type-id singleton, empty)
const regTypeDummy = ccc.Script.from({ codeHash: regDep.codeHash, hashType: "data1", args: "0x" + "00".repeat(32) });
const genTx = ccc.Transaction.from({ outputs: [{ lock, type: regTypeDummy, capacity: REG_CAP }], outputsData: ["0x"] });
await genTx.completeInputsByCapacity(signer);
const gin0 = genTx.inputs[0].previousOutput;
const typeId = ccc.hashCkb("0x" + Buffer.concat([u64le(0), hb(gin0.txHash), u32le(Number(gin0.index)), u64le(0)]).toString("hex"));
genTx.outputs[0].type = ccc.Script.from({ codeHash: regDep.codeHash, hashType: "data1", args: typeId });
genTx.cellDeps.push(ccc.CellDep.from(regDep.dataDep));
await genTx.completeFeeBy(signer, 1000);
const genHash = await client.sendTransaction(await signer.signTransaction(genTx));
await wait(client, genHash);
const regType = genTx.outputs[0].type, regTypeHash = regType.hash(), regOutPoint = { txHash: genHash, index: 0 };
console.log("registry genesis:", genHash, "| reg_type:", regTypeHash);

// 3) the owner lock = catom_mint_owner(anchor || reg_type || denom_len || denom || escrow); owner = its hash
const denomB = Buffer.from(W.denom), escrowB = Buffer.from(W.escrow);
const ownerArgs = Buffer.concat([hb(W.anchor), hb(regTypeHash), Buffer.from([denomB.length]), denomB, escrowB]);
const ownerLock = ccc.Script.from({ codeHash: ownerDep.codeHash, hashType: "data1", args: "0x" + ownerArgs.toString("hex") });
const owner = ownerLock.hash();

// 4) setup the owner authority cell (locked by ownerLock)
const setupTx = ccc.Transaction.from({ outputs: [{ lock: ownerLock, capacity: OWNER_CAP }], outputsData: ["0x"] });
await setupTx.completeInputsByCapacity(signer);
await setupTx.completeFeeBy(signer, 1000);
const setupHash = await client.sendTransaction(await signer.signTransaction(setupTx));
await wait(client, setupHash);
const ownerOp = { txHash: setupHash, index: 0 };
console.log("owner authority cell:", setupHash + ":0");

// 5) the χOSMO token = canonical xUDT(args = owner)
const xudtType = ccc.Script.from({ codeHash: XUDT_CODE, hashType: "type", args: owner });
const tokenId = xudtType.hash();
console.log("χOSMO token id (xUDT):", tokenId);

// 6) the mint tx: owner-mode xUDT mint + the Unique token-info cell, gated by the Cosmos escrow proof
const ownerCell = await client.getCellLive(ownerOp, true);
const regCell = await client.getCellLive(regOutPoint, true);
const oldRegData = regCell.outputData.replace(/^0x/, "");
const newRegData = "0x" + oldRegData + W.nfKey;                 // append the certified Cosmos tx's nullifier
const amount16 = Buffer.alloc(16); amount16.writeBigUInt64LE(BigInt(W.amount), 0);
const fund = (await plainCells(client, lock))[0];
const fundCap = BigInt(fund.cellOutput.capacity);
const uniqueType = ccc.Script.from({ codeHash: UNIQUE_CODE, hashType: "type", args: uniqueArgs(ownerOp, 1) });

const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: ownerOp, since: 0n }, { previousOutput: fund.outPoint, since: 0n }, { previousOutput: regOutPoint, since: 0n }],
  outputs: [
    { lock: recipientLock, type: xudtType, capacity: XOSMO_CAP },                         // 0: χOSMO xUDT to the recipient (owner mode)
    { lock, type: uniqueType, capacity: UNIQUE_CAP },                                     // 1: token-info (Unique) — issued WITH the xUDT
    { lock: ownerLock, capacity: BigInt(ownerCell.cellOutput.capacity) },                 // 2: recreate the owner authority cell
    { lock, type: regType, capacity: BigInt(regCell.cellOutput.capacity) },               // 3: continuing registry
    { lock, capacity: fundCap - FEE - XOSMO_CAP - UNIQUE_CAP },                           // 4: change
  ],
  outputsData: ["0x" + amount16.toString("hex"), tokenInfoBytes(TOKEN.decimals, TOKEN.name, TOKEN.symbol), "0x", newRegData, "0x"],
  cellDeps: [ccc.CellDep.from(ownerDep.dataDep), ccc.CellDep.from(XUDT_DEP), ccc.CellDep.from(regDep.dataDep), ccc.CellDep.from(UNIQUE_DEP)],
});
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + W.blob }));        // owner lock's GroupInput[0]: the Cosmos inclusion proof
tx.setWitnessArgsAt(2, ccc.WitnessArgs.from({ inputType: "0x" + W.nfKey })); // registry insert
const mintHash = await client.sendTransaction(await signer.signTransaction(tx));
await wait(client, mintHash);
console.log("\nχOSMO xUDT MINT:", mintHash);
console.log("  token id:", tokenId, "| amount", W.amount, "| name", TOKEN.name, TOKEN.symbol, TOKEN.decimals);

fs.writeFileSync(path.join(HERE, "catom_owner_live.json"), JSON.stringify({
  ownerCode: ownerDep.codeHash, registryCode: regDep.codeHash, registryGenesis: genHash, regTypeHash,
  ownerLockHash: owner, setupTx: setupHash, tokenId, mintTx: mintHash, token: TOKEN,
  amount: W.amount, recipient: W.recipient, osmoHeight: W.height, xosmoCell: mintHash + ":0", uniqueCell: mintHash + ":1",
}, null, 2));
console.log("wrote catom_owner_live.json");
