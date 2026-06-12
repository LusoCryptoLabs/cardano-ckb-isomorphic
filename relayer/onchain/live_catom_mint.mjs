// live_catom_mint.mjs — STEP 4 (final): mint a real chiOSMO token on CKB Pudge, gated on the real osmo-test-5
// escrow proven in-VM by catom_mint. Deploys the catom_mint + cosmos_nullifier_registry code cells, genesis-es
// the registry (type-id singleton, empty), then submits the mint tx: chiOSMO output (bound 1:1 to the escrow
// amount, locked to the recipient the memo named) + the registry recreated with the certified Cosmos tx's
// nullifier. Reads catom_witness.json (from spike/cosmos-ckb/build_catom_live_mock.mjs). Writes catom_mint_live.json.
import { signerOf, myLock, deployCodeCell, plainCells, wait } from "./_signer.mjs";
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REL = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release");
const W = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../spike/cosmos-ckb/catom_witness.json"), "utf8"));
const hb = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };

const { client, signer } = signerOf();
const lock = await myLock(signer);
const recipientLock = ccc.Script.from(W.recipientLock);

console.log("relayer:", (await signer.getAddressObjs())[0].toString());

// 1) deploy the two code cells (llvm-stripped: identical executable code, ~half the on-chain capacity cost)
const catomDep = await deployCodeCell(client, signer, fs.readFileSync(path.join(REL, "catom_mint.strip")), "catom_mint");
const regDep = await deployCodeCell(client, signer, fs.readFileSync(path.join(REL, "cosmos_nullifier_registry.strip")), "cosmos_nullifier_registry");
console.log("catom code:", catomDep.codeHash, "\nregistry code:", regDep.codeHash);

// 2) genesis the registry (type-id singleton, empty data)
const regTypeDummy = ccc.Script.from({ codeHash: regDep.codeHash, hashType: "data1", args: "0x" + "00".repeat(32) });
const genTx = ccc.Transaction.from({ outputs: [{ lock, type: regTypeDummy }], outputsData: ["0x"] });
await genTx.completeInputsByCapacity(signer);
const in0 = genTx.inputs[0].previousOutput;                          // CellInput[0] outpoint
const typeId = ccc.hashCkb("0x" + Buffer.concat([u64le(0), hb(in0.txHash), u32le(Number(in0.index)), u64le(0)]).toString("hex"));
genTx.outputs[0].type = ccc.Script.from({ codeHash: regDep.codeHash, hashType: "data1", args: typeId });
genTx.cellDeps.push(ccc.CellDep.from(regDep.dataDep));            // registry code, so its type script runs at genesis
await genTx.completeFeeBy(signer, 1000);
const genHash = await client.sendTransaction(await signer.signTransaction(genTx));
await wait(client, genHash);
const regType = genTx.outputs[0].type;
const regTypeHash = regType.hash();
const regOutPoint = { txHash: genHash, index: 0 };
console.log("registry genesis:", genHash, "| reg_type:", regTypeHash);

// 3) the chiOSMO type policy = catom_mint(args = anchor || reg_type || denom_len || denom || escrow)
const denomB = Buffer.from(W.denom), escrowB = Buffer.from(W.escrow);
const catomArgs = Buffer.concat([hb(W.anchor), hb(regTypeHash), Buffer.from([denomB.length]), denomB, escrowB]);
const catomType = ccc.Script.from({ codeHash: catomDep.codeHash, hashType: "data1", args: "0x" + catomArgs.toString("hex") });
const tokenId = catomType.hash();
console.log("chiOSMO token id (catom type hash):", tokenId);

// 4) the mint tx
const amount16 = Buffer.alloc(16); amount16.writeBigUInt64LE(BigInt(W.amount), 0);
const mintTx = ccc.Transaction.from({
  outputs: [
    { lock: recipientLock, type: catomType },   // output 0: chiOSMO, bound 1:1 to the escrow
    { lock, type: regType },                     // output 1: registry recreated with the new nullifier
  ],
  outputsData: ["0x" + amount16.toString("hex"), "0x" + W.nfKey],
});
// inputs: a big plain funding cell at idx0, the registry cell at idx1 (so witness slots don't collide:
// chiOSMO output(0) reads witness[0], registry input(1) reads witness[1]).
const plains = await plainCells(client, lock);
if (!plains.length) throw new Error("no plain funding cell");
mintTx.inputs.push(ccc.CellInput.from({ previousOutput: plains[0].outPoint, since: 0n }));
mintTx.inputs.push(ccc.CellInput.from({ previousOutput: regOutPoint, since: 0n }));
mintTx.cellDeps.push(ccc.CellDep.from(catomDep.dataDep));          // chiOSMO type script code
mintTx.cellDeps.push(ccc.CellDep.from(regDep.dataDep));            // registry type script code
// witnesses: [0]=lock sig (filled on sign) + the Cosmos inclusion blob; [1]=the nullifier key for the registry
mintTx.witnesses[0] = ccc.hexFrom(ccc.WitnessArgs.from({ inputType: "0x" + W.blob }).toBytes());
mintTx.witnesses[1] = ccc.hexFrom(ccc.WitnessArgs.from({ inputType: "0x" + W.nfKey }).toBytes());
await mintTx.completeInputsByCapacity(signer);
await mintTx.completeFeeBy(signer, 1000);
const mintHash = await client.sendTransaction(await signer.signTransaction(mintTx));
await wait(client, mintHash);
console.log("\nMINT tx:", mintHash);
console.log("chiOSMO", W.amount, W.denom, "minted to", W.recipient.slice(0, 16), "gated on osmo-test-5 escrow", W.height);

fs.writeFileSync(path.join(HERE, "catom_mint_live.json"), JSON.stringify({
  catomCode: catomDep.codeHash, registryCode: regDep.codeHash, registryGenesis: genHash, regTypeHash,
  tokenId, mintTx: mintHash, amount: W.amount, denom: W.denom, recipient: W.recipient, osmoHeight: W.height, osmoEscrowTx: undefined,
}, null, 2));
console.log("wrote catom_mint_live.json");
