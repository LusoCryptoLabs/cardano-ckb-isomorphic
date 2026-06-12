// live_catom_owner_mint.mjs — mint χOSMO as a REAL, displayable xUDT (Fix #1), gated on the real osmo-test-5
// escrow. χOSMO = canonical xUDT(args = owner_lock_hash), minted via xUDT OWNER MODE (the tx spends a cell
// locked by catom_mint_owner, the xUDT type skips its amount check, the owner lock enforces the bound mint),
// with the Unique token-info cell issued IN the mint tx so wallets/the explorer show "Chiral OSMO".
//
// ROBUST FUNDING: this lock holds so many code cells that CCC's auto input-gathering truncates on the RPC's
// 10MB cap. So every tx here EXPLICITLY picks a funding cell via the indexer's empty-data filter (a small,
// reliable query) and sets capacities by hand — no completeInputsByCapacity scan. Idempotent via a state file.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REL = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release");
const W = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../spike/cosmos-ckb/catom_witness.json"), "utf8"));
const hb = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const CKB = 100000000n;

const XUDT_CODE = "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb";
const XUDT_DEP = { outPoint: { txHash: "0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f", index: 0 }, depType: "code" };
const UNIQUE_CODE = "0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b";
const UNIQUE_DEP = { outPoint: { txHash: "0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef", index: 0 }, depType: "code" };
const TOKEN = { name: "Chiral OSMO", symbol: "xOSMO", decimals: 6 };
const tokenInfoBytes = (dec, name, sym) => { const n = new TextEncoder().encode(name), s = new TextEncoder().encode(sym);
  return "0x" + Buffer.concat([Buffer.from([dec]), Buffer.from([n.length]), Buffer.from(n), Buffer.from([s.length]), Buffer.from(s)]).toString("hex"); };
const uniqueArgs = (firstOp, outIdx) => { const ib = ccc.bytesFrom(ccc.CellInput.from({ previousOutput: firstOp, since: 0n }).toBytes());
  const pre = new Uint8Array(ib.length + 8); pre.set(ib, 0); pre[ib.length] = outIdx & 0xff; return ccc.hashCkb(pre).slice(0, 42); };

const OWNER_CAP = 250n * CKB, XOSMO_CAP = 300n * CKB, UNIQUE_CAP = 200n * CKB, REG_CAP = 250n * CKB, FEE = 1000000n; // 0.01 CKB (under the max fee-rate guard for these small txs)
const STATE = path.join(HERE, "catom_owner_state.json");
const st = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, "utf8")) : {};
const save = () => fs.writeFileSync(STATE, JSON.stringify(st, null, 2));

const { client, signer } = signerOf();
const lock = await myLock(signer);
const secpDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);
console.log("relayer:", (await signer.getAddressObjs())[0].toString());

// pick the smallest empty-data (plain) cell that covers `minCap` — reliable indexer query, no auto-gather scan.
async function pickFunding(minCap) {
  let best = null;
  for await (const c of client.findCells({ script: lock, scriptType: "lock", scriptSearchMode: "exact", filter: { outputDataLenRange: ["0x0", "0x1"] } }, "asc", 200)) {
    const cap = BigInt(c.cellOutput.capacity);
    if (cap >= minCap && (!best || cap < BigInt(best.cellOutput.capacity))) best = c;
  }
  if (!best) throw new Error(`no plain cell >= ${minCap / CKB} CKB`);
  return best;
}
const sign = async (tx) => { const h = await client.sendTransaction(await signer.signTransaction(tx)); await wait(client, h); return h; };

// deploy a code cell from an explicit funding cell (occupied = 8 + lock(53) + dataLen).
async function deploy(bytes) {
  const data = ccc.hexFrom(new Uint8Array(bytes));
  const dataLen = BigInt((data.length - 2) / 2);
  const codeCap = (8n + 53n + dataLen) * CKB;
  const fund = await pickFunding(codeCap + FEE + 100n * CKB);
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: fund.outPoint, since: 0n }],
    outputs: [{ lock, capacity: codeCap }, { lock, capacity: BigInt(fund.cellOutput.capacity) - codeCap - FEE }],
    outputsData: [data, "0x"], cellDeps: secpDeps,
  });
  const h = await sign(tx);
  return { codeHash: ccc.hashCkb(data), dataDep: { outPoint: { txHash: h, index: 0 }, depType: "code" } };
}

// 1) deploy owner + registry code (idempotent)
if (!st.ownerDep) { st.ownerDep = await deploy(fs.readFileSync(path.join(REL, "catom_mint_owner.strip"))); save(); }
if (!st.regDep) { st.regDep = await deploy(fs.readFileSync(path.join(REL, "cosmos_nullifier_registry.strip"))); save(); }
const ownerDep = st.ownerDep, regDep = st.regDep;
console.log("owner code:", ownerDep.codeHash, "| registry code:", regDep.codeHash);

// 2) genesis the registry (type-id singleton, empty) — idempotent
if (!st.regGenesis) {
  const fund = await pickFunding(REG_CAP + FEE + 100n * CKB);
  const in0 = fund.outPoint;
  const typeId = ccc.hashCkb("0x" + Buffer.concat([u64le(0), hb(in0.txHash), u32le(Number(in0.index)), u64le(0)]).toString("hex"));
  const regType = ccc.Script.from({ codeHash: regDep.codeHash, hashType: "data1", args: typeId });
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: in0, since: 0n }],
    outputs: [{ lock, type: regType, capacity: REG_CAP }, { lock, capacity: BigInt(fund.cellOutput.capacity) - REG_CAP - FEE }],
    outputsData: ["0x", "0x"], cellDeps: [...secpDeps, ccc.CellDep.from(regDep.dataDep)],
  });
  const h = await sign(tx);
  st.regGenesis = { txHash: h, index: 0, type: { codeHash: regDep.codeHash, hashType: "data1", args: typeId } }; save();
}
const regType = ccc.Script.from(st.regGenesis.type), regTypeHash = regType.hash(), regOutPoint = { txHash: st.regGenesis.txHash, index: 0 };
console.log("registry genesis:", st.regGenesis.txHash, "| reg_type:", regTypeHash);

// 3) owner lock = catom_mint_owner(anchor || reg_type || denom_len || denom || escrow)
const denomB = Buffer.from(W.denom), escrowB = Buffer.from(W.escrow);
const ownerArgs = Buffer.concat([hb(W.anchor), hb(regTypeHash), Buffer.from([denomB.length]), denomB, escrowB]);
const ownerLock = ccc.Script.from({ codeHash: ownerDep.codeHash, hashType: "data1", args: "0x" + ownerArgs.toString("hex") });
const owner = ownerLock.hash();

// 4) setup the owner authority cell — idempotent
if (!st.ownerCell) {
  const fund = await pickFunding(OWNER_CAP + FEE + 100n * CKB);
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: fund.outPoint, since: 0n }],
    outputs: [{ lock: ownerLock, capacity: OWNER_CAP }, { lock, capacity: BigInt(fund.cellOutput.capacity) - OWNER_CAP - FEE }],
    outputsData: ["0x", "0x"], cellDeps: secpDeps,
  });
  const h = await sign(tx);
  st.ownerCell = { txHash: h, index: 0 }; save();
}
const ownerOp = st.ownerCell;
console.log("owner authority cell:", ownerOp.txHash + ":" + ownerOp.index);

// 5) the χOSMO token = canonical xUDT(args = owner)
const xudtType = ccc.Script.from({ codeHash: XUDT_CODE, hashType: "type", args: owner });
const tokenId = xudtType.hash();
console.log("χOSMO token id (xUDT):", tokenId);

// 6) the mint tx: owner-mode xUDT mint + Unique token-info cell, gated by the Cosmos escrow proof
const ownerCell = await client.getCellLive(ownerOp, true);
const regCell = await client.getCellLive(regOutPoint, true);
const newRegData = "0x" + regCell.outputData.replace(/^0x/, "") + W.nfKey;   // append the certified Cosmos tx's nullifier
const amount16 = Buffer.alloc(16); amount16.writeBigUInt64LE(BigInt(W.amount), 0);
const REG_GROW = 50n * CKB;   // the registry cell gains 32 bytes (the nullifier); add headroom from funding
const fund = await pickFunding(XOSMO_CAP + UNIQUE_CAP + REG_GROW + FEE + 100n * CKB);
const uniqueType = ccc.Script.from({ codeHash: UNIQUE_CODE, hashType: "type", args: uniqueArgs(ownerOp, 1) });
const regOutCap = BigInt(regCell.cellOutput.capacity) + REG_GROW;
const change = BigInt(fund.cellOutput.capacity) - XOSMO_CAP - UNIQUE_CAP - REG_GROW - FEE;

const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: ownerOp, since: 0n }, { previousOutput: fund.outPoint, since: 0n }, { previousOutput: regOutPoint, since: 0n }],
  outputs: [
    { lock: recipientLockOf(), type: xudtType, capacity: XOSMO_CAP },                     // 0: χOSMO xUDT to the recipient (owner mode)
    { lock, type: uniqueType, capacity: UNIQUE_CAP },                                     // 1: token-info (Unique) — issued WITH the xUDT
    { lock: ownerLock, capacity: BigInt(ownerCell.cellOutput.capacity) },                 // 2: recreate the owner authority cell
    { lock, type: regType, capacity: regOutCap },                                         // 3: continuing registry (now holds the nullifier)
    { lock, capacity: change },                                                           // 4: change
  ],
  outputsData: ["0x" + amount16.toString("hex"), tokenInfoBytes(TOKEN.decimals, TOKEN.name, TOKEN.symbol), "0x", newRegData, "0x"],
  cellDeps: [...secpDeps, ccc.CellDep.from(ownerDep.dataDep), ccc.CellDep.from(XUDT_DEP), ccc.CellDep.from(regDep.dataDep), ccc.CellDep.from(UNIQUE_DEP)],
});
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + W.blob }));        // owner lock's GroupInput[0]: the Cosmos inclusion proof
tx.setWitnessArgsAt(2, ccc.WitnessArgs.from({ inputType: "0x" + W.nfKey })); // registry insert
const mintHash = await sign(tx);
console.log("\nχOSMO xUDT MINT:", mintHash, "| token id:", tokenId, "| amount", W.amount, "|", TOKEN.name, TOKEN.symbol, TOKEN.decimals);

st.tokenId = tokenId; st.mintTx = mintHash; save();
fs.writeFileSync(path.join(HERE, "catom_owner_live.json"), JSON.stringify({
  ownerCode: ownerDep.codeHash, registryCode: regDep.codeHash, registryGenesis: st.regGenesis.txHash, regTypeHash,
  ownerLockHash: owner, ownerCell: ownerOp, tokenId, mintTx: mintHash, token: TOKEN,
  amount: W.amount, recipient: W.recipient, osmoHeight: W.height, xosmoCell: mintHash + ":0", uniqueCell: mintHash + ":1",
}, null, 2));
console.log("wrote catom_owner_live.json");

function recipientLockOf() { return ccc.Script.from(W.recipientLock); }
