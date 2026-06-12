// live_xosmo_burn.mjs — the RETURN leg, CKB side: BURN χOSMO and emit a live xosmo_burn_receipt cell binding
// (amount, 20-byte osmo recipient). The receipt self-enforces Σχosmo_in − Σχosmo_out == amount, so it can never
// overstate the burn. This receipt is the on-chain state the leap_burn_windowed circuit proves, and whose proof
// the Cosmos ReleaseOnCkbBurn verifies to release uosmo.
//
// We burn a PORTION (keep a χOSMO change cell of the SAME token id) so "Chiral OSMO" stays displayable while the
// burn is demonstrated. Idempotent via xosmo_burn_state.json; explicit funding (the lock holds many code cells,
// so we never let CCC auto-scan past the RPC's 10MB cap).
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REL = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release");
const LIVE = JSON.parse(fs.readFileSync(path.join(HERE, "catom_owner_live.json"), "utf8"));
const RCP = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../spike/cosmwasm-ckb/osmo_recipient.json"), "utf8"));
const CKB = 100000000n;
const XUDT_CODE = "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb";
const XUDT_DEP = { outPoint: { txHash: "0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f", index: 0 }, depType: "code" };

const BURN_AMOUNT = 400000n;          // burn 0.4 χOSMO (of 1.0); keep 0.6 as a displayable change cell
const RECEIPT_CAP = 200n * CKB, XOSMO_CHANGE_CAP = 150n * CKB, FEE = 1000000n;
const MAGIC = Buffer.from("XOS1");

const STATE = path.join(HERE, "xosmo_burn_state.json");
const st = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, "utf8")) : {};
const save = () => fs.writeFileSync(STATE, JSON.stringify(st, null, 2));

const { client, signer } = signerOf();
const lock = await myLock(signer);
const secpDeps = (await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep);
const sign = async (tx) => { const h = await client.sendTransaction(await signer.signTransaction(tx)); await wait(client, h); return h; };

async function pickFunding(minCap) {
  let best = null;
  for await (const c of client.findCells({ script: lock, scriptType: "lock", scriptSearchMode: "exact", filter: { outputDataLenRange: ["0x0", "0x1"] } }, "asc", 200)) {
    const cap = BigInt(c.cellOutput.capacity);
    if (cap >= minCap && (!best || cap < BigInt(best.cellOutput.capacity))) best = c;
  }
  if (!best) throw new Error(`no plain cell >= ${minCap / CKB} CKB`);
  return best;
}

// 1) deploy xosmo_burn_receipt code cell (idempotent)
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
if (!st.receiptDep) { st.receiptDep = await deploy(fs.readFileSync(path.join(REL, "xosmo_burn_receipt.strip"))); save(); }
const receiptDep = st.receiptDep;
console.log("xosmo_burn_receipt code:", receiptDep.codeHash);

// 2) the burn tx
const [xtx, xidx] = LIVE.xosmoCell.split(":");
const xosmoOp = { txHash: xtx, index: BigInt(xidx) };
const xCell = await client.getCellLive(xosmoOp, true);
const inAmt = BigInt("0x" + Buffer.from(ccc.bytesFrom(xCell.outputData).slice(0, 16)).reverse().toString("hex"));
if (inAmt < BURN_AMOUNT) throw new Error(`χOSMO cell holds ${inAmt} < burn ${BURN_AMOUNT}`);
const keep = inAmt - BURN_AMOUNT;

// χOSMO xUDT type (must equal the input's type exactly so xUDT groups them)
const xudtType = ccc.Script.from({ codeHash: XUDT_CODE, hashType: "type", args: LIVE.ownerLockHash });
if (xudtType.hash() !== LIVE.tokenId) throw new Error(`xUDT type hash ${xudtType.hash()} != tokenId ${LIVE.tokenId}`);
const receiptType = ccc.Script.from({ codeHash: receiptDep.codeHash, hashType: "data1", args: LIVE.tokenId });

const amount16 = Buffer.alloc(16); amount16.writeBigUInt64LE(BURN_AMOUNT, 0);
const recip20 = Buffer.from(RCP.account20, "hex");
if (recip20.length !== 20) throw new Error("recipient must be 20 bytes");
const receiptData = "0x" + Buffer.concat([MAGIC, amount16, recip20]).toString("hex"); // 40 bytes
const keep16 = Buffer.alloc(16); keep16.writeBigUInt64LE(keep, 0);

const fund = await pickFunding(RECEIPT_CAP + XOSMO_CHANGE_CAP + FEE + 100n * CKB);
const change = BigInt(xCell.cellOutput.capacity) + BigInt(fund.cellOutput.capacity) - RECEIPT_CAP - XOSMO_CHANGE_CAP - FEE;
if (change < 61n * CKB) throw new Error("change below min cell");

const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: xosmoOp, since: 0n }, { previousOutput: fund.outPoint, since: 0n }],
  outputs: [
    { lock, type: receiptType, capacity: RECEIPT_CAP },        // 0: the burn receipt (proven by leap_burn_windowed)
    { lock, type: xudtType, capacity: XOSMO_CHANGE_CAP },      // 1: χOSMO change (same token id, stays displayable)
    { lock, capacity: change },                                // 2: CKB change
  ],
  outputsData: [receiptData, "0x" + keep16.toString("hex"), "0x"],
  cellDeps: [...secpDeps, ccc.CellDep.from(XUDT_DEP), ccc.CellDep.from(receiptDep.dataDep)],
});
const burnHash = await sign(tx);
console.log("\nχOSMO BURN:", burnHash, "| burned", BURN_AMOUNT.toString(), "kept", keep.toString());
console.log("receipt cell:", burnHash + ":0", "| recipient(osmo):", RCP.address);

st.burnTx = burnHash;
st.receipt = { txHash: burnHash, index: 0, amount: BURN_AMOUNT.toString(), recipient20: RCP.account20, recipientAddr: RCP.address, policy: LIVE.tokenId };
st.changeXosmo = burnHash + ":1"; st.keep = keep.toString();
save();
fs.writeFileSync(path.join(HERE, "xosmo_burn_live.json"), JSON.stringify({
  burnTx: burnHash, receiptCell: burnHash + ":0", receiptCode: receiptDep.codeHash, policy: LIVE.tokenId,
  amount: BURN_AMOUNT.toString(), recipient20: RCP.account20, recipientAddr: RCP.address,
  changeXosmoCell: burnHash + ":1", keptAmount: keep.toString(), token: LIVE.token,
}, null, 2));
console.log("wrote xosmo_burn_live.json");
