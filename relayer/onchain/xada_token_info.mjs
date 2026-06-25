// xada_token_info.mjs - publish the χADA token-info cell so wallets/explorers show name/symbol/decimals.
// xUDT (RFC-0052) carries ONLY the amount; identity lives in a Unique-type cell that the explorer indexes.
// Created in the SAME tx as a χADA xUDT output so the explorer binds the info to token id 0xe3a8d7be….
// Data format (canonical, = rgbpp encodeRgbppTokenInfo): decimal(1) ‖ nameLen(1) ‖ name ‖ symLen(1) ‖ symbol.
//   node xada_token_info.mjs [--dry]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";
import { pickPlain, FEE } from "./leap_common_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const O = JSON.parse(fs.readFileSync(path.join(HERE, "xada_owner_deploy.json"), "utf8"));
const MINT = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-xudt-mint.json"), "utf8"));

const NAME = "Chiral ADA", SYMBOL = "xADA", DECIMALS = 6;
// Unique type script on Pudge (CCC KnownScript.UniqueType)
const UNIQUE_CODE = "0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b";
const UNIQUE_DEP = { outPoint: { txHash: "0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef", index: 0 }, depType: "code" };
const UNIQUE_CAP = 150_00000000n;

function tokenInfoData(dec, name, sym) {
  const n = new TextEncoder().encode(name), s = new TextEncoder().encode(sym);
  return "0x" + Buffer.concat([Buffer.from([dec]), Buffer.from([n.length]), Buffer.from(n), Buffer.from([s.length]), Buffer.from(s)]).toString("hex");
}

async function main() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const xudtType = ccc.Script.from({ codeHash: O.xudt.codeHash, hashType: O.xudt.hashType, args: O.ownerLockHash });
  const xudtDep = { outPoint: { txHash: O.xudt.dep.txHash, index: O.xudt.dep.index }, depType: "code" };

  // current live χADA cell: a prior token-info tx may have moved it (xada-token-info.json), else the mint output.
  let TI = null; try { TI = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-token-info.json"), "utf8")); } catch {}
  const xadaOp = TI && TI.xada_cell
    ? { txHash: TI.xada_cell.split(":")[0], index: Number(TI.xada_cell.split(":")[1]) }
    : { txHash: MINT.mint_tx, index: 0 };
  const xadaCell = await client.getCellLive(xadaOp, true);
  if (!xadaCell) throw new Error(`χADA cell ${xadaOp.txHash}:${xadaOp.index} not live`);
  const xadaCap = BigInt(xadaCell.cellOutput.capacity);
  const xadaData = xadaCell.outputData;

  // CCC IssueXUdt structure (packages/demo .../IssueXUdtTypeId): xUDT cell BEFORE the Unique info cell, both in
  // ONE tx. Unique args = ckbhash(firstInput ‖ u64le(uniqueOutputIndex))[:20]; the Unique cell is output 1 here.
  const inp0 = ccc.CellInput.from({ previousOutput: xadaOp, since: 0n });
  const ib = ccc.bytesFrom(inp0.toBytes());
  const pre = new Uint8Array(ib.length + 8); pre.set(ib, 0); pre[ib.length] = 1;   // u64le(1)
  const uniqueArgs = ccc.hashCkb(pre).slice(0, 42);            // 0x + 40 hex = 20 bytes
  const uniqueType = ccc.Script.from({ codeHash: UNIQUE_CODE, hashType: "type", args: uniqueArgs });
  const infoData = tokenInfoData(DECIMALS, NAME, SYMBOL);

  if (process.argv.includes("--dry")) {
    console.log("token id :", xudtType.hash());
    console.log("uniqueArgs:", uniqueArgs);
    console.log("infoData  :", infoData, "(decimals", DECIMALS, "name", JSON.stringify(NAME), "symbol", JSON.stringify(SYMBOL) + ")");
    console.log("χADA in   :", xadaOp.txHash + ":" + xadaOp.index, "cap", (Number(xadaCap) / 1e8) + " CKB amount", xadaData);
    return;
  }

  const fund = await pickPlain(client, lock, UNIQUE_CAP + FEE + 100_00000000n);
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: xadaOp, since: 0n }, { previousOutput: fund.outPoint, since: 0n }],
    outputs: [
      { lock, type: xudtType, capacity: xadaCap },               // 0: χADA xUDT (re-output) - BEFORE the info cell, per CCC
      { lock, type: uniqueType, capacity: UNIQUE_CAP },          // 1: token-info (Unique) cell
      { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE - UNIQUE_CAP }, // 2: change
    ],
    outputsData: [xadaData, infoData, "0x"],
    cellDeps: [xudtDep, UNIQUE_DEP],
  });
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  console.log("token-info tx:", h, "| χADA:", h + ":0 | unique cell:", h + ":1");
  await wait(client, h);
  fs.writeFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-token-info.json"),
    JSON.stringify({ tx: h, token_id: xudtType.hash(), name: NAME, symbol: SYMBOL, decimals: DECIMALS, xada_cell: h + ":0", unique_cell: h + ":1" }, null, 2));
  console.log("DONE - name:", NAME, "symbol:", SYMBOL, "decimals:", DECIMALS, "| token id:", xudtType.hash());
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
