// xada_xudt_mint.mjs — mint χADA as a REAL xUDT (the proper-token forward leg). χADA = canonical
// xUDT(args = owner_lock_hash); the mint is authorized via xUDT OWNER MODE: the tx spends an owner-locked
// cell, the xUDT type script then skips its amount check, and the owner lock (xada_mint_owner) enforces the
// exact bound mint (Mithril cert + escrow binding + replay registry). Result: a wallet/DEX-recognized χADA.
//
//   node xada_xudt_mint.mjs --setup    # one-time: create an owner-locked authority cell
//   node xada_xudt_mint.mjs [--dump]   # mint (cert-gated); --dump = offline ckb-debugger of both scripts
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";
import { alignCheckpointAndWitness, getWitness, pickPlain, dumpMock, REG, regCodeDep, FEE } from "./leap_common_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const strip = (h) => (h || "").replace(/^0x/, "");
const O = JSON.parse(fs.readFileSync(path.join(HERE, "xada_owner_deploy.json"), "utf8"));
const ESC = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-escrow.json"), "utf8"));
const REG_STATE = path.join(HERE, "registry_state.json");
const BA_STATE = path.join(HERE, "boundasset_v2_state.json");
const OWNER_STATE = path.join(HERE, "xada_owner_cell.json");
const OWNER_CAP = 150_00000000n;   // the authority cell capacity
const XADA_CAP = 200_00000000n;    // the χADA xUDT cell

const ownerLock = ccc.Script.from({ codeHash: O.ownerCode.codeHash, hashType: "data1", args: O.ownerArgs });
const ownerDep = { outPoint: { txHash: O.ownerCode.txHash, index: 0 }, depType: "code" };
const xudtType = ccc.Script.from({ codeHash: O.xudt.codeHash, hashType: O.xudt.hashType, args: O.ownerLockHash });
const xudtDep = { outPoint: { txHash: O.xudt.dep.txHash, index: O.xudt.dep.index }, depType: "code" };

async function main() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);

  if (process.argv.includes("--setup")) {
    const fund = await pickPlain(client, lock, OWNER_CAP + FEE + 100_00000000n);
    const tx = ccc.Transaction.from({
      inputs: [{ previousOutput: fund.outPoint, since: 0n }],
      outputs: [{ lock: ownerLock, capacity: OWNER_CAP }, { lock, capacity: BigInt(fund.cellOutput.capacity) - OWNER_CAP - FEE }],
      outputsData: ["0x", "0x"], cellDeps: [],
    });
    const h = await client.sendTransaction(await signer.signTransaction(tx));
    await wait(client, h);
    fs.writeFileSync(OWNER_STATE, JSON.stringify({ txHash: h, index: 0 }, null, 2));
    console.log("owner authority cell created:", h + ":0  (locked by the bridge owner lock)");
    process.exit(0);
  }

  const escrowTx = strip(ESC.escrow_tx);
  const amount = BigInt(ESC.amount);
  const recipient = strip(ESC.ckb_recipient);
  if (strip(lock.hash()) !== recipient) throw new Error("escrow ckb_recipient != our lock");
  if (!fs.existsSync(OWNER_STATE)) throw new Error("no owner cell — run `node xada_xudt_mint.mjs --setup` first");
  const ownerOp = JSON.parse(fs.readFileSync(OWNER_STATE, "utf8"));
  const ownerCell = await client.getCellLive(ownerOp, true);
  if (!ownerCell) throw new Error(`owner cell ${ownerOp.txHash}:${ownerOp.index} not live — re-run --setup`);
  console.log("χADA token id (xUDT):", xudtType.hash());

  // CERT GATE: prefer the existing checkpoint if it already certifies the escrow tx (skip the flaky refresh).
  let wit, ckptDep;
  const ck2 = (() => { try { return JSON.parse(fs.readFileSync(path.join(HERE, "checkpoint_v2.json"), "utf8")); } catch { return null; } })();
  const w0 = getWitness(escrowTx);
  if (w0.status !== "ready") throw new Error("escrow tx not Mithril-certified yet: " + JSON.stringify(w0));
  if (ck2 && ck2.checkpoint && strip(w0.root) === strip(ck2.root)) {
    wit = w0; ckptDep = { outPoint: ck2.checkpoint, depType: "code" };
    console.log("using EXISTING checkpoint:", ck2.checkpoint.txHash.slice(0, 14), "root", strip(ck2.root).slice(0, 12));
  } else { ({ wit, ckptDep } = await alignCheckpointAndWitness(escrowTx)); }

  // registry insert keyed on blake2b256(escrow tx body).
  const wb = ccc.bytesFrom(wit.witness);
  const tlen = (wb[0] | (wb[1] << 8) | (wb[2] << 16) | (wb[3] << 24)) >>> 0;
  const txBodyHex = Buffer.from(wb.slice(4, 4 + tlen)).toString("hex");
  const ba = fs.existsSync(BA_STATE) ? JSON.parse(fs.readFileSync(BA_STATE, "utf8")) : {};
  const regOp = ba.registry ? { txHash: ba.registry.txHash, index: ba.registry.index } : { txHash: REG.registryGenesis.txHash, index: REG.registryGenesis.index };
  const regCell = await client.getCellLive(regOp, true);
  const regScript = ccc.Script.from(regCell.cellOutput.type);
  const reg = JSON.parse(execSync(`python xada_reg_witness.py ${txBodyHex} ${REG_STATE} ${regCell.outputData}`, { cwd: HERE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).trim());
  console.log(`registry key ${reg.key.slice(0, 14)} | set ${reg.n_keys} -> ${reg.n_keys + 1}`);

  const amtBuf = Buffer.alloc(16); amtBuf.writeBigUInt64LE(amount, 0);
  const xadaData = "0x" + amtBuf.toString("hex");
  const regCap = BigInt(regCell.cellOutput.capacity);
  const recipientLock = lock; // recipient == our lock
  const fund = await pickPlain(client, lock, FEE + XADA_CAP + 100_00000000n);

  // inputs: [owner authority cell (owner lock -> witness[0].lock = MKMap proof), funding (secp), registry]
  const tx = ccc.Transaction.from({
    inputs: [
      { previousOutput: ownerOp, since: 0n },
      { previousOutput: fund.outPoint, since: 0n },
      { previousOutput: regOp, since: 0n },
    ],
    outputs: [
      { lock: recipientLock, type: xudtType, capacity: XADA_CAP },   // 0: χADA xUDT to the recipient (owner mode)
      { lock: ownerLock, capacity: BigInt(ownerCell.cellOutput.capacity) },  // 1: recreate the owner authority cell
      { lock, type: regScript, capacity: regCap },                  // 2: continuing registry
      { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE - XADA_CAP },  // 3: change
    ],
    outputsData: [xadaData, "0x", reg.new_root, "0x"],
    cellDeps: [ownerDep, xudtDep, ckptDep, regCodeDep],
  });
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: wit.witness }));        // MKMap proof on the owner lock's GroupInput[0]
  tx.setWitnessArgsAt(2, ccc.WitnessArgs.from({ inputType: reg.witness }));   // registry SMT insert
  const signed = await signer.signTransaction(tx);

  if (process.argv.includes("--dump")) {
    const out = path.join(HERE, "xada_xudt_dump.json");
    await dumpMock(client, signed, out);
    console.log("dumped ckb-debugger mock ->", out);
    console.log("  verify owner lock: ckb-debugger --tx-file xada_xudt_dump.json --script-group-type lock --cell-type input --cell-index 0");
    console.log("  verify xUDT type : ckb-debugger --tx-file xada_xudt_dump.json --script-group-type type --cell-type output --cell-index 0");
    process.exit(0);
  }

  const h = await client.sendTransaction(signed);
  console.log(`χADA xUDT MINT: ${amount} χADA (token ${xudtType.hash().slice(0, 14)}) to ${recipient.slice(0, 14)} ->`, h);
  await wait(client, h);
  const rs = JSON.parse(fs.readFileSync(REG_STATE, "utf8"));
  if (!rs.keys.includes(reg.key)) rs.keys.push(reg.key);
  rs.root = reg.new_root; fs.writeFileSync(REG_STATE, JSON.stringify(rs, null, 2));
  if (ba.registry) { ba.registry = { txHash: h, index: 2, root: reg.new_root }; fs.writeFileSync(BA_STATE, JSON.stringify(ba, null, 2)); }
  fs.writeFileSync(OWNER_STATE, JSON.stringify({ txHash: h, index: 1 }, null, 2));  // owner cell recreated at output 1
  fs.writeFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-xudt-mint.json"),
    JSON.stringify({ mint_tx: h, xada_token_id: xudtType.hash(), amount: amount.toString(), recipient, escrow_tx: escrowTx }, null, 2));
  console.log("  REAL xUDT χADA minted. token id:", xudtType.hash(), "| cell:", h + ":0");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
