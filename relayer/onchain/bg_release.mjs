// Burn-gated RELEASE: spend the receipt with NO key - only the Mithril-certified burn + replay-once nullifier
// authorize it. input0 = receipt (burn_gated lock; witness = MKMap cert proof), input1 = registry (type;
// witness = 0x02 SMT insert), cellDeps include the LCKP at the burn's certified root.
import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait, plainCells } from "./_signer.mjs";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const J = (f) => JSON.parse(fs.readFileSync(path.join(HERE, f), "utf8"));
const BG = J("burn_gated_live.json"), CP = J("checkpoint_v2.json"), REG = J("v2_registry.json");
const RW = J("bg_release_wit.json"), GW = J("bg_reg_wit.json"), RCPT = J("bg_receipt.json");
const BL = J("bridge_lock_live.json");   // the unified receipt carries bridge_lock_v1 as its TYPE - dep its code
const REGSTATE = J("boundasset_v2_state.json").registry;   // current registry singleton outpoint
const FEE = 2_000_000n, CKB = 100000000n;
const { client, signer } = signerOf(); const lock = await myLock(signer);
// self-serve: release the unlocked CKB to the tester's address (CKB_RECIPIENT) if set, else our lock.
const recipientLock = process.env.CKB_RECIPIENT
  ? (await ccc.Address.fromString(process.env.CKB_RECIPIENT, client)).script
  : lock;

const regOp = { txHash: REGSTATE.txHash, index: REGSTATE.index };
const regCell = await client.getCellLive(regOp, true);
if (!regCell) throw new Error("registry singleton not live: " + regOp.txHash + ":" + regOp.index);
const regScript = ccc.Script.from(regCell.cellOutput.type);
if (regCell.outputData.toLowerCase() !== GW.old_root.toLowerCase()) throw new Error(`registry root drift: live ${regCell.outputData} != wit ${GW.old_root}`);
const regCap = BigInt(regCell.cellOutput.capacity);

const receiptOp = { txHash: RCPT.txHash, index: RCPT.index };
const receiptCell = await client.getCellLive(receiptOp, true);
if (!receiptCell) throw new Error("receipt not live (already released?)");
const receiptCap = BigInt(receiptCell.cellOutput.capacity);

const fund = (await plainCells(client, lock)).find((x) => BigInt(x.cellOutput.capacity) >= FEE + 63n * CKB);
if (!fund) throw new Error("no funding cell");
const tx = ccc.Transaction.from({
  inputs: [
    { previousOutput: receiptOp, since: 0n },                                  // 0: receipt (burn_gated lock)
    { previousOutput: regOp, since: 0n },                                      // 1: registry (type-script group)
    { previousOutput: fund.outPoint, since: 0n },                              // 2: funding (our lock)
  ],
  outputs: [
    { lock: recipientLock, capacity: receiptCap },                            // 0: RELEASED CKB -> the tester
    { lock, type: regScript, capacity: regCap },                              // 1: continuing registry (new root)
    { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE },               // 2: change
  ],
  outputsData: ["0x", GW.new_root, "0x"],
  cellDeps: [
    { outPoint: { txHash: BG.burn_gated_code_tx, index: 0 }, depType: "code" },     // burn_gated code
    { outPoint: { txHash: CP.checkpoint.txHash, index: CP.checkpoint.index }, depType: "code" }, // LCKP @ burn root
    { outPoint: { txHash: REG.registryCode.txHash, index: 0 }, depType: "code" },   // registry code
    { outPoint: { txHash: BL.bridge_code_tx, index: 0 }, depType: "code" },          // bridge_lock_v1 type code
  ],
});
tx.cellDeps.push(...(await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160)).cellDeps.map((cd) => cd.cellDep));
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: RW.witness })); // MKMap proof in LOCK field (burn_gated is a lock script)
tx.setWitnessArgsAt(1, ccc.WitnessArgs.from({ inputType: GW.witness }));   // 0x02 SMT insert on the registry input
const signed = await signer.signTransaction(tx);
console.log("release tx built | receipt", receiptOp.txHash.slice(0,14), "| LCKP root", CP.root.slice(0,14), "| reg", GW.old_root.slice(0,14), "->", GW.new_root.slice(0,14));
const h = await client.sendTransaction(signed);
console.log("BURN-GATED RELEASE BROADCAST:", h);
await wait(client, h);
fs.writeFileSync(path.join(HERE, "bg_release.json"), JSON.stringify({ releaseTx: h, receipt: receiptOp.txHash, lckp: CP.checkpoint.txHash, lckpRoot: CP.root, nullifier: GW.key, regOldRoot: GW.old_root, regNewRoot: GW.new_root, releasedCKB: (Number(receiptCap)/1e8) }, null, 2));
// keep state consistent for the NEXT release: record the new nullifier + move the registry singleton pointer
// to this tx's continuing registry (output 1) at the new root, so reg_null_burn + bg_release line up next time.
const regState = J("registry_state.json"); regState.keys = [...(regState.keys || []), GW.key];
fs.writeFileSync(path.join(HERE, "registry_state.json"), JSON.stringify(regState, null, 2));
const baState = J("boundasset_v2_state.json"); baState.registry = { txHash: h, index: 1, root: GW.new_root };
fs.writeFileSync(path.join(HERE, "boundasset_v2_state.json"), JSON.stringify(baState, null, 2));
console.log("*** RELEASED", (Number(receiptCap)/1e8), "CKB gated ONLY by the certified Cardano burn (no key authorized the receipt spend) ***");
process.exit(0);
