// leap_to_ckb_v2.mjs - S5 CKB leg of the ownership toggle (CardanoBound -> CkbOwned). THE DANGEROUS LEG.
// Consume the LIVE CardanoBound cell + the registry genesis singleton, and recreate a CkbOwned cell LOCKED
// to the owner-signed, Mithril-certified recipient. bound_asset_v2's S5 branch (leap_to_ckb) checks: the
// certified LeapToCkb tx consumed the SOURCE seal (B4), re-parks it (seal_at_lock==true), state UNCHANGED,
// the RC keystone (RC = blake2b256(state ‖ SOURCE seal ‖ recipient)) matches the certified datum, the cell's
// data lock slot AND its ACTUAL lock both equal recipient (B1+B3), and the SOURCE seal nullifier is inserted
// into the canonical registry (B4). The registry's SMT proves non-membership -> insert (single-use).
//   node leap_to_ckb_v2.mjs [--dump]
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";
import { SEAL, REG, baScript, baDep, regCodeDep, ckbOwnedData, alignCheckpointAndWitness, pickPlain, guard, dumpMock, FEE } from "./leap_common_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ST_PATH = path.join(HERE, "boundasset_v2_state.json");
const REG_STATE = path.join(HERE, "registry_state.json");          // off-chain mirror of the nullifier SMT
const strip = (h) => (h || "").replace(/^0x/, "");

async function main() {
  const st = JSON.parse(fs.readFileSync(ST_PATH, "utf8"));
  if (!st.cardanoBound) throw new Error("no CardanoBound cell in boundasset_v2_state.json - run leap_to_cardano_v2.mjs (S4) first");
  const s5txid = SEAL.s5_leap_tx, s5idx = SEAL.s5_seal_index ?? 0;
  const recipient = strip(SEAL.s5_recipient);
  if (!s5txid || !recipient) throw new Error("seal-instance-ours.json missing s5_leap_tx / s5_recipient - run leap_to_ckb_ours.py first");

  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  if (strip(lock.hash()) !== recipient) throw new Error(`recipient ${recipient} != our lock hash ${lock.hash()} (S5 demo recipient must be our lock so we own the result)`);

  // LIVE CardanoBound cell - src_seal36 = its seal field [2..38], out_state = its state [70..].
  const boundOp = { txHash: st.cardanoBound.txHash, index: st.cardanoBound.index };
  const inCell = await client.getCellLive(boundOp, true);
  if (!inCell) throw new Error(`CardanoBound cell ${boundOp.txHash}:${boundOp.index} not live`);
  const inData = inCell.outputData;
  const srcSeal36 = inData.slice(6, 78);                       // bytes 2..38 (txid32 ‖ idx4 LE)
  const stateHex = inData.slice(142);                          // bytes 70.. (state)
  console.log("CardanoBound cell:", boundOp.txHash, "| src seal36:", srcSeal36.slice(0, 16) + "..", "| state:", Buffer.from(stateHex, "hex").toString("utf8"));

  // LIVE registry cell - the CURRENT singleton outpoint (st.registry after the 1st leap, else the genesis
  // singleton). Read its exact type script + current root + capacity straight from chain.
  const regOp = st.registry ? { txHash: st.registry.txHash, index: st.registry.index }
                            : { txHash: REG.registryGenesis.txHash, index: REG.registryGenesis.index };
  const regCell = await client.getCellLive(regOp, true);
  if (!regCell) throw new Error(`registry cell ${regOp.txHash}:${regOp.index} not live (state out of sync?)`);
  const regScript = ccc.Script.from(regCell.cellOutput.type);
  const oldRoot = regCell.outputData;

  // registry insert witness over the CURRENT key set (registry_state.json). The helper rebuilds the real
  // siblings on the new key's path and asserts its reconstructed root == the live on-chain root.
  const reg = JSON.parse(execSync(`python reg_nullifier_witness.py ${srcSeal36} ${REG_STATE} ${oldRoot}`, { cwd: HERE, encoding: "utf8" }).trim());
  console.log(`nullifier key: ${reg.key} | registry root ${oldRoot.slice(0, 14)} -> ${reg.new_root.slice(0, 14)} | set size ${reg.n_keys} -> ${reg.n_keys + 1}`);

  const { ckpt, wit, ckptDep } = await alignCheckpointAndWitness(s5txid);

  const outData = ckbOwnedData(s5txid, s5idx, recipient, stateHex);   // CKB_OWNED, lock slot == recipient
  const bcCap = BigInt(inCell.cellOutput.capacity);                   // reuse CardanoBound capacity
  const regCap = BigInt(regCell.cellOutput.capacity);
  const fund = await pickPlain(client, lock, FEE + BigInt(63e8));
  const tx = ccc.Transaction.from({
    inputs: [
      { previousOutput: boundOp, since: 0n },                        // 0: CardanoBound (bound GroupInput[0])
      { previousOutput: regOp, since: 0n },                          // 1: registry singleton (registry GroupInput[0])
      { previousOutput: fund.outPoint, since: 0n },                  // 2: funding
    ],
    outputs: [
      { lock, type: baScript, capacity: bcCap },                     // 0: CkbOwned, locked to recipient (== our lock)
      { lock, type: regScript, capacity: regCap },                   // 1: continuing registry (new root)
      { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE },    // 2: change
    ],
    outputsData: [outData, reg.new_root, "0x"],
    cellDeps: [baDep, ckptDep, regCodeDep],                          // (ccc adds the secp lock dep_group when signing)
  });
  guard(tx.inputs);
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: wit.witness }));   // cert on the bound GroupInput[0]
  tx.setWitnessArgsAt(1, ccc.WitnessArgs.from({ inputType: reg.witness }));   // SMT insert on the registry GroupInput[0]
  const signed = await signer.signTransaction(tx);

  if (process.argv.includes("--dump")) {
    const out = path.join(HERE, "s5_dump.json");
    await dumpMock(client, signed, out);
    console.log("dumped ckb-debugger mock tx ->", out);
    console.log("  verify bound  : ckb-debugger --tx-file s5_dump.json --script-group-type type --cell-type input --cell-index 0");
    console.log("  verify registry: ckb-debugger --tx-file s5_dump.json --script-group-type type --cell-type input --cell-index 1");
    process.exit(0);
  }
  const h = await client.sendTransaction(signed);
  console.log("S5 LEAP_TO_CKB CardanoBound -> CkbOwned:", h);
  await wait(client, h);
  st.bound = { txHash: h, index: 0, seal_txid: s5txid, seal_idx: s5idx, lock_slot: lock.hash(), state: Buffer.from(stateHex, "hex").toString("utf8") };
  st.registry = { txHash: h, index: 1, root: reg.new_root };
  delete st.cardanoBound;                                            // back to CkbOwned; the toggle is complete
  fs.writeFileSync(ST_PATH, JSON.stringify(st, null, 2));
  // append the new nullifier to the off-chain SMT mirror (only after the tx is confirmed on-chain).
  const rs = JSON.parse(fs.readFileSync(REG_STATE, "utf8"));
  if (!rs.keys.includes(reg.key)) rs.keys.push(reg.key);
  rs.root = reg.new_root;
  fs.writeFileSync(REG_STATE, JSON.stringify(rs, null, 2));
  console.log("  CkbOwned cell data:", outData);
  console.log("  ownership is back on CKB, recipient-bound + seal nullified. FULL TOGGLE COMPLETE.");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
