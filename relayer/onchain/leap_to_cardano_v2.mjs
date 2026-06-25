// leap_to_cardano_v2.mjs - S4 CKB leg of the ownership toggle (CkbOwned -> CardanoBound).
// Consume the LIVE CkbOwned bound cell and recreate it as a CardanoBound cell that names the certified
// S4 Cardano Transfer (seal-instance-ours.json :: s4_transfer_tx) as its seal. bound_asset_v2's S4 branch
// (leap_to_cardano) checks: input-lock auth (owner signs the CkbOwned), state UNCHANGED, seal_at_lock==true
// on the certified tx, CardanoBound names the tx (out seal == blake2b256(tx_body)), lock slot ZEROED, and
// the state-only commitment. No nullifier (the CkbOwned input is a native single-use CKB UTXO).
//   node leap_to_cardano_v2.mjs [--dump]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";
import { SEAL, baScript, baDep, cardanoBoundData, alignCheckpointAndWitness, pickPlain, guard, dumpMock, FEE } from "./leap_common_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ST_PATH = path.join(HERE, "boundasset_v2_state.json");

async function main() {
  const st = JSON.parse(fs.readFileSync(ST_PATH, "utf8"));
  if (!st.bound) throw new Error("no genesis CkbOwned cell in boundasset_v2_state.json - run boundasset_v2.mjs genesis first");
  if (st.cardanoBound) console.log("note: a CardanoBound cell already recorded; this will leap the CURRENT CkbOwned cell again");
  const s4txid = SEAL.s4_transfer_tx;
  const s4idx = SEAL.s4_seal_index ?? 0;
  if (!s4txid) throw new Error("seal-instance-ours.json has no s4_transfer_tx - run leap_to_cardano_ours.py first");

  const { client, signer } = signerOf();
  const lock = await myLock(signer);

  // the LIVE CkbOwned cell - read its real data so out_state is byte-identical to in_state (S4 requires it).
  const boundOp = { txHash: st.bound.txHash, index: st.bound.index };
  const inCell = await client.getCellLive(boundOp, true);
  if (!inCell) throw new Error(`CkbOwned cell ${boundOp.txHash}:${boundOp.index} is not live (already leaped?)`);
  const inData = inCell.outputData;                                  // 0x02 02 seal(32) idx(4) lock(32) state...
  const stateHex = inData.slice(2 + 2 * 70);                         // bytes after offset 70 = state
  console.log("CkbOwned cell:", boundOp.txHash, "| state:", Buffer.from(stateHex, "hex").toString("utf8"));

  const { ckpt, wit, ckptDep } = await alignCheckpointAndWitness(s4txid);

  const outData = cardanoBoundData(s4txid, s4idx, stateHex);         // CARDANO_BOUND, names the S4 transfer, lock zeroed
  const bcCap = BigInt(inCell.cellOutput.capacity);                  // reuse the CkbOwned capacity (260 CKB)
  const fund = await pickPlain(client, lock, FEE + BigInt(63e8));    // covers fee + change min
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: boundOp, since: 0n }, { previousOutput: fund.outPoint, since: 0n }],
    outputs: [{ lock, type: baScript, capacity: bcCap }, { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE }],
    outputsData: [outData, "0x"],
    cellDeps: [baDep, ckptDep],
  });
  guard(tx.inputs);
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: wit.witness }));   // cert on the bound GroupInput[0]
  const signed = await signer.signTransaction(tx);

  if (process.argv.includes("--dump")) {
    const out = path.join(HERE, "s4_dump.json");
    await dumpMock(client, signed, out);
    console.log("dumped ckb-debugger mock tx ->", out);
    process.exit(0);
  }
  const h = await client.sendTransaction(signed);
  console.log("S4 LEAP_TO_CARDANO CkbOwned -> CardanoBound:", h);
  await wait(client, h);
  st.cardanoBound = { txHash: h, index: 0, seal_txid: s4txid, seal_idx: s4idx, state: Buffer.from(stateHex, "hex").toString("utf8") };
  delete st.bound;                                                   // the CkbOwned cell is consumed; CardanoBound is now current
  fs.writeFileSync(ST_PATH, JSON.stringify(st, null, 2));
  console.log("  CardanoBound cell data:", outData);
  console.log("  ownership is now CARDANO-side; S5 leap-to-ckb brings it back.");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
