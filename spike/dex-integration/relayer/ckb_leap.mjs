// ckb_leap.mjs - build the CKB leap-OUT (FINALIZE + burn) transaction, exactly as the deployed
// `bound_asset_unified` verifier requires (read from its source, spike/phase1/bound_asset_unified.rs):
//
//   FINALIZE = consume the user's BOUND CELL with NO continuing output, while the certified Cardano tx
//   (proved in the bound input's witness against the "LCKP" checkpoint cell-dep) consumed the seal and did
//   NOT recreate it at the binding lock. In the SAME tx the user's xUDT is burned (owner-mode, gated by the
//   leap-mint guard on the bridge OWNER cell). The guard sees the bound cell in INPUTS only -> leap-out BURN
//   -> requires burned == bound state.amount.
//
// So a broadcast-complete leap-out needs, beyond the user's xUDT:
//   • the user's BOUND cell (consumed, witness = the FINALIZE proof from the checkpoint/relayer);
//   • the bridge OWNER cell (locked by the guard) as input, recreated as output (so owner mode is on and
//     the guard runs), persisting the owner;
//   • cell-deps: the "LCKP" checkpoint cell, the guard code, the BoundAsset code, the xUDT dep group.
import { ccc } from "@ckb-ccc/core";

const U128_MAX = (1n << 128n) - 1n;
export function u128le(v) {
  if (v < 0n || v > U128_MAX) throw new Error("amount out of u128 range");
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return ccc.hexFrom(b);
}
export function decodeU128le(bytes) {
  if (bytes.length < 16) throw new Error("data too short for u128");
  let v = 0n;
  for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}
const minCap = (out, dataLen) => (BigInt(out.occupiedSize) + BigInt(dataLen)) * 100_000_000n;

/**
 * PURE assembler (no client): given the resolved inputs + the FINALIZE proof, produce the complete tx. The
 * bound cell is input[0] so its witness (input_type = proof) is at witness index 0, which is what
 * `load_witness_args(0, GroupInput)` reads. The owner cell is recreated; any unburned xUDT is returned.
 * @returns {ccc.Transaction}
 */
export function assembleFinalizeLeapOut({ xudtType, userLock, amount, gathered, xudtInputs, boundCell, ownerCell, finalizeWitness, deps }) {
  if (typeof amount !== "bigint" || amount <= 0n) throw new Error("amount must be a positive BigInt");
  if (gathered < amount) throw new Error(`insufficient xUDT: have ${gathered}, need ${amount}`);

  const boundInput = ccc.CellInput.from({ previousOutput: boundCell.outPoint, since: 0n, cellOutput: boundCell.cellOutput, outputData: boundCell.outputData });
  const ownerInput = ccc.CellInput.from({ previousOutput: ownerCell.outPoint, since: 0n, cellOutput: ownerCell.cellOutput, outputData: ownerCell.outputData });

  // recreate the bridge owner cell (persist it); return the xUDT remainder if this is a partial burn.
  const outputs = [ccc.CellOutput.from({ capacity: ownerCell.cellOutput.capacity, lock: ownerCell.cellOutput.lock })];
  const outputsData = ["0x"];
  const remainder = gathered - amount;
  if (remainder > 0n) {
    const change = ccc.CellOutput.from({ lock: userLock, type: xudtType });
    change.capacity = minCap(change, 16);
    outputs.push(change);
    outputsData.push(u128le(remainder));
  }

  const tx = ccc.Transaction.from({ inputs: [boundInput, ownerInput, ...xudtInputs], outputs, outputsData });
  // FINALIZE proof rides in the bound input's witness (index 0); pad the rest.
  tx.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ inputType: ccc.hexFrom(finalizeWitness) }).toBytes())];
  while (tx.witnesses.length < tx.inputs.length) tx.witnesses.push("0x");
  // cell-deps the verifier + guard + xUDT require
  tx.addCellDeps(
    ccc.CellDep.from({ outPoint: deps.checkpoint, depType: "code" }), // "LCKP" || root
    ccc.CellDep.from({ outPoint: deps.guardCode, depType: "code" }),
    ccc.CellDep.from({ outPoint: deps.boundCode, depType: "code" }),
  );
  return tx;
}

/**
 * Client wrapper: gather the user's xUDT cells to cover `amount`, then assemble. Caller then
 * `await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.XUdt)`, `completeFeeBy(signer)`, sign + send.
 */
export async function buildFinalizeLeapOut({ client, xudtType, userLock, amount, boundCell, ownerCell, finalizeWitness, deps }) {
  let gathered = 0n;
  const xudtInputs = [];
  for await (const cell of client.findCellsByLock(userLock, xudtType, true)) {
    const bytes = ccc.bytesFrom(cell.outputData);
    if (bytes.length < 16) continue;
    xudtInputs.push(ccc.CellInput.from({ previousOutput: cell.outPoint, since: 0n, cellOutput: cell.cellOutput, outputData: cell.outputData }));
    gathered += decodeU128le(bytes);
    if (gathered >= amount) break;
  }
  const tx = assembleFinalizeLeapOut({ xudtType, userLock, amount, gathered, xudtInputs, boundCell, ownerCell, finalizeWitness, deps });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.XUdt);
  return tx;
}
