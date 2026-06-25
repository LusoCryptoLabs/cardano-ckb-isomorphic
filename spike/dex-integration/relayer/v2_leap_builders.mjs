// v2_leap_builders.mjs - the off-chain "jump" builders for the v2 ownership-toggle leap (the RGB++
// genBtcJumpCkbVirtualTx / genCkbJumpBtcVirtualTx analogs). PURE assemblers (no client): given the resolved
// cells + the Mithril cert witness (+ the registry SMT proof for leap-in), produce the complete CKB tx that
// bound_asset_v2 accepts. Mirrors the style of ckb_leap.mjs.
//
// LEAP_TO_CKB (Cardano->CKB, S5): consume the CardanoBound cell + the nullifier registry; recreate the cell as
//   CkbOwned locked to the owner-signed recipient, and recreate the registry with the consumed seal inserted.
//   The bound cell is input[0] so its cert witness sits at witness index 0 (load_witness_args(0, GroupInput)).
// LEAP_TO_CARDANO (CKB->Cardano, S4): the CkbOwned cell's native lock authorizes; recreate the cell as
//   CardanoBound naming seal_prime (lock slot zeroed). NO nullifier (the CkbOwned input is a native single-use
//   UTXO). Pair with the Cardano seal_prime mint (cardano_leap.mjs), datum commitment = blake2b256(state).
import { ccc } from "@ckb-ccc/core";
import { ckbOwnedCellData, cardanoBoundCellData } from "./v2_cell.mjs";

/** @returns {ccc.Transaction} */
export function assembleLeapToCkb({ boundCell, registryCell, recipientLock, state, destTxHash, certWitness, registryWitness, registryNewRoot, deps }) {
  const recipientLockHash = ccc.Script.from(recipientLock).hash();
  const boundType = boundCell.cellOutput.type;                       // the v2 verifier type (per-instance)
  const boundInput = ccc.CellInput.from({ previousOutput: boundCell.outPoint, since: 0n, cellOutput: boundCell.cellOutput, outputData: boundCell.outputData });
  const regInput = ccc.CellInput.from({ previousOutput: registryCell.outPoint, since: 0n, cellOutput: registryCell.cellOutput, outputData: registryCell.outputData });

  const ckbOwned = ccc.CellOutput.from({ capacity: boundCell.cellOutput.capacity, lock: recipientLock, type: boundType });
  const ckbOwnedData = ckbOwnedCellData({ destTxHash, recipientLockHash, state });   // dest seal = th, lock slot = recipient
  const regOut = ccc.CellOutput.from({ capacity: registryCell.cellOutput.capacity, lock: registryCell.cellOutput.lock, type: registryCell.cellOutput.type });

  const tx = ccc.Transaction.from({ inputs: [boundInput, regInput], outputs: [ckbOwned, regOut], outputsData: [ckbOwnedData, registryNewRoot] });
  tx.witnesses = [
    ccc.hexFrom(ccc.WitnessArgs.from({ inputType: ccc.hexFrom(certWitness) }).toBytes()),       // index 0: bound cell
    ccc.hexFrom(ccc.WitnessArgs.from({ inputType: ccc.hexFrom(registryWitness) }).toBytes()),    // index 1: registry
  ];
  tx.addCellDeps(
    ccc.CellDep.from({ outPoint: deps.checkpoint, depType: "code" }),   // "LCKP" || cert_root
    ccc.CellDep.from({ outPoint: deps.boundCode, depType: "code" }),    // bound_asset_v2
    ccc.CellDep.from({ outPoint: deps.registryCode, depType: "code" }), // burn_nullifier_registry
  );
  return tx;
}

/** @returns {ccc.Transaction} */
export function assembleLeapToCardano({ boundCell, frozenLock, state, sealPrimeTxHash, certWitness, deps }) {
  const boundType = boundCell.cellOutput.type;
  const boundInput = ccc.CellInput.from({ previousOutput: boundCell.outPoint, since: 0n, cellOutput: boundCell.cellOutput, outputData: boundCell.outputData });
  const cardanoBound = ccc.CellOutput.from({ capacity: boundCell.cellOutput.capacity, lock: frozenLock ?? boundCell.cellOutput.lock, type: boundType });
  const data = cardanoBoundCellData({ sealPrimeTxHash, state });      // seal = seal_prime mint tx hash, slot = 0

  const tx = ccc.Transaction.from({ inputs: [boundInput], outputs: [cardanoBound], outputsData: [data] });
  tx.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ inputType: ccc.hexFrom(certWitness) }).toBytes())];
  tx.addCellDeps(
    ccc.CellDep.from({ outPoint: deps.checkpoint, depType: "code" }),
    ccc.CellDep.from({ outPoint: deps.boundCode, depType: "code" }),
  );
  return tx;
}
