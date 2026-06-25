// submit.ts - the real CKB submission plumbing: sign a built CCC transaction with the connected JoyID
// signer and broadcast it. This is the generic, correct primitive; the leap-specific tx construction
// (which consumes the deployed bridge owner/bound cells and carries the relayer's leap-proof witness)
// is built by the leap builders and depends on the deployed out-points from scripts/deploy_ckb.mjs.
import { ccc } from "@ckb-ccc/connector-react";

export interface SubmitResult {
  txHash: string;
}

/** Complete fee, sign with the user's signer, and broadcast. Returns the tx hash. */
export async function signAndSend(signer: ccc.Signer, tx: ccc.Transaction): Promise<SubmitResult> {
  await tx.completeFeeBy(signer); // add fee + change from the signer's cells
  const txHash = await signer.sendTransaction(tx);
  return { txHash };
}

/**
 * Build a leap-OUT BURN tx: spend the user's xUDT cells totalling >= `amount`, burning exactly `amount`
 * (returning any remainder to `changeLock`). The bridge owner cell + bound-cell FINALIZE + the release
 * proof are added by the caller from the deployed bridge config - this assembles the user-side burn so the
 * leap-out can be initiated from the wallet. Returns null if the user holds less than `amount`.
 */
export async function buildLeapBurn(
  client: ccc.Client,
  xudtType: ccc.Script,
  userLock: ccc.Script,
  amount: bigint,
): Promise<ccc.Transaction | null> {
  // gather the user's xUDT cells until we cover `amount`
  let gathered = 0n;
  const inputs: ccc.CellInput[] = [];
  for await (const cell of client.findCellsByLock(userLock, xudtType, true)) {
    const data = cell.outputData;
    const bytes = ccc.bytesFrom(data);
    if (bytes.length < 16) continue;
    let v = 0n;
    for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
    inputs.push(ccc.CellInput.from({ previousOutput: cell.outPoint, since: 0n }));
    gathered += v;
    if (gathered >= amount) break;
  }
  if (gathered < amount) return null;

  const outputs: ccc.CellOutputLike[] = [];
  const outputsData: string[] = [];
  const remainder = gathered - amount;
  if (remainder > 0n) {
    // return the unburned remainder to the user (a fresh xUDT cell)
    const rem = new Uint8Array(16);
    let r = remainder;
    for (let i = 0; i < 16; i++) { rem[i] = Number(r & 0xffn); r >>= 8n; }
    outputs.push({ lock: userLock, type: xudtType });
    outputsData.push(ccc.hexFrom(rem));
  }
  const tx = ccc.Transaction.from({ inputs, outputs, outputsData });
  // NOTE: the caller adds the bridge owner cell-dep (so the guard authorizes owner-mode), the bound-cell
  // FINALIZE output/consumption, and the release-side accounting - all from the deploy_ckb.mjs config.
  return tx;
}
