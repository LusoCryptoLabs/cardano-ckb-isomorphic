// balances.ts - real CKB on-chain reads via CCC: the bridged xUDT balance for a lock (the JoyID account),
// and the admin caps/pause policy cell. xUDT amount lives in the first 16 bytes of cell data (u128 LE),
// per MAPPING_SPEC; each token cell also occupies ~minTokenCellCkb CKB (state rent) we surface to the user.
import { ccc } from "@ckb-ccc/connector-react";
import { CKB } from "../config";
import { decodeU128le, hexToBytes } from "../lib/amount";
import { decodePolicy, GuardPolicy } from "../lib/policy";

/** the xUDT type script: owner (args) = the leap-mint guard hash; code = the deployed xUDT. */
export function xudtType(): ccc.Script {
  return ccc.Script.from({
    codeHash: CKB.xudtCodeHash,
    hashType: CKB.xudtHashType,
    args: CKB.bridgeLockHash,
  });
}

export interface XudtBalance {
  token: bigint; // base units across all the lock's xUDT cells
  cellCount: number;
  ckbReserved: bigint; // total occupied capacity (shannons) locked in those cells - the user gets it back on spend
}

/** Sum the lock's bridged-xUDT cells: token base units + the CKB reserved as their state rent. */
export async function xudtBalance(client: ccc.Client, lock: ccc.Script): Promise<XudtBalance> {
  let token = 0n;
  let ckbReserved = 0n;
  let cellCount = 0;
  for await (const cell of client.findCellsByLock(lock, xudtType(), true)) {
    const data = hexToBytes(cell.outputData);
    if (data.length >= 16) {
      token += decodeU128le(data);
      ckbReserved += cell.cellOutput.capacity;
      cellCount++;
    }
  }
  return { token, cellCount, ckbReserved };
}

/** Read the admin policy cell (caps/pause) by its full type script. Returns null if not deployed/found. */
export async function readPolicy(client: ccc.Client): Promise<GuardPolicy | null> {
  const policyType = ccc.Script.from({
    codeHash: CKB.policyType.codeHash,
    hashType: CKB.policyType.hashType,
    args: CKB.policyType.args,
  });
  for await (const cell of client.findCellsByType(policyType, true)) {
    const data = hexToBytes(cell.outputData);
    if (data.length >= 33) return decodePolicy(data);
  }
  return null;
}

/** Total free CKB (capacity) on a lock - for the "you need CKB to hold the token" UX hint. */
export async function ckbBalance(client: ccc.Client, lock: ccc.Script): Promise<bigint> {
  return client.getBalanceSingle(lock);
}
