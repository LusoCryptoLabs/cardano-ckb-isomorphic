// _signer.mjs - shared CKB Pudge signer for our-key on-chain orchestration (replaces the lost
// testnet-pq-common.mjs). Loads the relayer key from ~/.chiral/pudge_relayer.key (mode 600, outside
// the repo). Everything here is testnet (Pudge). Exposes the client, signer, our lock, and helpers
// to deploy a code cell and to wait for a tx.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const KEY_PATH = process.env.RELAYER_KEY || path.join(os.homedir(), ".chiral", "pudge_relayer.key");

export function signerOf() {
  const client = new ccc.ClientPublicTestnet();
  const priv = fs.readFileSync(KEY_PATH, "utf8").trim();
  const signer = new ccc.SignerCkbPrivateKey(client, priv);
  return { client, signer };
}

export async function myLock(signer) {
  return (await signer.getAddressObjs())[0].script;
}

export async function balance(client, lock) {
  let total = 0n;
  for await (const c of client.findCellsByLock(lock, null, true)) total += BigInt(c.cellOutput.capacity);
  return total;
}

// Deploy a binary as a code cell (lock = ours, no type). Returns { txHash, index:0, codeHash, dataDep }.
export async function deployCodeCell(client, signer, bytes, label = "code") {
  const lock = await myLock(signer);
  const data = ccc.hexFrom(new Uint8Array(bytes));
  const codeHash = ccc.hashCkb(data);
  const tx = ccc.Transaction.from({ outputs: [{ lock }], outputsData: [data] });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer, 1000);
  const txHash = await client.sendTransaction(await signer.signTransaction(tx));
  await client.waitTransaction(txHash, 1, { timeout: 180000 });
  return { txHash, index: 0, codeHash, dataDep: { outPoint: { txHash, index: 0 }, depType: "code" } };
}

export const wait = (client, h) => client.waitTransaction(h, 1, { timeout: 180000 });

// Plain spendable cells under our lock: no type script, empty data (i.e. NOT a code/checkpoint cell).
// Sorted by capacity descending. Used to fund txs without ever touching our big verifier code cells.
export async function plainCells(client, lock) {
  const out = [];
  for await (const c of client.findCellsByLock(lock, null, true)) {
    if (c.cellOutput.type == null && (c.outputData === "0x" || c.outputData === "0x" + "")) out.push(c);
  }
  out.sort((a, b) => (BigInt(b.cellOutput.capacity) > BigInt(a.cellOutput.capacity) ? 1 : -1));
  return out;
}

// Add the largest plain cell as an input so ccc's completeInputsByCapacity is satisfied immediately and
// never reaches for a code cell. Returns the added outpoint (for logging). Throws if no plain cell.
export async function addFunding(tx, client, lock) {
  const { ccc } = await import("@ckb-ccc/core");
  const cells = await plainCells(client, lock);   // capacity-descending
  if (!cells.length) throw new Error("no plain funding cell available");
  // Pick a random cell among the LARGEST few (top-K) - still large enough that ccc's completeInputsByCapacity
  // won't reach for a big code cell, but de-correlated so two concurrent funders don't both grab cells[0]
  // and throw "All inputs are spent". Falls back to the single cell when that's all there is.
  const K = Math.min(cells.length, 5);
  const c = cells[Math.floor(Math.random() * K)];
  tx.inputs.push(ccc.CellInput.from({ previousOutput: c.outPoint, since: 0n }));
  return c.outPoint;
}
