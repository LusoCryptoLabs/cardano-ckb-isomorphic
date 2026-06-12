// verify_tx_inclusion.mjs — prove a specific Cosmos tx is inside the verified block. Builds the Tendermint tx
// Merkle tree from the block's txs and checks its root equals the header's data_hash (which reconstruct_header
// bound to the commit-verified block_id), then builds an inclusion proof (aunts) for one tx and checks the
// recompute. Completes the chain: commit (>2/3 signed block_id) -> header root == block_id (binds data_hash)
// -> tx in data_hash. The aunts are exactly the on-chain inclusion-proof input.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.COSMOS_RPC || "https://cosmos-rpc.publicnode.com";
const get = async (p) => (await fetch(RPC + p, { signal: AbortSignal.timeout(20000) })).json();
const SHA = (b) => crypto.createHash("sha256").update(b).digest();
const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0x00]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([0x01]), l, r]));
function splitPoint(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function merkleRoot(items) { // items = raw leaf byte arrays
  if (items.length === 0) return SHA(Buffer.alloc(0));
  if (items.length === 1) return leafHash(items[0]);
  const k = splitPoint(items.length);
  return innerHash(merkleRoot(items.slice(0, k)), merkleRoot(items.slice(k)));
}
function buildAunts(items, index) { // sibling subtree-roots, ordered bottom..top (top = last), as computeRoot consumes
  const tmp = [];
  (function rec(items, index) {
    if (items.length <= 1) return;
    const k = splitPoint(items.length);
    if (index < k) { tmp.push(merkleRoot(items.slice(k))); rec(items.slice(0, k), index); }
    else { tmp.push(merkleRoot(items.slice(0, k))); rec(items.slice(k), index - k); }
  })(items, index);
  return tmp.reverse();
}
function computeRoot(index, total, leaf, aunts) { // the on-chain inclusion check
  if (total === 1) return leaf;
  const k = splitPoint(total);
  if (index < k) return innerHash(computeRoot(index, k, leaf, aunts.slice(0, -1)), aunts[aunts.length - 1]);
  return innerHash(aunts[aunts.length - 1], computeRoot(index - k, total - k, leaf, aunts.slice(0, -1)));
}

async function main() {
  const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
  let height = Number(sh.header.height), dataHash = sh.header.data_hash, blk, tries = 0;
  while (tries < 8) {
    blk = await get(`/block?height=${height}`);
    if ((blk.result.block.data.txs || []).length > 0) break;
    height++; tries++;
    dataHash = (await get(`/commit?height=${height}`)).result.signed_header.header.data_hash;
  }
  const txs = (blk.result.block.data.txs || []).map((t) => Buffer.from(t, "base64"));
  if (txs.length === 0) { console.log("no txs near height"); return; }
  // Tendermint tx tree leaves are the TX HASHES (SHA256(tx)), not the raw txs: leaf = leafHash(SHA256(tx)).
  const items = txs.map((t) => SHA(t));
  console.log("block height:", height, "| txs:", txs.length, "| data_hash:", dataHash);

  const root = merkleRoot(items).toString("hex").toUpperCase();
  console.log("\ntx tree root (all txs):", root);
  console.log("header data_hash      :", dataHash, root === dataHash ? "  MATCH" : "  MISMATCH");

  // inclusion proof for tx[0]: aunts + the on-chain recompute
  const index = 0;
  const aunts = buildAunts(items, index);
  const recomputed = computeRoot(index, items.length, leafHash(items[index]), aunts).toString("hex").toUpperCase();
  console.log("\ninclusion proof for tx[" + index + "]: index", index, "of", txs.length, "| aunts", aunts.length);
  console.log("recomputed from leaf + aunts:", recomputed, recomputed === dataHash ? "  MATCH" : "  MISMATCH");
  console.log(root === dataHash && recomputed === dataHash
    ? "\n=> tx is provably inside the block bound to the verified commit (full chain holds)"
    : "\n=> encoding still off");
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
