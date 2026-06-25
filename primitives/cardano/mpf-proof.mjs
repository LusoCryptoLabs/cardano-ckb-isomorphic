// mpf-proof.mjs - off-chain Merkle Patricia Forestry helper for the CARDANO replay
// accumulator (M1 scaling), the Cardano analogue of ckb-sidecar/smt-proof.mjs. The
// bridge_state datum holds a constant-size `processed_root` (an MPF root) instead of
// an unbounded `processed` list; every AssertProcess carries an absence+insertion
// proof (the redeemer's 3rd field) that the on-chain `mpf.insert` verifies. The
// canonical set of processed nonces is persisted (rebuildable from chain history).
//
// Uses @aiken-lang/merkle-patricia-forestry - the SAME library the on-chain verifier
// is proven against (lib/bridge/replay_smt_tests.ak), so proofs are accepted by
// construction. Commands:
//   node mpf-proof.mjs empty-root            -> { root }   (the genesis processed_root)
//   node mpf-proof.mjs proof <nonceHex>      -> { prevRoot, nextRoot, proof:[steps] }
//   node mpf-proof.mjs commit <nonceHex>     -> persist the nonce as processed
import { Trie } from "@aiken-lang/merkle-patricia-forestry";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STORE = path.join(HERE, "..", "deployed", "cardano", "processed-nonces.json");
const MARK = Buffer.from("01", "hex");
const norm = (h) => (h.startsWith("0x") ? h.slice(2) : h).toLowerCase();

function load() {
  try { return JSON.parse(fs.readFileSync(STORE, "utf8")); } catch { return []; }
}
function save(list) {
  fs.mkdirSync(path.dirname(STORE), { recursive: true });
  fs.writeFileSync(STORE, JSON.stringify([...new Set(list.map(norm))], null, 2));
}
async function trieOf(nonces) {
  const t = new Trie();
  for (const n of nonces) await t.insert(Buffer.from(norm(n), "hex"), MARK);
  return t;
}
const rootHex = (t) => (t.hash ? t.hash.toString("hex") : "00".repeat(32));

async function main() {
  const [cmd, arg] = process.argv.slice(2);
  if (cmd === "empty-root") {
    console.log(JSON.stringify({ root: rootHex(new Trie()) }));
    return;
  }
  if (cmd === "commit") {
    save([...load(), norm(arg)]);
    console.log(JSON.stringify({ ok: true, count: load().length }));
    return;
  }
  if (cmd === "proof") {
    const nonce = norm(arg);
    const priors = load().map(norm);
    if (priors.includes(nonce)) throw new Error(`nonce ${nonce.slice(0, 12)}… already processed (replay)`);
    const t = await trieOf(priors);
    const prevRoot = rootHex(t);
    const proof = (await t.prove(Buffer.from(nonce, "hex"), true)).toJSON(); // absence proof vs prevRoot
    await t.insert(Buffer.from(nonce, "hex"), MARK);
    const nextRoot = rootHex(t);
    console.log(JSON.stringify({ prevRoot, nextRoot, proof }));
    return;
  }
  throw new Error("usage: mpf-proof.mjs empty-root | proof <nonceHex> | commit <nonceHex>");
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
