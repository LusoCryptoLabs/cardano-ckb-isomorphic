// fetch_commit.mjs — pull a real Tendermint SignedHeader (commit) + validator set from a Cosmos RPC and save
// them as test vectors for the CKB-VM Tendermint verifier. These are the bytes CKB must learn to verify.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.COSMOS_RPC || "https://cosmos-rpc.publicnode.com";
const get = async (p) => (await fetch(RPC + p, { signal: AbortSignal.timeout(20000) })).json();

async function main() {
  const status = await get("/status");
  const tip = Number(status.result.sync_info.latest_block_height);
  const height = process.argv[2] ? Number(process.argv[2]) : tip - 12; // a few back, surely finalized
  console.log("chain:", status.result.node_info.network, "| tip:", tip, "| using height:", height);

  const commit = await get(`/commit?height=${height}`);
  const sh = commit.result.signed_header;
  // validator set for that height (paginate)
  let vals = [], page = 1, total = Infinity;
  while (vals.length < total) {
    const v = await get(`/validators?height=${height}&page=${page}&per_page=100`);
    total = Number(v.result.total);
    vals.push(...v.result.validators);
    page++;
    if (page > 10) break;
  }

  fs.writeFileSync(path.join(HERE, "commit.json"), JSON.stringify(sh, null, 2));
  fs.writeFileSync(path.join(HERE, "validators.json"), JSON.stringify(vals, null, 2));

  const sigs = sh.commit.signatures;
  const voted = sigs.filter((s) => s.block_id_flag === 2 && s.signature); // BLOCK_ID_FLAG_COMMIT
  const totalPower = vals.reduce((a, v) => a + Number(v.voting_power), 0);
  console.log("\nheader.chain_id     :", sh.header.chain_id);
  console.log("header.height       :", sh.header.height);
  console.log("commit.round        :", sh.commit.round);
  console.log("commit.block_id.hash:", sh.commit.block_id.hash);
  console.log("part_set_header     :", JSON.stringify(sh.commit.block_id.parts));
  console.log("validators          :", vals.length, "| total voting power:", totalPower);
  console.log("commit signatures   :", sigs.length, "| committed (flag=2):", voted.length);
  console.log("\nsample precommit[0] :", JSON.stringify(voted[0], null, 2).slice(0, 400));
  console.log("sample validator[0] :", JSON.stringify(vals[0]));
  console.log("\nwrote commit.json + validators.json");
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
