// deploy_verifiers.mjs - deploy the PARAMETERIZED cert-verify code cells (cv_advance, cv_deploy) on
// Pudge under our key. Verifies each deployed codeHash matches the canonical value the binaries were
// built/tested against (so cv_advance's type-hash stays 0x59efd99d, which cv_deploy's ADV_TYPEHASH binds).
// Saves outpoints to deployed.json for the chain steps. Idempotent-ish: skips a bin already recorded.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, balance, deployCodeCell } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/light-client-cell/cert-verify/adversarial/bin");
const STATE = path.join(HERE, "deployed.json");

// canonical codeHashes from the adversarial RESULTS (must match or the type-hash binding breaks)
const CANON = {
  cv_advance: "0xe877a8028eac379e962a596671d1cd918aceddfa4c4cd78163168ba3b533ac55",
  cv_deploy:  "0xdfc0aad01b4e3c307b9aa5966da83a965a7205c2647d234d415cfc7ad684f66f",
};

function load() { try { return JSON.parse(fs.readFileSync(STATE, "utf8")); } catch { return {}; } }
function save(s) { fs.writeFileSync(STATE, JSON.stringify(s, null, 2)); }

async function main() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  console.log("balance:", (Number(await balance(client, lock)) / 1e8).toLocaleString(), "CKB");
  const state = load();

  for (const name of ["cv_advance", "cv_deploy"]) {
    if (state[name]?.txHash) { console.log(`${name}: already deployed ${state[name].txHash}`); continue; }
    const bytes = fs.readFileSync(path.join(BIN, `${name}.bin`));
    const expect = CANON[name];
    const got = ccc.hashCkb(ccc.hexFrom(new Uint8Array(bytes)));
    if (got !== expect) throw new Error(`${name} codeHash ${got} != canonical ${expect} (wrong binary!)`);
    console.log(`deploying ${name} (${bytes.length} bytes, codeHash ${got.slice(0, 18)}..)`);
    const r = await deployCodeCell(client, signer, bytes, name);
    state[name] = { txHash: r.txHash, index: 0, codeHash: r.codeHash, size: bytes.length };
    save(state);
    console.log(`  ${name} deployed: ${r.txHash}`);
  }
  console.log("\nverifier code cells:", JSON.stringify(state, null, 2));
  console.log("balance now:", (Number(await balance(client, lock)) / 1e8).toLocaleString(), "CKB");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
