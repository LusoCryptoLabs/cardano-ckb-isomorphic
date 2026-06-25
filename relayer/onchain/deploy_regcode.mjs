// deploy_regcode.mjs - (re)deploy the burn_nullifier_registry CODE cell and pin the canonical v2 registry
// singleton. The registry genesis singletons already exist on-chain (from deploy_v2.mjs --stage registry); the
// fund-consolidation reclaimed the code cell, so we re-deploy it (same atomic-free binary -> same data hash
// 0x9d2fc246 -> the existing genesis cells become usable again). Writes v2_registry.json (protected from reclaim).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signerOf, myLock, deployCodeCell } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/burn_nullifier_registry");
// the canonical genesis singleton (one of the two on-chain; its type hash == CHIRAL_REG_TH)
const GENESIS = { txHash: "0x4e159851cb5459f41fd9548748c48ad378453dad278b0b39a16aa513057714d7", index: 0 };
const CHIRAL_REG_TH = "0xdc18fd562bca1834536c926ce8c9d94f608318c3a79a43959c0c46a84265a24e";
const EXPECT_CODE = "0x9d2fc246766108bda40b6818abd8adb137ac993699d04ba30ecad4127bbca743";

const { client, signer } = signerOf();
const lock = await myLock(signer);
const bin = fs.readFileSync(BIN);
console.log("deploying registry code cell (re-revive)…");
const r = await deployCodeCell(client, signer, bin, "registry_code");
if (r.codeHash !== EXPECT_CODE) throw new Error(`registry codeHash ${r.codeHash} != expected ${EXPECT_CODE}`);
const state = {
  registryCode: { txHash: r.txHash, index: 0, codeHash: r.codeHash },
  registryGenesis: GENESIS,
  chiralRegTh: CHIRAL_REG_TH,
};
fs.writeFileSync(path.join(HERE, "v2_registry.json"), JSON.stringify(state, null, 2));
console.log("registry code:", r.txHash, "codeHash:", r.codeHash);
console.log("registry genesis singleton:", `${GENESIS.txHash}:${GENESIS.index}`);
console.log("CHIRAL_REG_TH:", CHIRAL_REG_TH);
process.exit(0);
