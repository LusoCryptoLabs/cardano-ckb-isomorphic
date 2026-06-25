// deploy_bound.mjs - deploy the rebuilt bound_asset_v2 (forced-atomics, CHIRAL_LCKP_TH + CHIRAL_REG_TH baked)
// as an immutable code cell via the proven onchain deployCodeCell. Records to v2_registry.json.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signerOf, myLock, deployCodeCell } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/bound_asset_v2.stripped");
const REGPATH = path.join(HERE, "v2_registry.json");
const EXPECT = "0x4cc7ae86c48944f145dbe3c0f6bd44dda7be623c382e4b31c98feef97c1020b7"; // fixed: hex32 0x-strip + checkpoint OOM guard

const { client, signer } = signerOf();
const lock = await myLock(signer);
const bin = fs.readFileSync(BIN);
console.log("deploying bound_asset_v2 code cell…");
const r = await deployCodeCell(client, signer, bin, "bound_v2");
if (r.codeHash !== EXPECT) throw new Error(`bound codeHash ${r.codeHash} != expected ${EXPECT} (rebuild with forced-atomics + consts)`);
const reg = JSON.parse(fs.readFileSync(REGPATH, "utf8"));
reg.boundCode = { txHash: r.txHash, index: 0, codeHash: r.codeHash };
fs.writeFileSync(REGPATH, JSON.stringify(reg, null, 2));
console.log("bound_asset_v2 code:", r.txHash, "\nV2_BOUND_CODE_HASH:", r.codeHash);
process.exit(0);
