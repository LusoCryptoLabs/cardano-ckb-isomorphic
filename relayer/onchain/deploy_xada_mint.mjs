// deploy_xada_mint.mjs - deploy the χADA forward-mint type script CODE cell on CKB Pudge (XADA_LEG.md P4b).
// xada_mint is the keystone of the second leg: it mints χADA iff a Mithril-certified Cardano ADA-lock is proven
// in-VM. This just publishes the code cell (no genesis). The χADA type script = build_script(thisCode, args)
// where args = LCKP_type_hash(32) ‖ registry_type_hash(32) ‖ escrow_addr. Both baked hashes are recorded here
// so the escrow + mint steps can derive the exact χADA policy. Writes xada_mint_deploy.json (reclaim-protected).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signerOf, myLock, deployCodeCell, balance } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// NOTE: the deployed cell holds the LLVM-STRIPPED binary (`llvm-strip` on the riscv64 release artifact:
// 121,112 -> 56,664 bytes, identical executable code, re-verified by the 9 in-VM tests). Stripping is what
// keeps the code cell under the relayer's spendable budget. To reproduce the live code hash, strip first.
//   LIVE (Pudge): tx 0x9ec60f9ae81b131759ebf96cca0bb7e6e22a99c78989e8fa4885b94f49ce5531
//                 codeHash 0x92e9403546f98255752c6a150201718cd551291c6cc8537a139e790fafec2fbd
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/xada_mint");
// the two baked arg hashes (the χADA mint binds to THESE; same Mithril trust anchor as the live χCKB leg):
const LCKP_TYPE_HASH = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"))).cv_deploy_v2.lckpTypeHash;        // 0xa055798e…
const REG_TYPE_HASH  = JSON.parse(fs.readFileSync(path.join(HERE, "v2_registry.json"))).chiralRegTh;                   // 0xdc18fd56…

const { client, signer } = signerOf();
const lock = await myLock(signer);
const bin = fs.readFileSync(BIN);
console.log("xada_mint binary:", bin.length, "bytes");
console.log("relayer balance:", (await balance(client, lock)) / 100000000n, "CKB");
console.log("LCKP_TYPE_HASH:", LCKP_TYPE_HASH);
console.log("REG_TYPE_HASH :", REG_TYPE_HASH);
console.log("deploying xada_mint code cell…");
const r = await deployCodeCell(client, signer, bin, "xada_mint_code");
const state = {
  xadaMintCode: { txHash: r.txHash, index: 0, codeHash: r.codeHash, size: bin.length },
  lckpTypeHash: LCKP_TYPE_HASH,
  registryTypeHash: REG_TYPE_HASH,
};
fs.writeFileSync(path.join(HERE, "xada_mint_deploy.json"), JSON.stringify(state, null, 2));
console.log("xada_mint code:", r.txHash, "codeHash:", r.codeHash);
process.exit(0);
