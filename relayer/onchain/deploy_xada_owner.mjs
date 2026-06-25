// deploy_xada_owner.mjs - deploy the χADA xUDT OWNER lock code cell on Pudge, and derive the χADA xUDT type
// (the real, ecosystem-recognized token). χADA = xUDT(args = owner_lock_hash); minting is authorized via xUDT
// owner mode, gated by this lock (Mithril cert + escrow + replay). Writes xada_owner_deploy.json.
// NOTE: the deployed cell holds the llvm-STRIPPED owner-lock binary. Strip before deploy to reproduce the hash.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, deployCodeCell, balance } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(HERE, "../../spike/burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/xada_mint_owner");
// LCKP = the checkpoint type the owner lock reads. Pin to the LIVE WORKING lineage - the one the burn-gated
// release leg uses (burn_gated_live.json.lckp_type_hash = cae43266, refreshed by bg_refresh.mjs). The older
// cv_deploy_v2 type (a055798e) was orphaned by the Gate-1 cert-verify re-bake, so a token pinned to it can't
// be minted. Overridable via CHIRAL_XADA_LCKP for a future re-pin.
const LCKP = process.env.CHIRAL_XADA_LCKP
  || JSON.parse(fs.readFileSync(path.join(HERE, "burn_gated_live.json"))).lckp_type_hash;
const REGTH = JSON.parse(fs.readFileSync(path.join(HERE, "v2_registry.json"))).chiralRegTh;
const ESC = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-escrow.json")));
const ESCROW_ADDR = ESC.escrow_addr_hex; // 707a6be98e… (the ada_escrow address; new escrows lock at the same addr)
const strip = (h) => (h || "").replace(/^0x/, "");

const { client, signer } = signerOf();
const lock = await myLock(signer);
const bin = fs.readFileSync(BIN);
console.log("owner-lock binary:", bin.length, "bytes | balance:", (await balance(client, lock)) / 100000000n, "CKB");
const r = await deployCodeCell(client, signer, bin, "xada_owner_code");

// owner lock = Script{ owner_code, data1, args = salt(1) ‖ LCKP(32) ‖ reg(32) ‖ escrow_addr }; its hash = the
// xUDT args. SALT (logic-neutral, parsed-but-unused in xada_mint_owner.rs) gives this owner a DISTINCT lock
// hash → a DISTINCT χADA token id. Required because Magickbase fixes a token's name/symbol/decimals at its
// FIRST on-chain sighting, and the original id 0xe3a8d7be was first seen (mint 0x98f9383d) without an info
// cell → permanently un-namable. Same bridge verification (same LCKP/registry/escrow), new identity.
const SALT = process.env.CHIRAL_OWNER_SALT || "01";
const ownerArgs = "0x" + SALT + strip(LCKP) + strip(REGTH) + strip(ESCROW_ADDR);
const ownerLock = ccc.Script.from({ codeHash: r.codeHash, hashType: "data1", args: ownerArgs });
const ownerHash = ownerLock.hash();
// the χADA token = canonical xUDT(args = ownerHash).
const XUDT = await client.getKnownScript(ccc.KnownScript.XUdt);
const xadaType = ccc.Script.from({ codeHash: XUDT.codeHash, hashType: XUDT.hashType, args: ownerHash });

const state = {
  ownerCode: { txHash: r.txHash, index: 0, codeHash: r.codeHash, size: bin.length },
  ownerArgs, ownerLockHash: ownerHash,
  lckpTypeHash: LCKP, registryTypeHash: REGTH, escrowAddr: ESCROW_ADDR,
  xudt: { codeHash: XUDT.codeHash, hashType: XUDT.hashType, dep: { txHash: XUDT.cellDeps[0].cellDep.outPoint.txHash, index: Number(XUDT.cellDeps[0].cellDep.outPoint.index) } },
  xadaTokenType: { codeHash: xadaType.codeHash, hashType: xadaType.hashType, args: ownerHash },
  xadaTokenId: xadaType.hash(),   // the χADA xUDT type-script hash = the token id wallets/DEXes key on
};
fs.writeFileSync(path.join(HERE, "xada_owner_deploy.json"), JSON.stringify(state, null, 2));
console.log("owner code:", r.txHash, "codeHash:", r.codeHash);
console.log("owner lock hash (xUDT args):", ownerHash);
console.log("χADA token id (xUDT type hash):", state.xadaTokenId);
process.exit(0);
