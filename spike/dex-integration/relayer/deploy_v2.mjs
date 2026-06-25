// deploy_v2.mjs - deploy the v2 ownership-toggle leap scripts to Pudge testnet and print the exact constants
// to bake. DISJOINT from v1: bound_asset_v2 gets a fresh immutable code_hash deployed ALONGSIDE the live v1
// (0x42f74fbc); the nullifier registry is a brand-new type-id singleton. KEY SAFETY: the deployer key is read
// from CKB_DEPLOYER_KEY at runtime and NEVER written anywhere. Run this on YOUR machine.
//
// The two on-chain constants bound_asset_v2 bakes (option_env, src/bin/bound_asset_v2.rs):
//   CHIRAL_LCKP_TH - the type hash of the UPGRADED (44-byte "LCKP‖root‖height") cert-verify checkpoint singleton.
//                    M2 changed the checkpoint format (36->44 B), so v2 needs the upgraded checkpoint lineage -
//                    NOT the live 36-byte one. Deploy/identify it with the cert-verify tooling, pass its type
//                    hash in CHIRAL_LCKP_TH. (This script does not own the light-client subsystem.)
//   CHIRAL_REG_TH  - the type hash of the registry genesis singleton THIS script deploys (--stage registry).
//
// Because bound_asset_v2 embeds CHIRAL_REG_TH, the registry must be deployed FIRST, then the verifier rebuilt
// with that hash, then deployed. Hence two live stages:
//   node deploy_v2.mjs                                  # DRY: validate binaries, print code hashes + plan
//   CKB_DEPLOYER_KEY=0x.. node deploy_v2.mjs --live --stage registry
//   # rebuild: CHIRAL_LCKP_TH=0x.. CHIRAL_REG_TH=0x<from stage registry> cargo build --release ... bound_asset_v2
//   CKB_DEPLOYER_KEY=0x.. CHIRAL_LCKP_TH=0x.. node deploy_v2.mjs --live --stage bound
import { ccc } from "@ckb-ccc/core";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dir = dirname(fileURLToPath(import.meta.url));
const RISCV = "../../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release";
export const BOUND_BIN = resolve(__dir, RISCV, "bound_asset_v2");
export const REGISTRY_BIN = resolve(__dir, RISCV, "burn_nullifier_registry");

// the registry's empty 256-deep SMT root (blake2b256 personal "ckb-smt-null-set", folded 256x over ZERO);
// must equal burn_nullifier_registry::empty_root() or the genesis tx fails on-chain (error 23). Verified equal.
export const EMPTY_SMT_ROOT = "0x5b7ed70cdcbaae36e29a122fb0b7d2414f4ca62a2103d76850e3f8ad1eed663c";
const V1_BOUND_CODE_HASH = "0x42f74fbc"; // (prefix) the live immutable v1 verifier - v2 must NOT collide with it

/** The immutable (data1) code_hash a cell uses to reference a deployed binary = ckbhash(binary). Pure. */
export function dataCodeHash(bin) { return ccc.hashCkb(bin); }

/** The leap-tx cell-dep block, given the deployed pieces. Pure - shared with the relayer builders + docs. */
export function leapCellDeps({ boundCodeOutPoint, registryCodeOutPoint, registryStateOutPoint, checkpointOutPoint }) {
  return {
    boundCode: boundCodeOutPoint,           // dep_type code: bound_asset_v2 binary
    registryCode: registryCodeOutPoint,     // dep_type code: burn_nullifier_registry binary
    registryState: registryStateOutPoint,   // the singleton SMT cell (INPUT on leap-to-ckb, not a dep)
    checkpoint: checkpointOutPoint,          // dep_type code: the 44-byte "LCKP" cert-verify checkpoint
  };
}

/** Validate the two binaries exist and return their immutable code hashes + sizes. Pure (no chain). */
export function deriveCodeHashes() {
  for (const p of [BOUND_BIN, REGISTRY_BIN]) if (!existsSync(p)) throw new Error(`missing riscv binary: ${p} (build it first)`);
  const bound = readFileSync(BOUND_BIN), registry = readFileSync(REGISTRY_BIN);
  return {
    boundCodeHash: dataCodeHash(bound), boundBytes: bound.length,
    registryCodeHash: dataCodeHash(registry), registryBytes: registry.length,
  };
}

/** Deploy a binary as a plain immutable code cell (referenced by data1 code_hash). Returns its out-point. */
async function deployCodeCell(signer, bin, lock) {
  const data = ccc.bytesFrom(bin);
  const tx = ccc.Transaction.from({ outputs: [{ lock }], outputsData: [ccc.hexFrom(data)] });
  tx.outputs[0].capacity = (BigInt(tx.outputs[0].occupiedSize) + BigInt(data.length)) * 100_000_000n;
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer);
  const txHash = await signer.sendTransaction(tx);
  await signer.client.waitTransaction(txHash, 1, { timeout: 180000 }); // settle before the next tx funds itself
  return { txHash, outPoint: { txHash, index: 0 }, codeHash: ccc.hashCkb(data) };
}

/** Deploy the registry GENESIS singleton: one EMPTY cell typed by (regCodeHash, data1, args=ckbhash(input0)). */
async function deployRegistryGenesis(signer, regCodeOutPoint, regCodeHash, lock) {
  const placeholder = ccc.Script.from({ codeHash: regCodeHash, hashType: "data1", args: `0x${"00".repeat(32)}` });
  const tx = ccc.Transaction.from({ outputs: [{ lock, type: placeholder }], outputsData: [EMPTY_SMT_ROOT] });
  tx.outputs[0].capacity = (BigInt(tx.outputs[0].occupiedSize) + 32n) * 100_000_000n;
  await tx.completeInputsByCapacity(signer);
  // type-id: args == ckbhash(first input's OutPoint molecule bytes) - exactly what the genesis branch recomputes.
  const typeId = ccc.hashCkb(tx.inputs[0].previousOutput.toBytes());
  const regType = ccc.Script.from({ codeHash: regCodeHash, hashType: "data1", args: typeId });
  tx.outputs[0].type = regType;
  tx.addCellDeps(ccc.CellDep.from({ outPoint: regCodeOutPoint, depType: "code" })); // so the type script can run
  await tx.completeFeeBy(signer);
  const txHash = await signer.sendTransaction(tx);
  await signer.client.waitTransaction(txHash, 1, { timeout: 180000 });
  return { txHash, outPoint: { txHash, index: 0 }, typeScript: regType, typeHash: regType.hash() };
}

function printPlan(h, lckp) {
  console.log(`
// ===== v2 leap deploy plan (Pudge) =====
// bound_asset_v2 binary : ${h.boundBytes} bytes  immutable code_hash (data1) = ${h.boundCodeHash}
//     (note: this hash is only FINAL once rebuilt with the real CHIRAL_LCKP_TH + CHIRAL_REG_TH baked in)
//     v1 verifier (do NOT collide): ${V1_BOUND_CODE_HASH}…   v2 must differ ✓ (new code => new hash)
// registry binary       : ${h.registryBytes} bytes  immutable code_hash (data1) = ${h.registryCodeHash}
// empty SMT root        : ${EMPTY_SMT_ROOT}
// checkpoint (LCKP_TH)  : ${lckp ?? "<unset - pass CHIRAL_LCKP_TH = upgraded 44-byte cert-verify checkpoint type hash>"}
//
// Stages:
//   1) node deploy_v2.mjs --live --stage registry      -> prints CHIRAL_REG_TH (registry genesis type hash)
//   2) CHIRAL_LCKP_TH=0x.. CHIRAL_REG_TH=0x.. cargo build --release --bin bound_asset_v2 \\
//        --target riscv64imac-unknown-none-elf --manifest-path ../../burn-gated-unlock/Cargo.toml
//   3) CHIRAL_LCKP_TH=0x.. node deploy_v2.mjs --live --stage bound   -> prints the final v2 code_hash + deps
// =======================================`);
}

async function main() {
  const argv = process.argv.slice(2);
  const live = argv.includes("--live");
  const stage = (argv[argv.indexOf("--stage") + 1]) || "";
  const lckp = process.env.CHIRAL_LCKP_TH;
  const h = deriveCodeHashes();

  if (!live) { printPlan(h, lckp); console.error("\nDRY run only. Pass --live --stage <registry|bound> to broadcast."); return; }

  const key = process.env.CKB_DEPLOYER_KEY;
  if (!key) { console.error("Missing CKB_DEPLOYER_KEY for --live."); process.exit(1); }
  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, key);
  const lock = (await signer.getRecommendedAddressObj()).script;
  console.error(`deployer: ${await signer.getRecommendedAddress()}`);

  if (stage === "registry") {
    console.error("deploying registry code cell…");
    const regCode = await deployCodeCell(signer, readFileSync(REGISTRY_BIN), lock);
    console.error(`  registry code tx ${regCode.txHash}`);
    console.error("deploying registry GENESIS singleton (empty SMT)…");
    const reg = await deployRegistryGenesis(signer, regCode.outPoint, regCode.codeHash, lock);
    console.log(`
// ----- registry deployed -----
export const CHIRAL_REG_TH = "${reg.typeHash}";   // bake into bound_asset_v2, then --stage bound
//   registry code  : ${regCode.outPoint.txHash}:0  (dep_type code)
//   registry state : ${reg.outPoint.txHash}:0      (the singleton SMT cell - INPUT on each leap-to-ckb)
//   NEXT: rebuild bound_asset_v2 with CHIRAL_LCKP_TH + CHIRAL_REG_TH=${reg.typeHash}`);
    return;
  }

  if (stage === "bound") {
    if (!lckp) { console.error("Missing CHIRAL_LCKP_TH (the upgraded checkpoint type hash)."); process.exit(1); }
    console.error("deploying bound_asset_v2 code cell (must be rebuilt with the real constants)…");
    const boundCode = await deployCodeCell(signer, readFileSync(BOUND_BIN), lock);
    console.log(`
// ----- bound_asset_v2 deployed -----
export const V2_BOUND_CODE_HASH = "${boundCode.codeHash}";   // hashType: "data1"
//   bound code : ${boundCode.outPoint.txHash}:0  (dep_type code)
//   checkpoint : CHIRAL_LCKP_TH=${lckp}
//   A leap tx's cell-deps: bound code + registry code + checkpoint (and the registry STATE cell as an input).`);
    return;
  }

  console.error(`Unknown --stage "${stage}". Use registry or bound.`);
  process.exit(1);
}

// run only as a script (not when imported by the smoke test)
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("deploy_v2.mjs")) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
