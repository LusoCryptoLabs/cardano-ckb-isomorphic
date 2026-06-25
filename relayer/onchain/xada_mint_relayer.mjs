// xada_mint_relayer.mjs - χADA leg P4d: the LIVE forward mint (Cardano ADA-lock -> mint χADA on CKB Pudge).
// Adapts leap_to_ckb_v2.mjs (same Mithril witness + 44-byte checkpoint alignment + replay-once registry), but
// instead of toggling a bound cell it MINTS χADA against the certified `ada_escrow` lock. The on-chain logic
// is `xada_mint` (deployed code 0x9ec60f9a); this builder produces the exact tx its 9 in-VM tests exercise:
//   inputs : [funding(our lock), registry singleton]
//   outputs: [χADA cell (type=xada_mint, lock=recipient, data=amount u128 LE), continuing registry, change]
//   cellDeps: [xada_mint code, LCKP checkpoint, registry code]   witness[0].input_type = MKMapProof (read via
//   GroupOutput[0]); witness[1].input_type = registry SMT insert (key = blake2b256(escrow tx body)).
//
//   node xada_mint_relayer.mjs            # build (cert-gated) + submit; throws cleanly if not yet certified
//   node xada_mint_relayer.mjs --dump     # dry-run ckb-debugger mock (also cert-gated on the witness)
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";
import { alignCheckpointAndWitness, getWitness, pickPlain, guard, dumpMock, REG, regCodeDep, FEE } from "./leap_common_v2.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const strip = (h) => (h || "").replace(/^0x/, "");
const XADA = JSON.parse(fs.readFileSync(path.join(HERE, "xada_mint_deploy.json"), "utf8"));
const ESC = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-escrow.json"), "utf8"));
const REG_STATE = path.join(HERE, "registry_state.json");
const BA_STATE = path.join(HERE, "boundasset_v2_state.json");
const XADA_CAP = 300_00000000n;   // 300 CKB for the χADA cell (occupied ≈203 CKB: 93-byte xada_mint args + data)

async function main() {
  const escrowTx = strip(ESC.escrow_tx);
  const amount = BigInt(ESC.amount);
  const recipient = strip(ESC.ckb_recipient);
  const escrowAddr = strip(ESC.escrow_addr_hex);

  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  if (strip(lock.hash()) !== recipient)
    throw new Error(`escrow datum ckb_recipient ${recipient} != our lock ${strip(lock.hash())} (demo recipient must be our lock)`);

  // the χADA type script (policy) = xada_mint code applied with args = LCKP(32) ‖ reg_type(32) ‖ escrow_addr.
  const xadaArgs = "0x" + strip(XADA.lckpTypeHash) + strip(XADA.registryTypeHash) + escrowAddr;
  const xadaScript = ccc.Script.from({ codeHash: XADA.xadaMintCode.codeHash, hashType: "data1", args: xadaArgs });
  const xadaDep = { outPoint: { txHash: XADA.xadaMintCode.txHash, index: 0 }, depType: "code" };
  console.log("χADA policy (xada_mint type hash):", xadaScript.hash());

  // CERT GATE: prefer the EXISTING LCKP checkpoint if it already certifies the escrow tx - avoids the flaky
  // Mithril cert-fetch in refreshCheckpointV2 (the preview aggregator times out intermittently). Only refresh
  // if the witness root has drifted past the published checkpoint.
  let wit, ckptDep;
  const ck2 = (() => { try { return JSON.parse(fs.readFileSync(path.join(HERE, "checkpoint_v2.json"), "utf8")); } catch { return null; } })();
  const w0 = getWitness(escrowTx);
  if (w0.status !== "ready") throw new Error("escrow tx not Mithril-certified yet: " + JSON.stringify(w0));
  if (ck2 && ck2.checkpoint && strip(w0.root) === strip(ck2.root)) {
    wit = w0; ckptDep = { outPoint: ck2.checkpoint, depType: "code" };
    console.log("using EXISTING checkpoint (no refresh):", ck2.checkpoint.txHash.slice(0, 14), "root", strip(ck2.root).slice(0, 12));
  } else {
    console.log("witness root drift vs published checkpoint -> refreshing (may retry on aggregator flakiness)...");
    ({ wit, ckptDep } = await alignCheckpointAndWitness(escrowTx));
  }

  // extract the certified Cardano tx body (first lp field of the R-layout) -> the registry key = blake2b256(body).
  const wb = ccc.bytesFrom(wit.witness);
  const tlen = (wb[0] | (wb[1] << 8) | (wb[2] << 16) | (wb[3] << 24)) >>> 0;
  const txBodyHex = Buffer.from(wb.slice(4, 4 + tlen)).toString("hex");

  // LIVE registry singleton (shared with the χCKB leg): current outpoint + type + root from chain.
  const ba = fs.existsSync(BA_STATE) ? JSON.parse(fs.readFileSync(BA_STATE, "utf8")) : {};
  const regOp = ba.registry ? { txHash: ba.registry.txHash, index: ba.registry.index }
                            : { txHash: REG.registryGenesis.txHash, index: REG.registryGenesis.index };
  const regCell = await client.getCellLive(regOp, true);
  if (!regCell) throw new Error(`registry singleton ${regOp.txHash}:${regOp.index} not live (χCKB leg moved it? re-sync state)`);
  const regScript = ccc.Script.from(regCell.cellOutput.type);
  const oldRoot = regCell.outputData;

  // registry insert witness for key = blake2b256(escrow tx body) over the CURRENT key set.
  const reg = JSON.parse(execSync(`python xada_reg_witness.py ${txBodyHex} ${REG_STATE} ${oldRoot}`,
                                  { cwd: HERE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).trim());
  console.log(`registry key ${reg.key.slice(0, 14)} | root ${oldRoot.slice(0, 14)} -> ${reg.new_root.slice(0, 14)} | set ${reg.n_keys} -> ${reg.n_keys + 1}`);

  const amtBuf = Buffer.alloc(16); amtBuf.writeBigUInt64LE(amount, 0);   // u128 LE (amount < 2^64)
  const xadaData = "0x" + amtBuf.toString("hex");
  const regCap = BigInt(regCell.cellOutput.capacity);
  const fund = await pickPlain(client, lock, FEE + XADA_CAP + 200_00000000n);

  const tx = ccc.Transaction.from({
    inputs: [
      { previousOutput: fund.outPoint, since: 0n },   // 0: funding (our lock) -> witness[0].lock = sig
      { previousOutput: regOp, since: 0n },            // 1: registry singleton (registry GroupInput[0])
    ],
    outputs: [
      { lock, type: xadaScript, capacity: XADA_CAP },                       // 0: χADA, locked to recipient (== our lock)
      { lock, type: regScript, capacity: regCap },                          // 1: continuing registry (new root)
      { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE - XADA_CAP },// 2: change
    ],
    outputsData: [xadaData, reg.new_root, "0x"],
    cellDeps: [xadaDep, ckptDep, regCodeDep],
  });
  guard(tx.inputs);
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ inputType: wit.witness }));   // MKMapProof, read by xada_mint via GroupOutput[0]
  tx.setWitnessArgsAt(1, ccc.WitnessArgs.from({ inputType: reg.witness }));   // registry SMT insert
  const signed = await signer.signTransaction(tx);

  if (process.argv.includes("--dump")) {
    const out = path.join(HERE, "xada_mint_dump.json");
    await dumpMock(client, signed, out);
    console.log("dumped ckb-debugger mock ->", out);
    console.log("  verify mint    : ckb-debugger --tx-file xada_mint_dump.json --script-group-type type --cell-type output --cell-index 0");
    console.log("  verify registry: ckb-debugger --tx-file xada_mint_dump.json --script-group-type type --cell-type input --cell-index 1");
    process.exit(0);
  }

  const h = await client.sendTransaction(signed);
  console.log(`χADA MINT: ${amount} χADA minted to ${recipient.slice(0, 14)}.. ->`, h);
  await wait(client, h);

  // persist the SHARED registry state (the singleton moved) so the next leap (either direction) stays in sync.
  const rs = JSON.parse(fs.readFileSync(REG_STATE, "utf8"));
  if (!rs.keys.includes(reg.key)) rs.keys.push(reg.key);
  rs.root = reg.new_root;
  fs.writeFileSync(REG_STATE, JSON.stringify(rs, null, 2));
  if (ba.registry) { ba.registry = { txHash: h, index: 1, root: reg.new_root }; fs.writeFileSync(BA_STATE, JSON.stringify(ba, null, 2)); }
  fs.writeFileSync(path.resolve(HERE, "../../deployed/cardano/preview/xada-mint.json"),
                   JSON.stringify({ mint_tx: h, xada_policy: xadaScript.hash(), amount: amount.toString(), recipient, escrow_tx: escrowTx }, null, 2));
  console.log("  χADA policy:", xadaScript.hash(), "| χADA cell:", h + ":0 | data:", xadaData);
  console.log("  FORWARD LEG COMPLETE: real Cardano ADA-lock -> Mithril-certified -> χADA minted on CKB.");
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
