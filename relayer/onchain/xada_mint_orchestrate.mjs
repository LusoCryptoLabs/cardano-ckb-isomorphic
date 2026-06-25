// xada_mint_orchestrate.mjs - SELF-SERVE forward leg (Cardano → CKB): mint χADA xUDT to an ARBITRARY
// recipient against a Mithril-certified ADA escrow, on the LIVE WORKING checkpoint lineage (cae43266, the same
// the burn-gated release leg uses via bg_refresh.mjs). Generalizes the relayer-self-mint xada_xudt_mint.mjs:
// the recipient is the USER's CKB lock. Safe because the deployed xada_mint_owner lock enforces IN-VM that
// every minted χADA output's lock hash == the escrow datum's ckb_recipient (Err 28) and minted == locked
// lovelace (Err 24) - the relayer cannot redirect or inflate; it only assembles the tx the cert authorizes.
//
//   node xada_mint_orchestrate.mjs --setup                                   # one-time: owner authority cell
//   node xada_mint_orchestrate.mjs <escrowTxid> <amountLovelace> <recipientLockJSON> [--check]
//
// Keyless in spirit: no signature authorizes the mint - only the certified escrow + the replay-once registry.
// The relayer key signs the funding/owner-authority inputs (it pays cell capacity), never the user's funds.
// Prints exactly one JSON object on stdout (the dApp parses the last {...}); progress goes to stderr.
import fs from "node:fs";
import path from "node:path";
import { execSync, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock, wait } from "./_signer.mjs";
import { getWitness, pickPlain, REG, regCodeDep, FEE } from "./leap_common_v2.mjs";
import { REPO_SH, shInvoke } from "./_rt.mjs";   // WSL (this box) vs native-Linux (VPS)

const HERE = path.dirname(fileURLToPath(import.meta.url));
const log = (...a) => console.error("[xada]", ...a);          // progress -> stderr
const strip = (h) => (h || "").replace(/^0x/, "");
const out = (o) => { console.log(JSON.stringify(o)); process.exit(o.error ? 1 : 0); };
const REPO_WSL = REPO_SH;                                     // repo path as the shell/python see it (WSL or native)
const q = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
const wsl = (script) => { const [c, a] = shInvoke(script); return execFileSync(c, a, { encoding: "utf8", maxBuffer: 128 * 1024 * 1024 }); };
const node = (script, env = {}) => execFileSync("node", [script], { cwd: HERE, encoding: "utf8", env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "inherit"] });
const lastJson = (s) => JSON.parse(s.slice(s.lastIndexOf("{")));

const O = JSON.parse(fs.readFileSync(path.join(HERE, "xada_owner_deploy.json"), "utf8"));
const REG_STATE = path.join(HERE, "registry_state.json");
const BA_STATE = path.join(HERE, "boundasset_v2_state.json");
const OWNER_STATE = path.join(HERE, "xada_owner_cell.json");
const INFO_FLAG = path.join(HERE, `xada_info_issued_${strip(O.xadaTokenId).slice(0, 16)}.flag`);
const OWNER_CAP = 150_00000000n, XADA_CAP = 200_00000000n, UNIQUE_CAP = 150_00000000n;

const ownerLock = ccc.Script.from({ codeHash: O.ownerCode.codeHash, hashType: "data1", args: O.ownerArgs });
const ownerDep = { outPoint: { txHash: O.ownerCode.txHash, index: 0 }, depType: "code" };
const xudtType = ccc.Script.from({ codeHash: O.xudt.codeHash, hashType: O.xudt.hashType, args: O.ownerLockHash });
const xudtDep = { outPoint: { txHash: O.xudt.dep.txHash, index: O.xudt.dep.index }, depType: "code" };
// CCC Unique-type (token info) - emit the info cell IN the first mint so wallets/explorers name the token.
const UNIQUE_CODE = "0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b";
const UNIQUE_DEP = { outPoint: { txHash: "0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef", index: 0 }, depType: "code" };
const TOKEN = { name: "Chiral ADA", symbol: "xADA", decimals: 6 };
const tokenInfoBytes = (dec, name, sym) => { const n = new TextEncoder().encode(name), s = new TextEncoder().encode(sym);
  return "0x" + Buffer.concat([Buffer.from([dec]), Buffer.from([n.length]), Buffer.from(n), Buffer.from([s.length]), Buffer.from(s)]).toString("hex"); };
const uniqueArgs = (firstInputOp, outIdx) => { const ib = ccc.bytesFrom(ccc.CellInput.from({ previousOutput: firstInputOp, since: 0n }).toBytes());
  const pre = new Uint8Array(ib.length + 8); pre.set(ib, 0); pre[ib.length] = outIdx & 0xff; return ccc.hashCkb(pre).slice(0, 42); };

async function setup() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  const fund = await pickPlain(client, lock, OWNER_CAP + FEE + 100_00000000n);
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: fund.outPoint, since: 0n }],
    outputs: [{ lock: ownerLock, capacity: OWNER_CAP }, { lock, capacity: BigInt(fund.cellOutput.capacity) - OWNER_CAP - FEE }],
    outputsData: ["0x", "0x"], cellDeps: [],
  });
  const h = await client.sendTransaction(await signer.signTransaction(tx));
  await wait(client, h);
  fs.writeFileSync(OWNER_STATE, JSON.stringify({ txHash: h, index: 0 }, null, 2));
  return out({ setup: true, ownerCell: h + ":0", ownerLockHash: O.ownerLockHash, tokenId: O.xadaTokenId });
}

async function main() {
  if (process.argv.includes("--setup")) return setup();
  const [escrowArg, amountArg, recipientArg] = process.argv.slice(2);
  const escrowTx = strip(escrowArg);
  if (!/^[0-9a-f]{64}$/.test(escrowTx)) return out({ error: "escrowTxid must be a 64-hex Cardano tx hash" });

  // --- CERT GATE: cert witness (LCKP, for bg_refresh) + MKMap proof (for the owner lock). Either may be "not yet". ---
  let cw;
  try { cw = lastJson(wsl(`cd ${q(REPO_WSL + "/relayer")} && python3 gen_cert_witness.py ${q(escrowTx)} onchain/bg_ctwit.json`)); }
  catch (e) { return out({ error: "gen_cert_witness failed: " + String(e?.stderr || e?.message || e).slice(-300) }); }
  if (cw.status !== "ready") return out({ certified: false, status: cw.status || "wait-certification", escrowTx,
    message: "Mithril has not certified the ADA lock yet - retry shortly." });
  if (process.argv.includes("--check")) return out({ certified: true, escrowTx });

  let recipientLock;
  try { recipientLock = ccc.Script.from(JSON.parse(recipientArg)); }
  catch (e) { return out({ error: "recipientLock must be JSON {codeHash,hashType,args}: " + (e?.message || e) }); }
  const recipient = strip(recipientLock.hash());
  const amount = BigInt(amountArg || "0");
  if (amount <= 0n) return out({ error: "amountLovelace must be > 0" });

  const wit = getWitness(escrowTx);                            // MKMap proof (R-layout) for the owner lock witness
  if (wit.status !== "ready") return out({ certified: false, status: wit.status, escrowTx });
  if (strip(wit.root) !== strip(cw.root)) {                   // both target the latest cert; if they drift, retry once
    log("root drift between cert-witness and MKMap proof; regenerating MKMap proof…");
    const wit2 = getWitness(escrowTx);
    if (strip(wit2.root) !== strip(cw.root)) return out({ error: "could not align cert-witness and proof roots - retry" });
  }

  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  log("token", O.xadaTokenId.slice(0, 14), "| recipient", recipient.slice(0, 14), "| amount", amount.toString(), "| root", strip(cw.root).slice(0, 12));

  // advance the AVK light-client to the escrow's epoch if stale (one Mithril epoch per roll)
  let avkEpoch = Number(JSON.parse(fs.readFileSync(path.join(HERE, "chain_state.json"), "utf8")).ckpt.epoch);
  const certEpoch = Number(cw.epoch);
  while (avkEpoch < certEpoch) {
    log(`advancing AVK light-client ${avkEpoch} -> ${avkEpoch + 1} (escrow cert epoch ${certEpoch})`);
    wsl(`cd ${q(REPO_WSL + "/relayer/onchain")} && python3 gen_advance.py ${avkEpoch} advance.json`);
    node("advance_epoch.mjs");
    avkEpoch = Number(JSON.parse(fs.readFileSync(path.join(HERE, "chain_state.json"), "utf8")).ckpt.epoch);
  }

  // publish the cae43266 LCKP checkpoint at the escrow's certified root (bg_refresh reads onchain/bg_ctwit.json)
  log("publishing LCKP checkpoint at the escrow root (bg_refresh)…");
  node("bg_refresh.mjs");
  const ck = JSON.parse(fs.readFileSync(path.join(HERE, "checkpoint_v2.json"), "utf8"));
  if (strip(ck.lckpTypeHash) !== strip(O.lckpTypeHash)) return out({ error: `checkpoint type ${ck.lckpTypeHash} != owner-baked ${O.lckpTypeHash}` });
  if (strip(ck.root) !== strip(cw.root)) return out({ error: "published checkpoint root != cert root" });
  const ckptDep = { outPoint: ck.checkpoint, depType: "code" };

  // owner authority cell: trust OWNER_STATE if still live, else find it dynamically by lock (it migrates each
  // mint/burn to a new output, so a stale state file is normal - a self-serve burn moves it out from under us).
  let ownerOp = fs.existsSync(OWNER_STATE) ? JSON.parse(fs.readFileSync(OWNER_STATE, "utf8")) : null;
  let ownerCell = ownerOp ? await client.getCellLive(ownerOp, true) : null;
  if (ownerCell && strip(ownerCell.cellOutput.lock.args) !== strip(O.ownerArgs)) ownerCell = null;
  if (!ownerCell) {
    for await (const c of client.findCellsByLock(ownerLock, null, true)) {
      if (c.cellOutput.type == null && c.outputData === "0x") { ownerOp = { txHash: c.outPoint.txHash, index: Number(c.outPoint.index) }; ownerCell = c; break; }
    }
    if (!ownerCell) return out({ error: "no live owner authority cell - run xada_mint_orchestrate.mjs --setup first" });
    fs.writeFileSync(OWNER_STATE, JSON.stringify(ownerOp, null, 2));
    log("owner authority cell relocated dynamically ->", ownerOp.txHash.slice(0, 14) + ":" + ownerOp.index);
  }

  // registry: replay-once insert keyed on blake2b256(0x01 ‖ escrow tx body), against the LIVE on-chain root.
  const wb = ccc.bytesFrom(wit.witness);
  const tlen = (wb[0] | (wb[1] << 8) | (wb[2] << 16) | (wb[3] << 24)) >>> 0;
  const txBodyHex = Buffer.from(wb.slice(4, 4 + tlen)).toString("hex");
  const ba = fs.existsSync(BA_STATE) ? JSON.parse(fs.readFileSync(BA_STATE, "utf8")) : {};
  const regOp = ba.registry ? { txHash: ba.registry.txHash, index: ba.registry.index } : { txHash: REG.registryGenesis.txHash, index: REG.registryGenesis.index };
  const regCell = await client.getCellLive(regOp, true);
  if (!regCell) return out({ error: `registry singleton ${regOp.txHash}:${regOp.index} not live` });
  const regScript = ccc.Script.from(regCell.cellOutput.type);
  let reg;
  // cwd is HERE, so pass the registry-state filename RELATIVE (the absolute repo path "App - Chiral" has a space
  // that would split into argv under the shell and feed xada_reg_witness.py a "-" as the old-root).
  // CHIRAL_NULL_TAG=01 - the deployed owner lock (xada_mint_owner.rs) keys the nullifier as b2b256(0x01 ‖ tx_body)
  // (the χADA-mint leg domain tag); without it the witness key is untagged and the owner lock rejects (Err 25).
  try { reg = JSON.parse(execSync(`python xada_reg_witness.py ${txBodyHex} registry_state.json ${regCell.outputData}`, { cwd: HERE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env: { ...process.env, CHIRAL_NULL_TAG: "01" } }).trim()); }
  catch (e) { return out({ error: "registry witness failed (escrow may already be minted/replayed): " + String(e?.message || e).slice(-300) }); }
  log(`registry key ${reg.key.slice(0, 14)} | ${reg.n_keys} -> ${reg.n_keys + 1} keys`);

  const amtBuf = Buffer.alloc(16); amtBuf.writeBigUInt64LE(amount, 0);
  const xadaData = "0x" + amtBuf.toString("hex");
  const regCap = BigInt(regCell.cellOutput.capacity);
  const firstMint = !fs.existsSync(INFO_FLAG);                 // first on-chain mint of this token → issue the info cell
  const need = FEE + XADA_CAP + (firstMint ? UNIQUE_CAP : 0n) + 100_00000000n;
  const fund = await pickPlain(client, lock, need);

  // inputs: [owner authority (owner lock -> witness[0].lock = MKMap proof), funding (secp), registry singleton]
  const inputs = [
    { previousOutput: ownerOp, since: 0n },
    { previousOutput: fund.outPoint, since: 0n },
    { previousOutput: regOp, since: 0n },
  ];
  let outputs, outputsData, ownerIdx, regIdx;
  if (firstMint) {
    const uniqueType = ccc.Script.from({ codeHash: UNIQUE_CODE, hashType: "type", args: uniqueArgs(ownerOp, 1) });
    outputs = [
      { lock: recipientLock, type: xudtType, capacity: XADA_CAP },
      { lock, type: uniqueType, capacity: UNIQUE_CAP },
      { lock: ownerLock, capacity: BigInt(ownerCell.cellOutput.capacity) },
      { lock, type: regScript, capacity: regCap },
      { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE - XADA_CAP - UNIQUE_CAP },
    ];
    outputsData = [xadaData, tokenInfoBytes(TOKEN.decimals, TOKEN.name, TOKEN.symbol), "0x", reg.new_root, "0x"];
    ownerIdx = 2; regIdx = 3;
  } else {
    outputs = [
      { lock: recipientLock, type: xudtType, capacity: XADA_CAP },
      { lock: ownerLock, capacity: BigInt(ownerCell.cellOutput.capacity) },
      { lock, type: regScript, capacity: regCap },
      { lock, capacity: BigInt(fund.cellOutput.capacity) - FEE - XADA_CAP },
    ];
    outputsData = [xadaData, "0x", reg.new_root, "0x"];
    ownerIdx = 1; regIdx = 2;
  }
  const tx = ccc.Transaction.from({ inputs, outputs, outputsData,
    cellDeps: [ownerDep, xudtDep, ckptDep, regCodeDep, ...(firstMint ? [UNIQUE_DEP] : [])] });
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: wit.witness }));        // MKMap proof on the owner lock's GroupInput[0]
  tx.setWitnessArgsAt(2, ccc.WitnessArgs.from({ inputType: reg.witness }));   // registry SMT insert
  const signed = await signer.signTransaction(tx);

  let h;
  try { h = await client.sendTransaction(signed); }
  catch (e) { return out({ error: "mint tx rejected by CKB: " + String(e?.message || e).slice(-400) }); }
  log("χADA mint sent:", h, "- waiting for confirmation…");
  await wait(client, h);

  const rs = JSON.parse(fs.readFileSync(REG_STATE, "utf8"));
  if (!rs.keys.includes(reg.key)) rs.keys.push(reg.key);
  rs.root = reg.new_root; fs.writeFileSync(REG_STATE, JSON.stringify(rs, null, 2));
  if (ba.registry) { ba.registry = { txHash: h, index: regIdx, root: reg.new_root }; fs.writeFileSync(BA_STATE, JSON.stringify(ba, null, 2)); }
  fs.writeFileSync(OWNER_STATE, JSON.stringify({ txHash: h, index: ownerIdx }, null, 2));
  if (firstMint) fs.writeFileSync(INFO_FLAG, h);

  return out({ certified: true, minted: true, mintTxid: h, tokenId: xudtType.hash(),
    amount: amount.toString(), recipient, xadaCell: h + ":0", infoIssued: firstMint, escrowTx });
}
main().catch((e) => out({ error: String(e?.stack || e?.message || e).slice(-600) }));
