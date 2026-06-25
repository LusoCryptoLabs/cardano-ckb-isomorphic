// leap_orchestrator.mjs - autonomous relayer loop + monitoring for the v2 ownership-toggle leap.
// Drives the full toggle state machine end-to-end (S4 leap-to-cardano -> Mithril cert -> S4 CKB ->
// S5 leap-to-ckb -> cert -> S5 CKB), reusing the proven, ckb-debugger-validated builders as subprocesses.
// Adds the operational layer the manual runs lacked: pre-flight funding + code-cell health checks with safe
// auto-reclaim, cert polling with timeout, structured logging, a history log, and a both-chain `status`.
//
//   node leap_orchestrator.mjs status              # both-chain health snapshot (no tx)
//   node leap_orchestrator.mjs leg [recipientHex]  # run the ONE next leg (S4 or S5 per current state)
//   node leap_orchestrator.mjs toggle [recipientHex]  # run a full round-trip back to CkbOwned
//   node leap_orchestrator.mjs run <N> [recipientHex] # N consecutive toggles
//   flags: --verify (dump+ckb-debugger each CKB leg before live) · --no-reclaim (never auto-consolidate)
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ccc } from "@ckb-ccc/core";
import { signerOf, myLock } from "./_signer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");
const RELAYER = path.resolve(HERE, "..");
const ST_PATH = path.join(HERE, "boundasset_v2_state.json");
const REG_STATE = path.join(HERE, "registry_state.json");
const LOG_PATH = path.join(HERE, "leap_log.jsonl");
const DEPLOYED = JSON.parse(fs.readFileSync(path.join(HERE, "deployed.json"), "utf8"));
const REG = JSON.parse(fs.readFileSync(path.join(HERE, "v2_registry.json"), "utf8"));
const WSL_DISTRO = "ChiralSP1";
const WIN_TO_WSL = (p) => p.replace(/^([A-Za-z]):/, (_, d) => `/mnt/${d.toLowerCase()}`).replace(/\\/g, "/");
const WSL_REPO = WIN_TO_WSL(REPO);
const WSL_KEY = WIN_TO_WSL(path.join(os.homedir(), ".chiral", "preview_relayer.key"));
const WSL_ENV = `export CHIRAL_PREVIEW_KEY=${WSL_KEY}; export AIKEN=/root/.aiken/bin/aiken; source ~/.cargo/env 2>/dev/null || true;`;

// funding floor: a single plain cell big enough for a non-recycled cert-witness cell (~1.2k CKB) + a leap
// (~260) + change (~61) + fees, with margin. Below this, refresh/leap pickPlain can fail (see GOLIVE).
const FUND_FLOOR = BigInt(1500e8);

const now = () => new Date().toISOString().replace("T", " ").slice(0, 19);
const log = (lvl, msg) => console.log(`${now()} [${lvl}] ${msg}`);
const sh = (cmd, opts = {}) => execSync(cmd, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
const wslPy = (script, args = "") =>
  sh(`wsl -d ${WSL_DISTRO} -- bash -lc "${WSL_ENV} cd ${WSL_REPO}/cardano/binding && python3 ${script} ${args}"`);
const loadJSON = (p, dflt = {}) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return dflt; } };

function leapState() {
  const st = loadJSON(ST_PATH);
  if (st.bound && !st.cardanoBound) return { phase: "CkbOwned", next: "S4", st };
  if (st.cardanoBound) return { phase: "CardanoBound", next: "S5", st };
  return { phase: "EMPTY", next: null, st };
}

async function ckbHealth() {
  const { client, signer } = signerOf();
  const lock = await myLock(signer);
  let total = 0n, plain = [], ckptCap = 0n, ckptN = 0;
  const ckptCode = DEPLOYED.cv_deploy_v2.codeHash;
  for await (const c of client.findCellsByLock(lock, null, true)) {
    const cap = BigInt(c.cellOutput.capacity); total += cap;
    if (c.cellOutput.type == null && c.outputData === "0x") plain.push(cap);
    else if (c.cellOutput.type?.codeHash === ckptCode) { ckptCap += cap; ckptN++; }
  }
  plain.sort((a, b) => (b > a ? 1 : -1));
  // code-cell liveness (a swept code cell breaks the next leap - see the reclaim gotcha)
  const codeCells = {
    bound_v2: { txHash: REG.boundCode.txHash, index: 0 }, registry: { txHash: REG.registryCode.txHash, index: 0 },
    cv_deploy_v2: { txHash: DEPLOYED.cv_deploy_v2.txHash, index: 0 },
  };
  const missing = [];
  for (const [name, op] of Object.entries(codeCells))
    if (!(await client.getCellLive(op, true).catch(() => null))) missing.push(name);
  return { client, lock, total, plain, ckptCap, ckptN, missing };
}

function cardanoHealth() {
  try { return JSON.parse(wslPy("cardano_status.py").trim().split("\n").pop()); }
  catch (e) { return { error: String(e.message || e).slice(0, 120) }; }
}

async function status() {
  const s = leapState();
  log("INFO", `toggle state: ${s.phase}${s.next ? `  (next leg: ${s.next})` : ""}`);
  const h = await ckbHealth();
  const reg = loadJSON(REG_STATE, { keys: [] });
  console.log(`  CKB   : ${(h.total / BigInt(1e8)).toLocaleString()} CKB total | largest plain ${h.plain.length ? (h.plain[0] / BigInt(1e8)).toLocaleString() : 0} CKB (${h.plain.length} plain cells)`);
  console.log(`  ckb cell: ${s.st.bound ? `${s.st.bound.txHash.slice(0, 12)}… CkbOwned` : s.st.cardanoBound ? `${s.st.cardanoBound.txHash.slice(0, 12)}… CardanoBound` : "none"} | state "${s.st.bound?.state || s.st.cardanoBound?.state || "?"}"`);
  console.log(`  registry: ${reg.keys.length} nullifier(s), root ${(reg.root || "?").slice(0, 14)}…`);
  console.log(`  checkpoints parked: ${h.ckptN} cv_deploy_v2 cells = ${(h.ckptCap / BigInt(1e8)).toLocaleString()} CKB (accumulate; typed, not auto-reclaimed)`);
  console.log(`  code cells: ${h.missing.length ? "⚠ MISSING " + h.missing.join(",") : "all live ✓"}`);
  const cn = cardanoHealth();
  if (cn.error) console.log(`  Cardano: (query failed: ${cn.error})`);
  else console.log(`  Cardano: ${cn.tada.toLocaleString()} tADA | ${cn.collateral} collateral utxo(s) | seal at ${cn.seal || "-"}`);
  const fundLow = !h.plain.length || h.plain[0] < FUND_FLOOR;
  console.log(`  health: ${h.missing.length ? "⚠ code cell missing" : fundLow ? "⚠ funding low (will auto-reclaim)" : "OK ✓"}`);
  const hist = readLog().slice(-3);
  if (hist.length) { console.log("  recent legs:"); for (const e of hist) console.log(`    ${e.ts}  ${e.leg}  cardano ${String(e.cardano_tx).slice(0, 12)}… -> ckb ${String(e.ckb_tx).slice(0, 12)}…  (cert ${e.cert_s}s)`); }
  return { s, h };
}

// machine-readable snapshot for the demo server (the same data status() prints, as a plain object).
async function statusData() {
  const s = leapState();
  const h = await ckbHealth();
  const reg = loadJSON(REG_STATE, { keys: [] });
  const cn = cardanoHealth();
  const cell = s.st.bound || s.st.cardanoBound || null;
  const fundLow = !h.plain.length || h.plain[0] < FUND_FLOOR;
  const toN = (x) => Number(x / BigInt(1e8));
  return {
    ts: now(), phase: s.phase, next: s.next,
    cell: cell ? { txHash: cell.txHash, state: cell.state ?? null, side: s.phase } : null,
    ckb: { totalCKB: toN(h.total), plainTopCKB: h.plain.length ? toN(h.plain[0]) : 0, plainCells: h.plain.length,
           checkpointsParked: h.ckptN, checkpointCKB: toN(h.ckptCap), missingCodeCells: h.missing },
    registry: { keys: reg.keys.length, root: reg.root || null },
    cardano: cn.error ? { error: cn.error } : { tada: cn.tada ?? null, collateral: cn.collateral ?? null, seal: cn.seal || null },
    fundingFloorCKB: toN(FUND_FLOOR),
    health: h.missing.length ? "code-cell-missing" : fundLow ? "funding-low" : "ok",
    recent: readLog().slice(-5).reverse(),
  };
}

function readLog() { try { return fs.readFileSync(LOG_PATH, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } }
function appendLog(e) { fs.appendFileSync(LOG_PATH, JSON.stringify({ ts: now(), ...e }) + "\n"); }

async function pollCert(txid, { timeoutMs = 30 * 60 * 1000, intervalMs = 60 * 1000 } = {}) {
  const t0 = Date.now();
  log("INFO", `awaiting Mithril cert for ${txid.slice(0, 16)}… (poll ${intervalMs / 1000}s, timeout ${timeoutMs / 60000}m)`);
  for (;;) {
    let st = "";
    try { st = JSON.parse(sh(`python produce_witness.py ${txid}`, { cwd: RELAYER }).trim()).status; } catch (e) { st = "err"; }
    if (st === "ready") { const s = Math.round((Date.now() - t0) / 1000); log("INFO", `certified in ${s}s`); return s; }
    if (Date.now() - t0 > timeoutMs) throw new Error(`cert timeout for ${txid} after ${timeoutMs / 60000}m`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

async function ensureFunding(noReclaim) {
  const h = await ckbHealth();
  if (h.missing.length) throw new Error(`code cell(s) missing: ${h.missing.join(",")} - redeploy before leaping (see reclaim gotcha)`);
  const largest = h.plain[0] || 0n;
  if (largest >= FUND_FLOOR) { log("INFO", `funding OK (largest plain ${(largest / BigInt(1e8)).toLocaleString()} CKB)`); return; }
  if (noReclaim) throw new Error(`funding low (largest plain ${(largest / BigInt(1e8)).toLocaleString()} < ${FUND_FLOOR / BigInt(1e8)} CKB) and --no-reclaim set`);
  log("WARN", `funding low (largest plain ${(largest / BigInt(1e8)).toLocaleString()} CKB) - auto-reclaiming orphaned lock-only cells…`);
  sh(`node reclaim.mjs --live`, { cwd: HERE, stdio: "inherit" });
}

function cardanoLeg(kind, recipient) {
  const script = kind === "S4" ? "leap_to_cardano_ours.py" : "leap_to_ckb_ours.py";
  const args = kind === "S5" && recipient ? recipient : "";
  log("INFO", `Cardano ${kind}: running ${script}…`);
  const out = wslPy(script, args); process.stdout.write(out.split("\n").filter((l) => /tx:|RC =|recipient|seal/.test(l)).map((l) => "    " + l.trim()).join("\n") + "\n");
  const seal = loadJSON(path.join(REPO, "cardano/deployed/cardano/preview/seal-instance-ours.json"));
  const txid = kind === "S4" ? seal.s4_transfer_tx : seal.s5_leap_tx;
  if (!txid) throw new Error(`Cardano ${kind} produced no txid (check ${script} output)`);
  log("INFO", `Cardano ${kind} submitted: ${txid}`);
  return txid;
}

function ckbLeg(kind, verify) {
  const script = kind === "S4" ? "leap_to_cardano_v2.mjs" : "leap_to_ckb_v2.mjs";
  if (verify) {
    log("INFO", `CKB ${kind}: dump + ckb-debugger pre-check…`);
    sh(`node ${script} --dump`, { cwd: HERE, stdio: "inherit" });
    const dump = kind === "S4" ? "s4_dump.json" : "s5_dump.json";
    const groups = kind === "S4" ? [0] : [0, 1];
    for (const g of groups) {
      const r = sh(`wsl -d ${WSL_DISTRO} -- bash -lc "${WSL_ENV} cd ${WSL_REPO}/relayer/onchain && ckb-debugger --tx-file ${dump} --script-group-type type --cell-type input --cell-index ${g}"`);
      if (!/Run result: 0/.test(r)) throw new Error(`ckb-debugger group ${g} did not pass:\n${r.slice(-400)}`);
      log("INFO", `  ckb-debugger group ${g}: Run result 0 ✓`);
    }
  }
  log("INFO", `CKB ${kind}: sending live…`);
  sh(`node ${script}`, { cwd: HERE, stdio: "inherit" });
  const st = loadJSON(ST_PATH);
  return kind === "S4" ? st.cardanoBound?.txHash : st.bound?.txHash;
}

async function doLeg(recipient, { verify, noReclaim }) {
  const s = leapState();
  if (!s.next) throw new Error(`no leap cell in state (${s.phase}) - run boundasset_v2.mjs genesis first`);
  log("INFO", `=== leg ${s.next} (${s.phase} -> ${s.next === "S4" ? "CardanoBound" : "CkbOwned"}) ===`);
  await ensureFunding(noReclaim);
  const cardanoTx = cardanoLeg(s.next, recipient);
  const certS = await pollCert(cardanoTx);
  await ensureFunding(noReclaim);
  const ckbTx = ckbLeg(s.next, verify);
  appendLog({ leg: s.next, cardano_tx: cardanoTx, ckb_tx: ckbTx, cert_s: certS });
  log("INFO", `leg ${s.next} DONE - Cardano ${String(cardanoTx).slice(0, 12)}… -> CKB ${String(ckbTx).slice(0, 12)}…`);
  return leapState();
}

async function doToggle(recipient, opts) {
  const start = leapState();
  if (start.phase === "EMPTY") throw new Error("no leap cell - genesis first");
  log("INFO", `>>> TOGGLE from ${start.phase}`);
  await doLeg(recipient, opts);                    // first leg
  if (leapState().phase !== "CkbOwned") await doLeg(recipient, opts);   // second leg, back to CkbOwned
  log("INFO", `<<< TOGGLE complete (state: ${leapState().phase})`);
}

async function main() {
  const argv = process.argv.slice(2);
  const flags = { verify: argv.includes("--verify"), noReclaim: argv.includes("--no-reclaim") };
  const pos = argv.filter((a) => !a.startsWith("--"));
  const cmd = pos[0] || "status";
  const recipient = (pos.find((a) => /^[0-9a-fx]{64,66}$/i.test(a)) || "").replace(/^0x/, "") || undefined;

  if (cmd === "status") { if (argv.includes("--json")) console.log(JSON.stringify(await statusData())); else await status(); }
  else if (cmd === "leg") { await doLeg(recipient, flags); await status(); }
  else if (cmd === "toggle") { await doToggle(recipient, flags); await status(); }
  else if (cmd === "run") {
    const n = parseInt(pos[1], 10) || 1;
    for (let i = 0; i < n; i++) { log("INFO", `### toggle ${i + 1}/${n} ###`); await doToggle(recipient, flags); }
    await status();
  } else throw new Error(`unknown command: ${cmd} (status|leg|toggle|run)`);
  process.exit(0);
}
main().catch((e) => { log("ERROR", e.message || String(e)); process.exit(1); });
