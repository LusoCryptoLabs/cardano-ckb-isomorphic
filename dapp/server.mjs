// server.mjs - the dApp backend (the relayer's proof/witness service for the self-custody bridge).
//
// SELF-CUSTODY: this backend NEVER signs or holds the user's funds. It only (a) serves the bridge config the
// dApp needs to BUILD a lock tx (which the USER signs in their wallet), and (b, increment 3) turns a confirmed
// lock tx into a Groth16 proof the user presents on Cardano. It cannot move an asset; a wrong/missing response
// only delays a leap.
//
//   node server.mjs [--port=8799]
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import zlib from "node:zlib";
import { WSL_DISTRO, REPO_SH, shInvoke } from "../relayer/onchain/_rt.mjs";   // WSL (this box) vs native-Linux (VPS)
import { createJobRegistry } from "./jobreg.mjs";                             // idempotent, pollable heavy-op dedup

// Concurrency control for the experiment: the prover is CPU-heavy and the release pipeline mutates shared
// on-chain singletons. Cap concurrent proves (queue the rest) and serialize releases (mutex), so a few
// hundred people degrade GRACEFULLY (a wait) instead of corrupting each other.
function semaphore(max) {
  let active = 0; const q = [];
  const next = () => { if (active < max && q.length) { active++; q.shift()(); } };
  return (fn) => new Promise((resolve, reject) => {
    q.push(() => Promise.resolve().then(fn).then(resolve, reject).finally(() => { active--; next(); }));
    next();
  });
}
const proveGate = semaphore(Number(process.env.PROVE_CONCURRENCY || 2));  // N provers at once
const releaseGate = semaphore(1);                                         // releases strictly one-at-a-time
const xadaGate = semaphore(1);                                            // χADA mints strictly one-at-a-time
const xadaReturnGate = semaphore(1);                                      // χADA→ADA returns strictly one-at-a-time
const strip = (h) => String(h || "").replace(/^0x/, "");

// Idempotent, pollable job registry for the heavy ops (prove/release/mint/return). See jobreg.mjs for the
// dedup policy; the short version: a refresh/double-submit ATTACHES to the in-flight run keyed by the
// lock/burn/escrow txid instead of starting a second pipeline that would race the first on the same UTxOs.
const jobs = createJobRegistry();
const PROVE_CONCURRENCY = Number(process.env.PROVE_CONCURRENCY || 2);

// --- access gate + rate limit for the heavy, DoS-expensive endpoints -------------------------------------
// /api/leap/prove runs a ~1.39M-constraint Groth16 prove on any valid-shaped input - a DoS magnet. For the
// guided pilot: (a) if CHIRAL_ACCESS_TOKEN is set, the heavy POSTs require it (header x-chiral-access or ?t=),
// so ONLY known testers who got the tester link can trigger work; (b) a per-IP token-bucket caps the rate
// regardless. Static files, /api/*/config, /api/health and /api/job stay OPEN so the page always loads and a
// waiting client can still poll. Empty token = open (dev box); set CHIRAL_ACCESS_TOKEN on the VPS.
const ACCESS_TOKEN = process.env.CHIRAL_ACCESS_TOKEN || "";
const RATE_BURST = Number(process.env.CHIRAL_RATE_BURST || 4);        // immediate heavy requests allowed per IP
const RATE_PER_MIN = Number(process.env.CHIRAL_RATE_PER_MIN || 12);   // sustained heavy requests per IP per minute
const rateBuckets = new Map();   // ip -> { tokens, last }
function rateOk(ip) {
  const now = Date.now(), refill = RATE_PER_MIN / 60_000;            // tokens regenerated per ms
  let b = rateBuckets.get(ip);
  if (!b) { b = { tokens: RATE_BURST, last: now }; rateBuckets.set(ip, b); }
  b.tokens = Math.min(RATE_BURST, b.tokens + (now - b.last) * refill); b.last = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1; return true;
}
const clientIp = (req) => (String(req.headers["x-forwarded-for"] || "").split(",")[0].trim()) || req.socket.remoteAddress || "?";
// returns null if allowed, else {code,error} to send. Call FIRST in every heavy endpoint.
function gateHeavy(req, url) {
  if (ACCESS_TOKEN) {
    const tok = req.headers["x-chiral-access"] || url.searchParams.get("t") || "";
    if (tok !== ACCESS_TOKEN) return { code: 401, error: "access token required - open the tester link your operator gave you" };
  }
  if (!rateOk(clientIp(req))) return { code: 429, error: "rate limit - wait a moment and retry" };
  return null;
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number((process.argv.find((a) => a.startsWith("--port=")) || "").split("=")[1] || process.env.PORT || 8799);
const ONCHAIN = path.resolve(HERE, "../relayer/onchain");
const CKB_RPC = process.env.CKB_RPC || "https://testnet.ckb.dev";
// The proven fetch+prove pipeline is python3 + Linux-ELF provers, run via WSL (the distro that built them).
// All inner paths are /mnt-style so they resolve inside WSL; the prebuilt `relay_bind` needs no cargo.
const WSL_CKB = `${REPO_SH}/spike/ckb-to-cardano`;                       // χCKB pipeline dir (WSL mount or native repo)
const ASSET_NAME = process.env.CHI_ASSET_NAME || "chiCKB";              // must match the burn-gated lock's bound name
const DIST = path.join(HERE, "dist");
const readJSON = (p, d) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return d; } };

// Re-reading the config JSON on every request is wasteful (the source files change rarely). Cache the built
// config and rebuild only when one of its source files' mtime/size signature changes.
function memoizeByFiles(files, build) {
  let sig = null, val = null;
  return () => {
    const s = files.map((f) => { try { const st = fs.statSync(f); return st.mtimeMs + ":" + st.size; } catch { return "0"; } }).join("|");
    if (s !== sig) { val = build(); sig = s; }
    return val;
  };
}
// the resident warm prover's unix socket (leap_bound_windowed under CHIRAL_SERVE) - its presence is a cheap
// "is it hot?" probe for /api/health (native Linux/VPS; on the Windows dev box the WSL /tmp socket isn't visible).
const WARM_SOCK = process.env.CHIRAL_WARM_SOCK || process.env.CHIRAL_SERVE || "/tmp/chiral_warm.sock";

// The deployed CKB→Cardano (χCKB) bridge parameters the dApp needs to build the lock tx.
// The χCKB minting policy id (blake2b-224 of the zk_chiral_mint Plutus script) - the policy the leap MINTS
// and the burn-gated lock must release against. Deterministic from groth16/plutus.json; surfaced by
// emit_mint_redeemer.py as policy_id. Overridable for a redeploy.
// the deployed amount-binding zk_chiral_mint policy (vk + ft_name applied) - the policy the leap MINTS and
// the burn-gated lock releases against. Validated live: mint f598926b… minted qty == the locked amount.
// E1: derive the policy id from the live applied script at startup (kills the drift the analysis found across
// server/.env/bridge_lock_unified). Falls back to env, then the post-ceremony policy as a last resort.
const CHI_POLICY_ID = process.env.CHI_POLICY_ID || readJSON(path.join(ONCHAIN, "zk_chiral_mint.applied.json"), {}).policy_id
  || "5b4f5525a155fd86757bb3ba20da6e2ef66bcfb72e8853ef31bcf268";   // canonical-lock forward policy (2026-06-21; verifies any 1-input canonical lock)
const APPLIED_POLICY = `${REPO_SH}/relayer/onchain/zk_chiral_mint.applied.json`;   // build_chiral_policy.py output
// E1: the relay_bind ceremony proving key (CEREMONY_OUT output) - the prove step LOADS it instead of doing a
// per-request seeded setup, so the emitted vk == the deployed (ceremony) policy's vk. Without this the forward
// mint would prove under the forgeable seed_from_u64(7) vk and fail the policy-id check.
const RELAY_CEREMONY_PK = process.env.RELAY_CEREMONY_PK || `${WSL_CKB}/circuit/ceremony_relay_bind/relay_bind_pk.bin`;
// Optional WARM forward prover: if a resident `relay_bind` (CHIRAL_SERVE on this socket) is up, proveLeap uses
// it (~seconds) instead of a cold ~4-min key reload. warm_prove.py exits 1 if the socket is down, so the
// pipeline falls back to the cold prover - no warm daemon required for correctness.
const RELAY_WARM_SOCK = process.env.RELAY_WARM_SOCK || "/tmp/chiral_relay_warm.sock";

function bridgeConfigBuild() {
  const bl = readJSON(path.join(ONCHAIN, "bridge_lock_live.json"), {});
  const bg = readJSON(path.join(ONCHAIN, "burn_gated_live.json"), {});
  const burnGatedReady = !!(bg.burn_gated_code_hash && bg.lckp_type_hash && bg.registry_type_hash);
  return {
    network: "CKB Pudge + Cardano preview (testnet, unaudited)",
    ckbExplorer: "https://testnet.explorer.nervos.org/transaction/",
    cardanoExplorer: "https://preview.cardanoscan.io/transaction/",
    // bridge_lock_v1 receipt: capacity == amount, type = this code (data1, 32 zero args),
    // data = "BRG1"(4) | kind(1=00 CKB) | amount(u64 LE,8) | zeros(8) | recipient(28-byte Cardano payment cred)
    bridgeCodeHash: bl.bridge_code_hash || null,
    bridgeDep: bl.bridge_code_tx ? { txHash: bl.bridge_code_tx, index: 0 } : null,
    magic: "BRG1",
    // CONSERVATION-SAFE: the receipt is locked under burn_gated_unlock_v2 (deployed, code 0x771f7fa3…), whose
    // args bind (lckp_checkpoint, amount, χCKB policy, registry, name) so ONLY a Mithril-certified burn of the
    // minted χCKB releases it - the user cannot reclaim it and keep the wrapped token. The bound amount is the
    // same shannon amount the leap proof binds and the policy mints, so mint == burn == release amount.
    receiptLock: burnGatedReady ? "burn_gated_unlock_v2" : "user",
    burnGated: burnGatedReady ? {
      codeHash: bg.burn_gated_code_hash,                  // data1
      lckpTypeHash: bg.lckp_type_hash,                    // authenticated light-client checkpoint (32)
      registryTypeHash: bg.registry_type_hash,           // nullifier registry (32)
      policyId: CHI_POLICY_ID,                            // χCKB Cardano policy (28) - the burn that releases
      assetNameHex: Buffer.from(ASSET_NAME).toString("hex"),
    } : null,
    // capacity == amount; the burn-gated receipt's occupied bytes (lock args 114 + bridge type 32 + BRG1 data
    // 49) are ~269 CKB, so the smallest lockable amount rises accordingly.
    minLockCKB: 300,
    // Cardano provider for the in-browser mint (Lucid). NOTE: this preview Blockfrost project id is a TESTNET
    // key, intentionally surfaced to the browser for the demo; rotate via BLOCKFROST_PREVIEW. No mainnet value.
    cardano: {
      network: "Preview",
      blockfrostUrl: "https://cardano-preview.blockfrost.io/api/v0",
      blockfrostProjectId: process.env.BLOCKFROST_PREVIEW || "",
      // the applied zk_chiral_mint policy script - needed to BURN χCKB (reverse leg) without a prove step.
      mintScriptHex: readJSON(path.join(ONCHAIN, "zk_chiral_mint.applied.json"), {}).compiledCode || null,
    },
  };
}
const bridgeConfig = memoizeByFiles(
  [path.join(ONCHAIN, "bridge_lock_live.json"), path.join(ONCHAIN, "burn_gated_live.json"), path.join(ONCHAIN, "zk_chiral_mint.applied.json")],
  bridgeConfigBuild,
);

// --- leap proof pipeline (increment 3): lock txid -> witness -> VALUE-BOUND Groth16 proof -> mint redeemer ---
// Self-custody: this only PRODUCES the proof artifacts the user needs to sign the mint themselves. It never
// holds keys or submits. It runs the PROVEN, value-bound pipeline (validated live on the captured lock tx):
//   relayer.py (fetch the user's lock tx)  ->  relay_bind (binds amount+recipient from the receipt body)
//   ->  emit_mint_redeemer.py (redeemer CBOR + qty pinned to the proven amount).
// relay_bind (not relay_prove) is REQUIRED: relay_prove binds only the seal, so the mint amount would be
// free; relay_bind derives commitment = blake2b(amount||recipient||seal) from the authenticated receipt.
const wsl = (script) => new Promise((resolve) => {
  const [cmd, args] = shInvoke(script); const p = spawn(cmd, args);
  let out = "", err = "";
  p.stdout.on("data", (d) => (out += d));
  p.stderr.on("data", (d) => (err += d));
  p.on("error", (e) => resolve({ code: -1, out, err: String(e?.message || e) }));
  p.on("close", (code) => resolve({ code, out, err }));
});
const sh = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;   // single-quote for bash

async function proveLeap({ lockTxid, lockBlock }) {
  if (!/^0x[0-9a-f]{64}$/i.test(lockTxid || "")) throw new Error("lockTxid must be a 0x32-byte hash");
  const bridgeCode = readJSON(path.join(ONCHAIN, "bridge_lock_live.json"), {}).bridge_code_hash;
  if (!bridgeCode) throw new Error("bridge_lock_live.json missing bridge_code_hash (deploy the bridge first)");
  // PER-REQUEST temp dir - concurrent proves must not share /tmp files (that's the #1 multi-user corruption).
  const tmp = `/tmp/chiral-${randomUUID()}`;
  const wit = `${tmp}/wit.json`, red = `${tmp}/redeemer.json`, perlock = `${tmp}/perlock.json`;
  const tgt = `TARGET_TX=${sh(lockTxid)}` + (lockBlock ? ` TARGET_BLOCK=${sh(String(lockBlock))}` : "");

  // one WSL round-trip, no nested quotes:
  //   gen_bridge_body.py  rebuild THIS lock's receipt body+offsets from chain (works for any user lock)
  //   relayer.py          fetch the lock tx's header+CBMT witness
  //   relay_bind          value-bound Groth16 (binds amount+recipient from the receipt body)
  //   emit                redeemer CBOR + qty auto-pinned to the bound amount; prints the mint blob to stdout
  // the per-request temp dir is created up front and removed regardless of outcome (RC preserved).
  const pipeline = [
    `cd ${sh(WSL_CKB)}`,
    `python3 relayer/gen_bridge_body.py ${sh(lockTxid)} ${sh(bridgeCode)} --rpc ${sh(CKB_RPC)} --out ${perlock}`,
    `${tgt} python3 relayer/relayer.py ${sh(CKB_RPC)} ${wit}`,
    // WARM-first: a resident relay_bind (RELAY_WARM_SOCK) proves in ~seconds; warm_prove.py writes the redeemer
    // to ${red} and exits 0, or exits 1 (socket down/error) -> `||` falls back to the cold key-reloading prover.
    // warm_prove's status line is sent to stderr (>&2) so only emit_mint_redeemer's blob lands on stdout.
    `( python3 relayer/warm_prove.py prove ${wit} ${perlock} ${red} --sock ${sh(RELAY_WARM_SOCK)} >&2 || CEREMONY_PK=${sh(RELAY_CEREMONY_PK)} circuit/prover/target/release/relay_bind ${wit} ${perlock} > ${red} )`,
    `python3 relayer/emit_mint_redeemer.py --proof ${red} --applied ${sh(APPLIED_POLICY)}`,
  ].join(" && ");
  const r = await wsl(`mkdir -p ${tmp} && (${pipeline}); RC=$?; rm -rf ${tmp}; exit $RC`);
  if (r.code !== 0) throw new Error("fetch/prove/emit (gen_bridge_body + relayer.py + relay_bind + emit) failed: " + (r.err || r.out).slice(-800));

  // { redeemer_cbor, mint_script_hex, policy_id, asset_name_hex, unit, qty, commitment, amount, recipient, seal }
  const j = r.out.indexOf("{");
  if (j < 0) throw new Error("no mint params on stdout: " + (r.err || r.out).slice(-400));
  return JSON.parse(r.out.slice(j));
}

// --- reverse leg (CKB release): release the burn-gated receipt against a Mithril-certified χCKB burn ---
// Keyless: no signature authorizes the receipt spend - only the certified burn + the replay-once nullifier.
// Push-button: release_orchestrate.mjs drives the whole proven pipeline (cert gate -> advance the AVK
// light-client to the burn's epoch if stale -> publish the LCKP at the burn root -> insert the replay-once
// nullifier -> keyless bg_release to the tester's CKB address). If the burn isn't Mithril-certified yet it
// returns {certified:false} so the dApp can retry. Runs on this host (the funded relayer key + WSL prover).
const ORCH = path.resolve(HERE, "../relayer/onchain/release_orchestrate.mjs");
const ORCH_CWD = path.resolve(HERE, "../relayer/onchain");
async function releaseLeap({ burnTxid, receiptTxid, ckbRecipient }) {
  if (!/^[0-9a-f]{64}$/i.test(burnTxid || "")) throw new Error("burnTxid must be a 64-hex Cardano tx hash");
  if (!/^0x[0-9a-f]{64}$/i.test(receiptTxid || "")) throw new Error("receiptTxid (your lock tx) required");
  if (!ckbRecipient) throw new Error("ckbRecipient (your CKB address) required");
  const r = await new Promise((resolve) => {
    const p = spawn("node", [ORCH, burnTxid, receiptTxid, ckbRecipient], { cwd: ORCH_CWD });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));      // the .mjs steps log progress to stderr
    p.on("error", (e) => resolve({ code: -1, out, err: String(e?.message || e) }));
    p.on("close", (code) => resolve({ code, out, err }));
  });
  const j = r.out.lastIndexOf("{") >= 0 ? JSON.parse(r.out.slice(r.out.lastIndexOf("{"))) : null;
  if (!j) throw new Error("release orchestrator produced no result: " + (r.err || r.out).slice(-700));
  if (j.error) throw new Error(j.error);
  if (j.certified === false) {
    return { certified: false, status: j.status || "wait-certification", burnTxid,
      message: "Mithril has not certified the burn yet - retry once the aggregator certifies a tx-set covering it." };
  }
  return { certified: true, released: true, ...j };   // { releaseTxid, releasedCKB, recipient }
}

// --- native ADA → CKB leg (χADA): the symmetric MIRROR of the χCKB leg. The user locks real preview ADA at the
// deployed `ada_escrow` (signing it themselves), and the relayer - once Mithril certifies that lock - mints χADA
// (a real xUDT) to the USER's CKB wallet. Self-custody holds: the relayer never holds the user's ADA (their own
// signature locks it) and CANNOT redirect the χADA - the deployed xada_mint_owner lock enforces in-VM that every
// minted output's lock hash == the escrow datum's ckb_recipient and that minted == locked lovelace.
// NOTE: the escrow's RELEASE path (χADA → ADA return) uses a PLACEHOLDER vk (it is drainable) → cap locks at 5 ADA.
const XADA_ORCH = path.join(ONCHAIN, "xada_mint_orchestrate.mjs");
const XADA_ESCROW = path.resolve(HERE, "../deployed/cardano/preview/xada-escrow.json");
function xadaConfigBuild() {
  const owner = readJSON(path.join(ONCHAIN, "xada_owner_deploy.json"), {});
  const esc = readJSON(XADA_ESCROW, {});
  const ready = !!(owner.xadaTokenId && (esc.escrow_address || owner.escrowAddr));
  return {
    ready,
    network: "Cardano preview → CKB Pudge (testnet, unaudited)",
    cardanoExplorer: "https://preview.cardanoscan.io/transaction/",
    ckbExplorer: "https://testnet.explorer.nervos.org/transaction/",
    escrowAddress: esc.escrow_address || null,        // bech32 the user pays ADA to (stable script address)
    escrowAddrHex: owner.escrowAddr || esc.escrow_addr_hex || null,
    tokenId: owner.xadaTokenId || null,               // the χADA xUDT token id on CKB
    token: { name: "Chiral ADA", symbol: "xADA", decimals: 6 },
    minAda: 2, demoMaxAda: 5,                          // placeholder return-vk → drainable → cap at 5 ADA
    note: "Lock ≤5 ADA; the relayer mints χADA xUDT to your CKB wallet once Mithril certifies the lock. " +
      "The χADA → ADA return (burn → release) is P5 - not yet live (the escrow return path is a placeholder vk).",
  };
}
const xadaConfig = memoizeByFiles([path.join(ONCHAIN, "xada_owner_deploy.json"), XADA_ESCROW], xadaConfigBuild);

// Drive the cert-gated χADA mint to the user's CKB lock. Returns {certified:false,...} while Mithril is still
// certifying (the dApp retries), else {minted, mintTxid, tokenId, amount, recipient, xadaCell}. Relayer-driven
// on this host (funded CKB key + Windows produce_witness); serialized (mutates the registry singleton + owner cell).
async function mintXada({ escrowTxid, amountLovelace, recipientLock }) {
  if (!/^[0-9a-f]{64}$/i.test(strip(escrowTxid || ""))) throw new Error("escrowTxid must be a 64-hex Cardano tx hash");
  if (!(Number(amountLovelace) > 0)) throw new Error("amountLovelace must be > 0");
  if (!recipientLock?.codeHash) throw new Error("recipientLock (your connected CKB lock script) required");
  const r = await new Promise((resolve) => {
    const p = spawn("node", [XADA_ORCH, strip(escrowTxid), String(Math.round(Number(amountLovelace))), JSON.stringify(recipientLock)], { cwd: ONCHAIN });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));      // orchestrator logs progress to stderr
    p.on("error", (e) => resolve({ code: -1, out, err: String(e?.message || e) }));
    p.on("close", (code) => resolve({ code, out, err }));
  });
  const j = r.out.lastIndexOf("{") >= 0 ? JSON.parse(r.out.slice(r.out.lastIndexOf("{"))) : null;
  if (!j) throw new Error("χADA mint produced no result: " + (r.err || r.out).slice(-700));
  if (j.error) throw new Error(j.error);
  if (j.certified === false) {
    return { certified: false, status: j.status || "wait-certification", escrowTx: j.escrowTx,
      message: "Mithril has not certified your ADA lock yet - the aggregator certifies on a schedule. Retry shortly." };
  }
  return j;   // { certified:true, minted:true, mintTxid, tokenId, amount, recipient, xadaCell }
}

// --- χADA → ADA RETURN: the proven reverse of the χADA leg. Given a confirmed CKB χADA-burn tx, drive the
// full return: capture → re-anchor the CKB-header checkpoint to cover the burn → prove the burn (REUSING the
// burn proving key, fast) → lock the return escrow → ada_escrow.Release verifies the Groth16 proof ON-CHAIN →
// pay the ADA to the burn's bound recipient. Amount + recipient are read FROM the burn (the proof binds them).
// Heavy (re-anchors the checkpoint each call) + serialized. Runs on this host (funded relayer key + WSL prover).
const XADA_RETURN_ORCH = path.join(ONCHAIN, "xada_burn_orchestrate.mjs");
async function returnXada({ burnTxid }) {
  if (!/^(0x)?[0-9a-f]{64}$/i.test(burnTxid || "")) throw new Error("burnTxid (your CKB χADA-burn tx) required");
  const r = await new Promise((resolve) => {
    const p = spawn("node", [XADA_RETURN_ORCH, strip(burnTxid)], { cwd: ONCHAIN });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));      // orchestrator logs progress to stderr
    p.on("error", (e) => resolve({ code: -1, out, err: String(e?.message || e) }));
    p.on("close", (code) => resolve({ code, out, err }));
  });
  const j = r.out.lastIndexOf("{") >= 0 ? JSON.parse(r.out.slice(r.out.lastIndexOf("{"))) : null;
  if (!j) throw new Error("χADA return produced no result: " + (r.err || r.out).slice(-700));
  if (j.error) throw new Error(j.error);
  return j;   // { ok:true, released:true, releaseTxid, releasedAda, recipient, burnTxid }
}

// --- one-click χADA burn (self-serve): owner-mode burn is a co-signed tx - the relayer supplies the owner
// authority cell + funding, the user signs ONLY their χADA input in the browser. Two-call: BUILD the unsigned tx
// (relayer adds owner+funding) → the browser signs the χADA input → SUBMIT (relayer signs funding + sends).
const XADA_BURN_BUILD = path.join(ONCHAIN, "xada_burn_build.mjs");
const XADA_BURN_SUBMIT = path.join(ONCHAIN, "xada_burn_submit.mjs");
function spawnJson(script, args) {
  return new Promise((resolve) => {
    const p = spawn("node", [script, ...args], { cwd: ONCHAIN });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", (e) => resolve({ out, err: String(e?.message || e) }));
    p.on("close", () => resolve({ out, err }));
  });
}
async function buildXadaBurn({ recipientLock, amount, cardanoRecipient }) {
  if (!recipientLock?.codeHash) throw new Error("recipientLock (your CKB lock) required");
  if (!(Number(amount) > 0)) throw new Error("amount (χADA to burn) required");
  if (!/^(0x)?[0-9a-f]{56}$/i.test(cardanoRecipient || "")) throw new Error("cardanoRecipient must be a 28-byte payment credential");
  const r = await spawnJson(XADA_BURN_BUILD, [JSON.stringify(recipientLock), String(Math.round(Number(amount))), strip(cardanoRecipient)]);
  const j = r.out.lastIndexOf("{") >= 0 ? JSON.parse(r.out.slice(r.out.lastIndexOf("{"))) : null;
  if (!j) throw new Error("burn build produced no result: " + (r.err || r.out).slice(-500));
  if (j.error) throw new Error(j.error);
  return j;   // { txHex, burnAmount, recipient, chadaInputs }
}
async function submitXadaBurn({ signedTxHex }) {
  if (!/^0x[0-9a-f]+$/i.test(signedTxHex || "")) throw new Error("signedTxHex (user-signed burn tx) required");
  const r = await spawnJson(XADA_BURN_SUBMIT, [signedTxHex]);
  const j = r.out.lastIndexOf("{") >= 0 ? JSON.parse(r.out.slice(r.out.lastIndexOf("{"))) : null;
  if (!j) throw new Error("burn submit produced no result: " + (r.err || r.out).slice(-500));
  if (j.error) throw new Error(j.error);
  return j;   // { burnTxid, receiptCell }
}

// Readiness for hosting: the prove step needs the WSL prover (relay_bind + python). Check the config is
// wired AND the WSL pipeline is reachable, so the host can confirm the daemon can serve a leap before
// pointing testers at it. The forward leap (lock -> prove -> mint) works when ready === true.
// Cache the (forking) prover-reachability probe for ~30s so a polling /api/health loop doesn't spawn
// WSL+python on every hit. The probe rarely flips; 30s staleness is fine for an operator readiness signal.
let proverProbe = { at: 0, ok: false, warm: false, warmReturn: false };
const PROBE_TTL_MS = 30_000;
// One cached WSL round-trip: is the prover toolchain reachable, AND are the resident warm sockets serving?
// We probe the sockets THROUGH WSL (not fs.existsSync) because on the Windows dev box the dapp runs on Windows
// while the warm prover + its /tmp socket live in WSL - Windows can't stat them, but the actual prove (which
// runs warm_prove.py INSIDE WSL) reaches them fine. On a native-Linux VPS the same `test -S` works directly.
async function proverReachable() {
  const now = Date.now();
  if (proverProbe.at && now - proverProbe.at < PROBE_TTL_MS) return proverProbe;
  const r = await wsl(`test -x ${sh(WSL_CKB + "/circuit/prover/target/release/relay_bind")} && python3 -c 'import pycardano' && echo TOOLS; ` +
    `test -S ${sh(RELAY_WARM_SOCK)} && echo WARMFWD; test -S ${sh(WARM_SOCK)} && echo WARMRET; true`);
  proverProbe = { at: now, ok: r.out.includes("TOOLS"), warm: r.out.includes("WARMFWD"), warmReturn: r.out.includes("WARMRET") };
  return proverProbe;
}
async function health() {
  const cfg = bridgeConfig();
  const configOk = !!(cfg.bridgeCodeHash && cfg.burnGated?.policyId && cfg.cardano?.mintScriptHex);
  const probe = await proverReachable();
  const proverOk = probe.ok;
  const warm = probe.warm;             // FORWARD warm prover (what /api/leap/prove uses) - the banner's "warm ✓"
  const ready = configOk && proverOk;
  return {
    ready,
    config: configOk ? "ok" : "missing bridge/burn-gated/cardano config",
    prover: proverOk ? `ok (WSL ${WSL_DISTRO})` : `unreachable (need WSL ${WSL_DISTRO} with relay_bind + pycardano)`,
    warm,                       // FORWARD warm prover up -> ~10s proofs instead of a ~4min cold key reload
    warmReturn: probe.warmReturn,   // RETURN warm prover (χADA return) up
    load: jobs.load(PROVE_CONCURRENCY),
    note: ready ? "experiment: proves are queued at the cap; releases run one-at-a-time"
      : "not ready to prove - fix the prover/config before onboarding testers",
  };
}

const readBody = (req) => new Promise((resolve) => {
  let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => resolve(b));
});

const send = (res, code, body, type = "application/json") => {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "cache-control": "no-store" });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body)); // raw bytes for served files
};

const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".wasm": "application/wasm" };

// Static-asset serving: gzip + correct cache headers. The SPA is ~9.3MB uncompressed; gzipping the
// text+wasm bytes and letting hashed assets cache "immutable" cuts first load to ~2MB and repeat loads
// to ~0. Compress each file ONCE (cache keyed by path+mtime+size) so we don't re-gzip on every request.
const COMPRESSIBLE = new Set([".html", ".js", ".css", ".json", ".svg", ".wasm", ".map"]);  // skip png/ico (already compressed)
const fileCache = new Map();
function loadFile(abs) {
  const st = fs.statSync(abs);                       // throws if the file vanished mid-rebuild -> caught by the caller
  const hit = fileCache.get(abs);
  if (hit && hit.mtimeMs === st.mtimeMs && hit.size === st.size) return hit;
  const raw = fs.readFileSync(abs);
  const ext = path.extname(abs);
  const e = {
    raw, mtimeMs: st.mtimeMs, size: st.size,
    type: MIME[ext] || "application/octet-stream",
    gz: COMPRESSIBLE.has(ext) ? zlib.gzipSync(raw, { level: 6 }) : null,
  };
  fileCache.set(abs, e);
  return e;
}
function sendFile(req, res, abs, { index = false } = {}) {
  const e = loadFile(abs);
  // Vite emits content-hashed assets/* -> safe to cache forever; index.html (and the SPA fallback) must revalidate.
  const cache = index ? "no-cache"
    : abs.includes(`${path.sep}assets${path.sep}`) ? "public, max-age=31536000, immutable"
    : "public, max-age=3600";
  const useGz = !!e.gz && /\bgzip\b/.test(req.headers["accept-encoding"] || "");
  const headers = { "content-type": e.type, "cache-control": cache, "access-control-allow-origin": "*", vary: "Accept-Encoding" };
  if (useGz) headers["content-encoding"] = "gzip";
  res.writeHead(200, headers);
  res.end(useGz ? e.gz : e.raw);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "OPTIONS") return send(res, 204, "");
  // readiness: is this host actually able to serve a leap? (config + the WSL prover the prove step needs)
  if (url.pathname === "/api/health") {
    return health().then((h) => send(res, h.ready ? 200 : 503, h));
  }
  if (url.pathname === "/api/bridge/config") return send(res, 200, bridgeConfig());
  // poll a heavy job's state without re-triggering it: GET /api/job?key=<kind>:<txid-no-0x>
  // (e.g. prove:abcd…, release:dead…). The client already knows its txid, so it can recover after a dropped
  // socket. 404 => no live/recent job for that key (safe to (re)submit). Returns { state, position, result? }.
  if (url.pathname === "/api/job") {
    const key = url.searchParams.get("key");
    if (!key) return send(res, 400, { error: "key required, e.g. prove:<lockTxid-no-0x>" });
    const j = jobs.get(key);
    return j ? send(res, 200, jobs.view(j)) : send(res, 404, { state: "none", key });
  }
  // increment 3: prove a confirmed lock tx -> mint redeemer the user signs in their own wallet.
  // Deduped per lock tx: a refresh/double-submit attaches to the in-flight prove instead of starting a second.
  if (url.pathname === "/api/leap/prove" && req.method === "POST") {
    const g = gateHeavy(req, url); if (g) return send(res, g.code, { error: g.error });
    return readBody(req).then(async (raw) => {
      let body; try { body = JSON.parse(raw || "{}"); } catch { return send(res, 400, { error: "bad JSON" }); }
      const job = jobs.run("prove", strip(body.lockTxid), proveGate, () => proveLeap(body));   // queued at cap; no shared /tmp
      try { return send(res, 200, await job.promise); }
      catch (e) { return send(res, 502, { error: String(e?.message || e) }); }
    });
  }
  // reverse leg: release the locked CKB against a Mithril-certified χCKB burn (keyless).
  // Serialized AND deduped per burn tx: mutates shared singletons (light-client, registry) + the one key,
  // so a retry must NOT spawn a second release racing the first.
  if (url.pathname === "/api/leap/release" && req.method === "POST") {
    const g = gateHeavy(req, url); if (g) return send(res, g.code, { error: g.error });
    return readBody(req).then(async (raw) => {
      let body; try { body = JSON.parse(raw || "{}"); } catch { return send(res, 400, { error: "bad JSON" }); }
      const job = jobs.run("release", strip(body.burnTxid), releaseGate, () => releaseLeap(body));
      try { return send(res, 200, await job.promise); }
      catch (e) { return send(res, 502, { error: String(e?.message || e) }); }
    });
  }
  // native ADA → CKB leg: the bridge config the browser needs to build the ADA escrow-lock tx.
  if (url.pathname === "/api/xada/config") return send(res, 200, xadaConfig());
  // native ADA → CKB leg: mint χADA to the user's CKB wallet against their Mithril-certified ADA lock.
  if (url.pathname === "/api/xada/mint" && req.method === "POST") {
    const g = gateHeavy(req, url); if (g) return send(res, g.code, { error: g.error });
    return readBody(req).then(async (raw) => {
      let body; try { body = JSON.parse(raw || "{}"); } catch { return send(res, 400, { error: "bad JSON" }); }
      // serialized + deduped per escrow tx: the mint spends+recreates the shared registry singleton + owner cell.
      // (A not-yet-certified result isn't cached, so the dApp's cert-retry loop still re-runs until Mithril is ready.)
      const job = jobs.run("mint", strip(body.escrowTxid), xadaGate, () => mintXada(body));
      try { return send(res, 200, await job.promise); }
      catch (e) { return send(res, 502, { error: String(e?.message || e) }); }
    });
  }
  // native CKB → Cardano return: release ADA against a confirmed CKB χADA burn (on-chain Groth16 verify).
  if (url.pathname === "/api/xada/return" && req.method === "POST") {
    const g = gateHeavy(req, url); if (g) return send(res, g.code, { error: g.error });
    return readBody(req).then(async (raw) => {
      let body; try { body = JSON.parse(raw || "{}"); } catch { return send(res, 400, { error: "bad JSON" }); }
      // serialized + deduped per burn tx: the return re-anchors the shared checkpoint + spends the seal registry.
      const job = jobs.run("return", strip(body.burnTxid), xadaReturnGate, () => returnXada(body));
      try { return send(res, 200, await job.promise); }
      catch (e) { return send(res, 502, { error: String(e?.message || e) }); }
    });
  }
  // one-click χADA burn (self-serve), step 1: build the unsigned co-signed burn tx (relayer adds owner+funding).
  if (url.pathname === "/api/xada/burn/build" && req.method === "POST") {
    const g = gateHeavy(req, url); if (g) return send(res, g.code, { error: g.error });
    return readBody(req).then(async (raw) => {
      let body; try { body = JSON.parse(raw || "{}"); } catch { return send(res, 400, { error: "bad JSON" }); }
      try { return send(res, 200, await xadaReturnGate(() => buildXadaBurn(body))); }
      catch (e) { return send(res, 502, { error: String(e?.message || e) }); }
    });
  }
  // one-click χADA burn, step 2: the user signed their χADA input in the browser - relayer signs funding + submits.
  if (url.pathname === "/api/xada/burn/submit" && req.method === "POST") {
    const g = gateHeavy(req, url); if (g) return send(res, g.code, { error: g.error });
    return readBody(req).then(async (raw) => {
      let body; try { body = JSON.parse(raw || "{}"); } catch { return send(res, 400, { error: "bad JSON" }); }
      try { return send(res, 200, await xadaReturnGate(() => submitXadaBurn(body))); }
      catch (e) { return send(res, 502, { error: String(e?.message || e) }); }
    });
  }
  // serve the built dApp (prod). Wrapped in try/catch: a rebuild momentarily deletes dist/, and an unguarded
  // readFileSync ENOENT during that window would otherwise crash the whole daemon.
  try {
    const f = url.pathname === "/" ? "/index.html" : url.pathname;
    const abs = path.join(DIST, path.normalize(f));
    if (abs.startsWith(DIST) && fs.existsSync(abs) && fs.statSync(abs).isFile()) {
      return sendFile(req, res, abs, { index: path.basename(abs) === "index.html" });
    }
    const index = path.join(DIST, "index.html");
    if (fs.existsSync(index)) return sendFile(req, res, index, { index: true }); // SPA fallback
    return send(res, 503, { error: "dApp building or not built - retry in a moment (or run `npm run dev`)" });
  } catch (e) {
    return send(res, 503, { error: "serve transient error: " + String(e?.message || e) });
  }
});
// never let one bad request or a transient fs/network error take down the experiment for everyone.
process.on("uncaughtException", (e) => console.error("[daemon] uncaughtException:", e?.message || e));
process.on("unhandledRejection", (e) => console.error("[daemon] unhandledRejection:", e?.message || e));
server.listen(PORT, () => console.log(`Chiral dApp backend: http://localhost:${PORT}  (config + proof API)`));
