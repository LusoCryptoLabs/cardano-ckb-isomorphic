// demo_server.mjs - operator demo UI for the Chiral leap (both ways).
//
// OPERATOR demo: the relayer's own keys (the existing leap_orchestrator.mjs) do the work; this server
// observes it (Phase 1, read-only dashboard) AND drives it (Phase 2, the job runner below). No wallets, no
// user self-custody. The leap moves the bound cell on-chain (CkbOwned <-> CardanoBound) using the operator's
// CKB + Cardano keys and costs real testnet fees + minutes (Mithril cert wait). Testnet, unaudited.
//
//   node demo_server.mjs [--port=8788]
//
// Endpoints:
//   GET  /                  -> the dashboard (demo_ui.html)
//   GET  /api/config        -> deployed code hashes + explorer bases + current side
//   GET  /api/leap/status   -> live both-chain snapshot (cached; bg-refreshed every 30s)
//   GET  /api/leap/history  -> recent legs (leap_log.jsonl), newest first
//   POST /api/leap/leg      {recipient?,verify?} -> start the ONE next leg; -> {jobId}
//   POST /api/leap/toggle   {recipient?,verify?} -> start a full round-trip; -> {jobId}
//   GET  /api/leap/jobs      -> the current/last job (summary)
//   GET  /api/leap/jobs/:id  -> a job's live progress (phases, legs, tx links, log tail)
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number((process.argv.find((a) => a.startsWith("--port=")) || "").split("=")[1] || process.env.PORT || 8788);
const ORCH = path.join(HERE, "leap_orchestrator.mjs");
const LOG = path.join(HERE, "leap_log.jsonl");
const STATUS_TTL_MS = 30000;
const readJSON = (p, d) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return d; } };

// ---------- live status: cached + background-refreshed ----------
let statusCache = { ok: false, error: "warming up…" };
let refreshAt = 0, refreshing = false;
function spawnStatus() {
  return new Promise((resolve) => {
    const ch = spawn(process.execPath, [ORCH, "status", "--json"], { cwd: HERE });
    let out = "", err = "";
    ch.stdout.on("data", (d) => (out += d));
    ch.stderr.on("data", (d) => (err += d));
    ch.on("close", () => {
      const line = out.trim().split("\n").filter(Boolean).pop();
      try { resolve({ ok: true, ...JSON.parse(line) }); }
      catch (e) { resolve({ ok: false, error: (err || e.message || "status failed").slice(0, 400) }); }
    });
    ch.on("error", (e) => resolve({ ok: false, error: String(e.message) }));
  });
}
async function refreshStatus() {
  if (refreshing) return;
  refreshing = true;
  try { statusCache = await spawnStatus(); refreshAt = Date.now(); }
  finally { refreshing = false; }
}

const history = () => { try { return fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)).reverse(); } catch { return []; } };
const lastLog = () => history()[0] || null;

function config() {
  const dep = readJSON(path.join(HERE, "deployed.json"), {});
  const reg = readJSON(path.join(HERE, "v2_registry.json"), {});
  const st = readJSON(path.join(HERE, "boundasset_v2_state.json"), {});
  return {
    network: "CKB Pudge + Cardano preview (testnet, unaudited demo)",
    cv_deploy_v2: dep.cv_deploy_v2?.codeHash || null,
    cv_advance: dep.cv_advance?.codeHash || null,
    bound_v2_tx: reg.boundCode?.txHash || null,
    registry_tx: reg.registryCode?.txHash || null,
    ckbExplorer: "https://testnet.explorer.nervos.org/transaction/",
    cardanoExplorer: "https://preview.cardanoscan.io/transaction/",
    side: st.bound ? "CkbOwned" : st.cardanoBound ? "CardanoBound" : "EMPTY",
  };
}

// ---------- Phase 2: the leap job runner ----------
// One job at a time (concurrent legs would conflict on-chain). A job spawns leap_orchestrator.mjs leg|toggle,
// parses its [INFO]/[WARN]/[ERROR] log lines into phases + tx links, and reads the full per-leg record from
// leap_log.jsonl as each leg completes.
const jobs = new Map();
let activeJob = null, jobSeq = 0;
const PHASES = ["funding", "cardano", "cert", "ckb", "done"];

function classify(msg) {
  if (/^=== leg (S\d)/.test(msg)) return { phase: "funding", leg: msg.match(/=== leg (S\d)/)[1] };
  if (/funding (OK|low)/i.test(msg)) return { phase: "funding" };
  if (/^Cardano S\d: running/.test(msg)) return { phase: "cardano" };
  if (/^Cardano S\d submitted:/.test(msg)) return { phase: "cardano", tx: { chain: "cardano", hash: msg.split("submitted:")[1].trim() } };
  if (/awaiting Mithril cert|certified in/.test(msg)) return { phase: "cert" };
  if (/ckb-debugger|CKB S\d: (dump|sending)/.test(msg)) return { phase: "ckb" };
  if (/^leg S\d DONE/.test(msg)) return { phase: "done", legDone: true };
  return {};
}

function startJob(kind, recipient, verify) {
  const id = `${++jobSeq}-${Date.now()}`;
  const args = [ORCH, kind];
  if (recipient) args.push(recipient);
  if (verify) args.push("--verify");
  const baseN = history().length;
  const job = { id, kind, recipient: recipient || null, state: "running", phase: "funding", currentLeg: null,
                startedAt: new Date().toISOString().slice(0, 19).replace("T", " "), endedAt: null, error: null,
                legs: [], pendingCardanoTx: null, log: [], _baseN: baseN };
  jobs.set(id, job);
  activeJob = id;
  const ch = spawn(process.execPath, args, { cwd: HERE });
  let buf = "";
  const onData = (d) => {
    buf += d.toString();
    const lines = buf.split("\n"); buf = lines.pop();
    for (const raw of lines) {
      const m = raw.match(/\[(INFO|WARN|ERROR)\]\s+(.*)$/);
      if (!m) continue;
      const level = m[1], msg = m[2].trim();
      job.log.push({ level, msg });
      if (job.log.length > 60) job.log.shift();
      const c = classify(msg);
      if (c.leg) job.currentLeg = c.leg;
      if (c.phase) job.phase = c.phase;
      if (c.tx) job.pendingCardanoTx = c.tx.hash;   // show the Cardano tx live, during the cert wait
      if (level === "ERROR") job.error = msg;
      if (c.legDone) {
        // a leg just finished; pull its full record (cardano_tx, ckb_tx, cert_s) from leap_log.jsonl
        const h = history();
        const fresh = h.slice(0, Math.max(0, h.length - job._baseN));
        job.legs = fresh.reverse().map((e) => ({ leg: e.leg, cardano_tx: e.cardano_tx, ckb_tx: e.ckb_tx, cert_s: e.cert_s }));
        job.pendingCardanoTx = null;
      }
    }
  };
  ch.stdout.on("data", onData);
  ch.stderr.on("data", onData);
  ch.on("close", (code) => {
    const h = history();
    job.legs = h.slice(0, Math.max(0, h.length - job._baseN)).reverse().map((e) => ({ leg: e.leg, cardano_tx: e.cardano_tx, ckb_tx: e.ckb_tx, cert_s: e.cert_s }));
    job.state = code === 0 && !job.error ? "done" : "failed";
    job.phase = job.state === "done" ? "done" : job.phase;
    job.endedAt = new Date().toISOString().slice(0, 19).replace("T", " ");
    if (activeJob === id) activeJob = null;
    refreshStatus(); // reflect the new on-chain state
  });
  ch.on("error", (e) => { job.state = "failed"; job.error = String(e.message); job.endedAt = new Date().toISOString().slice(0, 19).replace("T", " "); if (activeJob === id) activeJob = null; });
  return job;
}

function jobView(job) {
  if (!job) return null;
  return { id: job.id, kind: job.kind, state: job.state, phase: job.phase, phases: PHASES, currentLeg: job.currentLeg,
           startedAt: job.startedAt, endedAt: job.endedAt, error: job.error, legs: job.legs, pendingCardanoTx: job.pendingCardanoTx, log: job.log.slice(-18) };
}

// ---------- http ----------
const send = (res, code, body, type = "application/json") => {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "access-control-allow-methods": "GET,POST,OPTIONS", "cache-control": "no-store" });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
};
const readBody = (req) => new Promise((resolve) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } }); });

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;
  try {
    if (req.method === "OPTIONS") return send(res, 204, "");
    if (p === "/" || p === "/index.html") return send(res, 200, fs.readFileSync(path.join(HERE, "demo_ui.html"), "utf8"), "text/html; charset=utf-8");
    if (p === "/api/config") return send(res, 200, config());
    if (p === "/api/leap/status") return send(res, 200, { ...statusCache, cacheAgeS: refreshAt ? Math.round((Date.now() - refreshAt) / 1000) : null, jobActive: !!activeJob });
    if (p === "/api/leap/history") return send(res, 200, history());
    if (p === "/api/leap/jobs") return send(res, 200, jobView(jobs.get(activeJob) || jobs.get([...jobs.keys()].pop())) || { state: "none" });
    if (p.startsWith("/api/leap/jobs/")) { const j = jobs.get(p.split("/").pop()); return j ? send(res, 200, jobView(j)) : send(res, 404, { error: "no such job" }); }
    if ((p === "/api/leap/leg" || p === "/api/leap/toggle") && req.method === "POST") {
      if (activeJob) return send(res, 409, { error: "a leap is already running", jobId: activeJob });
      const body = await readBody(req);
      const kind = p.endsWith("toggle") ? "toggle" : "leg";
      const job = startJob(kind, (body.recipient || "").replace(/^0x/, "") || undefined, !!body.verify);
      return send(res, 202, { jobId: job.id, kind });
    }
    return send(res, 404, { error: "not found" });
  } catch (e) {
    return send(res, 500, { error: String(e.message || e).slice(0, 300) });
  }
});

refreshStatus();
setInterval(refreshStatus, STATUS_TTL_MS);
server.listen(PORT, () => console.log(`Chiral leap demo: http://localhost:${PORT}  (Phase 2: drives live legs)`));
