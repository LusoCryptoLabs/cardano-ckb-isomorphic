// demo_server.mjs — Phase 1 of the operator demo UI for the Chiral leap (both ways).
//
// A tiny stdlib node HTTP server that serves the dashboard + the READ-ONLY leap state. This is the
// OPERATOR demo: the relayer's own keys (the existing leap_orchestrator.mjs) do the work; this server only
// OBSERVES it (no signing, no wallets, no value moved here). Phase 1 = read-only dashboard; the leap/toggle
// ACTIONS land in Phase 2 (the async job runner).
//
//   node demo_server.mjs [--port=8788]
//
// Endpoints:
//   GET /                  -> the dashboard (demo_ui.html)
//   GET /api/config        -> deployed code hashes + explorer bases + current side (from the state files)
//   GET /api/leap/status   -> live both-chain snapshot (CACHED; refreshed in the background every 30s by
//                             running `leap_orchestrator.mjs status --json`, which is ~30s of chain queries)
//   GET /api/leap/history  -> recent legs (reads leap_log.jsonl), newest first
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

// --- live status, cached + background-refreshed (one orchestrator spawn at a time) ---
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

const send = (res, code, body, type = "application/json") => {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "cache-control": "no-store" });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  try {
    if (url.pathname === "/" || url.pathname === "/index.html") {
      return send(res, 200, fs.readFileSync(path.join(HERE, "demo_ui.html"), "utf8"), "text/html; charset=utf-8");
    }
    if (url.pathname === "/api/config") return send(res, 200, config());
    if (url.pathname === "/api/leap/status") {
      return send(res, 200, { ...statusCache, cacheAgeS: refreshAt ? Math.round((Date.now() - refreshAt) / 1000) : null });
    }
    if (url.pathname === "/api/leap/history") return send(res, 200, history());
    return send(res, 404, { error: "not found" });
  } catch (e) {
    return send(res, 500, { error: String(e.message || e).slice(0, 300) });
  }
});

refreshStatus();                          // warm the cache on startup
setInterval(refreshStatus, STATUS_TTL_MS); // and keep it fresh in the background
server.listen(PORT, () => console.log(`Chiral leap demo (read-only, Phase 1): http://localhost:${PORT}`));
