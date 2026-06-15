// server.mjs — the dApp backend (the relayer's proof/witness service for the self-custody bridge).
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
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number((process.argv.find((a) => a.startsWith("--port=")) || "").split("=")[1] || process.env.PORT || 8799);
const ONCHAIN = path.resolve(HERE, "../relayer/onchain");
const DIST = path.join(HERE, "dist");
const readJSON = (p, d) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return d; } };

// The deployed CKB→Cardano (χCKB) bridge parameters the dApp needs to build the lock tx.
function bridgeConfig() {
  const bl = readJSON(path.join(ONCHAIN, "bridge_lock_live.json"), {});
  return {
    network: "CKB Pudge + Cardano preview (testnet, unaudited)",
    ckbExplorer: "https://testnet.explorer.nervos.org/transaction/",
    cardanoExplorer: "https://preview.cardanoscan.io/transaction/",
    // bridge_lock_v1 receipt: capacity == amount, type = this code (data1, 32 zero args),
    // data = "BRG1"(4) | kind(1=00 CKB) | amount(u64 LE,8) | zeros(8) | recipient(28-byte Cardano payment cred)
    bridgeCodeHash: bl.bridge_code_hash || null,
    bridgeDep: bl.bridge_code_tx ? { txHash: bl.bridge_code_tx, index: 0 } : null,
    magic: "BRG1",
    minLockCKB: 200, // capacity == amount, and the receipt cell's own occupied bytes are ~175 CKB
    // SECURITY NOTE (testnet demo): the receipt is locked under the USER's own lock here, so the user could
    // reclaim it without burning χCKB. A secure deployment locks it under burn_gated_unlock_v2 (built +
    // VM-tested, not yet deployed) so only a certified χCKB burn releases it. Surfaced in the UI.
    receiptLock: "user", // "user" (demo) | future: "burn_gated_unlock_v2"
  };
}

const send = (res, code, body, type = "application/json") => {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "cache-control": "no-store" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};

const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".ico": "image/x-icon" };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/api/bridge/config") return send(res, 200, bridgeConfig());
  // serve the built dApp (prod). In dev, vite serves the app and proxies /api here.
  let f = url.pathname === "/" ? "/index.html" : url.pathname;
  const abs = path.join(DIST, path.normalize(f));
  if (abs.startsWith(DIST) && fs.existsSync(abs) && fs.statSync(abs).isFile()) {
    return send(res, 200, fs.readFileSync(abs), MIME[path.extname(abs)] || "application/octet-stream");
  }
  if (fs.existsSync(DIST)) return send(res, 200, fs.readFileSync(path.join(DIST, "index.html")), "text/html"); // SPA fallback
  return send(res, 404, { error: "not found (dApp not built; run `npm run dev` for the dev server)" });
});
server.listen(PORT, () => console.log(`Chiral dApp backend: http://localhost:${PORT}  (config + proof API)`));
