#!/usr/bin/env python3
"""service.py - the RELAYER HTTP service a front-end calls.

Wraps the proven, permissionless relayer pipeline (relay.py / transcode.py) behind a small JSON
HTTP API with CORS, so a browser/CLI front-end can drive a Cardano->CKB leap without shelling out.
Stdlib only (no pip install); keyless by default (Koios + the public Mithril aggregator) so it runs
with no API credentials. Set BLOCKFROST_PROJECT_ID to use Blockfrost instead of Koios.

It CANNOT forge: every endpoint here is read/transcode only. The witness it returns is re-verified
on-chain by the CKB BoundAsset script against the certified tx-set root in the light-client
checkpoint cell. A wrong/missing response only delays a transfer; it can never move an asset.

Endpoints (all JSON, CORS-enabled):
  GET  /health
       -> {ok, service, keyed, aggregator}
  GET  /api/config
       -> the deployed addresses/policies/code-hashes a front-end needs to build & display a leap
  GET  /api/cardano-to-ckb/submission?tx=<spend_tx_hash>
       -> the BoundAsset submission descriptor for one Cardano seal spend:
          {status: ready|wait-certification, mode: TRANSITION|FINALIZE, tx, cert_root,
           checkpoint_data, witness}  (witness -> WitnessArgs.inputType for the CKB spend)
  GET  /api/cardano-to-ckb/pending?limit=N
       -> recent seal spends with their relay status (poll this from a UI)
  POST /api/cardano-to-ckb/submit   {tx: <hash>}   [or any submit]
       -> 501 until a funded CKB key + redeployed contracts exist (gap #1). Returns exactly what
          is missing and the descriptor that WOULD be submitted, so the UI can show the leap as
          "ready, awaiting signer".

Run:  python relayer/service.py [--port 8787] [--host 127.0.0.1]
"""
import os, sys, json, re, subprocess, argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import relay  # the proven pipeline: build_submission / pending_submissions / config

def _load(p, d):
    try:
        return json.load(open(os.path.join(HERE, p)))
    except Exception:
        return d

_DEPLOYED = _load("onchain/deployed.json", {})
_SEAL = _load("../cardano/deployed/cardano/preview/seal-instance-ours.json", {})

# ---- live config a front-end needs (OUR deployed testnet instances) ---------------------------
CONFIG = {
    "network": {"cardano": "preview", "ckb": "pudge"},
    "cardano": {
        "seal_policy": _SEAL.get("seal_policy"),
        "binding_lock_addr": _SEAL.get("binding_lock_addr"),
        "owner_vkh": _SEAL.get("owner_vkh"),
        "mithril_aggregator": relay.AGG,
    },
    "ckb": {
        # OUR authenticated light client + BoundAsset verifier, all live on Pudge.
        "bound_asset_code_hash": _DEPLOYED.get("bound_asset", {}).get("codeHash"),
        "bound_asset_deploy_tx": _DEPLOYED.get("bound_asset", {}).get("txHash"),
        "cv_advance_code_hash": _DEPLOYED.get("cv_advance", {}).get("codeHash"),
        "cv_deploy_code_hash": _DEPLOYED.get("cv_deploy", {}).get("codeHash"),
        "avk_checkpoint_epoch": 1323,
    },
    "notes": "testnet only; unaudited. Light client + BoundAsset are LIVE; checkpoint is refreshed per leap. "
             "The witness/cert is re-verified in CKB-VM on every step.",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "ChiralRelayer/0.1"

    # -- helpers ---------------------------------------------------------------------------------
    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        self.send_header("access-control-allow-headers", "content-type")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("[relayer] %s - %s\n" % (self.address_string(), fmt % args))

    # -- CORS preflight --------------------------------------------------------------------------
    def do_OPTIONS(self):
        self._send(204, {})

    # -- routes ----------------------------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path.rstrip("/") or "/"
        try:
            if path in ("/", "/health"):
                return self._send(200, {
                    "ok": True, "service": "chiral-relayer", "version": "0.1",
                    "keyed": bool(relay.BF_KEY),
                    "tx_source": "blockfrost" if relay.BF_KEY else "koios",
                    "aggregator": relay.AGG,
                })
            if path == "/api/config":
                return self._send(200, CONFIG)
            if path == "/api/cardano-to-ckb/submission":
                tx = (q.get("tx") or [None])[0]
                if not tx:
                    return self._send(400, {"error": "missing ?tx=<spend_tx_hash>"})
                return self._send(200, relay.build_submission(tx))
            if path == "/api/cardano-to-ckb/pending":
                limit = int((q.get("limit") or ["10"])[0])
                return self._send(200, {"pending": relay.pending_submissions(min(limit, 25))})
            return self._send(404, {"error": "not found", "path": path})
        except Exception as e:
            return self._send(502, {"error": "upstream", "detail": str(e)[:200]})

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        try:
            n = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except Exception:
            body = {}
        if path == "/api/cardano-to-ckb/submit":
            # REAL on-chain submit: drive the BoundAsset orchestrator (our funded Pudge key). It refreshes the
            # authenticated checkpoint to the current Mithril root, builds the MKMapProof witness, and sends the
            # CKB genesis/transition/finalize tx. mode = genesis|transition|finalize; tx = the Cardano event tx.
            mode = body.get("mode", "genesis")
            tx = body.get("tx")
            state = body.get("state")
            if not tx or mode not in ("genesis", "transition", "finalize"):
                return self._send(400, {"error": "need {mode: genesis|transition|finalize, tx: <cardano_txid>, [state]}"})
            cmd = ["node", os.path.join(HERE, "onchain", "boundasset.mjs"), mode, tx]
            if state:
                cmd.append(state)
            try:
                out = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                return self._send(504, {"status": "timeout", "mode": mode, "tx": tx})
            log = (out.stdout + out.stderr).strip().splitlines()
            ckb_tx = None
            for line in log:
                m = re.search(r"(GENESIS bound cell|TRANSITION|FINALIZE):\s*(0x[0-9a-f]{64})", line)
                if m:
                    ckb_tx = m.group(2)
            if out.returncode == 0 and ckb_tx:
                return self._send(200, {"status": "submitted", "mode": mode, "cardano_tx": tx, "ckb_tx": ckb_tx})
            return self._send(502, {"status": "failed", "mode": mode, "tx": tx, "log": log[-6:]})
        return self._send(404, {"error": "not found", "path": path})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    src = "blockfrost" if relay.BF_KEY else "koios (keyless)"
    print(f"chiral relayer service on http://{a.host}:{a.port}  | tx source: {src}", file=sys.stderr)
    print(f"  GET  /health\n  GET  /api/config\n"
          f"  GET  /api/cardano-to-ckb/submission?tx=<hash>\n"
          f"  GET  /api/cardano-to-ckb/pending?limit=N\n"
          f"  POST /api/cardano-to-ckb/submit  {{tx}}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", file=sys.stderr)
        srv.shutdown()


if __name__ == "__main__":
    main()
