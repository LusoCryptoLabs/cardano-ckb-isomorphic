#!/usr/bin/env python3
"""test_service.py - end-to-end check of the relayer HTTP service, KEYLESS (Koios + public Mithril).

Boots service.py in-process on an ephemeral port and asserts:
  1. /health responds and reports the keyless (koios) tx source.
  2. /api/config exposes the deployed instance the front-end needs.
  3. /api/cardano-to-ckb/submission?tx=<live transition tx> returns status=ready, mode=TRANSITION,
     the correct txid, and a witness whose tx_body is BYTE-IDENTICAL to the on-chain-accepted
     witness captured in deploy/pudge/p1t_hex.json (the proof items differ only by Mithril snapshot;
     the tx_body - what binds the asset - must match exactly).
  4. /api/cardano-to-ckb/submit returns 501 not-configured (gap #1: funded signer).

Run:  python relayer/test_service.py     (needs network: Koios preview + Mithril preview aggregator)
"""
import os, sys, json, struct, threading, urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import service  # noqa: E402

TXID = "a98b6636b3f08670cf0fe64a6176b64094d5929165ec62eb2944ac66b0f74da7"  # live preview transition


def _tx_body_from_witness(witness_hex):
    """Witness layout starts: u32 LE len(tx_body) || tx_body || ... -> return the tx_body bytes."""
    b = bytes.fromhex(witness_hex[2:] if witness_hex.startswith("0x") else witness_hex)
    n = struct.unpack("<I", b[:4])[0]
    return b[4:4 + n]


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), service.Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"

    def get(path):
        return json.load(urllib.request.urlopen(base + path, timeout=40))

    def post(path, obj):
        req = urllib.request.Request(base + path, data=json.dumps(obj).encode(),
                                     headers={"content-type": "application/json"})
        try:
            r = urllib.request.urlopen(req, timeout=40)
            return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    fails = []
    try:
        # 1) health
        h = get("/health")
        assert h["ok"] and h["tx_source"] == "koios", h
        print("1. /health             OK (keyless, koios)")

        # 2) config
        c = get("/api/config")
        assert c["cardano"]["seal_policy"] and c["ckb"]["bound_asset_code_hash"], c
        print("2. /api/config         OK (seal_policy + bound_asset code_hash present)")

        # 3) submission - live transcode vs on-chain-accepted tx_body
        s = get(f"/api/cardano-to-ckb/submission?tx={TXID}")
        assert s["status"] == "ready", s
        assert s["mode"] == "TRANSITION", s
        assert s["tx"] == TXID, s
        live_body = _tx_body_from_witness(s["witness"])
        onchain = json.load(open(os.path.join(HERE, "..", "deploy", "pudge", "p1t_hex.json")))
        onchain_body = _tx_body_from_witness(onchain["t_witness"])
        assert live_body == onchain_body, (
            f"tx_body mismatch: live {len(live_body)}B vs on-chain {len(onchain_body)}B")
        print(f"3. /api/.../submission OK (ready/TRANSITION; tx_body {len(live_body)}B "
              f"== on-chain-accepted byte-for-byte)")

        # 4) submit gated
        code, body = post("/api/cardano-to-ckb/submit", {"tx": TXID})
        assert code == 501 and body["status"] == "not-configured", (code, body)
        assert body["would_submit"]["status"] == "ready", body
        print("4. /api/.../submit     OK (501 not-configured; would_submit=ready)")
    except AssertionError as e:
        fails.append(str(e))
    finally:
        srv.shutdown()

    if fails:
        print("\nFAIL:", *fails, sep="\n  ")
        sys.exit(1)
    print("\nPASS - relayer service drives a live keyless Cardano->CKB transcode that reproduces "
          "the on-chain-accepted witness; only the funded signer (gap #1) is stubbed.")


if __name__ == "__main__":
    main()
