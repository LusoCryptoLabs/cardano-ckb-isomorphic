#!/usr/bin/env python3
"""relayer_window.py - fetch the REAL CKB-header window for leap_bound_windowed (go-live A).

The windowed leap circuit proves membership of the receipt block against a shallow WINDOW ROOT - a Merkle
root over the last W = 2^depth recent CKB header hashes, placed in a ring buffer at slot = height mod W (in
production AdvanceCKBCert maintains this root on the Cardano `ckbcert` checkpoint). The demo prover used
stand-in leaves; this fetches the ACTUAL W headers so the window root is real, while keeping the receipt block
K_MIN-deep below the tip so the reorg K-floor (diff = tip-height >= K_MIN) is provable.

  tip = receipt_height + K_MIN ; window = heights [tip-W+1 .. tip] ; leaves[h mod W] = blockhash(h)

Usage: relayer_window.py <RPC> <receipt_height> [out.json]   (env: CHIRAL_WINDOW_DEPTH=6, CHIRAL_K_MIN=12)
"""
import urllib.request, json, sys, time, os

RPC = sys.argv[1] if len(sys.argv) > 1 else "https://testnet.ckb.dev"
RECEIPT_H = int(sys.argv[2]) if len(sys.argv) > 2 else 21388341
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/window.json"
DEPTH = int(os.environ.get("CHIRAL_WINDOW_DEPTH", "6"))
K_MIN = int(os.environ.get("CHIRAL_K_MIN", "12"))
W = 1 << DEPTH
assert K_MIN < W, f"K_MIN {K_MIN} must be < W {W} (need a live window above the floor)"

def rpc(m, p):
    for a in range(6):
        try:
            req = urllib.request.Request(RPC, data=json.dumps({"id":1,"jsonrpc":"2.0","method":m,"params":p}).encode(),
                headers={"content-type":"application/json","User-Agent":"relayer-window/1"})
            r = json.load(urllib.request.urlopen(req, timeout=25))
            if r.get("error"): raise RuntimeError(r["error"])
            return r["result"]
        except Exception as e:
            if a==5: raise
            time.sleep(2*(a+1))

tip_now = int(rpc("get_tip_header", [])["number"], 16)
tip = RECEIPT_H + K_MIN
assert tip <= tip_now, f"tip {tip} (receipt+K_MIN) not yet confirmed; chain tip is {tip_now}"
lo = tip - W + 1
# ring buffer: leaves[h mod W] = blockhash(h) for h in [lo, tip]; 64 consecutive heights cover all W slots.
leaves = [None] * W
for h in range(lo, tip + 1):
    bh = rpc("get_header_by_number", [hex(h)])["hash"]
    leaves[h % W] = bh
assert all(x is not None for x in leaves), "window not fully populated"
slot = RECEIPT_H % W
out = {
    "rpc": RPC, "window_depth": DEPTH, "window_size": W, "k_min": K_MIN,
    "receipt_height": RECEIPT_H, "tip_height": tip, "slot": slot,
    "receipt_block_hash": leaves[slot],
    "leaves": leaves,            # ordered by ring slot 0..W-1; each is a REAL CKB block hash
}
json.dump(out, open(OUT, "w"), indent=1)
print(f"window: depth={DEPTH} W={W} heights [{lo}..{tip}] receipt@{RECEIPT_H} slot={slot} diff={tip-RECEIPT_H} (>=K_MIN {K_MIN})")
print(f"receipt_block_hash={leaves[slot]}  -> {OUT}")
