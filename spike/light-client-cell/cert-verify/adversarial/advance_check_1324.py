#!/usr/bin/env python3
"""advance_check_1324.py - compute + OFF-CHAIN validate the AVK advance 1323->1324 (the epoch roll that
unblocks the v2 44-byte checkpoint). Fetches the epoch-1323 Mithril preview cert, derives ck[1324] from its
next_aggregate_verification_key, and drives cv_advance.bin through ckb-debugger spending ck[1323]->ck[1324].
Prints ck[1323]/ck[1324] hex for the on-chain broadcaster. No on-chain effect.
"""
import os, sys, json, struct, urllib.request
AGG = "https://aggregator.testing-preview.api.mithril.network/aggregator"
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin")
sys.path.insert(0, HERE)
import harness

def g(p): return json.load(urllib.request.urlopen(AGG + p, timeout=30))
def avk_fields(avk_hex):
    j = json.loads(bytes.fromhex(avk_hex).decode())
    return bytes(j["mt_commitment"]["root"]), int(j["total_stake"])
def checkpoint(epoch, root, total):
    return struct.pack("<Q", epoch) + root + struct.pack("<Q", total)

def fetch_cert(epoch):
    cur = g("/certificates")[0]["hash"]
    for _ in range(400):
        c = g("/certificate/" + cur)
        if c.get("epoch") == epoch:
            return c
        cur = c.get("previous_hash")
        if not cur:
            break
    raise SystemExit(f"epoch {epoch} cert not found")

def main():
    c1323 = fetch_cert(1323)
    # ck[1323] from the 1323 cert's OWN avk (must equal the on-chain AVK checkpoint)
    r1323, t1323 = avk_fields(c1323["aggregate_verification_key"])
    ck1323 = checkpoint(1323, r1323, t1323)
    # ck[1324] from the 1323 cert's NEXT avk
    nav = c1323["protocol_message"]["message_parts"]["next_aggregate_verification_key"]
    r1324, t1324 = avk_fields(nav)
    ck1324 = checkpoint(1324, r1324, t1324)

    # sanity: 1323.next_avk == 1324.own_avk (Mithril chain consistency)
    c1324 = fetch_cert(1324)
    assert (r1324, t1324) == avk_fields(c1324["aggregate_verification_key"]), "chain break 1323->1324"

    wpath = os.path.join(HERE, "..", "..", "..", "..", "relayer", "onchain", "chain", "witnesses", "wit_1323.bin")
    wit = open(wpath, "rb").read() if os.path.exists(wpath) else open("/root/wit_1323.bin", "rb").read()

    adv = os.path.join(BIN, "cv_advance.bin")
    code, _ = harness.run(adv, celldeps=[(wit, None)], group_in=(ck1323, None), out_data=ck1324)
    print("ck1323   :", "0x" + ck1323.hex())
    print("ck1324   :", "0x" + ck1324.hex())
    print("advance 1323->1324 off-chain exit:", code, "(want 0)")
    print("RESULT:", "PASS - safe to broadcast" if code == 0 else "FAIL - do not broadcast")
    sys.exit(0 if code == 0 else 1)

if __name__ == "__main__":
    main()
