#!/usr/bin/env python3
"""gen_advance_1332.py - produce the AVK advance 1331->1332 witness + checkpoint data (the epoch roll that
unblocks the LCKP refresh against the burn's epoch-1332 Mithril cert). Mirrors advance_check_1326.py with the
epoch bumped: fetch the epoch-1331 cert, derive ck[1331] from its own avk and ck[1332] from its
next_aggregate_verification_key, assert Mithril chain consistency (1331.next_avk == 1332.own_avk), transcode
the 1331 MWIT witness -> wit_1331.bin. Writes advance_1332.json {ck1331, ck1332} for the on-chain advance tx.
Keyless (public Mithril). Needs transcode_witness in WSL."""
import json
import os
import struct
import subprocess
import sys
import urllib.request

AGG = "https://aggregator.testing-preview.api.mithril.network/aggregator"
TRANSCODE = "/root/mv/target/release/transcode_witness"
HERE = os.path.dirname(os.path.abspath(__file__))
WITDIR = os.path.join(HERE, "chain", "witnesses")


def g(p): return json.load(urllib.request.urlopen(AGG + p, timeout=30))
def avk_fields(avk_hex):
    j = json.loads(bytes.fromhex(avk_hex).decode())
    return bytes(j["mt_commitment"]["root"]), int(j["total_stake"])
def checkpoint(epoch, root, total): return struct.pack("<Q", epoch) + root + struct.pack("<Q", total)


def fetch_cert(epoch):
    cur = g("/certificates")[0]["hash"]
    for _ in range(600):
        c = g("/certificate/" + cur)
        if c.get("epoch") == epoch:
            return c
        cur = c.get("previous_hash")
        if not cur:
            break
    raise SystemExit(f"epoch {epoch} cert not found")


def main():
    c1331 = fetch_cert(1331)
    r1331, t1331 = avk_fields(c1331["aggregate_verification_key"]); ck1331 = checkpoint(1331, r1331, t1331)
    nav = c1331["protocol_message"]["message_parts"]["next_aggregate_verification_key"]
    r1332, t1332 = avk_fields(nav); ck1332 = checkpoint(1332, r1332, t1332)
    c1332 = fetch_cert(1332)
    assert (r1332, t1332) == avk_fields(c1332["aggregate_verification_key"]), "Mithril chain break 1331->1332"

    path = "/root/cert_1331.json"; open(path, "w").write(json.dumps(c1331))
    subprocess.run([TRANSCODE, path], check=True, capture_output=True, text=True)
    w = open("/tmp/cert_witness.bin", "rb").read()
    os.makedirs(WITDIR, exist_ok=True)
    open(os.path.join(WITDIR, "wit_1331.bin"), "wb").write(w)

    out = {"ck1331": "0x" + ck1331.hex(), "ck1332": "0x" + ck1332.hex(), "witFile": "wit_1331.bin",
           "witBytes": len(w)}
    open(os.path.join(HERE, "advance_1332.json"), "w").write(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
