#!/usr/bin/env python3
"""gen_advance.py <from_epoch> [out.json] - produce the AVK advance from_epoch -> from_epoch+1 witness +
checkpoint data. Generalized from gen_advance_1332.py: fetch the from_epoch cert, derive ck[from] from its
own avk and ck[from+1] from its next_aggregate_verification_key, assert Mithril chain consistency, transcode
the from_epoch MWIT witness -> wit_<from>.bin. Writes advance.json {ckFrom, ckTo, witFile, fromEpoch, toEpoch}
for advance_epoch.mjs. Keyless (public Mithril). Needs transcode_witness in WSL."""
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
    for _ in range(800):
        c = g("/certificate/" + cur)
        if c.get("epoch") == epoch:
            return c
        cur = c.get("previous_hash")
        if not cur:
            break
    raise SystemExit(f"epoch {epoch} cert not found")


def main():
    frm = int(sys.argv[1]); to = frm + 1
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "advance.json")
    cF = fetch_cert(frm)
    rF, tF = avk_fields(cF["aggregate_verification_key"]); ckF = checkpoint(frm, rF, tF)
    nav = cF["protocol_message"]["message_parts"]["next_aggregate_verification_key"]
    rT, tT = avk_fields(nav); ckT = checkpoint(to, rT, tT)
    cT = fetch_cert(to)
    assert (rT, tT) == avk_fields(cT["aggregate_verification_key"]), f"Mithril chain break {frm}->{to}"

    cert_path = f"/root/cert_{frm}.json"; open(cert_path, "w").write(json.dumps(cF))
    subprocess.run([TRANSCODE, cert_path], check=True, capture_output=True, text=True)
    w = open("/tmp/cert_witness.bin", "rb").read()
    os.makedirs(WITDIR, exist_ok=True)
    witfile = f"wit_{frm}.bin"
    open(os.path.join(WITDIR, witfile), "wb").write(w)

    out = {"ckFrom": "0x" + ckF.hex(), "ckTo": "0x" + ckT.hex(), "witFile": witfile,
           "fromEpoch": frm, "toEpoch": to, "witBytes": len(w)}
    open(out_path, "w").write(json.dumps(out, indent=2))
    print(json.dumps(out))


if __name__ == "__main__":
    main()
