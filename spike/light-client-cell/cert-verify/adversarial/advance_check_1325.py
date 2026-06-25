#!/usr/bin/env python3
"""advance_check_1325.py - compute + OFF-CHAIN validate the AVK advance 1324->1325 (the epoch roll that
unblocks the v2 checkpoint refresh against current epoch-1325 Mithril certs), AND build wit_1324.bin.
Fetches the epoch-1324 cert, derives ck[1324] from its OWN avk + ck[1325] from its next_aggregate_verification_key,
transcodes the 1324 MWIT witness, and drives cv_advance.bin through ckb-debugger spending ck[1324]->ck[1325].
Sanity-checks ck[1324] == the on-chain checkpoint before trusting the derivation. No on-chain effect.
"""
import os, sys, json, struct, subprocess, urllib.request
AGG = "https://aggregator.testing-preview.api.mithril.network/aggregator"
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin")
TRANSCODE = "/root/mv/target/release/transcode_witness"
sys.path.insert(0, HERE)
import harness

def g(p): return json.load(urllib.request.urlopen(AGG + p, timeout=30))
def avk_fields(avk_hex):
    j = json.loads(bytes.fromhex(avk_hex).decode()); return bytes(j["mt_commitment"]["root"]), int(j["total_stake"])
def checkpoint(epoch, root, total): return struct.pack("<Q", epoch) + root + struct.pack("<Q", total)
def fetch_cert(epoch):
    cur = g("/certificates")[0]["hash"]
    for _ in range(400):
        c = g("/certificate/" + cur)
        if c.get("epoch") == epoch: return c
        cur = c.get("previous_hash")
        if not cur: break
    raise SystemExit(f"epoch {epoch} cert not found")
def build_witness(cert, tag):
    path = f"/root/cert_{tag}.json"; open(path, "w").write(json.dumps(cert))
    subprocess.run([TRANSCODE, path], check=True, capture_output=True, text=True)
    w = open("/tmp/cert_witness.bin", "rb").read(); open(f"/root/wit_{tag}.bin", "wb").write(w); return w

# the on-chain epoch-1324 AVK checkpoint (from advance_1324.mjs CK1324) - our derivation MUST reproduce it.
EXPECT_CK1324 = "2c0500000000000001ce65944748f2d5c19bd4097144d795fc2f8b3438d6bc753ba2704ab049c651fe9aaf78613a0000"

def main():
    c1324 = fetch_cert(1324)
    r1324, t1324 = avk_fields(c1324["aggregate_verification_key"]); ck1324 = checkpoint(1324, r1324, t1324)
    nav = c1324["protocol_message"]["message_parts"]["next_aggregate_verification_key"]
    r1325, t1325 = avk_fields(nav); ck1325 = checkpoint(1325, r1325, t1325)
    # sanity: 1324.next_avk == 1325.own_avk (Mithril chain consistency)
    c1325 = fetch_cert(1325)
    assert (r1325, t1325) == avk_fields(c1325["aggregate_verification_key"]), "chain break 1324->1325"
    assert ck1324.hex() == EXPECT_CK1324, f"ck1324 {ck1324.hex()} != on-chain {EXPECT_CK1324} (derivation drift)"

    w = build_witness(c1324, "1324")
    wdir = os.path.join(HERE, "..", "..", "..", "..", "relayer", "onchain", "chain", "witnesses")
    if os.path.isdir(wdir):
        open(os.path.join(wdir, "wit_1324.bin"), "wb").write(w)
        print("wrote wit_1324.bin ->", os.path.relpath(os.path.join(wdir, "wit_1324.bin")))

    adv = os.path.join(BIN, "cv_advance.bin")
    code, _ = harness.run(adv, celldeps=[(w, None)], group_in=(ck1324, None), out_data=ck1325)
    print("ck1324   :", "0x" + ck1324.hex(), "(matches on-chain)")
    print("ck1325   :", "0x" + ck1325.hex())
    print("advance 1324->1325 off-chain exit:", code, "(want 0)")
    print("RESULT:", "PASS - safe to broadcast" if code == 0 else "FAIL - do not broadcast")
    sys.exit(0 if code == 0 else 1)

if __name__ == "__main__":
    main()
