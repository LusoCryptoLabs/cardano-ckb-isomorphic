#!/usr/bin/env python3
"""advance_check_1326.py - compute + OFF-CHAIN validate the AVK advance 1325->1326 (the epoch roll that
unblocks the v2 checkpoint refresh against current epoch-1326 Mithril certs), AND build wit_1325.bin.
Fetches the epoch-1325 cert, derives ck[1325] from its OWN avk + ck[1326] from its next_aggregate_verification_key,
transcodes the 1325 MWIT witness, and drives cv_advance.bin through ckb-debugger spending ck[1325]->ck[1326].
Sanity-checks ck[1325] == the on-chain checkpoint (CK1325 from advance_1325.mjs) before trusting the derivation.
No on-chain effect. Mirror of advance_check_1325.py with the epoch bumped by one.
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

# the on-chain epoch-1325 AVK checkpoint (from advance_1325.mjs CK1325) - our derivation MUST reproduce it.
EXPECT_CK1325 = "2d05000000000000cbcbcee27edb35c2cddc0e073c827872bcffd840f35416a5039ac70736ddf38606f3b8ed663a0000"

def main():
    c1325 = fetch_cert(1325)
    r1325, t1325 = avk_fields(c1325["aggregate_verification_key"]); ck1325 = checkpoint(1325, r1325, t1325)
    nav = c1325["protocol_message"]["message_parts"]["next_aggregate_verification_key"]
    r1326, t1326 = avk_fields(nav); ck1326 = checkpoint(1326, r1326, t1326)
    # sanity: 1325.next_avk == 1326.own_avk (Mithril chain consistency)
    c1326 = fetch_cert(1326)
    assert (r1326, t1326) == avk_fields(c1326["aggregate_verification_key"]), "chain break 1325->1326"
    assert ck1325.hex() == EXPECT_CK1325, f"ck1325 {ck1325.hex()} != on-chain {EXPECT_CK1325} (derivation drift)"

    w = build_witness(c1325, "1325")
    wdir = os.path.join(HERE, "..", "..", "..", "..", "relayer", "onchain", "chain", "witnesses")
    if os.path.isdir(wdir):
        open(os.path.join(wdir, "wit_1325.bin"), "wb").write(w)
        print("wrote wit_1325.bin ->", os.path.relpath(os.path.join(wdir, "wit_1325.bin")))

    adv = os.path.join(BIN, "cv_advance.bin")
    code, _ = harness.run(adv, celldeps=[(w, None)], group_in=(ck1325, None), out_data=ck1326)
    print("ck1325   :", "0x" + ck1325.hex(), "(matches on-chain)")
    print("ck1326   :", "0x" + ck1326.hex())
    print("advance 1325->1326 off-chain exit:", code, "(want 0)")
    print("RESULT:", "PASS - safe to broadcast" if code == 0 else "FAIL - do not broadcast")
    sys.exit(0 if code == 0 else 1)

if __name__ == "__main__":
    main()
