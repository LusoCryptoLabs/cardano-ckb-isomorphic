#!/usr/bin/env python3
"""Phase-5 adversarial test suite for the cert-verify light client.
Drives the three verifier modes under ckb-debugger with mock transactions,
asserting that every forged / replayed / equivocating / reorg'd input is
REJECTED with the expected script error code, and that the canonical inputs
are ACCEPTED. Soundness-regression evidence for the Cardano->CKB leg."""
import struct, sys, os
from harness import run, ckbhash, HERE
from witness import parse_layout, part_off, flip

# fixtures live in ./fixtures (repo) or /tmp (live dev); binaries in ./bin or /tmp
def fx(name, alt):
    for p in (os.path.join(HERE, "fixtures", name), os.path.join("/tmp", alt)):
        if os.path.exists(p): return p
    raise FileNotFoundError(name)
def binpath(name):
    for p in (os.path.join(HERE, "bin", name), os.path.join("/tmp", name)):
        if os.path.exists(p): return p
    raise FileNotFoundError(name)

W   = open(fx("cert_witness.bin", "cert_witness.bin"), "rb").read()  # MithrilStakeDistribution cert
W19 = open(fx("witness_1319.bin", "witness_1319.bin"), "rb").read()
W20 = open(fx("witness_1320.bin", "witness_1320.bin"), "rb").read()
L, L19, L20 = parse_layout(W), parse_layout(W19), parse_layout(W20)

def ck(epoch, avk, total):  # 48-byte light-client checkpoint cell
    return struct.pack("<Q", epoch) + avk + struct.pack("<Q", total)

def fields(w, lay):
    avk = w[lay["avk_root"][0]:lay["avk_root"][0]+32]
    total = struct.unpack_from("<Q", w, lay["total"][0])[0]
    return avk, total

AVK19, T19 = fields(W19, L19)
AVK20, T20 = fields(W20, L20)
GENESIS = ck(1319, AVK19, T19)        # == PINNED_GENESIS const in the verifier

# canonical advance verifier script -> its type-hash is the trusted ADV_TYPEHASH (0x59efd99d)
ADV_CODEHASH = "0xe877a8028eac379e962a596671d1cd918aceddfa4c4cd78163168ba3b533ac55"
ADV_TYPE = {"code_hash": ADV_CODEHASH, "hash_type": "data1", "args": "0x"}
OTHER_TYPE = {"code_hash": "0x" + "cd"*32, "hash_type": "data1", "args": "0x"}

STANDALONE = binpath("cv_standalone.bin")
DEPLOY     = binpath("cv_deploy.bin")
ADVANCE    = binpath("cv_advance.bin")

results = []
def check(name, got, want, out=""):
    # want can be an int (exact script code) or "REJECT" (any non-zero / fail-closed abort)
    if want == "REJECT":
        ok = got != 0
    else:
        ok = got == want
    results.append(ok)
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}: exit {got} (want {want})")
    if not ok and out:
        print("        " + out.strip().splitlines()[-1][:160])

print("== Battery A - forged cert (standalone): each tampered cert must be REJECTED ==")
# baselines
c,_ = run(STANDALONE, celldeps=[(W, None)]);                  check("A0 valid cert ACCEPTED", c, 0)
c,o = run(STANDALONE, celldeps=[(flip(W, L["signers"][0]["sigma_off"]), None)]); check("A1 tampered BLS signature (sigma)", c, 20, o)
c,o = run(STANDALONE, celldeps=[(flip(W, L["signers"][0]["mvk_off"]), None)]);   check("A2 tampered verification key (mvk)", c, 20, o)
c,o = run(STANDALONE, celldeps=[(flip(W, L["signers"][0]["stake_off"]), None)]); check("A3 tampered signer stake", c, 20, o)
c,o = run(STANDALONE, celldeps=[(flip(W, L["signed_message"][0]), None)]);       check("A4 tampered signed_message (M1)", c, 20, o)
c,o = run(STANDALONE, celldeps=[(flip(W, L["avk_root"][0]), None)]);             check("A5 tampered avk_root (merkle/BLS)", c, 20, o)
c,o = run(STANDALONE, celldeps=[(flip(W, L["bvals_off"]), None)]);               check("A6 tampered merkle batch value", c, 20, o)
# bump quorum threshold k above the available signatures -> quorum fails
wk = bytearray(W); struct.pack_into("<Q", wk, L["k"][0], 1<<40)
c,o = run(STANDALONE, celldeps=[(bytes(wk), None)]);                             check("A7 quorum k inflated (insufficient sigs)", c, 20, o)
# equivocation: forge a different next-avk -> it is in the SIGNED message parts, so M1 breaks
pv = part_off(L, b"next_aggregate_verification_key")
c,o = run(STANDALONE, celldeps=[(flip(W, pv[0]), None)]);                        check("A8 forged next-avk (equivocation, M1)", c, 20, o)
# malformed inputs
c,o = run(STANDALONE, celldeps=[(W[:200], None)]);                              check("A9 truncated witness (fail-closed abort)", c, "REJECT", o)
c,o = run(STANDALONE, celldeps=[(b"XXXX"+W[4:], None)]);                        check("A10 wrong magic (no witness found)", c, 1, o)

print("== Battery B - chain integrity (advance mode): pinning / replay / reorg ==")
fake_gen = ck(9999, b"\xaa"*32, 1)
c,o = run(ADVANCE, celldeps=[(W19, None)], out_data=fake_gen);                  check("B1 FAKE genesis (unpinned avk) REJECTED", c, 7, o)
c,o = run(ADVANCE, celldeps=[(W19, None)], out_data=GENESIS);                   check("B2 canonical genesis ACCEPTED", c, 0, o)
c,o = run(ADVANCE, celldeps=[(W19, None)], group_in=(GENESIS, None),
          out_data=ck(1320, AVK20, T20));                                        check("B3 advance 1319->1320 ACCEPTED", c, 0, o)
# replay: feed the 1320 cert against the 1319 checkpoint -> epoch mismatch
c,o = run(ADVANCE, celldeps=[(W20, None)], group_in=(GENESIS, None),
          out_data=ck(1320, AVK20, T20));                                        check("B4 replay wrong-epoch cert", c, 10, o)
# avk mismatch: input checkpoint avk doctored (epoch still matches cert)
c,o = run(ADVANCE, celldeps=[(W19, None)], group_in=(ck(1319, b"\xbb"*32, T19), None),
          out_data=ck(1320, AVK20, T20));                                        check("B5 input avk doctored", c, 11, o)
# reorg: advance, but output skips an epoch (1319 -> 1321)
c,o = run(ADVANCE, celldeps=[(W19, None)], group_in=(GENESIS, None),
          out_data=ck(1321, AVK20, T20));                                        check("B6 reorg/epoch-skip output", c, 5, o)
# reorg: advance, but output avk is attacker-chosen (not the cert's next-avk)
c,o = run(ADVANCE, celldeps=[(W19, None)], group_in=(GENESIS, None),
          out_data=ck(1320, b"\xcc"*32, T20));                                   check("B7 output avk not from cert", c, 5, o)
# forged cert inside an otherwise-valid advance
c,o = run(ADVANCE, celldeps=[(flip(W19, L19["signers"][0]["sigma_off"]), None)],
          group_in=(GENESIS, None), out_data=ck(1320, AVK20, T20));             check("B8 forged cert in advance", c, 20, o)

print("== Battery C - avk-source binding (deploy mode): only a canonically-typed checkpoint is trusted ==")
# the avk checkpoint cell must carry the cert's avk_root AND its total stake (the deploy path anchors total,
# code 17 - a zero/mismatched total is rejected before the tx-root gate). Use the cert's real total here.
TW = struct.unpack_from("<Q", W, L["total"][0])[0]
avk_cell_match = b"\x00"*8 + (W[L["avk_root"][0]:L["avk_root"][0]+32]) + struct.pack("<Q", TW)
# untrusted: a plain 48-byte cell (no type) must NOT be accepted as an avk source
c,o = run(DEPLOY, celldeps=[(W, None), (avk_cell_match, None)]);                check("C1 untyped checkpoint NOT trusted", c, 3, o)
# untrusted: 48-byte cell with a DIFFERENT type -> still not trusted
c,o = run(DEPLOY, celldeps=[(W, None), (avk_cell_match, OTHER_TYPE)]);          check("C2 wrong-type checkpoint NOT trusted", c, 3, o)
# trusted type but avk doesn't match the cert -> rejected at the avk gate
avk_cell_bad = b"\x00"*8 + b"\xdd"*32 + b"\x00"*8
c,o = run(DEPLOY, celldeps=[(W, None), (avk_cell_bad, ADV_TYPE)]);              check("C3 trusted checkpoint, avk mismatch", c, 6, o)
# trusted type AND matching avk -> passes the binding, reaches the tx-root check
# (this MSD cert has no cardano_transactions_merkle_root, so it stops at 14: binding satisfied)
c,o = run(DEPLOY, celldeps=[(W, None), (avk_cell_match, ADV_TYPE)]);            check("C4 trusted+matching avk reaches tx-root gate", c, 14, o)

print("== Battery D - singleton guard: a forged SIBLING checkpoint in the same type group must be REJECTED ==")
# RQ-SG: a CKB type script runs ONCE per group; the verifier validated only GroupOutput[0]. An attacker
# rode a SECOND cell wearing this trusted type (forged avk/LCKP data) which downstream consumers accept by
# type-hash alone -> forged cert -> unbacked mint. The guard must reject ANY sibling in the group.
fake_ck = ck(9999, b"\xaa"*32, 1)
# D1 genesis + a forged second output wearing the verifier type -> reject (40)
c,o = run(ADVANCE, celldeps=[(W19, None)], out_data=GENESIS,
          extra_outs=[(fake_ck, None)]);                                check("D1 genesis + forged sibling OUTPUT", c, 40, o)
# D2 advance + a forged second output -> reject (43)
c,o = run(ADVANCE, celldeps=[(W19, None)], group_in=(GENESIS, None),
          out_data=ck(1320, AVK20, T20), extra_outs=[(fake_ck, None)]); check("D2 advance + forged sibling OUTPUT", c, 43, o)
# D3 advance + a forged second GROUP INPUT -> reject (42)
c,o = run(ADVANCE, celldeps=[(W19, None)], group_in=(GENESIS, None),
          out_data=ck(1320, AVK20, T20), extra_ins=[(GENESIS, None)]);  check("D3 advance + forged sibling INPUT", c, 42, o)
# D4 deploy + a forged second output -> reject (45) before the witness/avk path even runs
c,o = run(DEPLOY, celldeps=[(W, None), (avk_cell_match, ADV_TYPE)],
          extra_outs=[(b"LCKP"+b"\x00"*40, None)]);                     check("D4 deploy + forged sibling OUTPUT", c, 45, o)
# D5 deploy + duplicate group inputs -> reject (44)
c,o = run(DEPLOY, celldeps=[(W, None), (avk_cell_match, ADV_TYPE)],
          extra_ins=[(b"\x00"*44, None), (b"\x00"*44, None)]);         check("D5 deploy + duplicate group INPUTS", c, 44, o)

print(f"\n==== {sum(results)}/{len(results)} scenarios behaved as specified ====")
sys.exit(0 if all(results) else 1)
