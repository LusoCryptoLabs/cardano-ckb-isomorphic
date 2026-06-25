#!/usr/bin/env python3
"""build_chain_pinned.py - validate the FULL AVK advance chain 1319->1331 off-chain (ckb-debugger) against
the RE-BAKED (STM-pinned + singleton-guarded) cv_advance_pinned.bin / cv_deploy_pinned.bin, then export
chain.json + witnesses for the on-chain orchestrator (lc_chain.mjs). Mirrors build_chain.py but parameterized
to the current preview epoch and pointed at the pinned binaries. No on-chain effect.
  EXPORT=<dir> python3 build_chain_pinned.py
"""
import os, sys, json, struct, subprocess, urllib.request

AGG = "https://aggregator.testing-preview.api.mithril.network/aggregator"
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin")
ADV = os.path.join(BIN, "cv_advance_pinned.bin")
DEP = os.path.join(BIN, "cv_deploy_pinned.bin")
TRANSCODE = "/root/mv/target/release/transcode_witness"
sys.path.insert(0, HERE)
import harness

FROM, TO = 1319, int(os.environ.get("TO_EPOCH", "1331"))

def g(p): return json.load(urllib.request.urlopen(AGG + p, timeout=30))
def avk_fields(avk_hex):
    j = json.loads(bytes.fromhex(avk_hex).decode()); return bytes(j["mt_commitment"]["root"]), int(j["total_stake"])
def checkpoint(epoch, root, total): return struct.pack("<Q", epoch) + root + struct.pack("<Q", total)
def build_witness(cert, tag):
    open(f"/root/cert_{tag}.json", "w").write(json.dumps(cert))
    subprocess.run([TRANSCODE, f"/root/cert_{tag}.json"], check=True, capture_output=True, text=True)
    w = open("/tmp/cert_witness.bin", "rb").read(); open(f"/root/wit_{tag}.bin", "wb").write(w); return w

def fetch_epoch_certs():
    want = set(range(FROM, TO + 1)); out = {}
    cur = g("/certificates")[0]["hash"]
    for _ in range(800):
        if want <= set(out): break
        c = g("/certificate/" + cur); e = c.get("epoch")
        if e in want and e not in out: out[e] = c
        cur = c.get("previous_hash")
        if not cur: break
    miss = want - set(out)
    if miss: raise SystemExit(f"missing epoch certs: {sorted(miss)}")
    return out

def main():
    certs = fetch_epoch_certs(); print("fetched epoch certs:", sorted(certs))
    ck = {}
    for e in range(FROM, TO + 1):
        root, total = avk_fields(certs[e]["aggregate_verification_key"]); ck[e] = checkpoint(e, root, total)
    for e in range(FROM, TO):
        nav = certs[e]["protocol_message"]["message_parts"]["next_aggregate_verification_key"]
        assert avk_fields(nav) == avk_fields(certs[e + 1]["aggregate_verification_key"]), f"chain break {e}->{e+1}"
    print(f"chain consistency {FROM}->{TO}: OK")
    PINNED = bytes([39,5,0,0,0,0,0,0,15,60,12,127,134,236,178,138,205,194,254,3,103,90,12,67,234,0,244,85,
                    46,131,188,98,13,67,41,100,111,63,233,218,61,139,157,218,67,58,0,0])
    assert ck[FROM] == PINNED, f"genesis mismatch: {ck[FROM].hex()} != {PINNED.hex()}"
    print("genesis pin (epoch 1319) matches PINNED_GENESIS: OK")

    adv_code = harness.ckbhash(open(ADV, "rb").read())
    adv_script = {"code_hash": harness.h(adv_code), "hash_type": "data1", "args": "0x"}
    results = []
    code, _ = harness.run(ADV, out_data=ck[FROM]); results.append((f"genesis -> PINNED({FROM})", code))
    for e in range(FROM, TO):
        w = build_witness(certs[e], str(e))
        code, _ = harness.run(ADV, celldeps=[(w, None)], group_in=(ck[e], None), out_data=ck[e + 1])
        results.append((f"advance {e}->{e+1}", code))
    wTO = build_witness(certs[TO], str(TO))
    pm = certs[TO]["protocol_message"]["message_parts"]
    txroot = bytes.fromhex(pm["cardano_transactions_merkle_root"])
    height = int(pm["latest_block_number"])
    out_data = b"LCKP" + txroot + struct.pack("<Q", height)   # M2: LCKP||root(32)||height(8 LE) = 44 bytes
    code, _ = harness.run(DEP, celldeps=[(wTO, None), (ck[TO], adv_script)], out_data=out_data)
    results.append((f"deploy auth tx-set checkpoint (epoch {TO}, h={height}) -> LCKP||root||height", code))

    print("\n=== AVK advance chain (off-chain ckb-debugger, PINNED binaries) ===")
    ok = all(c == 0 for _, c in results)
    for label, got in results: print(f"  [{'PASS' if got==0 else 'FAIL'}] {label}: exit {got}")
    print(f"\npublished tx-set root (epoch {TO}): {txroot.hex()}")
    print("ALL PASS - chain valid off-chain; safe to execute on Pudge." if ok else "FAILURES - do not deploy.")

    if ok and os.environ.get("EXPORT"):
        outdir = os.environ["EXPORT"]; os.makedirs(os.path.join(outdir, "witnesses"), exist_ok=True)
        meta = {"epochs": {}, "advances": [], "deploy": {}}
        for e in range(FROM, TO + 1):
            meta["epochs"][str(e)] = {"checkpoint": "0x" + ck[e].hex(), "witness": f"wit_{e}.bin"}
            open(os.path.join(outdir, "witnesses", f"wit_{e}.bin"), "wb").write(open(f"/root/wit_{e}.bin", "rb").read())
        for e in range(FROM, TO):
            meta["advances"].append({"from": e, "to": e + 1, "in_ck": "0x" + ck[e].hex(),
                                     "out_ck": "0x" + ck[e + 1].hex(), "witness": f"wit_{e}.bin"})
        meta["deploy"] = {"avk_checkpoint": "0x" + ck[TO].hex(), "witness": f"wit_{TO}.bin",
                          "tx_root": "0x" + txroot.hex(), "height": height, "out_data": "0x" + out_data.hex()}
        json.dump(meta, open(os.path.join(outdir, "chain.json"), "w"), indent=2)
        print(f"exported chain artifacts -> {outdir}/chain.json + witnesses/ (epochs {FROM}..{TO})")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
