#!/usr/bin/env python3
"""build_chain.py - validate the FULL AVK advance chain off-chain (ckb-debugger) before any on-chain
spend. Fetches Mithril preview certs for epochs 1319..1323, builds each MWIT witness via transcode_witness,
computes the 48-byte checkpoints (epoch u64LE | avk_root[32] | total u64LE), and drives the parameterized
cert-verify binaries through:  genesis(1319) -> advance x4 -> epoch-1323 AVK checkpoint -> authenticated
tx-set deploy (publishes LCKP||tx_root_1323).  Mirrors the on-chain sequence we will then execute.
"""
import os, sys, json, struct, subprocess, urllib.request, hashlib

AGG = "https://aggregator.testing-preview.api.mithril.network/aggregator"
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin")
TRANSCODE = "/root/mv/target/release/transcode_witness"
sys.path.insert(0, HERE)
import harness  # the ckb-debugger mock-tx runner

def g(p): return json.load(urllib.request.urlopen(AGG + p, timeout=30))

def avk_fields(avk_hex):
    """(root[32] bytes, total_stake u64) from a hex-encoded Mithril aggregate_verification_key."""
    j = json.loads(bytes.fromhex(avk_hex).decode())
    root = bytes(j["mt_commitment"]["root"])
    total = int(j["total_stake"])
    return root, total

def checkpoint(epoch, root, total):
    return struct.pack("<Q", epoch) + root + struct.pack("<Q", total)

def fetch_epoch_certs():
    """Walk the cert chain from latest; keep one cert per epoch 1319..1323."""
    want = set(range(1319, 1324))
    out = {}
    cur = g("/certificates")[0]["hash"]
    for _ in range(400):
        if want <= set(out): break
        c = g("/certificate/" + cur)
        e = c.get("epoch")
        if e in want and e not in out:
            out[e] = c
        cur = c.get("previous_hash")
        if not cur: break
    return out

def build_witness(cert, tag):
    path = f"/root/cert_{tag}.json"
    open(path, "w").write(json.dumps(cert))
    subprocess.run([TRANSCODE, path], check=True, capture_output=True, text=True)
    w = open("/tmp/cert_witness.bin", "rb").read()
    open(f"/root/wit_{tag}.bin", "wb").write(w)
    return w

def main():
    certs = fetch_epoch_certs()
    print("fetched epoch certs:", sorted(certs))

    # checkpoint for each epoch from its OWN avk
    ck = {}
    for e in range(1319, 1324):
        root, total = avk_fields(certs[e]["aggregate_verification_key"])
        ck[e] = checkpoint(e, root, total)
    # next-avk from each cert (what the advance should output)
    nxt = {}
    for e in range(1319, 1323):
        nav = certs[e]["protocol_message"]["message_parts"]["next_aggregate_verification_key"]
        root, total = avk_fields(nav)
        nxt[e] = (root, total)

    # sanity: each cert's next_avk must equal the NEXT epoch's own avk (Mithril chain consistency)
    for e in range(1319, 1323):
        assert nxt[e] == avk_fields(certs[e+1]["aggregate_verification_key"]), f"chain break at {e}->{e+1}"
    print("chain consistency 1319->1323: OK (each next_avk == next epoch's avk)")

    # genesis pin check: epoch-1319 checkpoint must equal the binary's PINNED_GENESIS
    PINNED = bytes([39,5,0,0,0,0,0,0,15,60,12,127,134,236,178,138,205,194,254,3,103,90,12,67,234,0,244,85,
                    46,131,188,98,13,67,41,100,111,63,233,218,61,139,157,218,67,58,0,0])
    assert ck[1319] == PINNED, f"genesis mismatch:\n got {ck[1319].hex()}\n pin {PINNED.hex()}"
    print("genesis pin (epoch 1319) matches PINNED_GENESIS: OK")

    adv = os.path.join(BIN, "cv_advance.bin")
    dep = os.path.join(BIN, "cv_deploy.bin")
    adv_code = harness.ckbhash(open(adv, "rb").read())
    adv_script = {"code_hash": harness.h(adv_code), "hash_type": "data1", "args": "0x"}

    results = []
    # 1) GENESIS: no input checkpoint -> output must be PINNED_GENESIS
    code, out = harness.run(adv, out_data=ck[1319])
    results.append(("genesis -> PINNED(1319)", code, 0));

    # 2) ADVANCE x4: e -> e+1
    for e in range(1319, 1323):
        w = build_witness(certs[e], str(e))
        code, out = harness.run(adv, celldeps=[(w, None)], group_in=(ck[e], None), out_data=ck[e+1])
        results.append((f"advance {e}->{e+1}", code, 0))

    # 3) DEPLOY (authenticated tx-set checkpoint): cert_1323 + avk checkpoint(1323) -> LCKP||tx_root
    w1323 = build_witness(certs[1323], "1323")
    txroot = bytes.fromhex(certs[1323]["protocol_message"]["message_parts"]["cardano_transactions_merkle_root"])
    out_data = b"LCKP" + txroot
    code, out = harness.run(dep, celldeps=[(w1323, None), (ck[1323], adv_script)], out_data=out_data)
    results.append(("deploy auth tx-set checkpoint -> LCKP||root", code, 0))

    print("\n=== AVK advance chain (off-chain ckb-debugger) ===")
    ok = True
    for label, got, want in results:
        flag = "PASS" if got == want else "FAIL"
        if got != want: ok = False
        print(f"  [{flag}] {label}: exit {got} (want {want})")
    print(f"\npublished tx-set root (epoch 1323): {txroot.hex()}")
    print("ALL PASS - chain valid off-chain; safe to execute on Pudge." if ok else "FAILURES - do not deploy.")

    # export artifacts for the on-chain orchestrator (lc_chain.mjs)
    if ok and os.environ.get("EXPORT"):
        outdir = os.environ["EXPORT"]
        os.makedirs(os.path.join(outdir, "witnesses"), exist_ok=True)
        meta = {"epochs": {}, "advances": [], "deploy": {}}
        for e in range(1319, 1324):
            meta["epochs"][str(e)] = {"checkpoint": "0x" + ck[e].hex()}
            wf = f"wit_{e}.bin"
            open(os.path.join(outdir, "witnesses", wf), "wb").write(open(f"/root/wit_{e}.bin", "rb").read())
            meta["epochs"][str(e)]["witness"] = wf
        for e in range(1319, 1323):
            meta["advances"].append({"from": e, "to": e + 1,
                                     "in_ck": "0x" + ck[e].hex(), "out_ck": "0x" + ck[e+1].hex(),
                                     "witness": f"wit_{e}.bin"})
        meta["deploy"] = {"avk_checkpoint": "0x" + ck[1323].hex(), "witness": "wit_1323.bin",
                          "tx_root": "0x" + txroot.hex(), "out_data": "0x" + (b"LCKP" + txroot).hex()}
        json.dump(meta, open(os.path.join(outdir, "chain.json"), "w"), indent=2)
        print(f"exported chain artifacts -> {outdir}/chain.json + witnesses/")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
