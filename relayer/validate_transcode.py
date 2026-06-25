#!/usr/bin/env python3
"""validate_transcode.py - proves the relayer transcode is correct against REAL, ON-CHAIN-ACCEPTED
data: it must reproduce, byte-for-byte, the transition witness that the live unified BoundAsset
script accepted on CKB Pudge (tx 0x94d0620f…), starting only from the raw Mithril proof JSON +
the raw spend-tx CBOR. If this matches, the relayer can drive transitions without trust (the script
re-verifies regardless)."""
import json, sys
from transcode import transcode, proof_from_aggregator_entry

# Real preview transfer (binding_lock Transfer, seal recreated) - the live transition's inputs:
xferproof = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/xferproof.json"))
xfertx    = json.load(open(sys.argv[2] if len(sys.argv) > 2 else "/tmp/xfertx.json"))
# The on-chain-accepted witness + root (deploy/pudge/p1t_hex.json), captured from the live tx:
onchain   = json.load(open(sys.argv[3] if len(sys.argv) > 3 else
                            "../deploy/pudge/p1t_hex.json"))

entry = xferproof["certified_transactions"][0]
proof = proof_from_aggregator_entry(entry)
full_tx = bytes.fromhex(xfertx["cbor"])

w, cert_root, txid = transcode(proof, full_tx)

want_w = bytes.fromhex(onchain["t_witness"][2:])
want_root = onchain["t_root"][2:]

print(f"txid               = {txid}")
print(f"cert_root (master) = {cert_root.hex()}")
print(f"witness bytes      = {len(w)}  (on-chain: {len(want_w)})")
ok_w = (w == want_w)
ok_r = (cert_root.hex() == want_root)
print(f"witness == on-chain-accepted : {ok_w}")
print(f"cert_root == checkpoint root : {ok_r}")
if ok_w and ok_r and txid == "a98b6636b3f08670cf0fe64a6176b64094d5929165ec62eb2944ac66b0f74da7":
    print("PASS - relayer transcode reproduces the on-chain-accepted transition witness from raw Mithril data.")
    sys.exit(0)
print("FAIL"); sys.exit(1)
