#!/usr/bin/env python3
"""Derive BOTH the per-tx MKMapProof (release witness) AND the MWIT cert witness (LCKP refresh) from the
SAME Mithril certificate, so the LCKP root == the release-witness root (no snapshot drift)."""
import sys, json, subprocess, urllib.request, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from relay import mithril_proof, tx_cbor
from transcode import transcode
BURN="26a5228f127ac444d531752ff1d170648054da0cc65d5760cec5595376b31cee"
AGG="https://aggregator.testing-preview.api.mithril.network/aggregator"
OUT="/mnt/c/Users/telmo/chiral-study/relayer/onchain"
proof, ch, ok = mithril_proof(BURN)
if not ok: raise SystemExit("burn not certified")
full = bytes.fromhex(tx_cbor(BURN))
w, root, got = transcode(proof, full)
json.dump({"status":"ready","txid":got,"witness":"0x"+w.hex(),"root":"0x"+root.hex()}, open(OUT+"/bg_release_wit.json","w"))
cert = json.load(urllib.request.urlopen(AGG+"/certificate/"+ch, timeout=25))
open("/root/ct_burn.json","w").write(json.dumps(cert))
pm = cert["protocol_message"]["message_parts"]
subprocess.run(["/root/mv/target/release/transcode_witness","/root/ct_burn.json"], check=True, capture_output=True)
witHex = open("/tmp/cert_witness.bin","rb").read().hex()
cert_root = pm["cardano_transactions_merkle_root"]
json.dump({"root":"0x"+cert_root,"height":int(pm["latest_block_number"]),"witHex":"0x"+witHex}, open(OUT+"/bg_ctwit.json","w"))
assert root.hex()==cert_root, f"proof root {root.hex()} != cert root {cert_root}"
print("ALIGNED on cert", ch[:16], "| root", root.hex()[:18], "| height", pm["latest_block_number"], "| MATCH")
