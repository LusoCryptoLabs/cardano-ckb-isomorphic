#!/usr/bin/env python3
"""Reproduce Mithril's certificate signed_message = Sha256( for each (key,value) in protocol_message
(BTreeMap/enum order): key_string||value ). Verified to match the REAL preview cert 7356eaa1.. exactly.
This is the exact in-circuit computation the STARK-Mithril proof attests (relation M1)."""
import json, hashlib, sys
c=json.load(open(sys.argv[1] if len(sys.argv)>1 else "cert.example.json"))
parts=c["protocol_message"]["message_parts"]
order=["cardano_transactions_merkle_root","next_aggregate_verification_key","next_protocol_parameters","current_epoch","latest_block_number"]
h=hashlib.sha256()
for k in [k for k in order if k in parts]:
    h.update(k.encode()); h.update(parts[k].encode())
got=h.hexdigest()
print("computed:", got); print("cert    :", c["signed_message"]); print("MATCH" if got==c["signed_message"] else "MISMATCH")
