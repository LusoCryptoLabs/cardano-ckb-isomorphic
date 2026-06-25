#!/usr/bin/env python3
"""compute_hash.py - reproduce mithril's ProtocolMessage::compute_hash (the exact bytes the
signers sign) from a certificate JSON, and check it equals the cert's signed_message.

CONFIRMED against a real preview cert: SHA-256 over the BTreeMap-ordered message parts,
hashing key.to_string() bytes then value bytes for each part, hex-encoded. Matches
signed_message bit-for-bit. (mithril-common entities/protocol_message.rs.)

Usage: curl .../certificate/<hash> > cert.json ; python3 compute_hash.py cert.json
"""
import json, sys, hashlib
c = json.load(open(sys.argv[1]))
parts = c['protocol_message']['message_parts']   # already in BTreeMap (enum) order from the API
h = hashlib.sha256()
for k, v in parts.items():
    h.update(k.encode()); h.update(v.encode())
got = h.hexdigest()
print("computed:", got)
print("cert    :", c['signed_message'])
print("MATCH" if got == c['signed_message'] else "MISMATCH")
