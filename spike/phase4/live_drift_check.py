#!/usr/bin/env python3
"""live_drift_check.py - fetch the CURRENT preview Mithril cert and re-confirm our in-script
compute_hash construction (SHA-256 over the BTreeMap-ordered message parts: key string bytes then
value bytes, hex-encoded) still equals mithril's own `signed_message`. If mithril changes the
message format upstream, this fails early - before it can silently break the on-chain verifier.
Network-dependent; the CI job is allowed to skip if the aggregator is unreachable."""
import sys, json, hashlib, urllib.request
AGG = "https://aggregator.testing-preview.api.mithril.network/aggregator"

def main():
    epochs = json.load(urllib.request.urlopen(f"{AGG}/certificates", timeout=30))
    ch = epochs[0]["hash"]
    cert = json.load(urllib.request.urlopen(f"{AGG}/certificate/{ch}", timeout=30))
    parts = cert["protocol_message"]["message_parts"]   # JSON order == mithril BTreeMap order
    h = hashlib.sha256()
    for k, v in parts.items():
        h.update(k.encode()); h.update(v.encode())
    ours = h.hexdigest()
    theirs = cert["signed_message"]
    print(f"cert {ch[:12]} parts={list(parts.keys())}")
    print(f"  our compute_hash  = {ours}")
    print(f"  signed_message    = {theirs}")
    if ours == theirs:
        print("OK - compute_hash construction still matches mithril's signed_message."); return 0
    print("DRIFT - message construction changed upstream; the in-script verifier needs updating."); return 1

if __name__ == "__main__":
    sys.exit(main())
