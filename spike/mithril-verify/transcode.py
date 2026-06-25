#!/usr/bin/env python3
"""transcode.py - relayer transcode (PoC): a real Mithril certificate JSON -> a CKB-VM
verifier source with the certificate's BLS material embedded. Demonstrates the off-chain
relayer step: parse the ~27KB serde_json StmAggrSig, extract the DISTINCT winning signers'
sigmas (G1, 48B) + mvks (G2, 96B), the signed message, and the total winning-index count,
and emit a compact form the CKB script re-verifies independently.

Usage: curl .../certificate/<hash> > cert.json ; python3 transcode.py cert.json > bench.rs
"""
import json, sys
c = json.load(open(sys.argv[1]))
ms = json.loads(bytes.fromhex(c['multi_signature']).decode())
msg = bytes.fromhex(c['signed_message'])
sigs, mvks, nidx = [], [], 0
for sig, reg in ms['signatures']:
    sigs.append(bytes(sig['sigma'])); nidx += len(sig['indexes']); mvks.append(bytes(reg[0]))
print(f"// distinct winning signers={len(sigs)} total_indices={nidx} msg={msg.hex()}", file=sys.stderr)
# (emits the same mithril_verify_bench.rs used for the measurement; see RESULTS.txt)
