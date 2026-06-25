#!/usr/bin/env python3
"""seal_cert_check.py <txid> - exit 0 if the Cardano tx is Mithril-certified (in a CardanoTransactions
snapshot) on preview, else exit 1. Used to gate the CKB genesis on certification."""
import urllib.request, json, sys
A = "https://aggregator.testing-preview.api.mithril.network/aggregator"
tx = sys.argv[1] if len(sys.argv) > 1 else "08000078bce80ed84d5409e12aa28c24e06591c87c23cdfff8606f947ba006cb"
try:
    d = json.load(urllib.request.urlopen(A + "/proof/cardano-transaction?transaction_hashes=" + tx, timeout=25))
    sys.exit(0 if tx in d.get("certified_transactions", []) else 1)
except Exception:
    sys.exit(1)
