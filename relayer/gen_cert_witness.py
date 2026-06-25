#!/usr/bin/env python3
"""gen_cert_witness.py <cardano_burn_txid> <out.json> - parameterized replacement for the stale
bg_ctwitness.sh. Queries the Mithril aggregator for the cert covering the burn, transcodes the BLS-STM
certificate into the CKB-VM cert witness (the AVK-rooted Mithril proof the light-client checkpoint verifies),
and writes {root, height, witHex} for bg_refresh.mjs to publish a fresh authenticated LCKP at that root.
Keyless (public Mithril). Needs transcode_witness in WSL (/root/mv/target/release)."""
import json
import subprocess
import sys
import urllib.request

AGG = "https://aggregator.testing-preview.api.mithril.network/aggregator"
TRANSCODE = "/root/mv/target/release/transcode_witness"


def main() -> int:
    burn, out = sys.argv[1], sys.argv[2]
    d = json.load(urllib.request.urlopen(f"{AGG}/proof/cardano-transaction?transaction_hashes={burn}", timeout=25))
    if burn in d.get("non_certified_transactions", []) or "certificate_hash" not in d:
        print(json.dumps({"status": "wait-certification", "burn": burn}))
        return 0
    c = json.load(urllib.request.urlopen(f"{AGG}/certificate/{d['certificate_hash']}", timeout=25))
    open("/root/ct_burn.json", "w").write(json.dumps(c))
    pm = c["protocol_message"]["message_parts"]
    root, height = pm["cardano_transactions_merkle_root"], int(pm["latest_block_number"])
    epoch = c.get("epoch") or c.get("beacon", {}).get("epoch")
    subprocess.run([TRANSCODE, "/root/ct_burn.json"], check=True, capture_output=True)
    wit = open("/tmp/cert_witness.bin", "rb").read().hex()
    json.dump({"root": "0x" + root, "height": height, "epoch": epoch, "witHex": "0x" + wit}, open(out, "w"))
    print(json.dumps({"status": "ready", "root": "0x" + root, "height": height, "epoch": epoch, "witbytes": len(wit) // 2}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
