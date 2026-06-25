#!/usr/bin/env python3
"""produce_witness.py <cardano_txid> - emit the BoundAsset input_type witness (MKMapProof) + the
certified tx-set root for a Cardano tx, as JSON. Keyless (Koios + public Mithril). Used by the
BoundAsset orchestrator for genesis/transition/finalize. The witness layout is exactly what the CKB
BoundAsset verifier parses (lp tx_body | lp sub_root | u64 sub_pos | ... ); the root must equal the
on-chain authenticated checkpoint's root for the verify to pass."""
import sys, json, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from relay import mithril_proof, tx_cbor
from transcode import transcode

def main():
    txid = sys.argv[1]
    proof, ch, ok = mithril_proof(txid)
    if not ok:
        print(json.dumps({"status": "wait-certification", "txid": txid, "tip_cert": ch})); return
    full = bytes.fromhex(tx_cbor(txid))
    w, root, got = transcode(proof, full)
    print(json.dumps({"status": "ready", "txid": got, "witness": "0x" + w.hex(), "root": "0x" + root.hex()}))

if __name__ == "__main__":
    main()
