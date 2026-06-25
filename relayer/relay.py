#!/usr/bin/env python3
"""relay.py - the PERMISSIONLESS relayer (Phase 3). Liveness only; it CANNOT forge - the CKB
BoundAsset script re-verifies the Mithril MKMapProof against the certified tx-set root from the
light-client checkpoint cell and binds the commitment. A stalled/byzantine relayer only delays a
transfer; anyone can run one.

Pipeline (per binding-lock seal spend on Cardano):
  1. WATCH   - poll Cardano (Blockfrost) for spends of the binding_lock seal UTxO.
  2. CERTIFY - wait until the spend tx is Mithril-certified (the latency gap we measured).
  3. FETCH   - pull the Mithril CardanoTransactions proof (aggregator) + the raw tx CBOR (Blockfrost)
               + the cert's cardano_transactions_merkle_root.
  4. TRANSCODE (transcode.py) - emit the compact length-prefixed witness the unified script reads.
  5. CLASSIFY - Transfer (seal recreated at lock) -> TRANSITION; Unbind (seal not recreated) -> FINALIZE.
  6. SUBMIT  - hand the witness + chosen checkpoint root to the CKB sidecar to build & send the
               BoundAsset transition/finalize tx (consume old bound cell -> new, or destroy on leap-out).

This module wires steps 1-5 and emits a submission descriptor (JSON) consumed by the ckb-sidecar
(deploy-unified-* / leapout-* mjs). Steps 3-5 are validated against real on-chain-accepted data by
relayer/validate_transcode.py (the transcode reproduces the live transition witness byte-for-byte).
"""
import os, sys, json, time, urllib.request, urllib.error, ssl
from transcode import transcode, proof_from_aggregator_entry, extract_tx_body

AGG = os.environ.get("MITHRIL_AGGREGATOR",
                     "https://aggregator.testing-preview.api.mithril.network/aggregator")
BF_BASE = os.environ.get("BLOCKFROST_BASE", "https://cardano-preview.blockfrost.io/api/v0")
BF_KEY = os.environ.get("BLOCKFROST_PROJECT_ID", "")
# binding-lock instance (preview):
SEAL_POLICY = "8855af1be1fd48ee096b72e91bee858db51b9ab75e866540c8647674"
LOCK_ADDR_HEX = "701cbba2088e24980d54a23bb65de2d1e233a336ccac5b75fb01acd270"

def _get(url, headers=None):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=30))

def _urlopen_tolerant(req, timeout=30):
    """urlopen with normal TLS verification; if the peer presents an EXPIRED cert (e.g. a third-party
    read-only data source like Koios serving a stale cert), retry ONCE unverified with a stderr warning.
    SAFE here ONLY because the fetched tx CBOR is re-verified ON-CHAIN: the Mithril MKMapProof binds
    blake2b256(tx_body) to the certified tx-set root, so a tampered/forged response fails the on-chain
    verify (it can DoS, never forge). Do NOT use this for any data the protocol trusts without on-chain proof."""
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.URLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e) and "expired" in str(e):
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            print("WARN: peer TLS cert expired; retrying unverified (CBOR is re-verified on-chain).", file=sys.stderr)
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raise

def mithril_proof(tx_hash):
    """Return (proof_json, certified) for a tx, or (None, False) if not yet certified."""
    d = _get(f"{AGG}/proof/cardano-transaction?transaction_hashes={tx_hash}")
    ct = d.get("certified_transactions", [])
    if not ct or tx_hash not in ct[0]["transactions_hashes"]:
        return None, d.get("certificate_hash"), False
    return proof_from_aggregator_entry(ct[0]), d["certificate_hash"], True

def cert_root(cert_hash):
    cert = _get(f"{AGG}/certificate/{cert_hash}")
    return cert["protocol_message"]["message_parts"]["cardano_transactions_merkle_root"]

KOIOS_BASE = os.environ.get("KOIOS_BASE", "https://preview.koios.rest/api/v1")

def tx_cbor(tx_hash):
    """Raw tx CBOR. Prefer Blockfrost if a key is set; otherwise fall back to Koios (keyless,
    free) so the relayer/front-end works with no API credentials. Both return identical bytes."""
    if BF_KEY:
        return _get(f"{BF_BASE}/txs/{tx_hash}/cbor", {"project_id": BF_KEY})["cbor"]
    req = urllib.request.Request(
        f"{KOIOS_BASE}/tx_cbor",
        data=json.dumps({"_tx_hashes": [tx_hash]}).encode(),
        headers={"content-type": "application/json", "accept": "application/json"})
    rows = json.load(_urlopen_tolerant(req, 30))
    if not rows:
        raise LookupError(f"tx {tx_hash} not found on Koios (not yet on-chain?)")
    return rows[0]["cbor"]

def classify(full_tx_cbor):
    """TRANSITION if the spend recreates the seal NFT at the binding_lock, else FINALIZE (leap-out)."""
    import cbor2
    body = cbor2.loads(extract_tx_body(full_tx_cbor))
    for o in body[1]:
        addr = o[0] if not isinstance(o, dict) else o[0]
        val = o[1] if not isinstance(o, dict) else o[1]
        if bytes(addr).hex() != LOCK_ADDR_HEX:
            continue
        if isinstance(val, list) and len(val) > 1 and any(bytes(p).hex() == SEAL_POLICY for p in val[1]):
            return "TRANSITION"
    return "FINALIZE"

def build_submission(spend_tx_hash):
    """Steps 3-5: returns a CKB submission descriptor (or a 'wait' status if not yet certified)."""
    proof, ch, ok = mithril_proof(spend_tx_hash)
    if not ok:
        return {"status": "wait-certification", "tx": spend_tx_hash, "tip_cert": ch}
    full = bytes.fromhex(tx_cbor(spend_tx_hash))
    witness, root, txid = transcode(proof, full)
    assert root.hex() == cert_root(ch), "proof master root must equal the cert's tx-set root"
    mode = classify(full)
    return {
        "status": "ready", "mode": mode, "tx": txid,
        "cert_root": "0x" + root.hex(),
        "checkpoint_data": "0x" + b"LCKP".hex() + root.hex(),
        "witness": "0x" + witness.hex(),   # -> WitnessArgs.inputType for the BoundAsset spend
    }

def seal_txs():
    """Recent txs that moved the seal NFT, newest first. Blockfrost if keyed, else Koios (keyless)."""
    asset_policy, asset_name = SEAL_POLICY, "5345414c"  # "SEAL"
    if BF_KEY:
        txs = _get(f"{BF_BASE}/assets/{asset_policy}{asset_name}/transactions?order=desc",
                   {"project_id": BF_KEY})
        return [t["tx_hash"] for t in txs]
    rows = _get(f"{KOIOS_BASE}/asset_txs?_asset_policy={asset_policy}"
                f"&_asset_name={asset_name}&_history=true")
    return [r["tx_hash"] for r in sorted(rows, key=lambda r: r.get("block_height", 0), reverse=True)]

def pending_submissions(limit=10):
    """One non-blocking pass: recent seal spends with their relay status (for an HTTP /pending call)."""
    out = []
    for h in seal_txs()[:limit]:
        try:
            out.append(build_submission(h))
        except Exception as e:
            out.append({"status": "error", "tx": h, "error": str(e)[:160]})
    return out

def watch_binding_lock(poll_s=30):
    """Step 1-2: poll for spends of the seal at the binding_lock; yield certified spends.
    (Generator; the daemon form.) Keyless via Koios unless BLOCKFROST_PROJECT_ID is set."""
    seen = set()
    while True:
        for h in seal_txs():
            if h in seen:
                continue
            seen.add(h)
            sub = build_submission(h)
            if sub["status"] == "ready":
                yield sub
        time.sleep(poll_s)

if __name__ == "__main__":
    # one-shot: relay a specific spend tx (e.g. the unbind 6c729ea6 or the transfer a98b6636)
    if len(sys.argv) < 2:
        print("usage: BLOCKFROST_PROJECT_ID=... relay.py <spend_tx_hash>", file=sys.stderr); sys.exit(2)
    print(json.dumps(build_submission(sys.argv[1]), indent=2))
