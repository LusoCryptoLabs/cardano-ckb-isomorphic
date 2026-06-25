#!/usr/bin/env python3
"""transcode.py - RELAYER core (Phase 3): turn a real Mithril CardanoTransactions proof + the raw
spend-tx CBOR into the COMPACT length-prefixed witness the unified BoundAsset script reads from
`input_type`. Liveness only - it CANNOT forge: the CKB script re-verifies the MKMapProof (two-level
Blake2s256 MMR) against the certified tx-set root taken from the light-client checkpoint cell, and
binds the commitment. A wrong/missing transcode just delays a transfer; it can never move an asset.

Witness layout (all little-endian; lp = u32 len + bytes; items = u32 count + lp*):
  lp tx_body | lp sub_root | u64 sub_pos | u64 sub_size | items sub_items |
  lp range_key | u64 master_pos | u64 master_size | items master_items
The certified tx-set root (master inner_root) is NOT in the witness - it lives in the checkpoint
cell (cellDep, "LCKP"||root), authenticated on-chain by AdvanceCert. This returns it separately so
the relayer can select/advance the matching checkpoint.
"""
import json, struct, hashlib

def _blake2b256(b): return hashlib.blake2b(b, digest_size=32).digest()

def _cbor_item_len(b, i):
    """Byte length of the single CBOR item starting at b[i] (enough subset for a Conway tx)."""
    ib = b[i]; m = ib >> 5; lo = ib & 0x1f
    if lo < 24: ai, j = lo, i + 1
    elif lo == 24: ai, j = b[i+1], i + 2
    elif lo == 25: ai, j = int.from_bytes(b[i+1:i+3], "big"), i + 3
    elif lo == 26: ai, j = int.from_bytes(b[i+1:i+5], "big"), i + 5
    elif lo == 27: ai, j = int.from_bytes(b[i+1:i+9], "big"), i + 9
    else: raise ValueError("indefinite/reserved not handled")
    if m in (0, 1, 7): return j - i
    if m in (2, 3): return j - i + ai
    if m == 4:
        for _ in range(ai): j += _cbor_item_len(b, j)
        return j - i
    if m == 5:
        for _ in range(ai): j += _cbor_item_len(b, j); j += _cbor_item_len(b, j)
        return j - i
    if m == 6: return j - i + _cbor_item_len(b, j)
    raise ValueError("bad major")

def extract_tx_body(full_tx_cbor: bytes) -> bytes:
    """A Cardano tx is array [body, witnesses, valid, aux]; the txid = blake2b256(body bytes).
    Slice element[0] from the original bytes (NOT re-encoded - the hash is over the exact bytes)."""
    assert full_tx_cbor[0] >> 5 == 4, "tx must be a CBOR array"
    hdr = 1 if (full_tx_cbor[0] & 0x1f) < 24 else 2  # tx arrays use a small (<24) count -> 1-byte hdr
    blen = _cbor_item_len(full_tx_cbor, hdr)
    return full_tx_cbor[hdr:hdr + blen]

def _lp(b): return struct.pack("<I", len(b)) + b
def _items(xs): return struct.pack("<I", len(xs)) + b"".join(_lp(x) for x in xs)
def _u64(n): return struct.pack("<Q", n)
def _h(node): return bytes(node["hash"])

def transcode(proof_json: dict, full_tx_cbor: bytes):
    """proof_json = one entry's decoded MKMapProof ({master_proof, sub_proofs}).
    Returns (witness_bytes, cert_root_bytes, txid_hex)."""
    tx_body = extract_tx_body(full_tx_cbor)
    txid = _blake2b256(tx_body)

    sub_range, sub_wrap = proof_json["sub_proofs"][0]
    sub_mp = sub_wrap["master_proof"]   # the sub-range's MMR proof is itself an MKMap "master_proof"
    rng = sub_range["inner_range"]
    range_key = f"{rng['start']}-{rng['end']}".encode("ascii")
    sub_root = _h(sub_mp["inner_root"])
    sub_pos = sub_mp["inner_leaves"][0][0]
    sub_size = sub_mp["inner_proof_size"]
    sub_items = [_h(it) for it in sub_mp["inner_proof_items"]]
    # the sub leaf the script recomputes must be the ascii-hex of the txid
    sub_leaf = _h(sub_mp["inner_leaves"][0][1])
    assert sub_leaf == txid.hex().encode("ascii"), "sub leaf must be ascii(hex(txid))"

    mp = proof_json["master_proof"]
    cert_root = _h(mp["inner_root"])
    master_pos = mp["inner_leaves"][0][0]
    master_size = mp["inner_proof_size"]
    master_items = [_h(it) for it in mp["inner_proof_items"]]

    w = (_lp(tx_body) + _lp(sub_root) + _u64(sub_pos) + _u64(sub_size) + _items(sub_items)
         + _lp(range_key) + _u64(master_pos) + _u64(master_size) + _items(master_items))
    return w, cert_root, txid.hex()

def proof_from_aggregator_entry(entry: dict) -> dict:
    """A /proof/cardano-transaction certified_transactions[] entry -> decoded MKMapProof."""
    return json.loads(bytes.fromhex(entry["proof"]).decode())

if __name__ == "__main__":
    import sys
    # self-test handled by relayer/validate_transcode.py
    print("transcode module - see relayer/validate_transcode.py", file=sys.stderr)
