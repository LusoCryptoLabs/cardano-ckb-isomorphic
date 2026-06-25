#!/usr/bin/env python3
"""Per-BURN body+offsets generator for the χADA RETURN leg - the mirror of gen_bridge_body.py.

The return Groth16 proof is `leap_bound_windowed` reused, fed an `xada_burn_live.json` (burn tx body + offsets +
the xada_burn_receipt code-hash) instead of `bridge_lock_live.json`. relay_bind authenticates the body via
ckbhash(body)==tx_hash and binds amount/recipient by reading the receipt at fixed offsets. The ONLY differences
from a bridge_lock_v1 receipt are the receipt LAYOUT (no `kind` byte) → the field offsets shift:

  bridge_lock_v1 : "BRG1"(4) | kind(1) | amount(16 LE) | recipient(28)   = 49 B  -> amount@+5, recipient@+21
  xada_burn_recpt: "XAD1"(4)          | amount(16 LE) | cardano_recip(28) = 48 B  -> amount@+4, recipient@+20

Everything else (the canonical RawTransaction molecule, the offset walk, ckbhash(body)==txid) is byte-identical.

  python3 gen_xada_burn_body.py <burn_txid> <xada_burn_receipt_code_hash> [--rpc URL] [--out PATH]
"""
import argparse, json, urllib.request, hashlib, sys

HT = {"data": 0, "type": 1, "data1": 2, "data2": 4}
DEP = {"code": 0, "dep_group": 1}


def rpc(url, m, p):
    req = urllib.request.Request(url, data=json.dumps({"id": 1, "jsonrpc": "2.0", "method": m, "params": p}).encode(),
                                 headers={"content-type": "application/json", "User-Agent": "gen_xada_burn_body/1"})
    r = json.load(urllib.request.urlopen(req, timeout=25))
    if r.get("error"):
        raise RuntimeError(r["error"])
    return r["result"]


def ckbhash(b): return hashlib.blake2b(b, digest_size=32, person=b"ckb-default-hash").digest()
def u32(n): return int(n).to_bytes(4, "little")
def u64(n): return int(n).to_bytes(8, "little")
def H(h): return bytes.fromhex(h[2:] if h.startswith("0x") else h)
def fixvec(items): return u32(len(items)) + b"".join(items)


def dynvec(items):
    off = 4 + 4 * len(items); offs = []
    for it in items:
        offs.append(off); off += len(it)
    return u32(off) + b"".join(u32(o) for o in offs) + b"".join(items)


table = dynvec
def molbytes(b): return u32(len(b)) + b
def script_mol(s): return table([H(s["code_hash"]), bytes([HT[s["hash_type"]]]), molbytes(H(s["args"]))])
def script_or_none(s): return script_mol(s) if s else b""
def outpoint(o): return H(o["tx_hash"]) + u32(int(o["index"], 16))
def cell_input(i): return u64(int(i["since"], 16)) + outpoint(i["previous_output"])
def cell_output(o): return table([u64(int(o["capacity"], 16)), script_mol(o["lock"]), script_or_none(o.get("type"))])
def cell_dep(d): return outpoint(d["out_point"]) + bytes([DEP[d["dep_type"]]])


def raw_tx_molecule(t):
    return table([
        u32(int(t["version"], 16)),
        fixvec([cell_dep(d) for d in t["cell_deps"]]),
        fixvec([H(h) for h in t["header_deps"]]),
        fixvec([cell_input(i) for i in t["inputs"]]),
        dynvec([cell_output(o) for o in t["outputs"]]),
        dynvec([molbytes(H(d)) for d in t["outputs_data"]]),
    ])


# offset walk over the serialized RawTransaction, locating receipt = outputs[0] fields (== gen_bridge_body.py)
def u32le(b, i): return int.from_bytes(b[i:i + 4], "little")
def field_off(b, i): return u32le(b, 4 + 4 * i)
def cellout_off(b): o = field_off(b, 4); return o + u32le(b, o + 4)
def type_off(b): co = cellout_off(b); return co + u32le(b, co + 12)
def type_code_off(b): t = type_off(b); return t + u32le(b, t + 4)
def data_off(b): o = field_off(b, 5); return o + u32le(b, o + 4) + 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("burn_txid")
    ap.add_argument("burn_receipt_code_hash", help="the xada_burn_receipt type code-hash (relay_bind pins it)")
    ap.add_argument("--rpc", default="https://testnet.ckb.dev")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    got = rpc(a.rpc, "get_transaction", [a.burn_txid])
    if not got or not got.get("transaction"):
        raise SystemExit(f"tx {a.burn_txid} not found on {a.rpc}")
    t = got["transaction"]
    body = raw_tx_molecule(t)
    re = "0x" + ckbhash(body).hex()
    if re != a.burn_txid:
        raise SystemExit(f"body reconstruction mismatch: {re} != {a.burn_txid} (molecule/serialization drift)")

    # χADA burn receipt: "XAD1"(4) | amount(16 LE) | cardano_recipient(28)  -> amount@+4, recipient@+20.
    off = {"type_code": type_code_off(body), "amount": data_off(body) + 4, "recipient": data_off(body) + 20}
    bch = a.burn_receipt_code_hash if a.burn_receipt_code_hash.startswith("0x") else "0x" + a.burn_receipt_code_hash
    got_code = "0x" + body[off["type_code"]:off["type_code"] + 32].hex()
    if got_code != bch:
        raise SystemExit(f"receipt type code-hash {got_code} != {bch} (outputs[0] is not an xada_burn_receipt)")
    magic = body[data_off(body):data_off(body) + 4]
    if magic != b"XAD1":
        raise SystemExit(f"receipt magic {magic!r} != b'XAD1' (outputs[0] data is not a burn receipt)")

    amount = int.from_bytes(body[off["amount"]:off["amount"] + 16], "little")
    recipient = body[off["recipient"]:off["recipient"] + 28].hex()
    # bridge_code_hash names the receipt code the circuit pins (here the burn receipt); same JSON shape as the lock.
    rec = {"bridge_code_hash": bch, "lock_txid": a.burn_txid, "tx_hash": a.burn_txid,
           "amount": str(amount), "recipient": recipient, "body_hex": "0x" + body.hex(), "offsets": off}
    text = json.dumps(rec, indent=2)
    if a.out:
        open(a.out, "w").write(text)
        print(f"per-burn body OK: {len(body)} bytes, amount={amount}, recipient={recipient[:12]}…, "
              f"offsets {off} -> {a.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
