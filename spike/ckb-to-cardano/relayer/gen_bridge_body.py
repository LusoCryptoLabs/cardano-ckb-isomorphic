#!/usr/bin/env python3
"""Per-lock body+offsets generator - make relay_bind work for ANY user lock, not just the captured demo.

relay_bind binds the leap's amount/recipient by reading them out of the receipt's RawTransaction body at
fixed offsets, and authenticates the body via ckbhash(body) == tx_hash. bridge_deploy_lock.mjs produced that
body+offsets for the ONE demo lock and froze it into bridge_lock_live.json. For a self-serve dApp, every
user's lock is a different tx, so this reconstructs the SAME artifact on the fly from a confirmed lock txid:

  fetch get_transaction(txid) -> rebuild the canonical RawTransaction molecule -> compute the receipt field
  offsets (type code-hash, amount, recipient) the exact way bridge_deploy_lock.mjs does -> verify
  ckbhash(body) == txid -> write {bridge_code_hash, body_hex, offsets, ...} (the relay_bind input).

Molecule builders mirror ckb_lock.py / bridge_deploy_lock.mjs (canonical CKB serialization). The receipt is
outputs[0]; its LOCK may be the user's lock (demo) or burn_gated_unlock_v2 (conservation-safe) - the offset
walk reads the molecule structure, so it is robust to the lock change.

  python3 gen_bridge_body.py <lock_txid> <bridge_code_hash> [--rpc URL] [--out PATH]
"""
import argparse, json, urllib.request, hashlib, sys

HT = {"data": 0, "type": 1, "data1": 2, "data2": 4}
DEP = {"code": 0, "dep_group": 1}


def rpc(url, m, p):
    req = urllib.request.Request(url, data=json.dumps({"id": 1, "jsonrpc": "2.0", "method": m, "params": p}).encode(),
                                 headers={"content-type": "application/json", "User-Agent": "gen_bridge_body/1"})
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
def script_or_none(s): return script_mol(s) if s else b""        # CellOutput.type is Option<Script>
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


# offset walk over the serialized RawTransaction, locating receipt = outputs[0] fields (== bridge_deploy_lock.mjs)
def u32le(b, i): return int.from_bytes(b[i:i + 4], "little")
def field_off(b, i): return u32le(b, 4 + 4 * i)                   # table field i absolute offset
def cellout_off(b): o = field_off(b, 4); return o + u32le(b, o + 4)      # outputs dynvec -> item[0]
def type_off(b): co = cellout_off(b); return co + u32le(b, co + 12)      # CellOutput table field 2 (type) at +12
def type_code_off(b): t = type_off(b); return t + u32le(b, t + 4)        # Script field 0 (code_hash) at +4
def data_off(b): o = field_off(b, 5); return o + u32le(b, o + 4) + 4     # outputs_data item[0] content (skip len)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lock_txid")
    ap.add_argument("bridge_code_hash", help="the pinned bridge_lock_v1 type code-hash (relay_bind asserts it)")
    ap.add_argument("--rpc", default="https://testnet.ckb.dev")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    got = rpc(a.rpc, "get_transaction", [a.lock_txid])
    if not got or not got.get("transaction"):
        raise SystemExit(f"tx {a.lock_txid} not found on {a.rpc}")
    t = got["transaction"]
    body = raw_tx_molecule(t)
    re = "0x" + ckbhash(body).hex()
    if re != a.lock_txid:
        raise SystemExit(f"body reconstruction mismatch: {re} != {a.lock_txid} (molecule/serialization drift)")

    off = {"type_code": type_code_off(body), "amount": data_off(body) + 5, "recipient": data_off(body) + 21}
    bch = a.bridge_code_hash if a.bridge_code_hash.startswith("0x") else "0x" + a.bridge_code_hash
    got_code = "0x" + body[off["type_code"]:off["type_code"] + 32].hex()
    if got_code != bch:
        raise SystemExit(f"receipt type code-hash {got_code} != bridge_code_hash {bch} (outputs[0] is not a bridge receipt)")

    amount = int.from_bytes(body[off["amount"]:off["amount"] + 16], "little")
    recipient = body[off["recipient"]:off["recipient"] + 28].hex()
    rec = {"bridge_code_hash": bch, "lock_txid": a.lock_txid, "tx_hash": a.lock_txid,
           "amount": str(amount), "recipient": recipient, "body_hex": "0x" + body.hex(), "offsets": off}
    text = json.dumps(rec, indent=2)
    if a.out:
        open(a.out, "w").write(text)
        print(f"per-lock body OK: {len(body)} bytes, amount={amount}, recipient={recipient[:12]}…, "
              f"offsets {off} -> {a.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
