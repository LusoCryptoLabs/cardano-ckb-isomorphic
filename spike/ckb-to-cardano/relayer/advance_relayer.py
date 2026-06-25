#!/usr/bin/env python3
"""advance_relayer.py - the off-chain state manager for AdvanceCKBCert (header-chain follower, advance_live.rs).

Maintains the Cardano ckbcert checkpoint's view of the CKB chain across advances and produces the per-advance
witness the SNARK consumes. State (one JSON file):
  chain_root        : the current tip's CKB block hash (the checkpoint commits THIS as chain_root)
  total_difficulty  : 32-byte BE cumulative work, anchored at 0 at genesis and summed each advance
  window_root       : Merkle root over the W-slot ring buffer (merge = ckbhash(l||r)); what the per-leap binds
  tip_height        : the current validated tip height
  window_leaves[W]  : ring buffer, leaves[h mod W] = blockhash(h) over the last W heights

The advance circuit (advance_live) reads {chain_root, total_difficulty, window_leaves} + the next header and
proves the transition; this relayer mirrors that transition NATIVELY (so it can advance its bookkeeping without
the SNARK) and emits step.json for the prover. The window construction MATCHES relayer_window.py exactly, so a
per-leap proof binds membership against the SAME window_root this advance maintains.

  advance_relayer.py init  <RPC> <H0> <state.json>        # anchor at height H0 from real CKB headers
  advance_relayer.py step  <RPC> <state.json> <step.json> # emit the next header (tip+1) for advance_live
  advance_relayer.py apply <state.json> <step.json> <new_state.json>   # native transition (no SNARK)
  advance_relayer.py check <state.json> <step.json> <redeemer.json>    # assert SNARK new_state == native next state
env: CHIRAL_WINDOW_DEPTH=6
"""
import sys, os, json, time, urllib.request, hashlib

DEPTH = int(os.environ.get("CHIRAL_WINDOW_DEPTH", "6"))
W = 1 << DEPTH


def ckbhash(d: bytes) -> bytes:
    """CKB default hash: blake2b-256 personalized with 'ckb-default-hash' (matches the circuit's b\"ckb-default-hash\")."""
    return hashlib.blake2b(d, digest_size=32, person=b"ckb-default-hash").digest()


def rpc(url, m, p):
    for a in range(6):
        try:
            req = urllib.request.Request(url, data=json.dumps({"id": 1, "jsonrpc": "2.0", "method": m, "params": p}).encode(),
                                         headers={"content-type": "application/json", "User-Agent": "advance-relayer/1"})
            r = json.load(urllib.request.urlopen(req, timeout=25))
            if r.get("error"):
                raise RuntimeError(r["error"])
            return r["result"]
        except Exception as e:
            if a == 5:
                raise
            time.sleep(2 * (a + 1))


def merge(l, r):
    return ckbhash(bytes.fromhex(l) + bytes.fromhex(r)).hex()


def window_root(leaves):
    """Pairwise bottom-up Merkle (merge = ckbhash(l||r)) over the W ring-buffer leaves - matches advance_live."""
    level = list(leaves)
    while len(level) > 1:
        level = [merge(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def target_from_compact(c):
    e = (c >> 24) & 0xff
    m = c & 0x007fffff
    t = bytearray(32)
    mb = m.to_bytes(4, "big")
    for k in range(3):
        p = 32 - e + k
        if 0 <= p < 32:
            t[p] = mb[1 + k]
    return bytes(t)


def native_difficulty(c):
    tg = int.from_bytes(target_from_compact(c), "big")
    mx = (1 << 256) - 1
    d = mx // tg if tg else 0
    return d.to_bytes(32, "big")


def header_fields(h):
    """Pass through the RawHeader fields advance_live.raw_of_json expects (CKB RPC header schema)."""
    return {k: h[k] for k in ("compact_target", "timestamp", "number", "epoch",
                              "parent_hash", "transactions_root", "proposals_hash", "extra_hash", "dao", "nonce")}


def init(url, H0, out):
    H0 = int(H0)
    lo = H0 - W + 1
    leaves = [None] * W
    for h in range(lo, H0 + 1):
        leaves[h % W] = rpc(url, "get_header_by_number", [hex(h)])["hash"][2:]
    assert all(x is not None for x in leaves), "window not fully populated"
    tip = rpc(url, "get_header_by_number", [hex(H0)])
    state = {
        "rpc": url, "window_depth": DEPTH, "window_size": W,
        "chain_root": tip["hash"][2:],                 # tip block hash == chain_root (header-chain follower)
        "total_difficulty": "00" * 32,                 # anchored at 0; cumulative work summed from here
        "window_root": window_root(leaves),
        "tip_height": H0,
        "window_leaves": leaves,
    }
    json.dump(state, open(out, "w"), indent=1)
    print(f"init: anchored at H0={H0}  chain_root={state['chain_root'][:16]}  window_root={state['window_root'][:16]}  -> {out}")


def step(url, state_path, out):
    st = json.load(open(state_path))
    H = st["tip_height"] + 1
    h = rpc(url, "get_header_by_number", [hex(H)])
    assert h["parent_hash"][2:] == st["chain_root"], \
        f"header {H} parent_hash {h['parent_hash'][2:][:16]} != state chain_root {st['chain_root'][:16]} (chain split or stale state)"
    json.dump({"height": H, "block_hash": h["hash"][2:], "header": header_fields(h)}, open(out, "w"), indent=1)
    print(f"step: height={H}  parent_ok  block_hash={h['hash'][2:][:16]}  -> {out}")


def native_next(st, step):
    """The native transition the SNARK proves: chain_root := new block hash; total += difficulty; window slot update."""
    h = step["header"]
    H = int(h["number"], 16)
    bh = step["block_hash"]
    compact = int(h["compact_target"], 16)
    old_total = int.from_bytes(bytes.fromhex(st["total_difficulty"]), "big")
    new_total = (old_total + int.from_bytes(native_difficulty(compact), "big")).to_bytes(32, "big").hex()
    leaves = list(st["window_leaves"])
    leaves[H % W] = bh
    return {
        "rpc": st.get("rpc"), "window_depth": DEPTH, "window_size": W,
        "chain_root": bh, "total_difficulty": new_total,
        "window_root": window_root(leaves), "tip_height": H, "window_leaves": leaves,
    }


def apply(state_path, step_path, out):
    st = json.load(open(state_path))
    step = json.load(open(step_path))
    ns = native_next(st, step)
    json.dump(ns, open(out, "w"), indent=1)
    print(f"apply: tip {st['tip_height']} -> {ns['tip_height']}  chain_root={ns['chain_root'][:16]}  window_root={ns['window_root'][:16]}  -> {out}")


def check(state_path, step_path, redeemer_path):
    """Safety gate: the SNARK's emitted new_state MUST equal the relayer's native transition, field by field."""
    st = json.load(open(state_path))
    step = json.load(open(step_path))
    rd = json.load(open(redeemer_path))
    ns = native_next(st, step)
    snark = rd["new_state"]
    keys = ["chain_root", "total_difficulty", "window_root", "tip_height"]
    bad = [k for k in keys if str(ns[k]) != str(snark[k])]
    assert not bad, f"relayer native_next != SNARK new_state on {bad}: native={ {k: ns[k] for k in bad} } snark={ {k: snark[k] for k in bad} }"
    print(f"check OK: SNARK new_state == relayer native_next (tip {ns['tip_height']}, window_root {ns['window_root'][:16]})")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "tip":
        print(int(rpc(sys.argv[2], "get_tip_header", [])["number"], 16))
    elif cmd == "init":
        init(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "step":
        step(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "apply":
        apply(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "check":
        check(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print(__doc__)
        sys.exit(1)
